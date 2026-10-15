#!/usr/bin/env bash
# analyser-pcap.sh — passe Suricata et Zeek sur une même capture et écrit un résumé chiffré.
#
# Usage   : ./scripts/analyser-pcap.sh <capture.pcap> <etiquette>
# Exemple : ./scripts/analyser-pcap.sh ~/pcaps/2026-xx-xx-famille.pcap c2-famille
#
# Produit, dans rapports/<date>_<etiquette>/ :
#   suricata/eve.json, fast.log   alertes et événements de Suricata
#   zeek/*.log                    journaux de Zeek (conn, dns, http, ssl, x509, files…)
#   balisement.md                 sortie de balisement.py sur le conn.log (rythme des connexions)
#   balisement-http.md            sortie de balisement.py sur le http.log (rythme des requêtes)
#   resume.md                     ce qu'on lit en premier : chiffres et principales lignes
#
# Le script mesure. Il ne conclut pas : la section Verdict de resume.md est à écrire.
#
# Garde-fous : lecture de fichier uniquement (-r), aucune extraction de fichiers,
# aucune résolution de nom. Les pcaps restent hors du dépôt.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage : $0 <capture.pcap> <etiquette>" >&2
    exit 2
fi

PCAP="$(readlink -f "$1")"
ETIQUETTE="$2"
RACINE="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$PATH:/opt/zeek/bin"

for outil in suricata zeek zeek-cut jq python3 sha256sum; do
    command -v "$outil" >/dev/null || { echo "ARRET : $outil introuvable." >&2; exit 1; }
done
[[ -f "$PCAP" ]] || { echo "ARRET : capture introuvable : $PCAP" >&2; exit 1; }

HORODATAGE="$(date +%Y-%m-%d_%H%M%S)"
SORTIE="$RACINE/rapports/${HORODATAGE}_${ETIQUETTE}"
mkdir -p "$SORTIE/suricata" "$SORTIE/zeek"

echo "[1/4] Empreinte de la capture"
EMPREINTE="$(sha256sum "$PCAP" | cut -d' ' -f1)"
TAILLE="$(du -h "$PCAP" | cut -f1)"

# -------------------------------------------------------------------------- Suricata
# -k none : ne pas rejeter les paquets à somme de contrôle invalide. Fréquent dans les
# captures faites sur la machine émettrice (déchargement des sommes vers la carte réseau) ;
# sans cette option, Suricata ignorerait silencieusement une partie du trafic.
echo "[2/4] Suricata"
suricata -r "$PCAP" -k none -l "$SORTIE/suricata" >"$SORTIE/suricata/suricata-console.log" 2>&1 \
    || { echo "ARRET : Suricata a échoué, voir $SORTIE/suricata/suricata-console.log" >&2; exit 1; }

# ------------------------------------------------------------------------------ Zeek
# -C : ignorer les sommes de contrôle, même raison que -k none ci-dessus.
# local : charge site/local.zeek (scripts standard de détection et d'analyse).
echo "[3/4] Zeek"
( cd "$SORTIE/zeek" && zeek -C -r "$PCAP" local >"zeek-console.log" 2>&1 ) \
    || { echo "ARRET : Zeek a échoué, voir $SORTIE/zeek/zeek-console.log" >&2; exit 1; }

# ------------------------------------------------------------------------ balisement
echo "[4/4] Balisement et résumé"
if [[ -f "$SORTIE/zeek/conn.log" ]]; then
    python3 "$RACINE/scripts/balisement.py" "$SORTIE/zeek/conn.log" --format md \
        > "$SORTIE/balisement.md" || true
fi
# Un implant peut garder une seule connexion ouverte et y enchaîner ses requêtes : son
# rythme n'apparaît alors qu'au niveau des requêtes HTTP (cas NetSupport du 2026-02-28).
if [[ -f "$SORTIE/zeek/http.log" ]]; then
    python3 "$RACINE/scripts/balisement.py" "$SORTIE/zeek/http.log" --format md \
        > "$SORTIE/balisement-http.md" || true
fi

# ---------------------------------------------------------------------------- résumé
EVE="$SORTIE/suricata/eve.json"
CONN="$SORTIE/zeek/conn.log"

compter() { grep -vc '^#' "$1" 2>/dev/null || true; }

# Le résumé enchaîne des tubes coupés par head : on relâche -e et pipefail ici, sinon
# un simple SIGPIPE de sort interromprait le script au milieu du rapport.
set +e +o pipefail

{
    echo "# Analyse — ${ETIQUETTE}"
    echo
    echo "| Champ | Valeur |"
    echo "|---|---|"
    echo "| Capture | \`$(basename "$PCAP")\` ($TAILLE) |"
    echo "| SHA-256 | \`$EMPREINTE\` |"
    echo "| Analyse | $HORODATAGE |"
    echo "| Suricata | $(suricata -V 2>/dev/null | head -1) |"
    echo "| Zeek | $(zeek --version 2>/dev/null | head -1) |"
    if [[ -f "$CONN" ]]; then
        debut=$(zeek-cut ts < "$CONN" | sort -n | head -1)
        fin=$(zeek-cut ts < "$CONN" | sort -n | tail -1)
        echo "| Période capturée (UTC) | $(date -u -d @"${debut%.*}" '+%Y-%m-%d %H:%M:%S') → $(date -u -d @"${fin%.*}" '+%Y-%m-%d %H:%M:%S') |"
    fi
    echo
    echo "## Suricata — alertes par signature"
    echo
    if [[ -s "$EVE" ]]; then
        total=$(jq -c 'select(.event_type=="alert")' "$EVE" | wc -l)
        echo "**$total alertes.**"
        echo
        echo "| Nombre | Gravité | Signature | SID |"
        echo "|---|---|---|---|"
        jq -r 'select(.event_type=="alert") | [.alert.severity, .alert.signature, .alert.signature_id] | @tsv' "$EVE" \
            | sort | uniq -c | sort -rn | head -30 \
            | awk -F'\t' '{split($1,a," "); printf "| %s | %s | %s | %s |\n", a[1], a[2], $2, $3}'
        echo
        echo "Événements Suricata par type :"
        echo
        jq -r '.event_type' "$EVE" | sort | uniq -c | sort -rn | awk '{printf "- `%s` : %s\n", $2, $1}'
    else
        echo "Aucun eve.json produit."
    fi
    echo
    echo "## Zeek — volume par journal"
    echo
    echo "| Journal | Lignes |"
    echo "|---|---|"
    for f in "$SORTIE"/zeek/*.log; do
        n="$(basename "$f")"
        [[ "$n" == "zeek-console.log" ]] && continue
        echo "| \`$n\` | $(compter "$f") |"
    done
    if [[ -f "$CONN" ]]; then
        echo
        echo "### Connexions par service"
        echo
        zeek-cut service < "$CONN" | sort | uniq -c | sort -rn | head -15 | awk '{printf "- `%s` : %s\n", $2, $1}'
        echo
        echo "### Destinations les plus contactées"
        echo
        echo "| Connexions | Destination | Port |"
        echo "|---|---|---|"
        zeek-cut id.resp_h id.resp_p < "$CONN" | sort | uniq -c | sort -rn | head -15 \
            | awk '{printf "| %s | %s | %s |\n", $1, $2, $3}'
    fi
    if [[ -f "$SORTIE/zeek/dns.log" ]]; then
        echo
        echo "### Noms résolus (DNS)"
        echo
        zeek-cut query rcode_name < "$SORTIE/zeek/dns.log" | sort | uniq -c | sort -rn | head -20 \
            | awk '{printf "- `%s` (%s) : %s\n", $2, $3, $1}'
    fi
    if [[ -f "$SORTIE/zeek/ssl.log" ]]; then
        echo
        echo "### Serveurs TLS (SNI)"
        echo
        zeek-cut server_name < "$SORTIE/zeek/ssl.log" | sort | uniq -c | sort -rn | head -20 \
            | awk '{printf "- `%s` : %s\n", $2, $1}'
    fi
    if [[ -f "$SORTIE/zeek/http.log" ]]; then
        echo
        echo "### Requêtes HTTP (hôte, méthode, agent)"
        echo
        zeek-cut host method user_agent < "$SORTIE/zeek/http.log" | sort | uniq -c | sort -rn | head -20 \
            | awk -F'\t' '{split($1,a," "); printf "- %s × `%s` · %s · `%s`\n", a[1], a[2], $2, $3}'
    fi
    if [[ -f "$SORTIE/zeek/notice.log" ]]; then
        echo
        echo "### Notices Zeek"
        echo
        zeek-cut note msg < "$SORTIE/zeek/notice.log" | sort | uniq -c | sort -rn | head -20 \
            | awk -F'\t' '{split($1,a," "); printf "- %s × `%s` — %s\n", a[1], a[2], $2}'
    fi
    if [[ -f "$CONN" ]]; then
        echo
        echo "### Port 443 sans TLS ni QUIC, plus d'une minute"
        echo
        echo "Le port 443 est celui du HTTPS : un flux long qui ne parle ni TLS ni QUIC s'y cache"
        echo "(cas NetSupport, HTTP en clair ; cas Natureforce, protocole propre au RAT)."
        echo
        lignes="$(zeek-cut ts id.orig_h id.resp_h id.resp_p service duration orig_bytes resp_bytes < "$CONN" \
            | awk -F'\t' '$4==443 && $5!~/ssl|quic/ && $6>60')"
        if [[ -z "$lignes" ]]; then
            echo "Aucun."
        else
            echo "| Début (UTC) | Source | Destination | Service | Durée | Envoyé (o) | Reçu (o) |"
            echo "|---|---|---|---|---|---|---|"
            echo "$lignes" | while IFS=$'\t' read -r ts o r p sv d ob rb; do
                echo "| $(date -u -d @"${ts%.*}" '+%F %T') | $o | $r | \`$sv\` | ${d%.*} s | $ob | $rb |"
            done
        fi
    fi
    echo
    echo "## Balisement — connexions (conn.log)"
    echo
    if [[ -s "$SORTIE/balisement.md" ]]; then
        tail -n +3 "$SORTIE/balisement.md"
    else
        echo "Aucune sortie (pas de conn.log, ou aucune paire évaluable)."
    fi
    echo
    echo "## Balisement — requêtes HTTP (http.log)"
    echo
    if [[ -s "$SORTIE/balisement-http.md" ]]; then
        tail -n +3 "$SORTIE/balisement-http.md"
    else
        echo "Aucune sortie (pas de http.log, ou aucune paire évaluable)."
    fi
    echo
    echo "## Verdict"
    echo
    echo "> À écrire à la main, en confrontant ce résumé au compte rendu publié avec la capture :"
    echo ">"
    echo "> - **Vu par Suricata** — quelles signatures, sur quelle partie de l'infection."
    echo "> - **Vu par Zeek et le balisement** — quelle conversation, quel score, quel indice."
    echo "> - **Vu par personne** — ce que le compte rendu décrit et qu'aucun outil n'a remonté."
    echo
    echo "**Vu par Suricata :**"
    echo
    echo "**Vu par Zeek / balisement :**"
    echo
    echo "**Vu par personne :**"
} > "$SORTIE/resume.md"

echo
echo "Rapport : $SORTIE/resume.md"
