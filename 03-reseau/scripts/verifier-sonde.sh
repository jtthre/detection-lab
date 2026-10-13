#!/usr/bin/env bash
# verifier-sonde.sh — les contrôles avant toute analyse de capture.
#
# Usage : ./scripts/verifier-sonde.sh
#
# Le script ne modifie rien. Il constate. Un contrôle en ÉCHEC : on n'analyse pas.
# Un contrôle en ALERTE : on peut analyser, mais on le note dans le rapport.

set -uo pipefail
export PATH="$PATH:/opt/zeek/bin"
RACINE="$(cd "$(dirname "$0")/.." && pwd)"
echecs=0

ok()     { printf '  %-28s OK      %s\n' "$1" "$2"; }
alerte() { printf '  %-28s ALERTE  %s\n' "$1" "$2"; }
echec()  { printf '  %-28s ECHEC   %s\n' "$1" "$2"; echecs=$((echecs + 1)); }

echo
echo "Point                        Etat    Constat"
echo "-----                        ----    -------"

# 1. Isolation : aucune route vers Internet pendant l'analyse.
if timeout 3 bash -c '</dev/tcp/1.1.1.1/443' 2>/dev/null; then
    echec "Isolation reseau" "1.1.1.1:443 joignable — passer la carte en reseau hote uniquement"
else
    ok "Isolation reseau" "aucune route sortante"
fi

# 2. Suricata présent et configuration valide.
if command -v suricata >/dev/null; then
    v="$(suricata -V 2>/dev/null | head -1)"
    if suricata -T -l /tmp >/dev/null 2>&1; then
        ok "Suricata" "$v — configuration valide"
    else
        echec "Suricata" "$v — suricata -T echoue (lancer : suricata -T -l /tmp)"
    fi
else
    echec "Suricata" "introuvable"
fi

# 3. Règles chargées : un Suricata sans règles n'alerte jamais, et ne le signale pas.
chemin="$(suricata --dump-config 2>/dev/null | awk -F' = ' '/^default-rule-path/ {print $2}')"
regles="${chemin:-/var/lib/suricata/rules}/suricata.rules"
if [[ -s "$regles" ]]; then
    n="$(grep -c '^alert' "$regles" 2>/dev/null || true)"
    ok "Regles Suricata" "$n regles actives dans $regles"
else
    echec "Regles Suricata" "$regles absent ou vide — lancer suricata-update"
fi

# 4. Extraction de fichiers désactivée (garde-fou du README).
if suricata --dump-config 2>/dev/null | grep -Eq '^outputs\.[0-9]+\.file-store\.enabled = yes'; then
    echec "Extraction Suricata" "file-store active — la desactiver dans suricata.yaml"
else
    ok "Extraction Suricata" "file-store desactive"
fi

# 5. Zeek et zeek-cut.
if command -v zeek >/dev/null && command -v zeek-cut >/dev/null; then
    ok "Zeek" "$(zeek --version 2>/dev/null | head -1)"
else
    echec "Zeek" "zeek ou zeek-cut introuvable (PATH : /opt/zeek/bin ?)"
fi

# 6. Outils annexes.
manque=""
for o in jq python3 sha256sum; do command -v "$o" >/dev/null || manque="$manque $o"; done
if [[ -z "$manque" ]]; then ok "Outils annexes" "jq, python3, sha256sum"; else echec "Outils annexes" "manquants :$manque"; fi

# 7. Aucune capture dans le dépôt : les pcaps restent hors de Git.
dans_depot="$(find "$RACINE" \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) -not -path '*/.git/*' 2>/dev/null | head -3)"
if [[ -n "$dans_depot" ]]; then
    echec "Captures hors depot" "capture trouvee dans le depot : $(echo "$dans_depot" | head -1)"
else
    ok "Captures hors depot" "aucun pcap sous $(basename "$RACINE")/"
fi

# 8. Espace disque : Zeek et Suricata écrivent beaucoup sur une grosse capture.
libre_go="$(df -BG --output=avail "$RACINE" | tail -1 | tr -dc '0-9')"
if (( libre_go >= 5 )); then
    ok "Espace disque" "${libre_go} Go libres"
else
    alerte "Espace disque" "${libre_go} Go libres — risque sur une grosse capture"
fi

echo
if (( echecs == 0 )); then
    echo "Prealables satisfaits. Verifiez encore a la main :"
    echo "  - instantane \"sonde outillee hors ligne\" present dans l'hyperviseur"
    echo "  - empreinte SHA-256 de chaque capture conforme a celle publiee"
    exit 0
else
    echo "$echecs controle(s) en echec : pas d'analyse tant qu'ils ne sont pas corriges."
    exit 1
fi
