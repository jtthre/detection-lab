#!/usr/bin/env bash
# convertir-sigma.sh — convertit les règles Sigma du module 01 pour Elastic Security.
#
# Usage   : ./scripts/convertir-sigma.sh [dossier_sigma]
#           (par défaut : ../01-socle-windows/sigma)
#           ATTACK_JSON=<fichier enterprise-attack.json> ./scripts/convertir-sigma.sh
#           (données ATT&CK locales, si github.com est injoignable)
#
# Produit, dans regles/ :
#   eql/<règle>.eql           la requête EQL, celle qu'on importe (like~ : insensible à la casse)
#   lucene/<règle>.txt        la même en Lucene, pour comparaison seulement (sensible à la casse
#                             sur process.command_line : décision du 26/10, voir le relevé)
#   sigma-elastic.ndjson      les règles EQL au format d'import de Kibana Security,
#                             DÉSACTIVÉES, limitées à l'index Sysmon de l'agent
#
# Pipelines : ecs_windows (écrit pour Winlogbeat), puis regles/pipeline-elastic-agent.yml qui
# corrige les écarts relevés dans les données réelles d'Elastic Agent (preuves/
# releve-champs-windows.md). Une règle convertie sans erreur peut quand même être muette :
# chaque requête se confronte au relevé avant import.

set -euo pipefail

RACINE="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="${1:-$RACINE/../01-socle-windows/sigma}"
SORTIE="$RACINE/regles"
CORRECTIF="$SORTIE/pipeline-elastic-agent.yml"
PIPELINES=(-p ecs_windows -p "$CORRECTIF")
INDEX_SYSMON="logs-windows.sysmon_operational-*"

command -v sigma >/dev/null || { echo "ARRET : sigma-cli introuvable (pip install sigma-cli pySigma-backend-elasticsearch)" >&2; exit 1; }
sigma list targets 2>/dev/null | grep -q '\beql\b' || { echo "ARRET : backend Elasticsearch absent (pip install pySigma-backend-elasticsearch)" >&2; exit 1; }
[[ -d "$SOURCE" ]]    || { echo "ARRET : dossier Sigma introuvable : $SOURCE" >&2; exit 1; }
[[ -f "$CORRECTIF" ]] || { echo "ARRET : pipeline correctif introuvable : $CORRECTIF" >&2; exit 1; }

# sigma-cli, avec des données ATT&CK locales si ATTACK_JSON est fourni.
sigma_() {
    if [[ -n "${ATTACK_JSON:-}" ]]; then
        python3 -c 'import sys, sigma.data.mitre_attack as m; m.set_url(sys.argv.pop(1)); sys.argv[0] = "sigma"; from sigma.cli.main import main; main()' \
            "$ATTACK_JSON" "$@"
    else
        sigma "$@"
    fi
}

mkdir -p "$SORTIE/lucene" "$SORTIE/eql"
echo "sigma-cli $(sigma version 2>/dev/null | head -1) · pipelines ecs_windows + $(basename "$CORRECTIF") · source $SOURCE"
echo

echecs=0
for regle in "$SOURCE"/*.yml; do
    nom="$(basename "$regle" .yml)"
    if sigma convert -t eql    "${PIPELINES[@]}" "$regle" 2>/dev/null | grep -v '^Parsing' > "$SORTIE/eql/$nom.eql" \
    && sigma convert -t lucene "${PIPELINES[@]}" "$regle" 2>/dev/null | grep -v '^Parsing' > "$SORTIE/lucene/$nom.txt"; then
        champs="$(grep -oE '\b(winlog\.event_data\.[A-Za-z]+|process\.[a-z_.]+|registry\.[a-z_.]+|network\.direction|user\.[a-z]+|destination\.ip)\b' "$SORTIE/eql/$nom.eql" | sort -u | tr '\n' ' ')"
        printf '  OK      %-36s %s\n' "$nom" "$champs"
    else
        printf '  ECHEC   %s\n' "$nom"
        echecs=$((echecs + 1))
    fi
done

echo
echo "Fichier d'import Kibana (EQL, règles désactivées, index $INDEX_SYSMON) :"
tmp="$(mktemp)"
if sigma_ convert -t eql "${PIPELINES[@]}" -f siem_rule_ndjson "$SOURCE" 2>/dev/null | grep -v '^Parsing' > "$tmp" && [[ -s "$tmp" ]]; then
    # Garde-fous appliqués à chaque règle : désactivée à l'import, un seul index, étiquetée.
    python3 - "$tmp" "$SORTIE/sigma-elastic.ndjson" "$INDEX_SYSMON" <<'PY'
import json, sys
src, dst, index = sys.argv[1:4]
regles = [json.loads(l) for l in open(src, encoding="utf-8") if l.strip()]
with open(dst, "w", encoding="utf-8") as out:
    for r in regles:
        r["enabled"] = False
        r["index"] = [index]
        r["tags"] = sorted(set(r.get("tags", []) + ["Sigma", "detection-lab", "module-04"]))
        out.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"  OK      regles/sigma-elastic.ndjson ({len(regles)} règles, toutes désactivées)")
PY
else
    echo "  ECHEC   données ATT&CK injoignables ? Relancer avec ATTACK_JSON=<enterprise-attack.json>."
    echecs=$((echecs + 1))
fi
rm -f "$tmp"

exit "$echecs"
