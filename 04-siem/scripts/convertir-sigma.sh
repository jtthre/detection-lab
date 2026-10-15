#!/usr/bin/env bash
# convertir-sigma.sh — convertit les règles Sigma du module 01 pour Elastic Security.
#
# Usage   : ./scripts/convertir-sigma.sh [dossier_sigma]
#           (par défaut : ../01-socle-windows/sigma)
#
# Produit, dans regles/ :
#   lucene/<règle>.txt        la requête Lucene, à LIRE avant tout import
#   eql/<règle>.eql           la même règle en EQL (pour les séquences et la corrélation)
#   sigma-elastic.ndjson      toutes les règles, prêtes à importer dans Kibana Security
#                             (le format siem_rule_ndjson télécharge les données ATT&CK :
#                              il faut un accès Internet au moment de la conversion)
#
# Le pipeline ecs_windows a été écrit pour Winlogbeat. Elastic Agent range certains champs
# ailleurs : une règle convertie SANS ERREUR peut être MUETTE. Chaque requête se confronte au
# relevé de champs de la phase 4 avant import, et chaque règle importée commence désactivée.

set -euo pipefail

RACINE="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="${1:-$RACINE/../01-socle-windows/sigma}"
SORTIE="$RACINE/regles"
PIPELINE="ecs_windows"

command -v sigma >/dev/null || { echo "ARRET : sigma-cli introuvable (pip install --user sigma-cli pySigma-backend-elasticsearch)" >&2; exit 1; }
sigma list targets 2>/dev/null | grep -q '\blucene\b' || { echo "ARRET : backend Elasticsearch absent (pip install --user pySigma-backend-elasticsearch)" >&2; exit 1; }
[[ -d "$SOURCE" ]] || { echo "ARRET : dossier Sigma introuvable : $SOURCE" >&2; exit 1; }

mkdir -p "$SORTIE/lucene" "$SORTIE/eql"
echo "sigma-cli $(sigma version 2>/dev/null | head -1) · pipeline $PIPELINE · source $SOURCE"
echo

echecs=0
for regle in "$SOURCE"/*.yml; do
    nom="$(basename "$regle" .yml)"
    if sigma convert -t lucene -p "$PIPELINE" "$regle" 2>/dev/null | grep -v '^Parsing' > "$SORTIE/lucene/$nom.txt" \
       && sigma convert -t eql -p "$PIPELINE" "$regle" 2>/dev/null | grep -v '^Parsing' > "$SORTIE/eql/$nom.eql"; then
        # Les champs qui méritent une vérification dans les données réelles de l'agent.
        a_verifier="$(grep -oE '(winlog\.event_data\.[A-Za-z]+|[a-z_.]+\.caseless|registry\.path|network\.direction|user\.name)' "$SORTIE/lucene/$nom.txt" | sort -u | tr '\n' ' ')"
        printf '  OK      %-36s champs à vérifier : %s\n' "$nom" "${a_verifier:--}"
    else
        printf '  ECHEC   %s\n' "$nom"
        echecs=$((echecs + 1))
    fi
done

echo
echo "Fichier d'import Kibana (télécharge les données ATT&CK, Internet requis) :"
if sigma convert -t lucene -p "$PIPELINE" -f siem_rule_ndjson "$SOURCE" 2>/dev/null | grep -v '^Parsing' > "$SORTIE/sigma-elastic.ndjson.tmp" \
   && [[ -s "$SORTIE/sigma-elastic.ndjson.tmp" ]]; then
    mv "$SORTIE/sigma-elastic.ndjson.tmp" "$SORTIE/sigma-elastic.ndjson"
    echo "  OK      regles/sigma-elastic.ndjson ($(wc -l < "$SORTIE/sigma-elastic.ndjson") règles)"
else
    rm -f "$SORTIE/sigma-elastic.ndjson.tmp"
    echo "  ECHEC   pas d'accès aux données ATT&CK ? Relancer avec la carte NAT branchée."
fi

exit "$echecs"
