#!/usr/bin/env bash
# =============================================================================
#  Conversion des règles Sigma vers trois cibles différentes
#  Module 01 — Socle de détection Windows
#
#  L'objectif n'est pas d'avoir trois jeux de requêtes : c'est de constater que
#  certaines règles NE SE CONVERTISSENT PAS proprement selon la cible, et de
#  comprendre pourquoi. C'est ça, le livrable intellectuel de l'exercice.
#
#  Prérequis :
#    pip3 install sigma-cli
#    sigma plugin install elasticsearch
#    sigma plugin install splunk
#    sigma plugin install microsoft365defender
#
#  Vérifier ce qui est disponible :
#    sigma plugin list
# =============================================================================

set -uo pipefail

RULES="./sigma"
OUT="./converti"
mkdir -p "$OUT"

echo "== Vérification de la syntaxe avant conversion =="
# sigma check valide la conformité à la spécification.
# Une règle qui échoue ici sera refusée par SigmaHQ : c'est le premier filtre
# à passer avant même de penser à ouvrir une pull request.
sigma check "$RULES" || echo "  (des règles ne passent pas la validation — voir ci-dessus)"
echo

# --- Cible 1 : Elasticsearch / Elastic Security ---------------------------
# Le pipeline ecs_windows traduit les noms de champs Sysmon vers le schéma
# commun d'Elastic. Sans lui, les requêtes cherchent des champs qui n'existent
# pas dans l'index : elles sont syntaxiquement valides et ne remontent rien.
# C'est l'erreur la plus coûteuse à diagnostiquer.
echo "== Elasticsearch (pipeline ecs_windows) =="
sigma convert --target lucene --pipeline ecs_windows "$RULES" \
    > "$OUT/elastic.txt" 2>"$OUT/elastic.err" \
    && echo "  -> $OUT/elastic.txt" \
    || echo "  échec — voir $OUT/elastic.err"

# --- Cible 2 : Splunk ------------------------------------------------------
# Le format savedsearches produit directement un fichier importable, plutôt
# qu'une simple liste de requêtes.
echo "== Splunk (pipeline splunk_windows) =="
sigma convert --target splunk --pipeline splunk_windows "$RULES" \
    > "$OUT/splunk.txt" 2>"$OUT/splunk.err" \
    && echo "  -> $OUT/splunk.txt" \
    || echo "  échec — voir $OUT/splunk.err"

# --- Cible 3 : Microsoft Defender / KQL ------------------------------------
# Celle qui casse le plus souvent. Defender expose une table de télémétrie qui
# lui est propre, et plusieurs champs Sysmon n'y ont aucun équivalent —
# typiquement GrantedAccess, utilisé par la règle 01.
# Quand la conversion échoue, NOTEZ-LE : expliquer pourquoi une règle n'est pas
# portable vaut plus, en entretien, que d'avoir dix règles qui se convertissent.
echo "== Microsoft Defender (KQL) =="
sigma convert --target microsoft365defender "$RULES" \
    > "$OUT/defender.txt" 2>"$OUT/defender.err" \
    && echo "  -> $OUT/defender.txt" \
    || echo "  échec — voir $OUT/defender.err"

echo
echo "== Terminé. Consultez les fichiers .err : ce sont eux qui vous apprennent le plus. =="
