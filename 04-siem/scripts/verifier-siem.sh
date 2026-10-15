#!/usr/bin/env bash
# verifier-siem.sh — l'état du SIEM avant de s'en servir.
#
# Usage : ES_API_KEY=<clé encodée> ./scripts/verifier-siem.sh
#
# La clé d'API se crée dans Kibana (Gestion de la pile → Clés d'API), avec des droits de
# LECTURE seulement, et se garde dans le gestionnaire de mots de passe. Elle ne s'écrit dans
# aucun fichier : on la donne au script par une variable d'environnement, le temps d'une
# commande (la ligne commence par une espace pour ne pas finir dans l'historique bash).
#
# Variables facultatives :
#   ES_URL  (https://192.168.234.20:9200)   KB_URL (http://192.168.234.20:5601)
#   ES_CA   (~/http_ca.crt : copie de /etc/elasticsearch/certs/http_ca.crt, illisible sans sudo)
#
# Le script ne modifie rien. Il constate.

set -uo pipefail
ES_URL="${ES_URL:-https://192.168.234.20:9200}"
KB_URL="${KB_URL:-http://192.168.234.20:5601}"
ES_CA="${ES_CA:-$HOME/http_ca.crt}"
echecs=0

ok()     { printf '  %-30s OK      %s\n' "$1" "$2"; }
alerte() { printf '  %-30s ALERTE  %s\n' "$1" "$2"; }
echec()  { printf '  %-30s ECHEC   %s\n' "$1" "$2"; echecs=$((echecs + 1)); }

[[ -n "${ES_API_KEY:-}" ]] || { echo "ARRET : ES_API_KEY non définie (voir l'en-tête du script)." >&2; exit 2; }
command -v jq >/dev/null || { echo "ARRET : jq introuvable." >&2; exit 2; }
[[ -r "$ES_CA" ]] || { echo "ARRET : autorité de certification illisible : $ES_CA" >&2; exit 2; }

es() { curl -s --max-time 10 --cacert "$ES_CA" -H "Authorization: ApiKey $ES_API_KEY" "$ES_URL$1"; }
kb() { curl -s --max-time 10 -H "Authorization: ApiKey $ES_API_KEY" "$KB_URL$1"; }

echo
echo "Point                          Etat    Constat"
echo "-----                          ----    -------"

# 1. Isolation : le SIEM ne sort pas sur Internet en service.
if timeout 3 bash -c '</dev/tcp/1.1.1.1/443' 2>/dev/null; then
    alerte "Isolation reseau" "1.1.1.1:443 joignable — carte NAT encore branchee ?"
else
    ok "Isolation reseau" "aucune route sortante"
fi

# 2. Elasticsearch répond, et quelle version.
version="$(es / | jq -r '.version.number // empty')"
if [[ -n "$version" ]]; then ok "Elasticsearch" "version $version"; else echec "Elasticsearch" "pas de reponse sur $ES_URL"; fi

# 3. Santé du cluster : vert attendu (réplicas à 0 via logs@custom), jaune toléré.
sante="$(es /_cluster/health | jq -r '.status // empty')"
case "$sante" in
    green)  ok "Sante du cluster" "verte" ;;
    yellow) alerte "Sante du cluster" "jaune — replicas non portes (logs@custom : number_of_replicas 0)" ;;
    *)      echec "Sante du cluster" "${sante:-inconnue}" ;;
esac

# 4. Kibana.
etat_kb="$(kb /api/status | jq -r '.status.overall.level // empty')"
if [[ "$etat_kb" == "available" ]]; then ok "Kibana" "disponible"; else echec "Kibana" "${etat_kb:-pas de reponse sur $KB_URL}"; fi

# 5. Agents Fleet : tous en bonne santé, tous à la version d'Elasticsearch.
agents="$(kb '/api/fleet/agents?perPage=100')"
if [[ -n "$agents" ]] && echo "$agents" | jq -e '.items' >/dev/null 2>&1; then
    total="$(echo "$agents" | jq '.items | length')"
    malades="$(echo "$agents" | jq '[.items[] | select(.status != "online")] | length')"
    decales="$(echo "$agents" | jq --arg v "$version" '[.items[] | select(.agent.version != $v)] | length')"
    liste="$(echo "$agents" | jq -r '[.items[] | "\(.local_metadata.host.hostname)=\(.status)"] | join(", ")')"
    if (( malades == 0 && decales == 0 )); then ok "Agents Fleet" "$total en ligne, version $version : $liste"
    else echec "Agents Fleet" "$malades hors ligne, $decales a une autre version : $liste"; fi
else
    echec "Agents Fleet" "API Fleet injoignable ou droits insuffisants"
fi

# 6. Les flux de données attendus, et leur volume.
for flux in logs-windows.sysmon_operational logs-system.security logs-zeek.connection logs-suricata.eve; do
    n="$(es "/$flux-*/_count" | jq -r '.count // empty')"
    if [[ -n "$n" && "$n" -gt 0 ]]; then ok "Flux $flux" "$n documents"
    else alerte "Flux $flux" "vide ou absent (normal tant que la source n'est pas branchee)"; fi
done

# 7. Disque du nœud : Elasticsearch passe en lecture seule vers 95 %.
disque="$(es '/_cat/allocation?format=json' | jq -r '.[0]["disk.percent"] // empty')"
if [[ -z "$disque" ]]; then echec "Disque du noeud" "inconnu"
elif (( disque < 80 )); then ok "Disque du noeud" "${disque} % utilises"
else alerte "Disque du noeud" "${disque} % utilises — seuils d'Elasticsearch a 85/90/95 %"; fi

# 8. Moteur de règles : combien de règles, combien actives.
regles="$(kb '/api/detection_engine/rules/_find?per_page=1' | jq -r '.total // empty')"
actives="$(kb '/api/detection_engine/rules/_find?per_page=1&filter=alert.attributes.enabled:true' | jq -r '.total // empty')"
if [[ -n "$regles" ]]; then ok "Regles de detection" "$regles installees, $actives actives"
else echec "Regles de detection" "API injoignable (cle de chiffrement de Kibana absente ?)"; fi

echo
if (( echecs == 0 )); then echo "SIEM pret."; exit 0
else echo "$echecs controle(s) en echec."; exit 1; fi
