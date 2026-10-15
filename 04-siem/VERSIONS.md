# Versions de l'outillage — module 04

**À remplir après installation**, avec ce que les binaires et Kibana affichent. Elasticsearch,
Kibana, Fleet Server et tous les agents doivent être **à la même version**.

| Composant | Commande de vérification | Version installée | Date |
|---|---|---|---|
| Ubuntu Server (VM siem) | `lsb_release -d` | | |
| Elasticsearch | `curl … https://localhost:9200` → `version.number` | | |
| Kibana | Kibana → Aide → À propos | | |
| Fleet Server (Elastic Agent) | Fleet → Agents | | |
| Elastic Agent — VM Windows | Fleet → Agents | | |
| Elastic Agent — sonde | Fleet → Agents | | |
| Intégration Windows | Intégrations → Windows | | |
| Intégration System | Intégrations → System | | |
| Intégration Zeek | Intégrations → Zeek | | |
| Intégration Suricata | Intégrations → Suricata | | |
| Règles Elastic prêtes à l'emploi | Security → Règles → version du paquet | | |
| sigma-cli | `sigma version` | | |
| pySigma-backend-elasticsearch | `pip show pySigma-backend-elasticsearch` | | |

## Repères au moment de l'écriture (15/10/2026)

- **Elastic 9.5.5** : dernière version publiée, avec correctifs de sécurité (bulletin AV26-1021
  du Centre canadien pour la cybersécurité, 08/10/2026 : Elasticsearch jusqu'à 9.5.5, Kibana
  jusqu'à 9.5.4). Vérifier au moment de l'installation qu'aucune version plus récente n'existe.
- **Intégration Zeek** : exige des journaux **JSON** (`LogAscii::use_json=T`).
- **pySigma-backend-elasticsearch** : branche 2.x.

## Sources inchangées depuis les modules précédents

| Source | Version | Module |
|---|---|---|
| Sysmon | 15.22, schéma 4.91 | 01 |
| Atomic Red Team | voir `02-boucle-de-preuve/` | 02 |
| Suricata | 8.0.7, règles ET Open du 13/10/2026 | 03 |
| Zeek | 9.0.0 | 03 |

## Emplacements retenus

| Quoi | Où |
|---|---|
| VM siem | `192.168.234.20`, réseau hôte uniquement (+ carte NAT débranchée hors installations) |
| Elasticsearch | `https://192.168.234.20:9200` |
| Kibana | `http://192.168.234.20:5601` |
| Fleet Server | `https://192.168.234.20:8220` |
| Autorité de certification d'Elasticsearch | `/etc/elasticsearch/certs/http_ca.crt` (VM siem) |
| Archives d'Elastic Agent | `~/agents/` (VM siem) |
