# Versions de l'outillage — module 04

**À remplir après installation**, avec ce que les binaires et Kibana affichent. Elasticsearch,
Kibana, Fleet Server et tous les agents doivent être **à la même version**.

| Composant | Commande de vérification | Version installée | Date |
|---|---|---|---|
| Ubuntu Server (VM siem-elastic) | `lsb_release -d` | 26.04.1 LTS, à jour | 15/10/2026 |
| Elasticsearch | `curl … https://localhost:9200` → `version.number` | **9.5.5** (build 48acba66, Lucene 10.5.1), `apt-mark hold` | 15/10/2026 |
| Kibana | Kibana → Aide → À propos | **9.5.5**, `apt-mark hold` | 15/10/2026 |
| Fleet Server (Elastic Agent) | Fleet → Agents | **9.5.5** (agent), intégration Fleet Server 1.6.1 | 16/10/2026 |
| Elastic Agent — VM Windows | Fleet → Agents | | |
| Elastic Agent — sonde | Fleet → Agents | | |
| Intégration Windows | Intégrations → Windows | 3.11.0 (ressources seules) | 26/10/2026 |
| Intégration System | Intégrations → System | 3.0.0 (politique Fleet Server ; mise à niveau 3.x proposée le 26/10) | 26/10/2026 |
| Intégration Zeek | Intégrations → Zeek | 5.0.1 (ressources seules) | 26/10/2026 |
| Intégration Suricata | Intégrations → Suricata | 2.27.1 (ressources seules) | 26/10/2026 |
| Règles Elastic prêtes à l'emploi | Security → Règles → version du paquet | paquet *Prebuilt Security Detection Rules* **9.5.9**, 2 157 règles, 0 active | 26/10/2026 |
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
| VM siem-elastic | `192.168.234.20` sur `ens33` (Host-only, sans passerelle) + `ens34` NAT débranchée hors installations |
| Elasticsearch | `https://192.168.234.20:9200` |
| Kibana | `http://192.168.234.20:5601` |
| Fleet Server | `https://192.168.234.20:8220`, certificat CN=fleet-server signé par l'autorité du lab (`/etc/fleet-server-certs/`, expire le 14/10/2028) |
| Pare-feu (ufw) | entrée refusée par défaut ; 22, 5601, 8220, 9200/tcp autorisés **sur ens33 seulement** |
| Clé d'API du script | `verificateur-siem`, lecture seule, id `M7FueaEBpt5M9gXn9siD`, expire le 24/01/2027 |
| Autorité de certification d'Elasticsearch | `/etc/elasticsearch/certs/http_ca.crt`, copie lisible `~/http_ca.crt` (VM siem-elastic) |
| Cluster / nœud | `detection-lab` / `siem-elastic` |
| Archives d'Elastic Agent | `~/agents/` (VM siem-elastic) : Windows x86_64 (228 Mo) et Linux x86_64 (434 Mo), SHA-512 vérifiés, + `fleet-ca.crt` |
