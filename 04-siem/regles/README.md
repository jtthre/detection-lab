# regles/

Les dix règles Sigma du module 01 (09 et 10 en v2), converties pour Elastic Security par
`scripts/convertir-sigma.sh` (sigma-cli 3.1.0, pySigma-backend-elasticsearch 2.1.1, pipeline
`ecs_windows`).

| Dossier / fichier | Contenu | Usage |
|---|---|---|
| `lucene/` | une requête Lucene par règle | à **lire** avant import, à coller dans Discover pour tester |
| `eql/` | la même règle en EQL | base des séquences de corrélation (phase 7) |
| `sigma-elastic.ndjson` | les dix règles au format d'import de Kibana Security | importées **désactivées** |

Le dépôt reste la source de vérité : une règle modifiée dans Kibana sans être reportée ici est
une règle perdue.

## Ce que la première conversion annonce déjà (15/10/2026, avant tout test)

Les dix règles se convertissent **sans erreur**. C'est exactement le moment où il ne faut pas
conclure : la conversion traduit des noms de champs selon le pipeline `ecs_windows`, **écrit
pour Winlogbeat**. Ce que l'intégration Windows d'Elastic Agent écrit réellement se vérifie en
phase 4. Les hypothèses à confronter :

| Champ produit par la conversion | Règles | Ce qu'il faut vérifier dans les données de l'agent |
|---|---|---|
| `process.executable.caseless`, `process.parent.executable.caseless` | 01 à 07, 09, 10 | Ce sous-champ insensible à la casse existe-t-il dans le modèle d'index de l'intégration Windows ? S'il n'existe pas, **neuf règles sur dix sont muettes**. |
| `winlog.event_data.TargetImage`, `winlog.event_data.GrantedAccess` | 01, 05 | Sysmon 10 et 8 : l'intégration laisse-t-elle ces champs bruts, ou les range-t-elle en ECS ? |
| `winlog.event_data.Details` | 04, 08 | Sysmon 13 (valeur de registre) : brut, ou `registry.data.strings` ? |
| `registry.path` | 04, 08 | Rempli par l'intégration pour Sysmon 12-13-14 ? |
| `network.direction:egress` | 07 | Quelle valeur l'intégration donne-t-elle à une connexion sortante de Sysmon 3 (`egress`, `outbound`…) ? |
| `user.name` (exclusion `AUTORITE NT\Système`) | 03 | En ECS, `user.name` vaut `SYSTEM` et le domaine est dans `user.domain` : l'exclusion écrite pour le journal brut **ne correspondra jamais** — bruit probable. |

**Une bonne nouvelle déjà acquise** : la règle 07 utilise `cidr`, que Chainsaw ne supportait
pas. La conversion Lucene l'écrit `destination.ip:10.0.0.0\/8`, qu'Elasticsearch comprend sur un
champ de type adresse IP. La règle « non testable » du module 02 devient testable.

**À noter** : la sortie ES|QL n'est pas disponible avec le pipeline `ecs_windows` (vérification
de compatibilité de sigma-cli) ; le format d'import Kibana télécharge les données ATT&CK, donc
s'exécute avec un accès Internet.
