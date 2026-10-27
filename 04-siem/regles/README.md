# regles/

Les dix règles Sigma du module 01 (09 et 10 en v2, 03 en v2 depuis le module 04), converties pour
Elastic Security par `scripts/convertir-sigma.sh` (sigma-cli 3.1.0, pySigma-backend-elasticsearch
2.1.1).

| Dossier / fichier | Contenu | Usage |
|---|---|---|
| `pipeline-elastic-agent.yml` | les corrections apportées au pipeline `ecs_windows` | appliqué **après** `ecs_windows` à chaque conversion |
| `eql/` | une requête EQL par règle | **ce qu'on importe** : `like~` et `:` sont insensibles à la casse |
| `lucene/` | la même en Lucene | comparaison seulement (sensible à la casse sur `process.command_line`) |
| `sigma-elastic.ndjson` | les dix règles EQL au format d'import de Kibana Security | importées **désactivées**, sur `logs-windows.sysmon_operational-*` |

Le dépôt reste la source de vérité : une règle modifiée dans Kibana sans être reportée ici est
une règle perdue.

## Les hypothèses du 15/10, et ce que les données ont répondu le 26/10

La première conversion (15/10) passait **sans erreur** pour les dix règles. Le relevé des champs
réellement écrits par Elastic Agent 9.5.5 et l'intégration Windows 3.11.0
(`preuves/releve-champs-windows.md`) a tranché :

| Hypothèse du 15/10 | Réponse des données (26/10) | Correction |
|---|---|---|
| `process.executable.caseless` existe-t-il ? (9 règles) | **Oui**, en minuscules ; un motif en majuscules est normalisé | aucune |
| `process.parent.executable.caseless` (règle 10) | **N'existe pas** : règle **muette** | pipeline : → `process.parent.executable` |
| `winlog.event_data.TargetImage`, `GrantedAccess` (01, 05) | Restent dans `winlog.event_data` | aucune |
| `winlog.event_data.Details` (04, 08) | **Disparu** : la valeur est dans `registry.data.strings`. Règles **muettes** | pipeline : → `registry.data.strings` |
| `registry.path` (04, 08) | Rempli | aucune ; EQL pour la casse (`HKLM\SOFTWARE`) |
| `network.direction` (07) | `egress` | aucune — mais règle non déclenchable dans le lab isolé (plages privées exclues) |
| Exclusion `AUTORITE NT\Système` sur `user.name` (03) | Le compte est éclaté (`user.domain` / `user.name: Système`) : exclusion **inopérante** | règle Sigma v2 : les deux formes, FR et EN. **Pas** `user.id` : il vaut `S-1-5-18` sur tous les événements Sysmon |
| — (non prévu) | `process.command_line` est sensible à la casse : `/Create` échappe à `* /create*` en Lucene (02, 03, 06, 09) | import en **EQL** |

Principe suivi : les règles Sigma décrivent **Sysmon** et restent portables ; ce qui est propre à
Elastic Agent se corrige dans la **traduction** (`pipeline-elastic-agent.yml`). Seule la 03 a
changé de fond, parce que son exclusion ne couvrait qu'une des deux façons d'écrire le compte.

## Reconvertir

```bash
./scripts/convertir-sigma.sh
# sans accès à github.com : données ATT&CK locales (dépôt mitre/cti)
ATTACK_JSON=/chemin/enterprise-attack.json ./scripts/convertir-sigma.sh
```

La sortie ES|QL n'est pas disponible avec `ecs_windows` (contrôle de compatibilité de
sigma-cli).
