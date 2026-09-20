# Preuves — Module 01

Captures horodatées du 20 septembre 2026, prises sur la VM de lab.

| Fichier | Ce qu'il prouve |
|---|---|
| `2026-09-20_sysmon-config-validee.png` | Sysmon v15.22 charge la configuration du dépôt — `Configuration file validated`. Montre aussi le message « already registered » qui distingue `-i` de `-c`. |
| `2026-09-20_sysmon-distribution-evenements.png` | Cinq événements `10` (accès à LSASS) horodatés, plus la distribution des sources sur 200 événements. Prouve que les événements désactivés par défaut sont bien actifs. |
| `2026-09-20_sigma-check-5-issues.png` | Validation des dix règles : 0 erreur, 5 anomalies — 3 blocs orphelins, 2 étiquettes ATT&CK. État avant correction. |

## Pourquoi garder l'état « avant correction »

La troisième capture montre des défauts, et c'est délibéré. Un dépôt qui ne montre que
des résultats propres ne prouve pas qu'on sait tester : il prouve qu'on sait publier.

Le couple « voici ce que le validateur a trouvé » / « voici le commit qui corrige » vaut
davantage qu'une capture verte seule — l'analyse est dans le [journal](../JOURNAL.md),
section 6.

## Convention

`AAAA-MM-JJ_sujet.png`. L'horodatage doit rester visible dans la capture elle-même :
c'est lui qui rattache la preuve au commit.
