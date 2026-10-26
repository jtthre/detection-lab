# Relevé des champs — VM Windows, intégration Windows 3.11.0 (26/10/2026)

**Pourquoi ce relevé.** La conversion Sigma de la phase 0 (pipeline `ecs_windows` de
pySigma-backend-elasticsearch 2.1.1) a été écrite pour Winlogbeat. Elle suppose des noms de
champs. Ce relevé dit lesquels **existent vraiment** dans les données d'Elastic Agent 9.5.5 avec
l'intégration Windows 3.11.0, et donc quelles règles fonctionneraient telles quelles.

**Méthode.** Événements Sysmon réels de la VM (`DESKTOP-93TE1KB`, Windows 11 Famille en
français, Sysmon 15.22 avec la configuration du module 01), lus dans Discover :
`whoami /groups` lancé à la main (Sysmon 1), un `svchost` lancé par SYSTEM (Sysmon 1), un accès à
LSASS (Sysmon 10), une écriture de registre (Sysmon 13). Aucun export brut n'est versionné : seuls
les noms de champs et des valeurs génériques sont recopiés ici.

## Constats

| # | Constat | Preuve |
|---|---|---|
| C1 | `process.executable.caseless` **existe**, en minuscules | `c:\windows\system32\whoami.exe` |
| C2 | Une requête Lucene en majuscules sur `.caseless` **trouve** quand même : le motif est normalisé | `process.executable.caseless:*\\WHOAMI.EXE` → 2 documents |
| C3 | `process.parent.executable.caseless` **n'existe pas** (seulement `process.parent.executable` et `.text`) ; `process.parent.name` n'a pas de `.caseless` non plus | document `whoami` |
| C4 | `process.command_line` est un `keyword` **sensible à la casse**, sans `.caseless` (seulement `.text`, analysé) | document `whoami` |
| C5 | Le compte est **éclaté** : `user.domain` + `user.name`, et **traduit** : SYSTEM devient `AUTORITE NT` / `Système` | `svchost` lancé par services.exe |
| C6 | `user.id` **n'est pas** le propriétaire du processus : il vaut `S-1-5-18` sur tous les événements Sysmon, y compris le `whoami` de `win11` — c'est le compte qui écrit le journal (le service Sysmon) | `whoami` : `user.name: win11`, `user.id: S-1-5-18` |
| C7 | Sysmon 10 : `TargetImage` et `GrantedAccess` **restent** dans `winlog.event_data.*` ; la source est dans `process.executable` | accès à LSASS |
| C8 | Sysmon 13 : `Details` **disparaît** de `winlog.event_data` ; la valeur écrite est dans `registry.data.strings` (et son type dans `registry.data.type`) ; la clé dans `registry.path` | écriture de registre |
| C9 | L'Elastic Agent **ouvre lui-même LSASS** (`elastic-otel-collector.exe`, `GrantedAccess: 0x1000`) : nouvelle source légitime d'événements Sysmon 10 depuis l'installation de l'agent | accès à LSASS |
| C10 | Les champs Sysmon qui ont un équivalent ECS (`Image`, `CommandLine`, `ParentImage`, `User`…) **ne sont plus** dans `winlog.event_data` ; restent ceux sans équivalent (`IntegrityLevel`, `LogonId`, `ParentUser`…) | les trois types |

## Conséquences pour les dix règles

| # | Règle | Champs visés par la conversion | Verdict | Correction à apporter (phase 5) |
|---|---|---|---|---|
| 01 | Accès mémoire LSASS | `winlog.event_data.TargetImage`, `GrantedAccess`, `process.executable.caseless` | **OK** (C7) | surveiller C9 : `0x1000` n'est pas dans la liste, pas de faux positif attendu |
| 02 | PowerShell encodé | `process.executable.caseless`, `process.command_line` | **fragile** (C4) | version EQL (`like~`, insensible à la casse) : `-EncodedCommand`, `-ENC` passent en Lucene |
| 03 | Tâche planifiée | `process.command_line`, exclusion sur `user.name` | **exclusion inopérante** (C5) et **casse** (C4) | exclure `user.domain : "AUTORITE NT" and user.name : "Système"` (+ `NT AUTHORITY` / `SYSTEM`) ; **pas** `user.id` (C6) ; version EQL : l'atomique T1053.005-1 écrit `/Create` |
| 04 | Clé de démarrage | `registry.path`, `winlog.event_data.Details` | **muette** (C8) | `Details` → `registry.data.strings` ; vérifier la casse de `registry.path` pour HKLM (`SOFTWARE` ?) |
| 05 | Thread distant | `winlog.event_data.TargetImage`, `process.executable.caseless` | **OK a priori** (C7, même schéma que Sysmon 10) | à confirmer sur un événement Sysmon 8 |
| 06 | Rundll32 détourné | `process.executable.caseless`, `process.command_line` | **fragile** (C4) | version EQL |
| 07 | LOLBin sortant | `network.direction`, `process.executable.caseless`, `destination.ip` | **à vérifier** | relever la valeur de `network.direction` sur un Sysmon 3 |
| 08 | Service suspect | `registry.path`, `winlog.event_data.Details` | **muette** (C8) | `Details` → `registry.data.strings` |
| 09 | Clichés instantanés | `process.executable.caseless`, `process.command_line` | **fragile** (C4) | version EQL |
| 10 | Exécution WMI | `process.parent.executable.caseless` | **muette** (C3) | `process.parent.name` (EQL `:` insensible à la casse) |

**Décision.** On importe les règles en **EQL** plutôt qu'en Lucene : l'opérateur `like~` d'EQL
est insensible à la casse, ce qui règle C4 sans dépendre d'un champ `.caseless` absent. Les
corrections C3, C5 et C8 se font **dans le dépôt** (règle Sigma ou pipeline de conversion), puis
on reconvertit — jamais en retouchant la requête à la main dans Kibana.

**Bilan avant rejeu** : 2 règles prêtes (01, 05), 4 fragiles (02, 03, 06, 09), 3 muettes
(04, 08, 10), 1 à vérifier (07). Sans ce relevé, trois règles auraient été importées, activées, et
silencieuses pour toujours.
