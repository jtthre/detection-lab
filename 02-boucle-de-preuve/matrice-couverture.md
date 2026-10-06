# Matrice de couverture — module 02

Campagne des 1ᵉʳ, 2 et 6 octobre 2026 · VM Windows 11 **Famille** isolée · Sysmon 15.22,
schéma 4.91 · Chainsaw sur les dix règles du module 01, Hayabusa en second avis.

Ce fichier est le livrable du module. Les règles prouvent qu'on sait écrire du YAML ; ce
tableau prouve qu'on sait mesurer ce qu'on détecte et **nommer ce qu'on ne détecte pas**.

---

## Tableau principal

| # | Règle | Technique | Atomique | Détections | Verdict |
|---|---|---|---|---|---|
| 01 | Accès mémoire LSASS | T1003.001 | **2** — comsvcs.dll | 14 → **0** | **Non éprouvée** — bloquée par le noyau |
| 02 | PowerShell encodé | T1059.001 | **15** + T1047-7 | 4 → **9** | **Corrigée** — faux négatif |
| 03 | Tâche planifiée | T1053.005 | **1** | **2** | **Validée** |
| 04 | Clé de démarrage | T1547.001 | — | 4 → **0**, puis 4 → **0** | **Corrigée** — faux positif, en deux temps |
| 05 | Thread distant | T1055.001 | **1** — mavinject | — | **Non éprouvée** — outil absent de l'édition |
| 06 | Rundll32 détourné | T1218.011 | *(effet de bord de T1003.001-2)* | **1** | **Validée** |
| 07 | LOLBin sortant | T1105 | — | — | **Non testable** sous Chainsaw |
| 08 | Service suspect | T1543.003 | *(lecture de -2 et -6)* | 1 → **0** | **Couverture partielle** — angle mort constaté |
| 09 | Clichés instantanés | T1490 | — | — | Non testée *(destructif)* |
| 10 | Exécution WMI | T1047 | **7** | **3** | **Validée** |

**Résultat : 3 validées · 2 corrigées · 1 couverture partielle · 2 non éprouvées · 1 non
testable · 1 non testée.**

---

## Les lignes closes, en détail

### 01 — Accès mémoire LSASS : non éprouvée

L'atomique a bien démarré : événement Sysmon 1 présent, `rundll32.exe` lancé avec la commande
MiniDump visant le PID de LSASS. Mais **aucun événement 10 depuis `rundll32`**, et aucun
fichier de dump créé.

Cause établie : `RunAsPPL = 2`. LSASS tourne en processus protégé ; l'ouverture du handle est
refusée **au niveau du noyau**, donc Sysmon n'a rien à journaliser. Defender était désactivé
pendant le test — la prévention vient du système, pas de l'antivirus.

Les 9 événements 10 de la fenêtre sont tous `svchost.exe` en `GrantedAccess: 0x1000`, une
simple requête d'information que la règle ne sélectionne pas. Comportement correct.

**Conséquence** : sur un poste Windows 11 avec RunAsPPL actif, cette règle ne détecte pas une
tentative bloquée. Elle reste pertinente là où la protection LSA n'est pas déployée — ce qui
reste le cas de beaucoup de serveurs.

**Validation complémentaire à prévoir** : VM dédiée avec RunAsPPL désactivé, ou variante de la
technique n'exigeant pas `PROCESS_VM_READ`.

**Faux positif corrigé au passage.** `csrss.exe` et `wininit.exe` ouvrent un handle `0x1fffff`
sur LSASS au démarrage de Windows : **14 occurrences** sur le journal du 20/09 au 02/10. Le
filtre a été repris **en chemin complet** au lieu de `|endswith` — un filtre d'exclusion est
la porte de sortie de la règle, il doit être le plus étroit possible. Réanalyse du même EVTX
après correction : **0**.

### 02 — PowerShell encodé : faux négatif corrigé

**C'est la ligne la plus instructive de la campagne.**

Avant correction, la règle remontait 4 détections — **toutes fausses**. Toutes portaient la
même signature : `powershell.exe & {Out-ATHPowerShellCommandLineParameter … -EncodedCommandParamVariation …}`.
La règle matchait le **texte** ` -enco` à l'intérieur d'un bloc de script, pas un
comportement.

Dans le même journal se trouvaient **5 vraies commandes encodées** qu'elle ne voyait pas
(horodatages UTC) :

| Horodatage | Parent | Forme |
|---|---|---|
| 18:05:24 | `wbem\WmiPrvSE.exe` | `powershell.exe -NoProfile -E <base64>` |
| 18:28:32 | `wbem\WmiPrvSE.exe` | idem |
| 18:31:39 | `wbem\WmiPrvSE.exe` | idem |
| 18:37:21 | `cmd.exe` | `powershell -exec bypass -e <base64>` |
| 18:41:33 | `powershell.exe` | nettoyage de l'atomique — `-NoProfile -E <base64>` |

La règle cherchait `' -enc '`, `' -enco'`, `' -encodedcommand'`, `' -ec '` — **pas `' -e '`**.
Or `powershell.exe` accepte `-e` comme abréviation de `-EncodedCommand`, et c'est la forme la
plus courte, donc celle qu'un attaquant soucieux de discrétion choisira.

**Taux de vrais positifs avant correction : 0 %.** La règle passait `sigma check` sans erreur
et remontait des alertes — elle paraissait fonctionner. Elle était aveugle.

Après ajout de `' -e '`, réanalyse : **9 détections, dont 5 vraies**.

**Les 4 faux positifs ne sont pas filtrés, délibérément.** Ils viennent d'une correspondance
de sous-chaîne sur une ligne de commande. Le seul correctif propre serait une expression
régulière avec limite de mot, que Chainsaw ne supporte pas — même famille de problème que
`cidr` sur la règle 07. Documenté, et à valider au module 04 sous Elastic.

### 03 — Tâche planifiée : validée

Atomique `T1053.005-1`, création de la tâche `T1053_005_OnLogon` confirmée par le système.
**2 détections**, toutes deux liées au test. La règle exige bien ses deux critères depuis la
correction des blocs orphelins du module 01.

### 04 — Clé de démarrage : faux positif corrigé

Aucun atomique lancé — le faux positif est apparu pendant l'analyse de la campagne 01.

**4 occurrences, toutes imputables à `OneDriveSetup.exe`**, qui écrit des entrées `RunOnce` de
nettoyage dont le `Details` référence `\AppData\` :

```
RunOnce\Delete Cached Update Binary
RunOnce\Delete Cached Standalone Update Binary
RunOnce\Uninstall 26.163.0823.0004
```

Quatre alertes à **chaque** mise à jour de OneDrive, sur **chaque** poste du parc : c'est une
règle désactivée en deux semaines.

Filtre ancré sur **deux** champs — le binaire et la forme de la commande — car un seul serait
trop facile à imiter. Limite assumée : filtre sur nom de binaire, impossible à verrouiller sur
un chemin absolu puisque OneDrive s'installe dans le profil utilisateur. À compenser par une
vérification de signature au module 04.

Réanalyse du même EVTX après correction : **0**.

**Le filtre a cédé trois jours plus tard.** Le 6 octobre à 01:57 UTC, 4 nouvelles alertes : même
mécanisme, nouvelle version (`26.168.0830.0006`), mais écrites cette fois par
`…\OneDrive\StandaloneUpdater\OneDriveSetup.exe`. **OneDrive possède deux programmes de mise à
jour**, et le filtre n'en connaissait qu'un. Il tenait sur cinq heures de mesure ; il n'a pas
tenu trois jours. Les deux chemins sont désormais listés, réanalyse : **4 → 0**.

C'est l'illustration la plus nette de la campagne : **un filtre validé sur une fenêtre courte
n'est pas un filtre validé.**

### 05 — Thread distant : non éprouvée

Atomique `T1055.001-1`. La cible a bien été lancée (deux processus Notepad à 19:19:16 et
19:19:18 locale), mais **l'outil d'injection n'a jamais démarré** : aucun événement 1 pour lui,
aucun événement 8 dans la fenêtre du test. `Test-Path` confirme qu'il n'existe pas sur la VM —
c'est un composant des éditions Entreprise et Éducation, absent de l'édition Famille.

La règle n'est pas en cause : il n'y avait rien à observer.

**Bruit de fond constaté au passage.** Deux événements 8 à source `<unknown process>` en
quelques heures — l'un vers `powershell.exe` (hors liste de cibles, pas d'alerte), l'autre vers
`svchost.exe` à 01:35 UTC, une minute après une mise à jour de Defender (**1 alerte**). Le
processus source se termine avant que Sysmon puisse le résoudre. **Ce faux positif n'est
délibérément pas filtré** : exclure les sources inconnues offrirait une échappatoire à tout
processus qui se termine assez vite.

### 06 — Rundll32 détourné : validée

Pas d'atomique dédié : la règle a déclenché **sur le test de la règle 01**, qui utilisait
`rundll32.exe` pour charger `comsvcs.dll`.

Enseignement : la technique testée était `T1003.001` (vol d'identifiants), c'est la règle
`T1218.011` (binaire détourné) qui l'a attrapée. **Un attaquant qui détourne un LOLBin se fait
voir deux fois** — et la règle qui le voit n'est pas forcément celle qu'on croit.

### 07 — LOLBin sortant : non testable sous ce moteur

```
chainsaw lint : \07_lolbin_network_connection.yml: unsupported modifiers - cidr
```

La règle utilise `DestinationIp|cidr` pour exclure les plages privées. C'est du Sigma
parfaitement valide, que `sigma check` accepte sans réserve. **Chainsaw ne connaît pas ce
modificateur.**

**Décision : ne pas dégrader une règle correcte pour contenter un seul moteur.** Réécrire les
plages en `startswith` sur des préfixes d'adresses abîmerait la règle pour Elastic et Splunk,
qui gèrent `cidr`. Validation reportée au module 04.

S'ajoute une seconde contrainte : la VM est hors ligne, donc l'événement Sysmon 3 n'est jamais
produit. Le groupe 3 de la configuration est une **liste blanche** — un binaire hors liste ne
produit aucun événement, ce qui ne dit rien sur la règle.

### 08 — Service suspect : couverture partielle

**Aucun atomique n'a été lancé — le verdict vient de leur lecture.** L'atomique n°1 réécrit le
service Fax, absent de l'édition Famille. Les n°2 et n°6, examinés avec `-ShowDetails`,
inscrivent un `ImagePath` qui ne contient aucun des motifs de la règle (`\Users\`,
`\AppData\`, `\Windows\Temp\`, `\ProgramData\`, `powershell`, `cmd.exe`, `rundll32`). Le n°3
n'a pas été examiné.

**Angle mort constaté** : la règle repose sur une liste noire de chemins. Un binaire de service
installé dans n'importe quel autre répertoire lui échappe entièrement. Elle est correcte pour
ce qu'elle décrit, mais elle ne décrit qu'une partie de la technique.

**Piste de correction, non appliquée** : inverser la logique — signaler tout `ImagePath` *hors*
des emplacements légitimes (`System32`, `Program Files`). Plus robuste, mais plus bruyante :
à mesurer contre une ligne de base de plusieurs jours avant adoption.

**Faux positif corrigé au passage.** Le 6 octobre à 01:34 UTC, `services.exe` réécrit
l'`ImagePath` de `MDCoreSvc` vers `C:\ProgramData\Microsoft\Windows Defender\Platform\…` : une
mise à jour de la plateforme Defender, attrapée par le motif `\ProgramData\`. Ce cas était
anticipé dans le champ `falsepositives` dès le module 01. Filtre ajouté sur ce répertoire, qui
n'est inscriptible que par le système. Réanalyse : **1 → 0**.

### 10 — Exécution WMI : validée

Atomique `T1047-7`. **3 détections**, toutes avec `ParentImage = C:\Windows\System32\wbem\WmiPrvSE.exe`.
La règle détecte bien un processus enfant du fournisseur WMI.

**Note d'environnement** : `wmic.exe` est désactivé par défaut depuis Windows 11 24H2 et retiré
en 25H2. Les atomiques 1 à 4, 10 et 12 sont donc inutilisables sur un système récent. La
technique reste entière par PowerShell et `Win32_Process` — c'est ce que fait l'atomique 7.
Un plan de test qui s'appuierait sur `wmic` serait périmé sans que personne s'en aperçoive.

---

## Mesure de bruit au repos

Fenêtre du 02/10 21:11 au 03/10 02:37 · aucun atomique lancé · **réseau branché (NAT) et
Defender actif**, contrairement aux tests qui ont tourné hors ligne avec la protection en
temps réel désactivée. Le référentiel n'est donc pas identique — c'est délibéré : une ligne
de base doit ressembler à un poste ordinaire.

### Résultat : zéro

**Aucune des dix règles n'a déclenché pendant la fenêtre de repos.**

| | |
|---|---|
| Événements Sysmon collectés | **1 743** |
| Détections nouvelles | **0** |
| Dernière détection du journal | 02/10 18:41:33 UTC, soit 30 min **avant** le début de la fenêtre |

Répartition des 1 743 événements : 13 → 553 · 23 → 472 · 5 → 252 · 1 → 242 · 10 → 163 ·
22 → 52 · 11 → 7 · 3 → 1 · 8 → 1.

Deux identifiants apparaissent pour la première fois de la campagne : **l'événement 3**
(connexion réseau, rendu possible par le NAT) et **l'événement 8** (thread distant). Le
second est la donnée de la règle 05 — il existe donc sur cette machine, ce qui lève un doute
avant même de tester cette règle.

### Ce que cette mesure valide

**Le filtre `filter_onedrive` a tenu sur cette fenêtre.** Sur cinq heures et demie, réseau
branché et Defender actif, la règle 04 n'a produit aucune alerte. *Il a cédé trois jours plus
tard sur le second programme de mise à jour de OneDrive — voir la section 04, et la section
suivante.*

**Les deux correctifs de la journée se tiennent ensemble** : 19 détections ramenées à 1 sur
l'EVTX du 01/10, et 0 détection de bruit sur une fenêtre de repos indépendante.

### Les limites de cette mesure

**La fenêtre n'est pas celle annoncée.** Le script attendait 3 600 secondes de temps
d'exécution, mais la VM a été suspendue par l'hyperviseur pendant une partie de la nuit —
l'hôte s'est mis en veille — et les Outils VMware ont resynchronisé l'horloge au réveil.
Résultat : 5 h 26 de temps mural pour environ 1 h de fonctionnement effectif. **Le compte de
détections reste valide** (elles sont horodatées et toutes antérieures à la fenêtre), **mais
le dénominateur ne l'est pas** : on ne peut pas dire « 1 743 événements par heure ».

**Leçon retenue : une mesure de ligne de base exige que la veille soit désactivée sur l'hôte
ET sur l'invité.** Sinon on mesure une machine endormie et on en conclut à tort que les règles
sont silencieuses.

```powershell
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /change monitor-timeout-ac 0
```

**Une heure sur une machine n'est pas une ligne de base, c'est un sondage.** Un vrai
référentiel se mesure sur plusieurs jours et plusieurs postes, parce que le bruit a des
cycles : maintenance nocturne, mises à jour hebdomadaires, sauvegardes. Ce qui est affirmé
ici, et rien de plus : *sur une fenêtre de repos de 5 h 26 dont environ 1 h de fonctionnement
effectif, 0 détection sur 1 743 événements collectés.*

### Ce que trois jours ont montré de plus

Entre le 3 et le 6 octobre, la VM a tourné normalement, sans test. L'analyse du 6 octobre a
fait apparaître **6 alertes de bruit**, toutes dans la nuit, toutes hors de toute fenêtre de
test :

| Heure UTC | Règle | Source | Traitement |
|---|---|---|---|
| 01:34:21 | 08 | Mise à jour de la plateforme Defender (`MDCoreSvc`) | Filtrée |
| 01:35:32 | 05 | `<unknown process>` → `svchost.exe` | Documentée, **non filtrée** |
| 01:57:08 – 01:57:47 | 04 ×4 | Second updater de OneDrive | Filtrée |

**Cinq heures donnaient zéro ; trois jours en donnent six.** C'est exactement l'argument écrit
plus haut — une heure est un sondage — et cette fois il est démontré. Après correction, il
reste **1 alerte de bruit sur trois jours**, celle qu'on garde volontairement.

---

## Limite structurelle du lab : l'édition Famille

Trois atomiques sont restés inutilisables pour des raisons d'édition ou de version de Windows :

| Atomique | Ce qui manque | Pourquoi |
|---|---|---|
| T1047-1 à -4, -10, -12 | `wmic.exe` | Désactivé en 24H2, retiré en 25H2 |
| T1543.003-1 | Service Fax | Fonctionnalité absente de l'édition Famille |
| T1055.001-1 | `mavinject.exe` | Composant des éditions Entreprise et Éducation |

Les vrais parcs d'entreprise tournent en Pro ou Entreprise, et c'est précisément sur leurs
composants que s'appuient beaucoup de techniques. **Un lab en édition Famille sous-représente
la surface d'attaque réelle.** Conséquence retenue : le module 05 (annuaire) sera monté sur une
version d'évaluation Entreprise, et les règles 05 et 08 y seront éprouvées de nouveau.

---

## Ce que la campagne a changé dans le dépôt

| Règle | Avant | Après | Nature |
|---|---|---|---|
| 01 | 14 détections | 0 | Faux positifs `csrss` / `wininit`, filtre en chemin complet |
| 02 | 4 détections, 0 vraie | 9 détections, 5 vraies | Faux négatif sur `-e` |
| 04 | 4 + 4 détections | 0 | Faux positif `OneDriveSetup.exe`, **deux** programmes de mise à jour |
| 08 | 1 détection | 0 | Faux positif mise à jour de la plateforme Defender |

**Sur l'EVTX du 01/10 : 19 détections ramenées à 1**, la seule authentique.

**Sur l'EVTX du 06/10 : 21 détections ramenées à 16** — les 15 issues des tests, plus le seul
faux positif conservé délibérément.

---

## Reste à faire

- **Test 09 (T1490)** — destructif et non réversible par le framework. En dernier, instantané
  restauré juste après, preuves poussées **avant**.
- **Règles 05 et 08** — à éprouver de nouveau sur une VM en édition Entreprise (module 05).
- **Règle 08** — concevoir et mesurer la variante en liste blanche.
- **Divergence Hayabusa** — 10 alertes « Potential PrintNightmare Exploitation Attempt » sans
  équivalent dans les règles du dépôt. Bruit d'installation de pilotes ou angle mort : à
  qualifier.
- **Mesure de bruit refaite proprement** — plusieurs jours, veille désactivée sur l'hôte et
  l'invité, pour obtenir un dénominateur exploitable.

---

## Enseignements de méthode

**`Exit code: 0` d'Atomic Red Team signifie « le script s'est terminé », pas « la technique a
réussi ».** Deux tests ont rendu 0 sans rien exécuter.

**Les prérequis s'installent pendant la phase d'outillage, pas pendant la campagne.** Trois
tests ont été bloqués par un prérequis réseau sur une VM volontairement isolée. La phase
d'outillage doit se terminer par un `-GetPrereqs` sur toute la campagne prévue.

**Une exclusion de chemin Defender ne couvre pas le comportement.** `C:\Lab` était exclu, et
Defender a bloqué sur la ligne de commande (`HackTool:Win32/DumpLsass.E`).

**Désactiver la protection en temps réel change ce qu'on mesure** : on passe d'un test
« détection + prévention » à un test « détection seule ». C'est ce qu'on veut pour valider des
règles, et ça se note.

**Le dépôt GitHub ne peut pas être le seul pont hôte ↔ VM pendant une campagne**, puisque la
VM est isolée. Pendant une campagne, le clone de la VM est la copie de travail : commit local,
réseau rebranché, push, *puis* restauration d'instantané.

**On versionne la preuve, pas le produit dérivé.** Sorties Hayabusa exclues (20 Mo pièce,
régénérables depuis l'EVTX), journal compressé en archive de campagne (39 Mo → 3,4 Mo).

---

*Campagne menée par Mamadou Lamine Thiore — Master 2 Cybersécurité, EPSI Lyon.*
