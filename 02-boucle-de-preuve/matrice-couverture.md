# Matrice de couverture — module 02

Campagne des 1ᵉʳ et 2 octobre 2026 · VM Windows 11 isolée · Sysmon 15.22, schéma 4.91 ·
Chainsaw sur les dix règles du module 01, Hayabusa en second avis.

Ce fichier est le livrable du module. Les règles prouvent qu'on sait écrire du YAML ; ce
tableau prouve qu'on sait mesurer ce qu'on détecte et **nommer ce qu'on ne détecte pas**.

---

## Tableau principal

| # | Règle | Technique | Atomique | Détections | Verdict |
|---|---|---|---|---|---|
| 01 | Accès mémoire LSASS | T1003.001 | **2** — comsvcs.dll | 14 → **0** | **Non éprouvée** — bloquée par le noyau |
| 02 | PowerShell encodé | T1059.001 | **15** + T1047-7 | 4 → **8** | **Corrigée** — faux négatif |
| 03 | Tâche planifiée | T1053.005 | **1** | **2** | **Validée** |
| 04 | Clé de démarrage | T1547.001 | — | 4 → **0** | **Corrigée** — faux positif |
| 05 | Thread distant | T1055 | — | — | Non testée |
| 06 | Rundll32 détourné | T1218.011 | *(effet de bord de T1003.001-2)* | **1** | **Validée** |
| 07 | LOLBin sortant | T1105 | — | — | **Non testable** sous Chainsaw |
| 08 | Service suspect | T1543.003 | — | — | Non testée |
| 09 | Clichés instantanés | T1490 | — | — | Non testée *(destructif)* |
| 10 | Exécution WMI | T1047 | **7** | **3** | **Validée** |

**Résultat : 3 validées · 2 corrigées · 1 non éprouvée · 1 non testable · 3 non testées.**

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

Dans le même journal se trouvaient **4 vraies commandes encodées** qu'elle ne voyait pas :

| Horodatage | Parent | Forme |
|---|---|---|
| 18:05:24 | `wbem\WmiPrvSE.exe` | `powershell.exe -NoProfile -E <base64>` |
| 18:28:32 | `wbem\WmiPrvSE.exe` | idem |
| 18:31:39 | `wbem\WmiPrvSE.exe` | idem |
| 18:37:21 | `cmd.exe` | `powershell -exec bypass -e <base64>` |

La règle cherchait `' -enc '`, `' -enco'`, `' -encodedcommand'`, `' -ec '` — **pas `' -e '`**.
Or `powershell.exe` accepte `-e` comme abréviation de `-EncodedCommand`, et c'est la forme la
plus courte, donc celle qu'un attaquant soucieux de discrétion choisira.

**Taux de vrais positifs avant correction : 0 %.** La règle passait `sigma check` sans erreur
et remontait des alertes — elle paraissait fonctionner. Elle était aveugle.

Après ajout de `' -e '`, réanalyse du même EVTX : **8 détections, dont 4 vraies**.

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

### 10 — Exécution WMI : validée

Atomique `T1047-7`. **3 détections**, toutes avec `ParentImage = C:\Windows\System32\wbem\WmiPrvSE.exe`.
La règle détecte bien un processus enfant du fournisseur WMI.

**Note d'environnement** : `wmic.exe` est désactivé par défaut depuis Windows 11 24H2 et retiré
en 25H2. Les atomiques 1 à 4, 10 et 12 sont donc inutilisables sur un système récent. La
technique reste entière par PowerShell et `Win32_Process` — c'est ce que fait l'atomique 7.
Un plan de test qui s'appuierait sur `wmic` serait périmé sans que personne s'en aperçoive.

---

## Ce que la campagne a changé dans le dépôt

| Règle | Avant | Après | Nature |
|---|---|---|---|
| 01 | 14 détections | 0 | Faux positifs `csrss` / `wininit`, filtre en chemin complet |
| 02 | 4 détections, 0 vraie | 8 détections, 4 vraies | Faux négatif sur `-e` |
| 04 | 4 détections | 0 | Faux positif `OneDriveSetup.exe` |

**Sur l'EVTX du 01/10 : 19 détections ramenées à 1**, la seule authentique. Même journal,
mêmes outils, règles corrigées.

---

## Reste à faire

- **Tests 05 (T1055), 08 (T1543.003)** — non destructifs, à mener.
- **Test 09 (T1490)** — destructif et non réversible par le framework. En dernier, instantané
  restauré juste après, preuves poussées **avant**.
- **Mesure de bruit au repos** — 60 minutes, `-SansAtomique`. Sans ce dénominateur, le nombre
  de faux positifs ne veut rien dire. C'est la mesure manquante la plus importante.

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
