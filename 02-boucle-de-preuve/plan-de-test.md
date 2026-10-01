# Plan de test atomique — module 02

Un test par règle du module 01. Chaque ligne du dépôt `01-socle-windows/sigma/` doit
recevoir une réponse chiffrée à une seule question : **est-ce qu'elle se déclenche sur le
comportement qu'elle prétend détecter ?**

Tant qu'une règle n'a pas déclenché sur un test contrôlé, elle n'est pas une détection.
C'est une hypothèse.

---

## Comment lire ce document

Ce plan ne contient **aucune commande d'attaque**. C'est délibéré, et ce n'est pas de la
pudeur : Atomic Red Team maintient un catalogue de tests versionné, révisé et corrigé en
continu. Recopier ici une commande figée, c'est se retrouver dans six mois avec un test qui
ne correspond plus à la technique qu'il prétend simuler — exactement l'erreur que le module
01 a servi à éviter côté règles.

La bonne pratique est l'inverse : pour chaque technique, on demande au framework ce qu'il
propose, on lit, on choisit, on note le numéro retenu.

```powershell
Invoke-AtomicTest T1003.001 -ShowDetailsBrief
```

La colonne « atomique retenu » de ce tableau est **vide par construction**. Vous la
remplissez au moment du test, avec le numéro que vous avez effectivement lancé. C'est cette
colonne qui rend la campagne reproductible.

---

## Ordre d'exécution

L'ordre n'est pas indifférent.

1. **Tests 01 à 08** — non destructifs, réversibles par le nettoyage du framework.
2. **Test 10** — WMI, non destructif mais laisse des artefacts de service.
3. **Test 09 en dernier** — suppression des clichés instantanés. **Destructif et non
   réversible par le framework.** Il supprime les points de restauration de la VM. On le
   lance en tout dernier, et on restaure l'instantané juste après.

Entre deux tests, on ne restaure pas. On restaure **entre deux campagnes** — c'est-à-dire
quand on a modifié la configuration Sysmon ou les règles, et qu'on veut repartir propre.

---

## Préalables à vérifier avant le premier test

| Point | Commande de vérification | Attendu |
|---|---|---|
| VM hors ligne | `Test-NetConnection 8.8.8.8 -Port 53` | `TcpTestSucceeded : False` |
| Instantané pris | Console de l'hyperviseur | « VM outillée hors ligne » présent |
| Sysmon actif | `Get-Service sysmon` | `Running` |
| Config chargée | `sysmon -c` | Les 12 groupes du module 01 |
| Journal accessible | `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1` | Un événement |

Si l'un des cinq échoue, on ne lance rien. Un test sur un capteur mal configuré produit un
résultat faux, et un résultat faux coûte plus cher que pas de résultat du tout.

---

## Le tableau de test

| # | Règle | Technique | Atomique retenu | Événement Sysmon attendu | Critère de réussite |
|---|---|---|---|---|---|
| 01 | Accès mémoire à LSASS | `T1003.001` | *(à remplir)* | **10** — `TargetImage` se terminant par `\lsass.exe`, `GrantedAccess` en lecture mémoire | La règle 01 remonte l'événement, et `SourceImage` est le binaire du test |
| 02 | PowerShell encodé | `T1059.001` | *(à remplir)* | **1** — `CommandLine` contenant un argument d'encodage | La règle 02 remonte, et la ligne de commande capturée est complète (pas tronquée) |
| 03 | Tâche planifiée | `T1053.005` | *(à remplir)* | **1** — création via l'utilitaire de planification | La règle 03 remonte **et** exige bien ses deux critères (voir note ci-dessous) |
| 04 | Clé de démarrage | `T1547.001` | *(à remplir)* | **13** — `TargetObject` sous une ruche `Run` | La règle 04 remonte, et `Details` contient le chemin écrit |
| 05 | Thread distant | `T1055` (voir note) | *(à remplir)* | **8** — `TargetImage` = processus système visé | La règle 05 remonte, et `SourceImage` n'est pas dans le filtre légitime |
| 06 | Rundll32 détourné | `T1218.011` | *(à remplir)* | **1** — `Image` = `rundll32.exe` | La règle 06 remonte sur l'une **ou** l'autre de ses deux branches |
| 07 | LOLBin sortant | `T1105` | *(à remplir)* | **3** — `Image` dans la liste blanche du groupe 3 | **Test conditionnel — voir la section « Le cas du test 07 »** |
| 08 | Service suspect | `T1543.003` | *(à remplir)* | **13** — `TargetObject` sous `Services\...\ImagePath` | La règle 08 remonte, et le chemin capturé est bien inscriptible |
| 09 | Clichés instantanés | `T1490` | *(à remplir)* | **1** — utilitaire de gestion des clichés | La règle 09 remonte au niveau `critical`. **Dernier test de la campagne.** |
| 10 | Exécution WMI | `T1047` | *(à remplir)* | **1** — `ParentImage` = le fournisseur WMI | La règle 10 remonte, et le parent capturé est bien le fournisseur, pas le shell |

---

## Notes par test

### Test 03 — le piège que le module 01 a corrigé

La règle 03 avait un bloc de détection orphelin : son `condition: all of selection_*` ne
voyait qu'un critère sur deux. Corrigée, elle exige maintenant **le binaire ET un motif de
ligne de commande**. Le test doit donc valider les deux :

- un atomique qui crée une tâche → **doit** déclencher ;
- une création de tâche légitime et banale (par exemple depuis l'interface graphique) →
  **ne doit pas** déclencher.

Une règle qui passe le premier test mais échoue le second n'est pas corrigée, elle est
bruyante. Les règles 04 et 08 portaient le même défaut — appliquez-leur le même
double test.

### Test 05 — la technique de base n'a pas toujours d'atomique direct

`T1055` est un parapluie. Le catalogue documente surtout ses sous-techniques
(`T1055.001`, `T1055.002`, `T1055.012`…). Listez-les et choisissez celle qui crée
effectivement un thread dans un autre processus — toutes les variantes d'injection ne
passent pas par là, et c'est précisément le point que la règle 05 exploite.

Si l'atomique choisi ne produit **pas** d'événement 8, ce n'est pas un échec de la règle.
C'est la démonstration que la technique a plusieurs implémentations et que la règle n'en
couvre qu'une. Notez-le dans la matrice : c'est un résultat, pas un raté.

### Le cas du test 07 — la VM est hors ligne

La règle 07 détecte une connexion sortante depuis un binaire système détourné. Une VM sans
réseau ne peut pas produire cette donnée. Trois options, par ordre de préférence :

1. **Serveur local dans la VM.** Lancez un service d'écoute sur la boucle locale, puis
   faites-le contacter par l'un des binaires de la liste blanche du groupe 3. Sysmon
   journalise les connexions sur `127.0.0.1`. Isolation préservée, aucun paquet ne sort.
2. **Réseau interne hyperviseur.** Une seconde VM ou un réseau « host-only ». Plus réaliste,
   plus long à monter.
3. **Marquer le test comme non exécuté.** Acceptable si c'est écrit. Inacceptable si on
   laisse croire que la règle est validée.

Le point d'attention : le groupe 3 de la configuration Sysmon est une **liste blanche**. Si
le test utilise un binaire absent de cette liste, l'absence d'événement 3 ne dit rien sur la
règle — elle dit que la configuration ne collectait pas la donnée. C'est le piège
`include`/`exclude` du module 01, rencontré cette fois-ci en conditions réelles.

### Test 09 — destructif

Ce test supprime les clichés instantanés de la VM. Il n'est pas réversible par le nettoyage
du framework. Conséquences concrètes :

- il se lance **en dernier** ;
- l'instantané de l'hyperviseur est restauré **juste après** ;
- les preuves de la campagne sont exportées **avant** la restauration, sinon elles
  disparaissent avec.

---

## Ce qu'on consigne pour chaque test

Un test qui n'a pas produit ces cinq éléments n'est pas terminé :

1. **L'horodatage de lancement** — utilisé pour découper la fenêtre d'analyse.
2. **L'export EVTX** du journal Sysmon sur la fenêtre du test.
3. **Le verdict Hayabusa et Chainsaw** sur cet EVTX.
4. **Le nombre d'événements** générés par le test, par identifiant.
5. **La décision** : règle validée, règle à corriger, ou donnée absente.

Le script `scripts/Invoke-TestAtomique.ps1` produit les quatre premiers automatiquement. Le
cinquième est un jugement — c'est votre travail, pas celui de l'outil.

---

## Le critère d'échec qu'on oublie

Une règle qui remonte **trop** est aussi fausse qu'une règle muette. Après la campagne
offensive, laissez la VM tourner au repos une heure, puis relancez l'analyse sur cette
période. Toute détection sur une machine au repos est un faux positif, et se documente dans
le champ `falsepositives` de la règle concernée.

C'est cette mesure-là — et pas le nombre de règles — qui distingue un lab d'un portfolio.
