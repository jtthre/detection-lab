# Journal de mise en place — Module 01

Compte rendu de bout en bout du socle de détection Windows : ce qui a été monté, dans
quel ordre, ce qui a résisté, et ce que les mesures prouvent.

Écrit pour trois usages : refaire l'installation de zéro sans rien redécouvrir, retrouver
plus tard pourquoi tel choix a été fait, et pouvoir expliquer le banc d'essai à quelqu'un
d'autre sans improviser.

**Auteur :** Mamadou Lamine Thiore
**Période :** 14 au 20 septembre 2026
**Statut :** socle opérationnel, mesures validées

---

## 1. Objectif du module

Savoir partir d'une technique d'attaque et remonter jusqu'à la donnée qu'il faut
collecter pour la voir — puis écrire la règle qui la cherche.

Trois outils, dans cet ordre, et cet ordre seul :

| Outil | Rôle |
|---|---|
| **MITRE ATT&CK** | Nomme la technique d'attaque |
| **Sysmon** | Produit la donnée qui la rend visible |
| **Sigma** | Écrit la règle qui la cherche dans cette donnée |

Écrire la règle avant d'avoir vérifié que la donnée existe produit une règle muette.
C'est l'erreur la plus répandue, et tout le module est construit pour l'éviter.

---

## 2. Environnement

| Élément | Valeur |
|---|---|
| Système invité | Windows 11 Famille |
| Réseau | NAT pendant l'outillage, hôte uniquement ensuite |
| Fuseau horaire | Romance Standard Time (UTC+01:00, Paris) |
| Sysmon | v15.22 — publiée le 10 septembre 2026 |
| Schéma de configuration | 4.91 |
| Dépôt | `detection-lab`, cloné dans `C:\Lab\detection-lab` |
| Exclusion Defender | `C:\Lab` |

**Pourquoi Windows Famille.** L'édition Famille ne permet pas de rejoindre un domaine.
Sans conséquence pour les modules 01 à 04 : GOAD, au module 05, déploie ses propres
machines et n'a pas besoin de ce poste.

---

## 3. Déroulé, étape par étape

### 3.1 Installation de Windows hors ligne

Windows 11 Famille avec une connexion Internet **impose un compte Microsoft**. Sur une VM
de lab qui exécutera du code malveillant, c'est à éviter — et un compte local simplifie
les restaurations d'instantané.

L'écran « Il est temps de vous connecter à un réseau » se contourne avec `Maj + F10`,
puis :

```
OOBE\BYPASSNRO
```

La machine redémarre et propose « Je n'ai pas Internet » → « Continuer avec l'installation
limitée ». Compte local créé.

> **Règle retenue :** on isole avant le premier test, pas avant l'installation. La VM est
> saine tant qu'aucun test n'a tourné ; le réseau ne devient un risque qu'après.

### 3.2 Fuseau horaire

```powershell
Set-TimeZone -Id 'Romance Standard Time'
Get-TimeZone
```

La synchronisation `w32tm /resync` échoue sur une VM (« aucune donnée de temps
disponible ») : c'est l'hyperviseur qui maintient l'horloge. Sans conséquence tant que
`Get-Date` est juste.

L'heure exacte n'est pas un détail : au module 02, le triage repose sur la corrélation
entre l'heure de lancement d'un test et les événements produits.

### 3.3 Exclusion Defender, **avant** tout téléchargement

```powershell
New-Item -ItemType Directory -Path C:\Lab -Force
Add-MpPreference -ExclusionPath 'C:\Lab'
(Get-MpPreference).ExclusionPath
```

L'ordre compte : Defender supprime les charges utiles d'Atomic Red Team pendant le
téléchargement si l'exclusion n'est pas déjà posée. Defender reste actif partout ailleurs.

### 3.4 Outillage

```powershell
winget install --id Git.Git -e
winget install --id Python.Python.3.12 -e
winget install --id 7zip.7zip -e
winget install --id Microsoft.VisualStudioCode -e
winget install --id Microsoft.Sysinternals.Sysmon -e
```

Fermer et rouvrir PowerShell après les installations : le `PATH` n'est rechargé qu'au
démarrage d'une nouvelle session.

### 3.5 Récupération des fichiers dans la VM

```powershell
cd C:\Lab
git clone https://github.com/<compte>/detection-lab.git
```

### 3.6 Application de la configuration Sysmon

Le binaire était déjà enregistré comme service. Deux commandes à ne pas confondre :

| Commande | Effet |
|---|---|
| `sysmon -accepteula -i <fichier>` | **Installe** le service. Échoue si déjà enregistré. |
| `sysmon -c <fichier>` | **Recharge** la configuration à chaud. |
| `sysmon -c` (sans argument) | **Affiche** la configuration active. |

```powershell
sysmon -c .\sysmon-config.xml
```

Sortie obtenue : `Configuration file validated.`

---

## 4. Obstacles rencontrés

Ce sont eux qui font la valeur de ce journal : refaire l'installation sans les
reproduire prend une heure au lieu d'une journée.

### 4.1 Espace parasite dans un identifiant

`Set-TimeZone -Id "Romance Standard Time "` renvoyait « ID introuvable ». Une espace
avant le guillemet fermant, invisible à la lecture.

**Réflexe :** guillemets simples en PowerShell quand il n'y a rien à substituer, et une
seule commande par ligne.

### 4.2 Deux commandes collées sur une ligne

`Set-TimeZone -Id "..." w32tm /resync` → `PositionalParameterNotFound`. PowerShell prend
le second mot pour un paramètre du premier verbe.

### 4.3 Le service ne s'appelle pas Sysmon64

`Get-Service Sysmon64` renvoyait « service introuvable » alors que Sysmon tournait. Le
service installé par winget s'appelle **`sysmon`**.

**Réflexe :** chercher large avant de conclure à une absence — `Get-Service *sysmon*`.

### 4.4 « The service sysmon is already registered »

Symptôme d'une confusion entre `-i` et `-c`. Le service existait déjà ; il fallait
recharger, pas réinstaller.

### 4.5 Dossier téléversé ≠ dépôt local

Le dépôt GitHub avait été créé en déposant le dossier depuis le navigateur. Un
téléversement web **ne transforme pas le dossier local en dépôt git** : `git status`
répondait « not a git repository ».

**Ce qui crée le lien, c'est `git clone`.** Un dossier copié à la main n'a ni `pull` ni
`push`. Copie locale supprimée après le clone pour éviter deux versions divergentes.

### 4.6 Écart de version de schéma

La configuration déclarait `schemaversion="4.90"`, le binaire annonçait 4.91. Sysmon
accepte un schéma antérieur, mais l'écart a été corrigé pour rester propre.

---

## 5. Résultats mesurés

### 5.1 Accès mémoire à LSASS

Le gestionnaire des tâches ouvre un handle sur `lsass.exe`. Après l'avoir lancé :

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 |
  Where-Object { $_.Id -eq 10 } |
  Select-Object -First 5 TimeCreated, Id
```

Cinq événements `10` horodatés. **C'est la mesure la plus importante du module :**
l'événement 10 est désactivé par défaut dans Sysmon. Sa présence prouve que la
configuration est bien appliquée, et que la donnée sur laquelle repose la règle 01 existe.

### 5.2 Distribution des sources

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 200 |
  Group-Object Id | Sort-Object Count -Descending | Select-Object Count, Name
```

Relevé du 20 septembre 2026 sur les 200 derniers événements :

| Événement | Nombre | Nature | Règles concernées |
|---|---|---|---|
| 12 | 71 | Clé de registre créée ou supprimée | — |
| 13 | 40 | Valeur de registre modifiée | 04, 08 |
| 23 | 31 | Fichier supprimé | — |
| 10 | 22 | Accès à un processus | 01 |
| 1 | 15 | Création de processus | 02, 03, 06, 09, 10 |
| 5 | 13 | Processus terminé | — |
| 22 | 8 | Requête DNS | — |

Un relevé antérieur comportait en plus un événement `16` — **la reconfiguration de Sysmon
elle-même**, c'est-à-dire la commande `sysmon -c` qui venait d'être lancée.

### 5.3 Trois lectures de ce tableau

**Le registre représente 111 événements sur 200**, soit plus de la moitié du volume — et
ce, alors que la configuration ne journalise déjà que les ruches de persistance. C'est
l'argument chiffré qui justifie de ne jamais collecter le registre en entier.

**Les événements 3, 7, 8 et 11 n'apparaissent pas, et c'est voulu.** Leurs filtres sont
des listes blanches étroites : l'événement 3 n'attend qu'un binaire système détourné
sortant sur le réseau, l'événement 8 qu'une injection de thread. Rien de tout cela ne se
produit sur une machine au repos. Ils se déclencheront au module 02.

**L'événement 16 est un signal anti-altération.** Sysmon journalise sa propre
reconfiguration : un attaquant qui neutralise le capteur laisse cette trace. À surveiller
en production.

---

## 6. Validation des règles Sigma

```powershell
sigma check C:\Lab\detection-lab\01-socle-windows\sigma
```

**Résultat brut :** 0 erreur, 0 erreur de condition, **5 anomalies**.

| Nombre | Anomalie | Gravité |
|---|---|---|
| 3 | `DanglingDetectionIssue` | HIGH |
| 2 | `InvalidATTACKTagIssue` | MEDIUM |

### 6.1 Blocs de détection orphelins — corrigé

Règles 03, 04 et 08. Chacune définissait un bloc nommé exactement `selection` plus un
bloc `selection_<suffixe>`, avec pour condition `all of selection_*`.

**Le motif `selection_*` exige le tiret bas : il ne couvre pas un bloc nommé
`selection`.** Ce bloc n'était donc jamais évalué — la règle se serait déclenchée sur un
critère au lieu de deux, produisant des faux positifs en masse.

Correction par renommage, pour que chaque bloc entre dans le motif :

| Règle | Ancien nom | Nouveau nom |
|---|---|---|
| 03 | `selection` | `selection_img` |
| 04 | `selection` | `selection_key` |
| 08 | `selection` | `selection_path` |

> **Leçon générale :** un validateur qui signale un bloc orphelin signale une règle dont
> la logique est amputée. Gravité HIGH méritée.

### 6.2 Étiquette ATT&CK invalide — en cours

Règles 05 et 06, étiquette `attack.defense-evasion`.

Le validateur compare l'étiquette à la liste des `x_mitre_shortname` téléchargée depuis
MITRE, lesquels sont **écrits avec des tirets**. Les quatre autres tactiques employées
dans le dépôt — `credential-access`, `privilege-escalation`, `lateral-movement`,
`command-and-control` — passent sans erreur, ce qui confirme la forme.

**Le cas de `defense-evasion` reste à élucider.** Commande qui tranche, en affichant la
liste exacte acceptée par la version installée :

```powershell
python -c "from sigma.data.mitre_attack import mitre_attack_tactics; print(sorted(mitre_attack_tactics.values()))"
```

Anomalie de gravité MEDIUM : elle n'empêche ni la conversion ni le déclenchement, mais
bloquerait une contribution à SigmaHQ.

---

## 7. État à la clôture

| Point | Statut |
|---|---|
| VM isolée, instantané propre | fait |
| Sysmon avec configuration personnalisée | fait, validé |
| Événements 1, 10, 13, 22, 23 actifs | vérifié par relevé |
| 10 règles Sigma, 0 erreur de syntaxe | vérifié |
| Blocs orphelins corrigés | fait |
| Étiquette `defense-evasion` | à trancher |
| Preuves horodatées au dépôt | fait, dossier `preuves/` |

---

## 8. Refaire de zéro

1. VM Windows 11, réseau hôte uniquement, `OOBE\BYPASSNRO`, compte local
2. Fuseau horaire, puis vérifier `Get-Date`
3. Réseau en NAT
4. `C:\Lab` créé **puis** exclu de Defender
5. winget : git, python, 7zip, VS Code, Sysmon
6. Rouvrir PowerShell en administrateur
7. `git clone` du dépôt dans `C:\Lab`
8. `sysmon -accepteula -i .\sysmon-config.xml` — ou `-c` si le service existe déjà
9. Vérifier : `Get-Service *sysmon*`, `sysmon -c`, puis le test de l'événement 10
10. `sigma check` sur le dossier des règles
11. Réseau en hôte uniquement, puis instantané « VM outillée hors ligne »

Compter deux heures en suivant ce journal, une journée sans.

---

## 9. Ce qu'il faut savoir expliquer

Cinq points, à dire sans notes :

**« Sysmon installé » et « Sysmon configuré » sont deux choses différentes.** La moitié
des événements utiles sont inactifs par défaut — connexion réseau, thread distant, accès
processus, registre, DNS. Un poste avec Sysmon posé sans configuration est aveugle au vol
d'identifiants et à l'injection de code.

**Une balise `include` vide ne journalise rien ; une balise `exclude` vide journalise
tout.** C'est l'erreur de configuration la plus fréquente, et le premier endroit à
regarder quand une règle reste muette.

**On détecte le geste inévitable, pas l'outil.** La règle 01 ne cherche pas Mimikatz : elle
cherche l'ouverture d'un handle en lecture mémoire sur LSASS, ce que tout voleur
d'identifiants doit faire quels que soient son nom, sa version ou son obfuscation. C'est
la différence entre une détection qui tient six mois et une qui meurt à la prochaine
recompilation.

**Une règle sans faux positifs déclarés est une règle qui n'a jamais tourné sur des
données réelles.** Le champ `falsepositives` est la preuve du test.

**J'écris en Sigma pour que mes détections soient portables** d'un SIEM à l'autre — Elastic,
Splunk, Sentinel. Le travail reste valable quel que soit l'outil de l'employeur.

---

## 10. Suite

Module 02 — la boucle de preuve. Vingt tests atomiques confrontés à ces dix règles, triés
avec Hayabusa et Chainsaw, et une matrice de couverture qui dit, technique par technique :
détectée, partielle ou manquée — et pourquoi.

Le module 02 suppose l'instantané « VM outillée hors ligne » en place, et les événements
3, 7, 8 et 11 prêts à se déclencher.
