# Module 01 — Socle de détection Windows

Premier module du cursus. Objectif : savoir partir d'une technique d'attaque et
remonter jusqu'à la donnée qu'il faut collecter pour la voir — puis écrire la règle
qui la cherche.

**Auteur** : Mamadou Lamine Thiore
**Date** : septembre 2026
**Outils** : MITRE ATT&CK · Sysmon v15.22 · Sigma

---

## Le principe du module

Trois outils qu'il est inutile d'apprendre séparément :

- **ATT&CK** nomme la technique d'attaque
- **Sysmon** produit la donnée qui la rend visible
- **Sigma** écrit la règle qui la cherche dans cette donnée

La chaîne se lit dans cet ordre, et c'est le seul ordre qui fonctionne. Écrire une
règle avant d'avoir vérifié que la donnée existe, c'est produire une règle qui ne se
déclenchera jamais — et c'est l'erreur la plus répandue chez les débutants.

---

## Contenu du dépôt

```
01-socle-windows/
├── README.md                    ce fichier
├── matrice.md                   le livrable central : technique → donnée → règle
├── convert.sh                   conversion des règles vers trois cibles
├── sysmon/
│   └── sysmon-config.xml        configuration commentée bloc par bloc
├── sigma/                       10 règles, une par technique ATT&CK
│   ├── 01_lsass_process_access.yml
│   ├── 02_powershell_encoded_command.yml
│   ├── 03_scheduled_task_creation.yml
│   ├── 04_run_key_persistence.yml
│   ├── 05_create_remote_thread.yml
│   ├── 06_rundll32_suspicious.yml
│   ├── 07_lolbin_network_connection.yml
│   ├── 08_service_creation_registry.yml
│   ├── 09_shadow_copy_deletion.yml
│   └── 10_wmi_remote_execution.yml
└── preuves/                     captures de déclenchement (module 02)
```

---

## Mise en place

### 1. La machine virtuelle

Windows 10 ou 11, **réseau en mode hôte uniquement**, sans route vers votre réseau
domestique. Prenez un instantané de la VM propre avant toute manipulation : vous y
reviendrez à chaque test du module 2.

### 2. Sysmon

Téléchargez Sysmon depuis Sysinternals (v15.22, publiée le 10 septembre 2026), puis :

```
sysmon64.exe -accepteula -i sysmon-config.xml
```

Pour modifier la configuration sans réinstaller :

```
sysmon64.exe -c sysmon-config.xml
```

Pour vérifier ce qui est réellement actif :

```
sysmon64.exe -c
```

Les événements arrivent dans l'observateur d'événements, sous
`Journaux des applications et des services → Microsoft → Windows → Sysmon → Operational`.

### 3. Vérification immédiate

Ouvrez le gestionnaire des tâches, puis cherchez un événement 10 ciblant `lsass.exe`
dans le journal Sysmon. S'il n'y a rien, l'événement 10 n'est pas actif : la
configuration n'a pas été appliquée. **Faites cette vérification avant d'écrire quoi
que ce soit** — elle vous évitera des heures de recherche sur des règles muettes.

### 4. Les règles

```
pip3 install sigma-cli
sigma plugin install elasticsearch
sigma check ./sigma
bash convert.sh
```

---

## Les quatre notions à retenir

### Sysmon ne journalise presque rien par défaut

Les événements qui portent l'essentiel de la valeur défensive — connexion réseau (3),
thread distant (8), accès processus (10), registre (13), DNS (22) — sont **désactivés**
tant qu'une configuration ne les active pas.

Concrètement : **cinq des dix règles de ce module reposent sur un événement inactif par
défaut**. C'est le chiffre à retenir du module, et un excellent argument d'entretien.

### `include` et `exclude` ne se choisissent pas au hasard

- `onmatch="include"` — liste blanche. On ne journalise **que** ce qui correspond.
- `onmatch="exclude"` — liste noire. On journalise **tout sauf** ce qui correspond.

Une balise `include` vide ne journalise **rien**. Une balise `exclude` vide journalise
**tout**. C'est la source d'erreur la plus fréquente dans une configuration Sysmon, et
la configuration fournie utilise délibérément les deux pour que la différence vous
saute aux yeux.

### Une règle sans faux positifs déclarés est une règle non testée

Le champ `falsepositives` n'est pas décoratif. Une règle dont vous ne savez pas ce
qu'elle remonte à tort n'a jamais tourné sur des données réelles. En entretien,
savoir dire ce que votre détection rate vaut plus que le nombre de règles écrites.

### On détecte le geste inévitable, pas l'outil

La règle 01 ne cherche pas Mimikatz. Elle cherche l'ouverture d'un handle en lecture
mémoire sur `lsass.exe` — ce que **tout** outil de vol d'identifiants doit faire, quel
que soit son nom, sa version ou son niveau d'obfuscation. Même logique pour la règle 05
avec la création de thread distant.

C'est la différence entre une détection qui survit six mois et une détection qui meurt
à la prochaine recompilation du maliciel.

---

## Résultats de validation

Tous les fichiers ont été validés automatiquement :

- **XML** : bien formé, 12 groupes de règles couvrant 12 types d'événements Sysmon
- **Sigma** : 10 règles valides, 10 identifiants uniques, 10 techniques ATT&CK
  distinctes, 5 catégories de source de données
- **Champs obligatoires** présents sur les 10 règles, condition définie sur chacune

Deux pièges rencontrés et corrigés pendant la construction, qui valent d'être notés :

1. **Les doubles tirets sont interdits à l'intérieur d'un commentaire XML.** Un
   séparateur `-----` dans un commentaire rend le fichier non conforme et Sysmon
   refuse la configuration.
2. **Un ` : ` dans une chaîne YAML non quotée** la transforme silencieusement en
   dictionnaire. Le fichier reste valide, la règle se charge, mais le champ
   `falsepositives` n'est plus du texte. Aucune erreur n'est levée — d'où l'intérêt de
   valider le **type** des champs et pas seulement leur présence.

---

## Suite

Le module 02 confronte ces dix règles à vingt tests atomiques réels et ajoute à la
matrice la colonne qui compte : détectée, partielle, ou manquée.
