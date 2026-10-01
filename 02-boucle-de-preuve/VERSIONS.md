# Versions de l'outillage

Ce fichier n'est pas décoratif. Une campagne de tests n'est reproductible que si l'on sait
avec quoi elle a été menée — et les trois outils du module 02 changent de numéro de version
et parfois de nom d'option plusieurs fois par an.

**À remplir après installation**, avec la sortie réelle des commandes. Ne recopiez pas un
numéro trouvé dans une documentation : prenez celui que votre binaire affiche.

| Outil | Commande de vérification | Version installée | Date d'installation |
|---|---|---|---|
| Sysmon | `sysmon -c` (première ligne) | | |
| Schéma Sysmon | `sysmon -c` (schemaversion) | 4.91 | |
| sigma-cli | `sigma version` | | |
| Atomic Red Team | `Get-Module Invoke-AtomicRedTeam` | | |
| Hayabusa | `hayabusa.exe help` (bandeau) | **4.1.0 — Suzumushi** | 01/10/2026 |
| Chainsaw | `chainsaw.exe --version` | | |

## Dérives d'options rencontrées

Le tableau ci-dessus donne les versions ; celui-ci donne ce qu'elles ont cassé. C'est lui
qu'on relit quand un script cesse de fonctionner après une mise à jour.

| Outil | Version | Ce qui a changé | Conséquence |
|---|---|---|---|
| Hayabusa | 4.1.0 | `--version` n'est plus une option globale — l'outil attend une commande | `hayabusa.exe help` affiche le bandeau de version |
| Hayabusa | 4.1.0 | La commande **`csv-timeline` a été renommée `dfir-timeline`** | `Invoke-Analyse.ps1` corrigé le 01/10/2026 |
| Hayabusa | 4.1.0 | Refuse d'écraser un fichier de sortie existant | `--clobber` ajouté, sinon la 2ᵉ campagne échoue |

**L'archive compte autant que la version.** Les deux outils publient des archives
multi-plateformes : `hayabusa-4.1.0-all-platforms.zip` contient cinq binaires (Linux, macOS,
Windows arm64/x64/x86) et Chainsaw publie un fichier par cible plus un bundle
`all_platforms+rules+examples`. Un renommage au joker attrape le premier par ordre
alphabétique — en l'occurrence `win-arm64`, qui ne démarre pas sur un hôte x64. **On nomme
l'architecture explicitement, jamais `hayabusa*.exe`.**

Les mappings de Chainsaw ne sont livrés que dans le bundle `all_platforms+rules+examples` :
l'archive par plateforme ne contient que l'exécutable. Sans mapping, aucune règle ne remonte
— et l'outil ne signale rien.

## Pourquoi je ne fige pas les numéros ici

Les trois projets publient leurs binaires sur la page des versions de leur dépôt GitHub, et
renomment régulièrement leurs options. Un script qui code en dur `--output` là où la version
courante attend `--out` échoue sans expliquer pourquoi.

C'est la raison du bloc de configuration en tête de `scripts/Invoke-Analyse.ps1` : les
quatre chemins et le nom du mapping y sont isolés, commentés, et vous les corrigez une seule
fois après avoir lu :

```powershell
hayabusa.exe --help
chainsaw.exe hunt --help
```

C'est le même principe que la couche de traduction du module 01 : `--pipeline` pour
sigma-cli, `--mapping` pour Chainsaw, le module d'ingestion pour Elastic. **Quand une règle
valide ne remonte rien, on suspecte cette couche avant de suspecter la règle.**

## Empreintes des binaires

À remplir pour les binaires téléchargés hors gestionnaire de paquets. C'est ce qui permet de
dire, six mois plus tard, que le binaire utilisé est bien celui qu'on croit.

```powershell
Get-FileHash C:\Lab\outils\hayabusa\hayabusa.exe -Algorithm SHA256
Get-FileHash C:\Lab\outils\chainsaw\chainsaw.exe -Algorithm SHA256
```

| Binaire | SHA-256 | Vérifié contre la publication officielle |
|---|---|---|
| hayabusa.exe | | |
| chainsaw.exe | | |
