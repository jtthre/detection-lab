# Matrice technique → donnée → règle

Le livrable central du module 1. Elle se lit de gauche à droite comme le raisonnement
à tenir : je pars d'une technique ATT&CK, je détermine quelle donnée la rend visible,
je vérifie que ma configuration Sysmon produit bien cette donnée, et seulement ensuite
j'écris la règle.

Faire l'inverse — écrire la règle d'abord — est la raison pour laquelle tant de règles
de débutants ne se déclenchent jamais.

| # | Technique ATT&CK | Nom | Événement Sysmon | Catégorie Sigma | Activé par défaut ? | Règle | Sévérité |
|---|---|---|---|---|---|---|---|
| 01 | T1003.001 | Vol d'identifiants — mémoire LSASS | 10 ProcessAccess | `process_access` | **Non** | `01_lsass_process_access.yml` | high |
| 02 | T1059.001 | Exécution — PowerShell | 1 ProcessCreate | `process_creation` | Oui | `02_powershell_encoded_command.yml` | medium |
| 03 | T1053.005 | Persistance — tâche planifiée | 1 ProcessCreate | `process_creation` | Oui | `03_scheduled_task_creation.yml` | medium |
| 04 | T1547.001 | Persistance — clé Run | 13 RegistryEvent | `registry_set` | **Non** | `04_run_key_persistence.yml` | high |
| 05 | T1055 | Évasion — injection de code | 8 CreateRemoteThread | `create_remote_thread` | **Non** | `05_create_remote_thread.yml` | high |
| 06 | T1218.011 | Évasion — exécution par proxy signé | 1 ProcessCreate | `process_creation` | Oui | `06_rundll32_suspicious.yml` | high |
| 07 | T1105 | Commande et contrôle — transfert d'outil | 3 NetworkConnect | `network_connection` | **Non** | `07_lolbin_network_connection.yml` | high |
| 08 | T1543.003 | Persistance — création de service | 13 RegistryEvent | `registry_set` | **Non** | `08_service_creation_registry.yml` | high |
| 09 | T1490 | Impact — inhibition de la restauration | 1 ProcessCreate | `process_creation` | Oui | `09_shadow_copy_deletion.yml` | **critical** |
| 10 | T1047 | Exécution et latéralisation — WMI | 1 ProcessCreate | `process_creation` | Oui | `10_wmi_remote_execution.yml` | high |

## Le chiffre qui compte

**Cinq règles sur dix reposent sur un événement Sysmon désactivé par défaut.**

C'est le résultat le plus important du module, et celui à retenir pour un entretien :
la moitié de votre couverture de détection n'existe pas tant que la configuration
n'active pas explicitement les événements 3, 8, 10 et 13. Un poste Windows avec
Sysmon installé « par défaut » est aveugle au vol d'identifiants, à l'injection de
code, à la persistance par le registre et aux connexions sortantes.

## Répartition par source de données

| Catégorie Sigma | Règles | Commentaire |
|---|---|---|
| `process_creation` | 5 | La source la plus riche et la moins coûteuse à activer |
| `registry_set` | 2 | Nécessite un filtrage serré, sinon volume ingérable |
| `process_access` | 1 | Filtrée sur LSASS uniquement — sans ce filtre, le journal sature |
| `create_remote_thread` | 1 | Volume naturellement faible, valeur élevée |
| `network_connection` | 1 | Liste blanche de binaires détournés |

Cinq sources distinctes pour dix règles : c'est volontaire. Une couverture qui repose
entièrement sur `process_creation` s'effondre dès qu'un attaquant évite de créer un
processus — ce que font la plupart des techniques modernes.

## Couverture par tactique ATT&CK

| Tactique | Règles |
|---|---|
| Exécution | 02, 10 |
| Persistance | 03, 04, 08 |
| Élévation de privilèges | 03, 05, 08 |
| Évasion de défense | 05, 06 |
| Accès aux identifiants | 01 |
| Déplacement latéral | 10 |
| Commande et contrôle | 07 |
| Impact | 09 |

**Tactiques non couvertes :** reconnaissance, accès initial, découverte, collecte,
exfiltration. C'est normal à ce stade et il faut savoir le dire : dix règles ne
couvrent pas ATT&CK. Annoncer ses trous vaut mieux que de laisser croire à une
couverture complète — un recruteur technique repère immédiatement la seconde posture.

## À faire après ce module

1. Relever, après 48 h de collecte, les trois processus les plus bruyants de votre VM
   et les ajouter aux exclusions de `ProcessCreate`. Mesurer la réduction de volume.
2. Comparer cette configuration à celles de SwiftOnSecurity et d'Olaf Hartong.
   Identifier trois blocs qu'elles ont et que celle-ci n'a pas, et expliquer pourquoi.
3. Au module 2, chaque règle sera confrontée à un test atomique réel. La colonne
   « détectée / partielle / manquée » viendra s'ajouter à cette matrice.
