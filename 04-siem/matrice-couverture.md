# Matrice de couverture — module 04

Le livrable du module. Pour chaque règle : **la donnée arrive-t-elle dans le SIEM, dans quels
champs, la règle convertie la trouve-t-elle, et combien d'alertes produit-elle au repos ?**

**À remplir au fil des phases.**

---

## Sources dans le SIEM

| Source | Machine | Flux de données | Événements reçus | Champs ECS vérifiés | Statut |
|---|---|---|---|---|---|
| Sysmon | VM Windows | `logs-windows.sysmon_operational-*` | | | |
| PowerShell | VM Windows | `logs-windows.powershell*` | | | |
| Sécurité Windows | VM Windows | `logs-system.security-*` | | | |
| Zeek | sonde | `logs-zeek.*` | | | |
| Suricata | sonde | `logs-suricata.eve-*` | | | |

## Règles Sigma du module 01, portées dans Elastic

| # | Règle | Conversion | Rejeu | Alerte de notre règle | Règle Elastic équivalente | Alertes au repos | Statut |
|---|---|---|---|---|---|---|---|
| 01 | Accès mémoire LSASS | | T1003.001-2 | | | | |
| 02 | PowerShell encodé | | T1059.001-15 | | | | |
| 03 | Tâche planifiée | | T1053.005-1 | | | | |
| 04 | Clé de démarrage | | T1547.001-1 | | | | |
| 05 | Thread distant | | — | | | | |
| 06 | Rundll32 détourné | | T1003.001-2 | | | | |
| 07 | LOLBin sortant | | T1105 | | | | |
| 08 | Service suspect | | T1543.003 | | | | |
| 09 | Clichés instantanés (v2) | | T1490-1, -5 | | | | |
| 10 | Exécution WMI (v2) | | T1047-7 | | | | |

Valeurs du statut : **Validée** (alerte au rejeu, bruit au repos expliqué) · **Corrigée** (a
demandé une correction de champ, de pipeline ou de règle) · **Muette** (convertie sans erreur,
ne trouve rien) · **Non éprouvée**.

## Le réseau dans le SIEM

| Capture (module 03) | Ce qu'on doit retrouver | Retrouvé ? | Requête |
|---|---|---|---|
| Lumma | `POST /api/set_agent …&act=log` ; alertes 1000001-1000002 | | |
| NetSupport | 264 POST vers `45.131.214.85:443`, agent `NetSupport Manager/1.3` | | |
| Natureforce | flux de 37 min vers `195.63.128.106:443`, sans protocole ; alerte 1000003 | | |

## Corrélation

| Scénario | Langage | Sources | Résultat |
|---|---|---|---|
| Natureforce reconstitué : `curl` → exécutable sur port inhabituel → 443 sans protocole | EQL | Zeek | |
| Attaque rejouée suivie du processus au paquet | EQL | Sysmon + Zeek | *(si la sonde voit le trafic de la VM Windows)* |

## Les lignes, en détail

*(une section par règle et par source : ce qui est arrivé, dans quels champs, ce qui a été corrigé)*

## Enseignements de méthode

*(à écrire en fin de module)*
