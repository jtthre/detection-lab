# Plan de test — module 04

Une question par phase : **la donnée arrive-t-elle, dans quels champs, et la règle qui la vise
déclenche-t-elle — et seulement elle ?** La même boucle de preuve qu'au module 02, appliquée au
SIEM.

Les commandes ci-dessous sont celles prévues au 15/10/2026 pour Elastic **9.5.5**. Les étapes
qui dépendent de l'interface de Kibana sont décrites, pas scriptées : on note dans `VERSIONS.md`
et dans `preuves/` ce qu'on a réellement fait.

---

## Phase 0 — La place sur l'hôte

L'hôte a **24 Go de RAM** et son disque a déjà fait tomber une VM au module 03. Avant tout :

```powershell
[math]::Round((Get-PSDrive C).Free/1GB,1)      # objectif : au moins 60 Go libres
```

Libérer la place en **déplaçant** `srv-wazuh` (44 Go) sur un autre disque : VM éteinte, dossier
copié, VM rouverte depuis son nouvel emplacement (réponse « I Moved It »), démarrage vérifié, puis
seulement l'ancien dossier retiré du disque C:.

## Phase 1 — La VM siem

| Réglage | Valeur | Pourquoi |
|---|---|---|
| Système | Ubuntu Server **26.04.1 LTS**, OpenSSH, aucun snap | même base que la sonde |
| Ressources | **8 Go** de RAM, **4 processeurs**, **60 Go** alloués à la demande | Elasticsearch (tas 4 Go) + Kibana + Fleet Server |
| Carte 1 | **Réseau hôte uniquement**, adresse fixe `192.168.234.20/24` | le réseau du lab, permanent |
| Carte 2 | **NAT**, branchée seulement pendant les installations | paquets, intégrations et règles viennent d'Elastic |

Adresse fixe, sur le modèle de la sonde (`/etc/netplan/60-siem-ip-fixe.yaml`, droits 600) :

```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: true
      addresses: [192.168.234.20/24]
```

Le nom de la carte (`ens33`, `ens34`…) se lit avec `ip -br a` : la carte hôte uniquement est celle
qui reçoit une adresse en `192.168.234.`.

## Phase 2 — Elasticsearch et Kibana (carte NAT branchée)

```bash
sudo apt-get update && sudo apt-get install -y apt-transport-https gpg curl jq
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/elastic-9.x.list
sudo apt-get update
apt-cache policy elasticsearch kibana          # prendre la DERNIÈRE version publiée, identique pour les deux
sudo apt-get install -y elasticsearch=9.5.5 kibana=9.5.5
sudo apt-mark hold elasticsearch kibana        # pas de mise à jour surprise au milieu du module
```

L'installation affiche un mot de passe pour le superutilisateur `elastic`. On ne le recopie pas :
on le **remplace** par un mot de passe choisi, tapé directement et rangé dans le gestionnaire :

```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i
```

**Le tas de la JVM** — fixé, pas laissé au calcul automatique :

```bash
printf -- '-Xms4g\n-Xmx4g\n' | sudo tee /etc/elasticsearch/jvm.options.d/heap.options
```

Dans `/etc/elasticsearch/elasticsearch.yml` : `cluster.name: detection-lab`,
`node.name: siem`. Puis :

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now elasticsearch
curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic https://localhost:9200
```

**Kibana**, inscrit auprès d'Elasticsearch par un jeton à usage unique (valable 30 min) :

```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
sudo /usr/share/kibana/bin/kibana-setup --enrollment-token <jeton>
sudo /usr/share/kibana/bin/kibana-encryption-keys generate -q    # 3 clés à ajouter à kibana.yml
```

Dans `/etc/kibana/kibana.yml` : `server.host: "0.0.0.0"`,
`server.publicBaseUrl: "http://192.168.234.20:5601"`, et les trois clés
`xpack.encryptedSavedObjects.encryptionKey`, `xpack.reporting.encryptionKey`,
`xpack.security.encryptionKey`. **Sans la première, le moteur de règles de Security refuse de
démarrer.** Ces clés sont des secrets : `kibana.yml` ne va pas dans le dépôt.

```bash
sudo systemctl enable --now kibana
```

**Un seul nœud = santé jaune** : les modèles d'index demandent un réplica qu'aucun second nœud ne
peut porter. On le dit à Elasticsearch une fois pour toutes, dans le modèle personnalisable
`logs@custom` (Kibana → Gestion de la pile → Modèles de composants), avec
`"index": { "number_of_replicas": 0 }`.

## Phase 3 — Fleet, intégrations et règles Elastic (carte NAT encore branchée)

Dans Kibana (`http://<adresse NAT>:5601` depuis l'hôte, puis `192.168.234.20` ensuite) :

1. **Fleet → Paramètres** : hôte Fleet Server `https://192.168.234.20:8220` ; sortie
   Elasticsearch `https://192.168.234.20:9200` avec l'empreinte de l'autorité de certification
   (`openssl x509 -fingerprint -sha256 -noout -in /etc/elasticsearch/certs/http_ca.crt`).
2. **Ajouter Fleet Server** sur la VM siem (mode démarrage rapide) : Kibana génère la commande
   d'installation de l'agent, avec un jeton de service. Elle se lance telle quelle sur la VM siem.
3. **Intégrations** : installer les ressources de **Windows**, **System**, **Zeek** et
   **Suricata** (onglet Paramètres de chaque intégration).
4. **Security → Règles → Ajouter les règles Elastic** : installer le paquet de règles prêtes à
   l'emploi. **N'en activer aucune pour l'instant.**
5. **Agents pour les autres VM** : télécharger sur la VM siem, dans `~/agents/`, les archives
   d'Elastic Agent de la **même version** pour Linux (`.tar.gz`) et Windows (`.zip`). Les VM
   du lab les récupéreront par `scp` depuis la siem : elles n'ont pas besoin d'Internet.

Puis **débrancher la carte NAT** (VMware → Network Adapter 2 → décocher *Connected*), et :

```bash
cd ~/detection-lab/04-siem && ./scripts/verifier-siem.sh
```

Instantané **« siem installée hors ligne »**, VM éteinte.

## Phase 4 — La source poste : la VM Windows

VM Windows : instantané « VM outillée hors ligne — module 02 », **6 Go de RAM**, carte en réseau
hôte uniquement. La sonde peut rester éteinte : elle ne sert qu'à partir de la phase 6.

1. Politique d'agent **« poste-windows »** dans Fleet : intégrations **Windows** (Sysmon +
   PowerShell) et **System** (Sécurité, Système).
2. Copier l'archive Windows d'Elastic Agent depuis la siem (`scp`), puis l'installer avec la
   commande d'inscription donnée par Fleet. Le certificat de Fleet Server est auto-signé en mode
   démarrage rapide : l'option `--insecure` est acceptable **dans ce lab uniquement**, et notée
   comme limite.
3. **Vérifier la donnée avant toute règle** :
   - l'agent est « Healthy » dans Fleet ;
   - Discover, `logs-windows.sysmon_operational-*` : des événements arrivent ;
   - un `whoami` lancé dans la VM apparaît en moins d'une minute, et on note **dans quels champs** :
     `process.executable`, `process.command_line`, `process.parent.executable`,
     `winlog.event_data.*`.

Ce relevé de champs décide de tout le reste : il dit si le pipeline `ecs_windows` de Sigma
correspond à ce que l'agent écrit vraiment.

## Phase 5 — Porter les règles du module 01

```bash
pip install --user sigma-cli pySigma-backend-elasticsearch pySigma-pipeline-windows
./scripts/convertir-sigma.sh
```

Le script convertit les dix règles et écrit un fichier par règle dans `regles/`. Pour chaque règle :

1. **Lire la requête produite** et la confronter au relevé de champs de la phase 4.
2. **Importer désactivée** (Security → Règles → Importer, ou API).
3. **Rejouer** l'atomique du module 02 correspondant, dans la VM Windows.
4. **Constater** : l'événement est-il dans le SIEM ? la règle, lancée à la main sur la fenêtre du
   rejeu, le trouve-t-elle ?
5. **Corriger** dans le dépôt (pipeline, champ, règle), reconvertir, réimporter.
6. **Activer**, puis laisser tourner sur une fenêtre de repos et **compter les alertes**.

| # | Règle | Atomique de rejeu | Attendu dans le SIEM |
|---|---|---|---|
| 01 | Accès mémoire LSASS | T1003.001-2 | toujours bloqué par RunAsPPL : **0**, comme au module 02 |
| 02 | PowerShell encodé | T1059.001-15 | ≥ 1 |
| 03 | Tâche planifiée | T1053.005-1 | ≥ 1 |
| 04 | Clé de démarrage | T1547.001-1 | ≥ 1, **et 0 au repos** (le faux positif du module 02) |
| 05 | Thread distant | — | non éprouvée (outil absent de l'édition Famille) |
| 06 | Rundll32 détourné | effet de bord de T1003.001-2 | ≥ 1 |
| 07 | LOLBin sortant | T1105 (à choisir) | **première mesure** : le modificateur `cidr` est géré par Elasticsearch |
| 08 | Service suspect | T1543.003 | angle mort du module 02 à revérifier |
| 09 | Clichés instantanés (v2) | T1490-1 et -5 | ≥ 1 chacun |
| 10 | Exécution WMI (v2) | T1047-7 | ≥ 1 |

En parallèle, activer les **règles Elastic équivalentes** (même technique ATT&CK) et noter qui
voit quoi : c'est la colonne « Elastic » de la matrice.

## Phase 6 — La source réseau : la sonde

Sonde à **3 Go de RAM**, carte en réseau hôte uniquement (`192.168.234.10`). La VM Windows peut
rester éteinte : les données réseau de cette phase viennent des pcaps du module 03.

1. **Zeek en JSON** : l'intégration d'Elastic ne lit pas le format TSV. On relit les captures du
   module 03 avec `LogAscii::use_json=T`, dans un dossier que l'agent surveille
   (`/var/log/lab/zeek/<étiquette>/`), et Suricata dans `/var/log/lab/suricata/<étiquette>/`.
   Le script de relecture s'écrit dans cette phase, sur le modèle d'`analyser-pcap.sh`.
2. Politique d'agent **« sonde »** : intégrations **Zeek** et **Suricata**, chemins réglés sur
   ces dossiers.
3. Agent Linux copié depuis la siem par `scp`, inscrit auprès de Fleet.
4. **Vérifier les champs ECS** : `source.ip`, `destination.ip`, `destination.port`,
   `network.protocol`, `user_agent.original`, `dns.question.name`, `tls.server.name` (SNI).
5. **Retrouver les trois C2 du module 03 dans le SIEM** : Lumma (`/api/set_agent`), NetSupport
   (264 POST vers `45.131.214.85:443`), Natureforce (le flux de 37 min sans protocole). Les
   règles locales 1000001 à 1000003 doivent apparaître dans les alertes Suricata ingérées.

## Phase 7 — Corréler

**Sur une même source** : une séquence EQL qui reconstitue Natureforce dans les données Zeek —
`curl` vers un domaine, puis téléchargement d'un exécutable sur un port inhabituel, puis
connexion longue sur 443 sans protocole reconnu, le tout depuis le même hôte en moins de 5 min.

**Entre le poste et le réseau** : n'est possible que si la sonde voit le trafic de la VM Windows.
À vérifier avant de le promettre : la sonde, carte en mode promiscuité sur le réseau hôte
uniquement, reçoit-elle les paquets échangés entre la VM Windows et un autre hôte ? Si oui, une
attaque rejouée produit à la fois un événement Sysmon 3 (connexion réseau) et une ligne
`conn.log`, que la requête relie par `source.ip`, `destination.ip` et l'heure.

## Phase 8 — Régler

Pour chaque règle activée, une fenêtre de repos (VM allumée, aucun test) et le compte des alertes.
Chaque alerte de repos est expliquée ; une exception n'est ajoutée qu'**avec sa justification
dans le dépôt** — jamais une exclusion large « pour que ça se taise ».

## Phase 9 — Un tableau de bord qui répond à une question

Une question opérationnelle, formulée avant le tableau. Candidate : **« Quelles machines ont
parlé à une destination jamais vue, sur le port 443, sans TLS, cette semaine ? »** — la leçon du
module 03 transformée en écran de SOC. Export dans `tableaux-de-bord/`.

## Phase 10 — Splunk (fin de module)

Une semaine. Splunk Enterprise en essai, jeu de données Boss of the SOC, une investigation menée
et rédigée en SPL. Version, taille du jeu de données et place nécessaire vérifiées au moment de
s'y mettre — le disque de l'hôte décide.

---

## Ce qu'on consigne

1. Les versions réelles (`VERSIONS.md`).
2. Pour chaque source : le relevé des champs ECS réellement remplis (`preuves/`).
3. Pour chaque règle : requête convertie, rejeu, résultat, bruit au repos (`matrice-couverture.md`).
4. Les règles converties et leurs corrections (`regles/`).
5. Le tableau de bord exporté (`tableaux-de-bord/`).

## Le critère d'échec qu'on oublie

Une règle importée « sans erreur » n'est pas une règle qui fonctionne. Au module 01, le piège
était la donnée absente ; au module 04, c'est **le champ mal nommé** : la règle cherche
`process.executable`, l'agent a écrit ailleurs, la règle est muette — et Kibana ne le signale pas.
