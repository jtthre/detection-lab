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

## Phase 1 — La VM siem-elastic

Nom `siem-elastic` (VM, dossier et nom d'hôte) : une ancienne VM « SIEM » existe déjà dans la
bibliothèque VMware ; elle reste **éteinte** pendant le module.

| Réglage | Valeur | Pourquoi |
|---|---|---|
| Système | Ubuntu Server **26.04.1 LTS**, OpenSSH, aucun snap, clavier **French (AZERTY)** | même base que la sonde |
| Ressources | **8 Go** de RAM, **4 cœurs**, **60 Go** alloués à la demande, accélération 3D désactivée, ni carte son ni imprimante | Elasticsearch (tas 4 Go) + Kibana + Fleet Server |
| Carte 1 (`ens33`) | **Host-only**, `192.168.234.20/24` fixe, **sans passerelle ni DNS** | le réseau du lab, permanent |
| Carte 2 (`ens34`) | **NAT**, DHCP, branchée seulement pendant les installations | paquets, intégrations et règles viennent d'Elastic |

Assistant VMware en mode **Custom** avec *I will install the operating system later* (l'*Easy
Install* imposerait un clavier QWERTY et créerait l'utilisateur). L'adresse fixe se règle dans
l'installateur (écran réseau → `ens33` → *Edit IPv4* → *Manual*). Sans passerelle sur `ens33`, la
seule route par défaut passe par la carte NAT : la débrancher coupe toute sortie.

**Stockage** : l'installateur ne donne que la moitié du groupe LVM à `/` (29 Go sur 58). Éditer
`ubuntu-lv` et lui donner tout l'espace.

Contrôles (attendus) :

```bash
ip -br a          # ens33 192.168.234.20/24, ens34 en 192.168.64.x
ip route          # une seule route par défaut, via ens34
free -h           # ≈ 7,2 Gi
df -h /           # ≈ 57 G
```

Depuis la sonde : `ping -c 3 192.168.234.20`. Ensuite on travaille **en SSH depuis l'hôte**
(`ssh mthiore@192.168.234.20`) : copier-coller sans VMware Tools. Mise à jour
(`apt full-upgrade`, `apt autoremove`), puis instantané **« siem-elastic installée (phase 1) »**.

## Phase 2 — Elasticsearch et Kibana (carte NAT branchée)

```bash
sudo apt-get install -y apt-transport-https gpg curl jq
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/elastic-9.x.list
sudo apt-get update
apt-cache policy elasticsearch kibana          # prendre la DERNIÈRE version publiée, identique pour les deux
sudo apt-get install -y elasticsearch=9.5.5 kibana=9.5.5
sudo apt-mark hold elasticsearch kibana        # pas de mise à jour surprise au milieu du module
```

L'installation affiche un mot de passe généré pour le superutilisateur `elastic`. On ne le
recopie pas : on le remplacera, **une fois Elasticsearch démarré** (l'outil passe par l'API).

**Le tas de la JVM** — fixé, pas laissé au calcul automatique — et le nom du cluster :

```bash
printf -- '-Xms4g\n-Xmx4g\n' | sudo tee /etc/elasticsearch/jvm.options.d/heap.options
sudo sed -i 's/^#cluster.name:.*/cluster.name: detection-lab/; s/^#node.name:.*/node.name: siem-elastic/' /etc/elasticsearch/elasticsearch.yml
sudo systemctl daemon-reload && sudo systemctl enable --now elasticsearch
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i   # mot de passe choisi, rangé dans le gestionnaire
```

Saisir le mot de passe **par collage** depuis le gestionnaire (clic droit dans le terminal), sans
caractères accentués : une frappe à la main a donné un 401 au premier essai.

**L'autorité de certification** : `/etc/elasticsearch` n'est lisible que par root et le groupe
`elasticsearch` ; `curl` lancé par l'utilisateur répond « le fichier n'existe pas ». On en garde une
copie dans le dossier personnel (certificat **public**, pas un secret) — c'est aussi elle que lit
`verifier-siem.sh` :

```bash
sudo cp /etc/elasticsearch/certs/http_ca.crt ~/http_ca.crt && sudo chown mthiore: ~/http_ca.crt
curl --cacert ~/http_ca.crt -u elastic https://localhost:9200     # name siem-elastic, cluster detection-lab, 9.5.5
```

**Kibana**, inscrit auprès d'Elasticsearch par un jeton à usage unique (valable 30 min). Le jeton et
les clés de chiffrement passent d'un outil à l'autre **sans s'afficher** :

```bash
sudo /usr/share/kibana/bin/kibana-setup --enrollment-token "$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)"
sudo /usr/share/kibana/bin/kibana-encryption-keys generate -q | sudo tee -a /etc/kibana/kibana.yml > /dev/null
sudo grep -c 'encryptionKey' /etc/kibana/kibana.yml      # 3
sudo sed -i 's|^#server.host:.*|server.host: "192.168.234.20"|; s|^#server.publicBaseUrl:.*|server.publicBaseUrl: "http://192.168.234.20:5601"|' /etc/kibana/kibana.yml
sudo systemctl enable --now kibana
```

- `server.host` sur l'adresse du lab, **pas `0.0.0.0`** : Kibana n'écoute pas sur la carte NAT.
- Les trois clés (`xpack.encryptedSavedObjects`, `xpack.reporting`, `xpack.security`) : **sans la
  première, le moteur de règles de Security refuse de démarrer.** Ce sont des secrets :
  `kibana.yml` ne va pas dans le dépôt.

**Un seul nœud** : les modèles d'index demandent un réplica qu'aucun second nœud ne peut porter.
On le dit à Elasticsearch une fois pour toutes, dans le modèle personnalisable `logs@custom` :

```bash
curl --cacert ~/http_ca.crt -u elastic -X PUT "https://localhost:9200/_component_template/logs@custom" \
  -H 'Content-Type: application/json' -d '{"template":{"settings":{"index":{"number_of_replicas":0}}}}'
curl --cacert ~/http_ca.crt -u elastic "https://localhost:9200/_cluster/health?pretty"   # green
```

Constat du 15/10 : Kibana s'ouvre depuis l'hôte (`http://192.168.234.20:5601`), cluster **green**,
51 partitions primaires actives, 0 non assignée. Instantané **« phase 2 : Elastic + Kibana »**.

## Phase 3 — Fleet Server, intégrations et règles Elastic (carte NAT encore branchée)

### 3a — Deux corrections avant Fleet

**Kibana joignait Elasticsearch par la carte NAT.** Le jeton d'inscription de la phase 2 a inscrit
`elasticsearch.hosts: [https://192.168.64.140:9200]` : débrancher la carte NAT aurait coupé Kibana.
Le certificat HTTP d'Elasticsearch couvre `192.168.234.20` (vérifié avec `openssl s_client … |
openssl x509 -noout -ext subjectAltName`), on corrige donc, et on limite Elasticsearch au lab :

```bash
sudo sed -i 's|192.168.64.140|192.168.234.20|' /etc/kibana/kibana.yml
sudo sed -i 's|^http.host: 0.0.0.0|http.host: [_local_, "192.168.234.20"]|' /etc/elasticsearch/elasticsearch.yml
sudo systemctl restart elasticsearch && sudo systemctl restart kibana
sudo ss -ltnp | grep -E ':9200|:5601'      # 9200 sur .20, 127.0.0.1, ::1 ; 5601 sur .20
```

**Une autorité de certification du lab pour Fleet Server.** Le *Quick Start* de Kibana donne à
Fleet Server un certificat auto-signé : chaque agent devrait alors s'inscrire avec `--insecure`.
On signe plutôt un certificat pour `192.168.234.20` avec une autorité propre au lab.
`elasticsearch-certutil` résout les chemins relatifs dans **son** dossier
(`/usr/share/elasticsearch`) : chemins absolus obligatoires.

```bash
mkdir -p ~/fleet-certs && cd ~/fleet-certs
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil ca --pem --days 730 --out "$PWD/ca.zip" && sudo unzip -o ca.zip
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert --pem --ca-cert "$PWD/ca/ca.crt" --ca-key "$PWD/ca/ca.key" \
  --name fleet-server --ip 192.168.234.20 --dns siem-elastic --days 730 --out "$PWD/fleet-server.zip" && sudo unzip -o fleet-server.zip
sudo chown -R mthiore: ~/fleet-certs && chmod 600 ca/ca.key fleet-server/fleet-server.key
sudo install -d -m 750 /etc/fleet-server-certs
sudo install -m 644 ca/ca.crt fleet-server/fleet-server.crt ~/http_ca.crt /etc/fleet-server-certs/
sudo install -m 600 fleet-server/fleet-server.key /etc/fleet-server-certs/
openssl x509 -fingerprint -sha256 -noout -in ~/http_ca.crt | cut -d= -f2 | tr -d ':'   # empreinte pour Fleet
```

Les clés privées (`ca.key`, `fleet-server.key`) ne quittent pas la siem et ne vont pas dans le
dépôt. Seul `ca.crt` (public) part avec les agents.

### 3b — Fleet Server

1. **Fleet → Paramètres** : hôte Fleet Server `https://192.168.234.20:8220` (par défaut) ;
   sortie `default` sur `https://192.168.234.20:9200` avec l'empreinte de l'étape précédente.
2. **Ajouter un serveur Fleet → Advanced**, mode **Production**, politique
   `fleet-server-policy`, *Générer un token de service*. Plateforme **Linux x86_64** (l'assistant
   a proposé `arm64` par défaut).
3. **Le jeton de service est un secret** : on le copie avec l'icône de copie et il passe au
   terminal sans s'afficher.

```bash
cd ~ && curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.5.5-linux-x86_64.tar.gz
tar xzf elastic-agent-9.5.5-linux-x86_64.tar.gz
read -rsp "Jeton de service : " FLEET_TOKEN && echo        # seule, collage du jeton
cd ~/elastic-agent-9.5.5-linux-x86_64 && sudo ./elastic-agent install \
  --url=https://192.168.234.20:8220 \
  --fleet-server-es=https://192.168.234.20:9200 \
  --fleet-server-service-token="$FLEET_TOKEN" \
  --fleet-server-policy=fleet-server-policy \
  --fleet-server-es-ca-trusted-fingerprint=<empreinte> \
  --certificate-authorities=/etc/fleet-server-certs/ca.crt \
  --fleet-server-cert=/etc/fleet-server-certs/fleet-server.crt \
  --fleet-server-cert-key=/etc/fleet-server-certs/fleet-server.key \
  --fleet-server-port=8220 \
  --install-servers ; unset FLEET_TOKEN
```

**Incident du 16/10** : un premier essai (Quick Start, `arm64`, espaces après `=`) a fait
apparaître un jeton complet sur une capture d'écran. Les deux jetons émis ont été **révoqués**
(Outils de développement) avant de recommencer :

```
GET _security/service/elastic/fleet-server/credential
DELETE _security/service/elastic/fleet-server/credential/token/<nom>
```

Contrôles :

```bash
sudo elastic-agent status          # fleet HEALTHY Connected, elastic-agent HEALTHY
openssl s_client -connect 192.168.234.20:8220 -CAfile ~/fleet-certs/ca/ca.crt -brief </dev/null
# Peer certificate: CN=fleet-server — Verification: OK — TLSv1.3
```

**Pare-feu.** Fleet Server écoutait sur `*:8220` et l'intégration Fleet Server 1.6.1 n'a plus de
champ « Hôte ». On ferme donc la carte NAT au niveau du système, une règle pour tous les services :

```bash
sudo ufw default deny incoming && sudo ufw default allow outgoing
sudo ufw allow in on ens33 to any port 22 proto tcp
sudo ufw allow in on ens33 to any port 5601,8220,9200 proto tcp
sudo ufw enable
```

9200 reste ouvert sur le lab : les agents envoient leurs données **directement** à Elasticsearch.

### 3c — Ce qui demande Internet

1. **Ressources des intégrations** (Intégrations → *nom* → Paramètres → Installer les
   ressources) : Windows, System, Zeek, Suricata. Aucune n'est ajoutée à une politique avant
   les phases 4 et 6.
2. **Règles Elastic** (Security → Règles → Ajouter les règles Elastic → Installer toutes) :
   elles arrivent désactivées… **sauf deux**, qu'Elastic active d'office :
   *Endpoint Security (Elastic Defend)* et *Container Workload Protection*. On les désactive :
   **0 règle active** au départ, chaque activation sera un choix justifié.
3. **Listes de valeurs de Security** : le premier passage dans Security crée `.lists-default` et
   `.items-default`, dont le modèle n'hérite pas de `logs@custom` → cluster jaune. Correction
   ciblée (0 réplica sur un nœud, 1 s'il en vient un second) :

   ```
   PUT .lists-default,.items-default/_settings
   { "index.auto_expand_replicas": "0-1" }
   ```

4. **Agents pour les autres VM**, vérifiés avant usage :

   ```bash
   mkdir -p ~/agents && cd ~/agents
   curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.5.5-windows-x86_64.zip
   curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.5.5-windows-x86_64.zip.sha512
   curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.5.5-linux-x86_64.tar.gz.sha512
   mv ~/elastic-agent-9.5.5-linux-x86_64.tar.gz . && sha512sum -c *.sha512
   cp ~/fleet-certs/ca/ca.crt ~/agents/fleet-ca.crt
   ```

5. **Clé d'API en lecture seule** pour `verifier-siem.sh`. On ne devine pas les noms des
   privilèges Kibana : on crée un rôle `verificateur-siem` dans l'interface (cluster `monitor` ;
   `logs-*` en `read` + `view_index_metadata` ; Kibana : Fleet *Read*, Security → *Rules and
   Exceptions* *Read*), on lit ce que Kibana a généré (`GET _security/role/verificateur-siem` →
   `feature_fleetv2.read`, `feature_securitySolutionRulesV4.read`), et on crée la clé avec
   exactement ces droits :

   ```
   POST _security/api_key
   {
     "name": "verificateur-siem",
     "expiration": "90d",
     "role_descriptors": { "verificateur-siem": {
       "cluster": ["monitor"],
       "indices": [ { "names": ["logs-*"], "privileges": ["read", "view_index_metadata"] } ],
       "applications": [ { "application": "kibana-.kibana",
         "privileges": ["feature_fleetv2.read", "feature_securitySolutionRulesV4.read"],
         "resources": ["space:default"] } ] } }
   }
   ```

   La valeur `encoded` de la réponse va directement au gestionnaire de mots de passe (pas de
   capture). Révocation : `DELETE _security/api_key { "ids": ["<id>"] }`.

### Hors ligne

Débrancher la carte NAT (VMware → Network Adapter 2 → décocher *Connected*), puis :

```bash
read -rsp "Clé d'API : " ES_API_KEY && echo && export ES_API_KEY
~/verifier-siem.sh ; unset ES_API_KEY
```

Constat du 26/10 : isolement **OK (aucune route sortante)**, Elasticsearch 9.5.5, cluster
**vert**, Kibana disponible, 1 agent en ligne (9.5.5), disque 30 %, 2 157 règles installées ;
les quatre flux en alerte « vide » (aucune source branchée). Instantané
**« siem-elastic installée hors ligne (phase 3) »**, VM éteinte.

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
