# Plan de test — module 03

Une question par capture : **le canal de commande documenté est-il visible, par quel outil, et
pourquoi pas par les autres ?** Et une question pour la capture de trafic normal : **combien
de fausses alertes sur un poste sain ?**

---

## Phase 1 — La sonde

| Réglage | Valeur | Pourquoi |
|---|---|---|
| Système | Ubuntu Server **26.04.1 LTS** (24.04 était prévue) | Les deux outils ont des paquets pour la 26.04 : Suricata via le PPA de l'OISF, Zeek via le dépôt `xUbuntu_26.04` du service openSUSE Build Service |
| Ressources | 4 Go de RAM, 2 processeurs, 30 Go de disque (un seul fichier) | Zeek et Suricata en mode fichier sont modestes ; le disque sert aux journaux |
| Réseau | **NAT** pendant l'installation, puis **réseau hôte uniquement** | SSH depuis l'hôte reste possible, aucune route vers Internet ni le réseau domestique |
| Paquets | OpenSSH server, aucun snap | Travail depuis Windows Terminal en `ssh`, copier-coller direct |

## Phase 2 — L'outillage (VM en NAT)

**Suricata**, depuis les paquets de l'OISF :

```bash
sudo apt-get update
sudo apt-get install -y software-properties-common jq python3
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata
suricata -V
# Le paquet active un service Suricata sur la carte réseau : inutile ici, on lit des fichiers.
sudo systemctl disable --now suricata
# Les règles ne sont lisibles que par root et le groupe suricata. On analyse SANS root :
# la 8.0.7 a corrigé 67 failles, en majorité dans les analyseurs de protocoles — faire
# lire des captures de maliciels par un processus root, c'est exposer root au premier
# paquet piégé.
sudo usermod -aG suricata $USER     # puis se déconnecter / reconnecter
```

**Les règles ET Open**, téléchargées et assemblées par `suricata-update` :

```bash
sudo suricata-update
sudo suricata -T          # test de configuration avec les règles chargées
```

**Zeek**, depuis ses paquets officiels (service openSUSE Build Service) :

```bash
V=$(. /etc/os-release; echo $VERSION_ID)     # le dépôt dépend de la version d'Ubuntu
echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${V}/ /" \
  | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_${V}/Release.key" \
  | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt-get update
sudo apt-get install -y zeek
echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc && source ~/.bashrc
zeek --version
```

**`zeekctl` installe un serveur de courrier** (Courier, sur Ubuntu 26.04) pour envoyer ses
alertes par mail. Il démarre et écoute sur le réseau. Une sonde n'a pas à exposer de service
inutile :

```bash
sudo systemctl disable --now courier courierfilter courier-mta courier-mta-ssl courier-msa
sudo ss -tlnp      # attendu : seulement SSH (22) et le résolveur local (127.0.0.53/54:53)
```

**L'installateur d'Ubuntu n'utilise que la moitié du disque** (14 Go sur 30). Étendre :

```bash
sudo lvextend -r -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
```

**Le dépôt** : `git clone` de `detection-lab` dans `~/detection-lab`, puis
`chmod +x 03-reseau/scripts/*`.

Reporter **toutes** les versions affichées dans `VERSIONS.md`.

## Phase 3 — Les captures (VM encore en NAT)

### Les captures d'infection

Trois captures de **Malware-Traffic-Analysis.net**, choisies selon ces critères :

| Critère | Pourquoi |
|---|---|
| Compte rendu publié avec indicateurs du C2 (domaines, adresses, ports) | c'est la vérité terrain : sans elle, pas de verdict |
| **Trois canaux différents** : un C2 en HTTP clair, un en TLS, un sur port non standard ou en DNS | chaque canal met en échec un outil différent |
| Au moins une capture **récente** (2026) | vérifier ce que valent les règles ET Open sur une menace de l'année |
| Durée suffisante pour voir **au moins 20 rappels** du C2 | en dessous, le balisement n'est pas mesurable |

Pour chaque capture :

```bash
sudo apt-get install -y 7zip poppler-utils
mkdir -p ~/pcaps && cd ~/pcaps
wget <URL de l'archive, notée dans preuves/sources.md>
7z x <archive>.zip        # 7z et non unzip : les archives chiffrées en AES ne s'ouvrent pas avec unzip
ls -l                     # AUCUN fichier à 0 octet : une extraction ratée laisse un fichier vide
sha256sum <capture>.pcap
```

Le mot de passe est donné sur la page « about » du site ; il **change selon l'archive**. Un
mauvais mot de passe laisse un fichier vide, dont l'empreinte (`e3b0c442…b855`) est celle de
n'importe quel fichier vide : on contrôle la taille avant de reporter l'empreinte.

Les réponses des exercices (PDF) se lisent dans la sonde, sans interface graphique :
`pdftotext <fichier>.pdf - | less`.

Reporter source, nom, empreinte et ce que dit le compte rendu dans `preuves/sources.md`
**avant** l'analyse. On écrit la vérité terrain d'abord, on regarde les outils ensuite.

### La capture de trafic normal

Le trafic ordinaire de la **VM Windows du lab**, Defender actif, réseau en NAT, **hors de toute
campagne de test** : navigation, mises à jour, télémétrie. Plusieurs heures, veille désactivée.

Windows intègre un capteur, `pktmon`, disponible aussi sur l'édition Famille. Dans la VM Windows,
en PowerShell administrateur :

```powershell
pktmon start --capture --comp nics --pkt-size 0 --file-name C:\Lab\normal.etl --file-size 2048
# … laisser tourner plusieurs heures …
pktmon stop
pktmon etl2pcap C:\Lab\normal.etl --out C:\Lab\normal.pcapng
```

`--comp nics` capture au niveau de la carte réseau seulement. Sans cette option, `pktmon` voit
chaque paquet à plusieurs étages de la pile et le **compte plusieurs fois**, ce qui fausserait le
balisement.

Le fichier passe ensuite vers la sonde (`scp` depuis l'hôte). C'est du trafic personnel :
il ne va **jamais** dans le dépôt.

### Puis : isoler et figer

1. Carte réseau de la sonde en **réseau hôte uniquement**.
2. `./scripts/verifier-sonde.sh` : tous les contrôles à OK.
3. Instantané **« sonde outillée hors ligne »**, VM éteinte.

## Phase 4 — Les analyses

```bash
cd ~/detection-lab/03-reseau
./scripts/analyser-pcap.sh ~/pcaps/<capture>.pcap <etiquette>
```

Une analyse par capture, plus une pour le trafic normal (étiquette `normal`). Puis, pour
chaque capture d'infection, le balisement **avec la référence** :

```bash
python3 scripts/balisement.py rapports/<dossier>/zeek/conn.log \
    --reference rapports/<dossier normal>/zeek/conn.log --format md
```

Le balisement se mesure à **deux niveaux**, et `analyser-pcap.sh` produit les deux :

| Journal | Un événement = | Voit | Rate |
|---|---|---|---|
| `conn.log` → `balisement.md` | une connexion | l'implant qui ouvre une connexion par rappel | l'implant qui garde une connexion ouverte et y enchaîne ses requêtes |
| `http.log` → `balisement-http.md` | une requête HTTP | ce second cas, si le C2 parle HTTP en clair | tout C2 chiffré (TLS) : `http.log` est vide pour lui |

`--externes-seulement` écarte les destinations privées, multicast et de diffusion : le trafic
Windows interne (NetBIOS toutes les ~5 min, contrôleur de domaine) est régulier par nature et
occupe sinon le haut du classement. L'option masque aussi un C2 interne : on la cite dans le
verdict quand on l'utilise.

## Phase 5 — Le tableau de test

| # | Capture | Canal C2 documenté | Attendu de Suricata | Attendu de Zeek / balisement |
|---|---|---|---|---|
| 1 | *(à remplir)* | HTTP clair | alertes ET sur la famille ou l'URI | conversation régulière, `http.log` lisible |
| 2 | *(à remplir)* | TLS | alertes sur l'empreinte TLS ou le certificat, **peut-être aucune** | conversation régulière ; certificat remarquable dans `x509.log` |
| 3 | *(à remplir)* | port non standard ou DNS | dépend de la famille | `conn.log` montre le port ; `dns.log` le volume ou la longueur des noms |
| N | trafic normal | aucun | **0 alerte** attendue, chacune à expliquer | conversations régulières légitimes : mises à jour, télémétrie |

## Phase 6 — Une règle à soi

À partir d'un indicateur **observé** dans une capture (pas recopié du compte rendu) :

1. l'écrire dans `regles/local.rules` (SID 1000000 et plus) ;
2. la tester **seule**, sans toucher au jeu installé ni passer root — `-S` remplace les règles
   par ce seul fichier :
   `suricata -r <capture> -k none -S regles/local.rules -l /tmp/test-regles` ;
   d'abord sur le banc synthétique (`regles/tests/`), puis :
3. prouver qu'elle déclenche sur la capture ;
4. prouver qu'elle reste muette sur le trafic normal ;
5. seulement ensuite, l'ajouter au jeu de la sonde :
   `sudo suricata-update --local ~/detection-lab/03-reseau/regles/local.rules` ;
6. écrire ce qu'un attaquant devrait changer pour lui échapper.

## Ce qu'on consigne pour chaque capture

1. La **vérité terrain** : famille, indicateurs, chronologie du compte rendu.
2. Le **dossier de rapport** produit par `analyser-pcap.sh`.
3. La section **Verdict** de `resume.md` : vu par Suricata, vu par Zeek / balisement, vu par
   personne.
4. La ligne dans `matrice-couverture.md`.

## Le critère d'échec qu'on oublie

Comme au module 02 : un outil qui alerte sur tout est aussi inutile qu'un outil muet. Le
résultat sur le **trafic normal** compte autant que les détections sur les captures
d'infection.
