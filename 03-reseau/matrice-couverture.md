# Matrice de couverture — module 03

Le livrable du module. Pour chaque capture : ce que chaque outil a vu du canal de commande
documenté, et pourquoi les autres ne l'ont pas vu. Pour le trafic normal : chaque fausse alerte,
expliquée.

État au 14/10/2026 : **2 captures d'infection sur 3 analysées** (canal HTTP clair, canal sur
port non standard) et **référence de trafic normal analysée**. Reste la capture à C2 chiffré (TLS).

---

## Tableau principal — captures d'infection

| # | Capture | Famille | Canal C2 | Suricata (ET Open) | Zeek / balisement | Verdict |
|---|---|---|---|---|---|---|
| 1 | `lumma-2026-01-31` | Lumma Stealer | HTTP clair sur 80 (`/api/set_agent`) + TLS sur 443, même serveur `153.92.1[.]49` | **Vu** — 30 alertes Lumma, dont 29 sur des noms de domaine et 1 seule sur le comportement (URI) | **Vu** : vol en clair dans `http.log`, 2,08 Mo envoyés en TLS dans `conn.log` · balisement **non applicable** (rafale de 29 s) | **Vu, fragile** : sans les noms de domaine, il reste une signature et un volume |
| 2 | `netsupport-2026-02-28` | NetSupport Manager RAT | HTTP clair sur le port 443, `45.131.214[.]85` | **Vu** — 264 « NetSupport Remote Admin Checkin » (un par rappel) + heuristique « HTTP sur 443 » | **Vu** dans `http.log` (agent `NetSupport Manager/1.3`) · balisement : **pas vu** sur `conn.log`, **1,000** sur `http.log` (60,1 s, gigue 0 %) | **Vu par les trois approches**, à condition de mesurer les requêtes et non les connexions |
| 3 | *(capture TLS à choisir)* | | TLS | | | |

Valeurs : **Vu** (le C2 lui-même est identifié) · **Partiel** (l'infection est vue, pas le
canal de commande) · **Pas vu**.

## Trafic normal — faux positifs

| Source | Durée | Alertes Suricata | Paires au-dessus du seuil de balisement | Explication |
|---|---|---|---|---|
| VM Windows du lab (`pktmon`, 14/10/2026) | **1 h 36** (10:00:24 → 11:36:27 UTC), 1 248 072 paquets | **160 692**, dont 160 458 artefacts de capture, 73 anomalies de flux et 161 alertes ET INFO / HUNTING, toutes expliquées : **0 alerte malveillante** | `conn.log` : 4 au-dessus de 0,70, **toutes internes** ; 0 externe (max. 0,507). `http.log` : 1 à 0,797, **0 au-dessus de 0,85** | Windows Update, Defender, optimisation de livraison, NetBIOS, mDNS — voir ci-dessous |

## Règles écrites pour ce module

| SID | Indicateur | Capture d'origine | Déclenche sur la capture | Sur le trafic normal | Ce qu'un attaquant changerait |
|---|---|---|---|---|---|
| 1000001 | `GET /api/set_agent?id=<32 hex>&token=…&agent=` (sans domaine, adresse ni port) | `lumma-2026-01-31` | **2 / 2** — Chrome 23:05:39.577 et Edge 23:05:47.406 ; ET 2066606 ne voit que Chrome | **0** sur 1 248 072 paquets | renommer le chemin ou les paramètres ; passer ce volet en HTTPS |
| 1000002 | `POST /api/set_agent?…&agent=…&act=log` | `lumma-2026-01-31` | **2 / 2** — 23:05:40.514 et 23:05:47.793 ; aucune règle ET sur cet envoi | **0** | idem |

Banc d'essai synthétique (`regles/tests/generer-cas-lumma.py`, 8 cas écrits à la main) :
4 positifs détectés dont 2 vers un autre nom d'hôte, 4 négatifs muets — Suricata 7.0.3,
14/10/2026. Puis la capture réelle, sous Suricata 8.0.7 avec ces seules règles (`-S`) :
**exactement les 4 alertes prédites**, de `10.1.21.58` vers `153.92.1.49:80`, et rien d'autre.
Sur la capture NetSupport (15 512 paquets, autre famille, 264 POST HTTP) : **0 alerte** —
les règles ne confondent pas un autre canal HTTP malveillant avec Lumma.
Enfin la référence de trafic normal (1 h 36, 1 248 072 paquets) : **0 alerte**. Les deux
règles sont validées : elles voient les 4 requêtes Lumma là où ET Open n'en voit qu'une, et
restent muettes sur une autre famille et sur un poste sain.

## Les lignes, en détail

### 1 — Lumma Stealer, 2026-01-31

**Vérité terrain** (`preuves/sources.md`) : victime `10.1.21.58` (DESKTOP-ES9F3ML), C2
`153.92.1[.]49`, domaine `whitepepper[.]su`. Capture de 10 min (23:04:03 → 23:14:25 UTC).

**Suricata — vu, par les noms.** 30 alertes propres à Lumma, dont **29 sur un nom de
domaine** : 16 sur le SNI `whitepepper[.]su` (2066542), 10 sur sa résolution DNS (2066541),
3 sur un second domaine, `whooptm[.]cyou` (2066850/2066851, vers `62.72.32.156:443`).
**Une seule** sur le comportement : « Victim Fingerprinting Activity » (2066606), sur l'URI
`GET /api/set_agent?…&agent=Chrome` ; la même requête pour Edge ne la redéclenche pas. Les 20
alertes sur `.su` / `.cc` sont des heuristiques de nom, elles aussi.

**Zeek — vu, et davantage.** `http.log` montre le vol en clair vers `153.92.1.49:80` : pour
Chrome puis Edge, `GET /api/set_agent` puis `POST …&act=log` (8 023 et 7 975 o). Les requêtes
portent les en-têtes d'un vrai navigateur (agent Chrome / Edge 144, Referer, `/favicon.ico`) :
l'agent HTTP ne trahit rien. Et `conn.log` montre que **l'essentiel part en TLS** : 2,08 Mo
envoyés vers `153.92.1.49:443` en 18 connexions (dont 253 Ko, 388 Ko et 1,42 Mo), contre
70 Ko reçus, entre 23:05:36 et 23:06:05. Le volet HTTP clair ne pèse que 19 Ko.

**Balisement — non applicable.** Un voleur frappe une fois : tout tient en 29 s. Aucune paire
n'atteint 20 événements sur 300 s. L'indice exploitable est ailleurs : le **rapport envoyé /
reçu** (30 pour 1) vers une destination jamais vue.

**Ce que personne ne voit.** Le contenu des 2,08 Mo partis en TLS — seuls le SNI et le volume
les rattachent au C2 — et la nature des données volées (aucune extraction, par garde-fou).
L'infection initiale n'est pas dans la capture.

**Constat.** Un attaquant qui change de domaine fait tomber 29 alertes sur 30. Restent la
signature sur l'URI `/api/set_agent` et le volume sortant. C'est sur l'URI, observée ici, que
portera la règle locale.

### 2 — NetSupport Manager RAT, 2026-02-28

**Vérité terrain** : C2 `45.131.214[.]85`, TCP 443, à partir de 19:55 UTC ; réseau
`10.2.28.0/24`. Victime observée : `10.2.28.88` (DESKTOP-TEYQ2NR) ; contrôleur de domaine
`10.2.28.2`. Capture de 4 h 21 (19:55:06 → 00:16:30 UTC).

**Suricata — vu.** 264 × « ET REMOTE_ACCESS NetSupport Remote Admin Checkin » (2035892,
gravité 3) : **une alerte par rappel**, exactement autant que de requêtes dans `http.log`.
264 × « ET INFO HTTP traffic on port 443 (POST) » (2013926) : générique, mais juste — du HTTP
en clair sur le port du HTTPS, c'est T1571. 2 × « Remote Admin Response » (2035895).

**Zeek — vu.** `http.log` : 264 `POST /fakeurl.htm` vers `45.131.214[.]85:443`, agent
`NetSupport Manager/1.3`. Enregistrement à 19:55:51 (deux échanges : 22 → 69 o, 244 → 153 o),
puis 260 rappels identiques de 36 o.
`conn.log` : **une seule connexion**, longue de 15 637 s (4 h 20), qui porte les 264 requêtes
(historique `ShADdaTX`, `missed_bytes` = 0 : la capture est complète). Le serveur ne répond
que **deux fois**, à l'enregistrement : 262 requêtes sans réponse HTTP, 2 réponses `200` —
exactement les 2 alertes « Remote Admin Response » de Suricata. Les 30 « excessive header
repetition » viennent des serveurs de mise à jour d'Edge : bruit. Ses 274 paquets sont presque tous de simples
acquittements TCP (11 612 o d'IP, environ 530 o de contenu).

Aucune résolution DNS vers le C2 : l'implant joint `45.131.214.85` **par son adresse**. Le
domaine `easyas123[.]tech` du compte rendu est celui de l'**Active Directory de la victime**
(contrôleur `easyas123-dc` → `10.2.28.2`, enregistrements SRV LDAP, nom NetBIOS `EASYAS123`,
requêtes WPAD sans réponse) : un nom interne, pas un indicateur du C2.

**Balisement — pas vu, puis vu.** Sur `conn.log`, le C2 n'est même pas évaluable : une
connexion ne fait pas une série. En tête du classement sortaient au contraire des paires
internes notées 1,000 — annonces NetBIOS toutes les 310 s vers la diffusion et le contrôleur de
domaine : du Windows normal. Sur `http.log` (une ligne par requête), la paire
`10.2.28.88 → 45.131.214.85:443` sort seule, à **1,000** : 264 requêtes toutes les 60,1 s,
gigue 0 %, sur toute la capture.

**Ce que personne ne voit.** Rien du canal ne manque : sur cette capture, l'implant rappelle
et le serveur ne lui confie presque rien (2 réponses en 4 h 20). Ce que la capture ne dit pas,
c'est comment la machine a été infectée avant 19:55 — l'infection initiale n'y figure pas.

**Constat.** À l'inverse de Lumma, la détection Suricata ne dépend d'**aucun nom** : le C2 est
joint par adresse, et la signature reconnaît le contenu du rappel. Changer d'adresse ne
l'éteint pas ; il faudrait modifier le protocole de l'outil. Un RAT qui garde sa connexion
ouverte efface en revanche son rythme de `conn.log`. Le
balisement doit se mesurer au niveau des requêtes — ce que fait désormais `balisement.py` — et
cette mesure ne vaut **que tant que le canal est en clair**.

### Référence — trafic normal de la VM Windows, 2026-10-14

**Capture.** `pktmon --comp nics --pkt-size 0`, fichier circulaire de 2 Go, VM Windows du lab
revenue à l'instantané « VM outillée hors ligne — module 02 » (aucun test joué), Defender actif,
NAT. L'instantané datant du 01/10, la VM a rattrapé deux semaines de mises à jour : les 2 Go
ont été remplis en **1 h 36**. La conversion `etl2pcap` a été interrompue deux fois par un écran
bleu 0x124 de la VM, causé par le **disque plein de l'hôte** (1,2 Go libres) ; le dernier bloc
du pcapng est tronqué, ce qui ne prive l'analyse que des derniers paquets. Le fichier n'est
**jamais versionné** (trafic personnel) ; seul un résumé sans noms de domaine l'est.

**Suricata — 160 692 alertes, aucune malveillante.**

| Alertes | Signature | Explication |
|---|---|---|
| 160 258 | `SURICATA IPv4 / TCPv4 / UDPv4 / UDPv6 invalid checksum` | **Artefact de capture** : Windows délègue les sommes de contrôle à la carte, `pktmon` voit les paquets sortants avant |
| 200 | `SURICATA IPv4 total length smaller than header size` | **Artefact de capture** : segmentation déléguée à la carte (LSO), même mécanisme |
| 73 | `Applayer Wrong direction first data`, `STREAM excessive retransmissions` | Anomalies de flux banales |
| 156 | `ET INFO Windows Update P2P Activity` (2027766) | Optimisation de livraison vers `192.168.64.1:7680` : 156 connexions, autant qu'au balisement |
| 3 | `ET INFO Packed Executable Download` (2014819) | Mises à jour de **Defender** (`/msdownload/update/software/defu/…/am_delta_…exe`, `am_base_patch1`, `am_engine_patch`) |
| 1 | `ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response` (2021076, gravité 2) | Le même `am_delta_…exe`, servi par un **nœud de cache Windows Update joint par adresse IP** (`85.208.10.203`, `cacheHostOrigin=2.au.download.windowsupdate.com`) : légitime |
| 1 | `ET INFO Microsoft Connection Test` | Test de connectivité de Windows (NCSI) |

**Balisement `conn.log`.** Quatre paires au-dessus de 0,70, toutes internes : NetBIOS vers la
passerelle NAT toutes les 120 s (**1,0**), optimisation de livraison vers l'hôte toutes les 40 s
(0,867), mDNS en IPv4 et IPv6 toutes les 121 s (0,72). Avec `--externes-seulement`, la meilleure
paire externe plafonne à **0,507**.

**Balisement `http.log`.** Une paire à **0,797** : 728 requêtes vers `85.208.10.201:80` (cache
Windows Update joint par IP), morceaux de **262 144 octets** exactement, toutes les 1,5 s (gigue
42 %). C'est la constance de la taille des morceaux qui fait le score. Les 3 589 requêtes vers
`199.232.82.172` (`*.delivery.mp.microsoft.com`, `*.download.windowsupdate.com`) restent à 0,30.

**Seuil retenu.** `http.log` + `--externes-seulement`, seuil **0,85** : 0 paire sur le trafic
normal, et le C2 NetSupport sort à **1,0, marqué « destination inédite »** quand on compare à
cette référence (`--reference`).

**Limite.** 1 h 36 dominées par Windows Update : c'est une référence de poste qui se met à jour,
pas d'une journée de travail. À refaire sur plusieurs heures (`--file-size 8192`) une fois la
VM à jour.

## Enseignements de méthode

1. **Mesurer au bon niveau.** Connexion ou requête : le même C2 passe de « non évaluable » à
   1,000 selon le journal choisi (NetSupport). `analyser-pcap.sh` produit désormais les deux.
2. **Une alerte qui nomme un domaine ne prouve pas qu'on détecte le maliciel.** 29 des 30
   alertes Lumma tombent si l'attaquant change de nom (Lumma). À l'opposé, la
   signature NetSupport lit le contenu du rappel et survit à un changement d'adresse.
3. **Le réseau interne Windows est régulier par nature.** NetBIOS et le contrôleur de domaine
   occupent le haut du balisement ; `--externes-seulement` les écarte, au prix de masquer un
   C2 interne (pivot).
4. **Un voleur ne balise pas.** Le balisement cible les implants persistants ; contre une
   rafale de 30 s, ce sont les signatures, `http.log` et le **volume sortant** (2,08 Mo envoyés
   pour 70 Ko reçus) qui répondent.

5. **Recouper le compte rendu avec les journaux.** Le domaine cité avec la capture NetSupport
   est l'Active Directory de la victime, pas le C2 ; la capture Lumma comporte deux coquilles.
   Une vérité terrain se vérifie comme le reste.

6. **Capturer sur la machine elle-même fausse le paquet.** 99,9 % des alertes du trafic normal
   viennent des sommes de contrôle et longueurs non encore calculées par la carte réseau. Un
   capteur réseau (port miroir, TAP) n'a pas ce biais ; ici, on les identifie et on les écarte.
7. **Une règle de chasse est une piste, pas un verdict.** `Dotted Quad Host MZ Response` a
   raison sur le plan technique — un exécutable servi par une adresse IP — et tort sur
   l'intention : c'est un cache Windows Update.
8. **Une référence se dimensionne.** 2 Go = 1 h 36 sur un poste qui rattrape ses mises à jour.
   Et l'hôte doit avoir la place : un disque plein a fait tomber la VM deux fois.

*(à compléter avec la capture TLS)*
