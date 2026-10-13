# Matrice de couverture — module 03

Le livrable du module. Pour chaque capture : ce que chaque outil a vu du canal de commande
documenté, et pourquoi les autres ne l'ont pas vu. Pour le trafic normal : chaque fausse alerte,
expliquée.

État au 13/10/2026 : **2 captures sur 3 analysées** (canal HTTP clair, canal sur port non
standard). Restent la capture à C2 chiffré (TLS) et la référence de trafic normal.

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
| VM Windows du lab | | | | |

## Règles écrites pour ce module

| SID | Indicateur | Capture d'origine | Déclenche sur la capture | Sur le trafic normal | Ce qu'un attaquant changerait |
|---|---|---|---|---|---|

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

*(à compléter avec la capture TLS et le trafic normal)*
