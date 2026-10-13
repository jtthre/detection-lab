# Analyse — lumma-2026-01-31

| Champ | Valeur |
|---|---|
| Capture | `2026-01-31-traffic-analysis-exercise.pcap` (26M) |
| SHA-256 | `f755444d0b6eac847e07b73dea0774084b232d8577f536547a12f39b959d7833` |
| Analyse | 2026-10-13_232323 |
| Suricata | This is Suricata version 8.0.7 RELEASE |
| Zeek | zeek version 9.0.0 |
| Période capturée (UTC) | 2026-01-27 23:04:03 → 2026-01-27 23:14:25 |

## Suricata — alertes par signature

**55 alertes.**

| Nombre | Gravité | Signature | SID |
|---|---|---|---|
| 16 | 1 | ET MALWARE Observed Win32/Lumma Stealer Related Domain (whitepepper .su) in TLS SNI | 2066542 |
| 10 | 2 | ET DNS Query for .su TLD (Soviet Union) Often Malware Related | 2014169 |
| 10 | 1 | ET MALWARE Win32/Lumma Stealer Related CnC Domain in DNS Lookup (whitepepper .su) | 2066541 |
| 6 | 2 | ET INFO HTTP Request to .su TLD (Soviet Union) Often Malware Related | 2014170 |
| 4 | 2 | ET DNS Query for .cc TLD | 2027758 |
| 2 | 3 | SURICATA STREAM excessive retransmissions | 2210054 |
| 2 | 1 | ET MALWARE Win32/Lumma Stealer Related CnC Domain in DNS Lookup (whooptm .cyou) | 2066850 |
| 1 | 3 | SURICATA SMB too many transactions | 2225018 |
| 1 | 3 | SURICATA SMB malformed response data | 2225003 |
| 1 | 3 | ET INFO Microsoft Connection Test | 2031071 |
| 1 | 1 | ET MALWARE Observed Win32/Lumma Stealer Related Domain (whooptm .cyou) in TLS SNI | 2066851 |
| 1 | 1 | ET MALWARE Lumma Stealer Victim Fingerprinting Activity | 2066606 |

Événements Suricata par type :

- `smb` : 2822
- `dns` : 418
- `flow` : 315
- `tls` : 108
- `dcerpc` : 60
- `alert` : 55
- `ldap` : 25
- `mdns` : 17
- `krb5` : 16
- `quic` : 15
- `fileinfo` : 10
- `http` : 8
- `stats` : 2
- `anomaly` : 2
- `dhcp` : 1

## Zeek — volume par journal

| Journal | Lignes |
|---|---|
| `capture_loss.log` | 2 |
| `conn.log` | 325 |
| `dce_rpc.log` | 3598 |
| `dhcp.log` | 1 |
| `dns.log` | 266 |
| `files.log` | 20 |
| `http.log` | 8 |
| `kerberos.log` | 28 |
| `known_hosts.log` | 2 |
| `known_services.log` | 16 |
| `ldap.log` | 13 |
| `ldap_search.log` | 12 |
| `loaded_scripts.log` | 551 |
| `notice.log` | 4 |
| `ocsp.log` | 10 |
| `packet_filter.log` | 1 |
| `quic.log` | 3 |
| `smb_files.log` | 1 |
| `smb_mapping.log` | 6 |
| `software.log` | 3 |
| `ssl.log` | 111 |
| `stats.log` | 4 |
| `weird.log` | 5 |
| `x509.log` | 10 |

### Connexions par service

- `dns` : 155
- `ssl` : 108
- `-` : 12
- `krb_tcp` : 8
- `krb,gssapi,ldap_tcp` : 8
- `http` : 6
- `dce_rpc` : 6
- `ldap_udp` : 5
- `ldap_tcp,krb,gssapi` : 5
- `krb,gssapi,dce_rpc` : 4
- `quic,ssl` : 3
- `gssapi,smb,krb,dce_rpc` : 3
- `dhcp` : 2

### Destinations les plus contactées

| Connexions | Destination | Port |
|---|---|---|
| 149 | 10.1.21.2 | 53 |
| 18 | 153.92.1.49 | 443 |
| 18 | 10.1.21.2 | 389 |
| 17 | 142.251.116.95 | 443 |
| 8 | 10.1.21.2 | 88 |
| 6 | 153.92.1.49 | 80 |
| 5 | 52.109.0.142 | 443 |
| 5 | 150.171.28.11 | 443 |
| 5 | 10.1.21.2 | 49668 |
| 5 | 10.1.21.2 | 135 |
| 4 | 10.1.21.2 | 445 |
| 3 | 142.250.115.84 | 443 |
| 2 | 239.255.255.250 | 1900 |
| 2 | 23.222.241.148 | 443 |
| 2 | 23.222.241.141 | 443 |

### Noms résolus (DNS)

- `edge.microsoft.com` (NOERROR) : 14
- `WIN11OFFICE` (-) : 14
- `wpad.win11office.com` (NXDOMAIN) : 13
- `wpad.mshome.net` (NXDOMAIN) : 13
- `DESKTOP-ES9F3ML` (-) : 12
- `whitepepper.su` (NOERROR) : 9
- `www.bing.com` (NOERROR) : 8
- `_googlecast._tcp.local` (-) : 7
- `_ldap._tcp.default-first-site-name._sites.dc._msdcs.desktop-es9f3ml.win11office.com` (NXDOMAIN) : 5
- `_ldap._tcp.default-first-site-name._sites.dc._msdcs.desktop-es9f3ml.mshome.net` (NXDOMAIN) : 5
- `_ldap._tcp.dc._msdcs.desktop-es9f3ml.win11office.com` (NXDOMAIN) : 5
- `_ldap._tcp.dc._msdcs.desktop-es9f3ml.mshome.net` (NXDOMAIN) : 5
- `www.google.com` (NOERROR) : 4
- `oauthaccountmanager.googleapis.com` (NOERROR) : 4
- `desktop-es9f3ml` (-) : 4
- `accounts.google.com` (NOERROR) : 4
- `www.msn.com` (NOERROR) : 3
- `odc.officeapps.live.com` (NOERROR) : 3
- `assets.msn.com` (NOERROR) : 3
- `_ldap._tcp.default-first-site-name._sites.dc._msdcs.win11office.com` (NOERROR) : 3

### Serveurs TLS (SNI)

- `whitepepper.su` : 16
- `oauthaccountmanager.googleapis.com` : 13
- `edge.microsoft.com` : 7
- `odc.officeapps.live.com` : 5
- `www.bing.com` : 4
- `www.google.com` : 3
- `www.msn.com` : 2
- `waa-pa.clients6.google.com` : 2
- `peoplestack-pa.clients6.google.com` : 2
- `optimizationguide-pa.googleapis.com` : 2
- `login.microsoftonline.com` : 2
- `communicationfirewall-security.cc` : 2
- `cloudflare-ech.com` : 2
- `cdnjs.cloudflare.com` : 2
- `blobcomments-pa.clients6.google.com` : 2
- `assets.msn.com` : 2
- `assets.adobedtm.com` : 2
- `api.msn.com` : 2
- `accounts.google.com` : 2
- `youtube.googleapis.com` : 1

### Requêtes HTTP (hôte, méthode, agent)

- 2 × `whitepepper.su` · GET · `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0`
- 2 × `whitepepper.su` · GET · `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36`
- 1 × `www.msftconnecttest.com` · GET · `Microsoft NCSI`
- 1 × `whitepepper.su` · POST · `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0`
- 1 × `whitepepper.su` · POST · `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36`
- 1 × `clients2.google.com` · GET · `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36`

### Notices Zeek

- 4 × `SSL::Invalid_Server_Cert` — SSL certificate validation failed with (unable to get local issuer certificate)

## Balisement — connexions (conn.log)

conn.log · 325 connexions lues · 77 paires · 1 évaluées (>= 20 connexions sur >= 300 s)

| Score | Niveau | Source | Destination | Port | Service | Conn. | Intervalle médian | Gigue | Octets médians | Inédite |
|---|---|---|---|---|---|---|---|---|---|---|
| 0.242 | peu probant | 10.1.21.58 | 10.1.21.2 | 53 | dns | 149 | 0.0 s | 100.0 % | 172 | — |

## Balisement — requêtes HTTP (http.log)

http.log · 8 requêtes lues · 3 paires · 0 évaluées (>= 20 requêtes sur >= 300 s)

Aucune paire évaluable au-dessus du seuil.

## Verdict

> À écrire à la main, en confrontant ce résumé au compte rendu publié avec la capture :
>
> - **Vu par Suricata** — quelles signatures, sur quelle partie de l'infection.
> - **Vu par Zeek et le balisement** — quelle conversation, quel score, quel indice.
> - **Vu par personne** — ce que le compte rendu décrit et qu'aucun outil n'a remonté.

**Vu par Suricata : oui — mais presque uniquement par les noms.** 30 alertes propres à Lumma.
29 tiennent à un nom de domaine : 16 sur le SNI `whitepepper[.]su` (2066542), 10 sur sa
résolution DNS (2066541), 3 sur le second domaine `whooptm[.]cyou` (2066850/2066851, vers
`62.72.32.156:443`, 23:05:34). **Une seule** décrit le comportement : « Lumma Stealer Victim
Fingerprinting Activity » (2066606), sur l'URI `GET /api/set_agent?id=…&token=…&agent=Chrome`
à 23:05:39 ; la même requête pour Edge, 8 s plus tard, ne la redéclenche pas. Les 20 alertes
sur les domaines de premier niveau `.su` / `.cc` (2014169, 2014170, 2027758) sont des
heuristiques de nom, elles aussi. Le reste (SMB, flux, test de connexion Microsoft) est du bruit.

**Vu par Zeek : oui, et plus que Suricata.** `http.log` montre le vol en clair vers
`153.92.1.49:80` : pour Chrome puis pour Edge, un `GET /api/set_agent` (6,5 Ko renvoyés par
le serveur) puis un `POST … &act=log` (8 023 et 7 975 o envoyés). Les requêtes portent les
en-têtes d'un vrai navigateur — agent Chrome 144 puis Edge 144, Referer, demande de
`/favicon.ico` : **l'agent HTTP ne trahit rien.** Surtout, `conn.log` montre que l'essentiel
part ailleurs : **2,08 Mo envoyés en TLS** vers `153.92.1.49:443` (18 connexions, dont trois
de 253 Ko, 388 Ko et 1,42 Mo), contre 70 Ko reçus, entre 23:05:36 et 23:06:05.
**Balisement : non applicable.** Un voleur frappe une fois : toute l'activité vers le C2
tient en 29 s, sur une capture de 10 min. Aucune paire n'atteint 20 événements sur 300 s
(seul le DNS interne est évalué, 0,24). L'indice utile n'est pas le rythme mais le
**rapport envoyé / reçu** (30 pour 1) vers une destination jamais vue.

**Vu par personne :** le contenu des 2,08 Mo exfiltrés en TLS — seuls le SNI et le volume les
rattachent au C2 — et la nature exacte des données volées (aucune extraction de fichier, par
garde-fou). L'infection initiale ne figure pas dans la capture.
