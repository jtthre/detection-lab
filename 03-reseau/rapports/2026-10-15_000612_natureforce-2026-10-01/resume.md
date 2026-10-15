# Analyse — natureforce-2026-10-01

| Champ | Valeur |
|---|---|
| Capture | `2026-10-01-traffic-analysis-exercise.pcap` (36M) |
| SHA-256 | `287d6dee90cfef71f98a97c42e30444608de2cf59d2f7392a0a6df8dbbc8274b` |
| Analyse | 2026-10-15_000612 |
| Suricata | This is Suricata version 8.0.7 RELEASE |
| Zeek | zeek version 9.0.0 |
| Période capturée (UTC) | 2026-10-01 19:27:27 → 2026-10-01 20:07:29 |

## Suricata — alertes par signature

**9 alertes.**

| Nombre | Gravité | Signature | SID |
|---|---|---|---|
| 1 | 3 | SURICATA STREAM excessive retransmissions | 2210054 |
| 1 | 3 | SURICATA HTTP Response excessive header repetition | 2221036 |
| 1 | 3 | ET INFO Packed Executable Download | 2014819 |
| 1 | 3 | ET INFO Observed Google DNS over HTTPS Domain (dns .google in TLS SNI) | 2047866 |
| 1 | 3 | ET INFO Microsoft Connection Test | 2031071 |
| 1 | 2 | ET INFO Executable Download from dotted-quad Host | 2016141 |
| 1 | 2 | ET HUNTING curl User-Agent to Dotted Quad | 2034567 |
| 1 | 2 | ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response | 2021076 |
| 1 | 1 | ET INFO PE EXE or DLL Windows file download HTTP | 2018959 |

Événements Suricata par type :

- `flow` : 322
- `dns` : 319
- `smb` : 158
- `dcerpc` : 128
- `tls` : 89
- `krb5` : 54
- `ldap` : 52
- `http` : 16
- `fileinfo` : 15
- `quic` : 10
- `alert` : 9
- `mdns` : 3
- `stats` : 1
- `dhcp` : 1
- `anomaly` : 1

## Zeek — volume par journal

| Journal | Lignes |
|---|---|
| `capture_loss.log` | 4 |
| `conn.log` | 346 |
| `dce_rpc.log` | 145 |
| `dhcp.log` | 1 |
| `dns.log` | 205 |
| `files.log` | 24 |
| `http.log` | 16 |
| `kerberos.log` | 64 |
| `known_hosts.log` | 2 |
| `known_services.log` | 18 |
| `ldap.log` | 24 |
| `ldap_search.log` | 28 |
| `loaded_scripts.log` | 551 |
| `notice.log` | 9 |
| `ocsp.log` | 15 |
| `packet_filter.log` | 1 |
| `pe.log` | 1 |
| `quic.log` | 2 |
| `smb_files.log` | 7 |
| `smb_mapping.log` | 6 |
| `software.log` | 5 |
| `ssl.log` | 91 |
| `stats.log` | 9 |
| `weird.log` | 5 |
| `x509.log` | 9 |

### Connexions par service

- `dns` : 130
- `ssl` : 89
- `krb_tcp` : 27
- `-` : 20
- `http` : 16
- `ldap_udp` : 13
- `ldap_tcp,krb,gssapi` : 12
- `krb,gssapi,ldap_tcp` : 12
- `dce_rpc` : 10
- `krb,gssapi,dce_rpc` : 9
- `gssapi,smb,krb` : 3
- `quic,ssl` : 2
- `dhcp` : 2
- `gssapi,smb,krb,dce_rpc` : 1

### Destinations les plus contactées

| Connexions | Destination | Port |
|---|---|---|
| 112 | 10.10.1.10 | 53 |
| 41 | 10.10.1.10 | 389 |
| 27 | 10.10.1.10 | 88 |
| 11 | 10.10.1.255 | 138 |
| 9 | 10.10.1.10 | 49669 |
| 9 | 10.10.1.10 | 135 |
| 8 | 10.10.1.255 | 137 |
| 8 | 10.10.1.10 | 137 |
| 6 | 142.250.26.94 | 443 |
| 5 | 150.171.30.11 | 443 |
| 4 | 52.123.250.8 | 443 |
| 4 | 23.201.96.192 | 443 |
| 4 | 142.251.116.95 | 443 |
| 4 | 10.10.1.10 | 445 |
| 3 | 20.190.157.14 | 443 |

### Noms résolus (DNS)

- `wpad.natureforce.com` (NXDOMAIN) : 20
- `NATUREFORCE` (-) : 17
- `edge.microsoft.com` (NOERROR) : 8
- `DESKTOP-4VGYQX7` (-) : 8
- `-` (YXDOMAIN) : 8
- `settings-win.data.microsoft.com` (NOERROR) : 6
- `fonts.gstatic.com` (NOERROR) : 6
- `www.youtube.com` (NOERROR) : 4
- `www.google.com` (NOERROR) : 4
- `www.bing.com` (NOERROR) : 4
- `v20.events.data.microsoft.com` (NOERROR) : 4
- `v10.events.data.microsoft.com` (NOERROR) : 4
- `_ldap._tcp.default-first-site-name._sites.dc._msdcs.natureforce.com` (NOERROR) : 4
- `settings-win.data.microsoft.com` (-) : 3
- `_googlecast._tcp.local` (-) : 3
- `www.gstatic.com` (NOERROR) : 2
- `www.googletagmanager.com` (NOERROR) : 2
- `www.googleadservices.com` (NOERROR) : 2
- `www.ars-soar.com` (NOERROR) : 2
- `win-lekbu2oy51n.natureforce.com` (NOERROR) : 2

### Serveurs TLS (SNI)

- `settings-win.data.microsoft.com` : 6
- `fonts.gstatic.com` : 6
- `edge.microsoft.com` : 6
- `www.bing.com` : 5
- `v20.events.data.microsoft.com` : 4
- `v10.events.data.microsoft.com` : 4
- `ecs.office.com` : 4
- `ogads-pa.clients6.google.com` : 3
- `login.microsoftonline.com` : 3
- `www.youtube.com` : 2
- `www.googletagmanager.com` : 2
- `www.google.com` : 2
- `play.google.com` : 2
- `odc.officeapps.live.com` : 2
- `mobile.events.data.microsoft.com` : 2
- `login.live.com` : 2
- `holtandberyl.com` : 2
- `ep1.adtrafficquality.google` : 2
- `client.wns.windows.com` : 2
- `assets.adobedtm.com` : 2

### Requêtes HTTP (hôte, méthode, agent)

- 2 × `holtandberyl.com` · GET · `curl/8.21.0`
- 2 × `ctldl.windowsupdate.com` · GET · `Microsoft-CryptoAPI/10.0`
- 1 × `yr.c.lencr.org` · GET · `Microsoft-CryptoAPI/10.0`
- 1 × `ye2.c.lencr.org` · GET · `Microsoft-CryptoAPI/10.0`
- 1 × `ye.c.lencr.org` · GET · `Microsoft-CryptoAPI/10.0`
- 1 × `x2.c.lencr.org` · GET · `Microsoft-CryptoAPI/10.0`
- 1 × `x1.c.lencr.org` · GET · `Microsoft-CryptoAPI/10.0`
- 1 × `www.msftconnecttest.com` · GET · `Microsoft NCSI`
- 1 × `oneocsp.microsoft.com` · GET · `Microsoft-CryptoAPI/10.0`
- 1 × `ocsp.digicert.com` · GET · `Microsoft-CryptoAPI/10.0`
- 1 × `edge.microsoft.com` · GET · `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36 Edg/154.0.0.0`
- 1 × `crt.sectigo.com` · GET · `Microsoft-CryptoAPI/10.0`
- 1 × `acroipm2.adobe.com` · GET · `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)`
- 1 × `107.175.82.242:9000` · GET · `curl/8.21.0`

### Notices Zeek

- 9 × `SSL::Invalid_Server_Cert` — SSL certificate validation failed with (unable to get local issuer certificate)

### Port 443 sans TLS ni QUIC, plus d'une minute

Le port 443 est celui du HTTPS : un flux long qui ne parle ni TLS ni QUIC s'y cache
(cas NetSupport, HTTP en clair ; cas Natureforce, protocole propre au RAT).

| Début (UTC) | Source | Destination | Service | Durée | Envoyé (o) | Reçu (o) |
|---|---|---|---|---|---|---|
| 2026-10-01 19:30:44 | 10.10.1.128 | 195.63.128.106 | `-` | 2233 s | 83716 | 13382927 |

## Balisement — connexions (conn.log)

conn.log · 346 connexions lues · 86 paires · 2 évaluées (>= 20 connexions sur >= 300 s) · 1 écartées car trop brèves

| Score | Niveau | Source | Destination | Port | Service | Conn. | Intervalle médian | Gigue | Octets médians | Inédite |
|---|---|---|---|---|---|---|---|---|---|---|
| 0.237 | peu probant | 10.10.1.128 | 10.10.1.10 | 53 | dns | 112 | 0.1 s | 100.0 % | 161 | — |
| 0.176 | peu probant | 10.10.1.128 | 10.10.1.10 | 389 | -,krb,gssapi,ldap_tcp,ldap_tcp,krb,gssapi,ldap_udp | 41 | 0.1 s | 91.7 % | 3214 | — |

## Balisement — requêtes HTTP (http.log)

http.log · 16 requêtes lues · 13 paires · 0 évaluées (>= 20 requêtes sur >= 300 s)

Aucune paire évaluable au-dessus du seuil.

## Verdict

> À écrire à la main, en confrontant ce résumé au compte rendu publié avec la capture :
>
> - **Vu par Suricata** — quelles signatures, sur quelle partie de l'infection.
> - **Vu par Zeek et le balisement** — quelle conversation, quel score, quel indice.
> - **Vu par personne** — ce que le compte rendu décrit et qu'aucun outil n'a remonté.

**Chronologie reconstituée (UTC, 2026-10-01).** 19:28:30 : la victime `10.10.1.128` ouvre
`www.ars-soar.com` (TLS). 19:28:59–19:29:01 : **`curl/8.21.0`** demande `holtandberyl.com/prw`
puis `/crv` en HTTP, redirigé (301) vers HTTPS — deux téléchargements dont on ne voit que le nom
du serveur. 19:30:36 : `curl` télécharge `http://107.175.82.242:9000/wilow/runner_ilove.exe`
(1 646 592 o). 19:30:43 : résolution de `dns.google` ; 19:30:44.127 : connexion **DNS over HTTPS**
à 8.8.4.4 ; 19:30:44.329 : ouverture du **C2 `195.63.128.106:443`**, gardé 37 min.

**Vu par Suricata : la livraison, pas le C2.** Sur le téléchargement de l'exécutable, 5 alertes ET :
`PE EXE or DLL Windows file download HTTP` (2018959, gravité 1), `Executable Download from
dotted-quad Host` (2016141), `curl User-Agent to Dotted Quad` (2034567), `Dotted Quad Host MZ
Response` (2021076, gravité 2), `Packed Executable Download` (2014819), plus une anomalie HTTP
(2221036). Sur le C2 : une seule alerte, `STREAM excessive retransmissions` (2210054) ;
protocole classé `failed`. Les deux requêtes `curl` vers `holtandberyl.com` : aucune alerte.
Avec la règle locale **1000003** (rev 3) : **1 alerte sur le C2**.

**Vu par Zeek / balisement : tout le déroulé, en métadonnées.** `http.log` montre l'agent `curl`
— une commande, pas un navigateur — vers `holtandberyl.com` puis vers l'adresse IP sur le port 9000.
`files.log` calcule le SHA-256 de l'exécutable, **identique au compte rendu**
(`b789adce…ad35061`) sans extraction ; `pe.log` le décrit : PE 64 bits, interface graphique, **non
signé**, date de compilation **2059-01-16** (falsifiée). `conn.log` isole le C2 : port 443, service
**`-`** (ni TLS ni HTTP), 2 233 s, 83 716 o envoyés, **13 382 927 o reçus** — section « Port 443
sans TLS ni QUIC » ci-dessus. Le compte rendu donne `195.64.128[.]106` : **coquille**, l'adresse de
la capture est `195.63.128.106`. **Balisement non applicable** : une seule connexion, pas de
requêtes HTTP sur ce canal.

**Vu par personne :** le contenu des téléchargements HTTPS depuis `holtandberyl.com` (vraisemblablement
le script de l'étape 1) et le contenu des 13,4 Mo reçus par le canal C2 — modules, charge
supplémentaire ou ordres, rien ne permet de trancher sans décoder le protocole. Le lien entre la
requête DoH et le C2 reste une hypothèse : la chronologie (200 ms) la soutient, une adresse écrite
en dur dans le binaire donnerait la même absence de DNS en clair. Le rôle de `www.ars-soar.com`
(page d'appât ?) n'est pas établi par la capture.
