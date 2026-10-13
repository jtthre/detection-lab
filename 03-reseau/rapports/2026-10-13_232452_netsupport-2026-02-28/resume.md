# Analyse — netsupport-2026-02-28

| Champ | Valeur |
|---|---|
| Capture | `2026-02-28-traffic-analysis-exercise.pcap` (6.3M) |
| SHA-256 | `3dc470f5490ec15b4024c513e87c67e0b17caeae2a2ce3d83541be24ef407e61` |
| Analyse | 2026-10-13_232452 |
| Suricata | This is Suricata version 8.0.7 RELEASE |
| Zeek | zeek version 9.0.0 |
| Période capturée (UTC) | 2026-02-28 19:55:06 → 2026-03-01 00:16:30 |

## Suricata — alertes par signature

**561 alertes.**

| Nombre | Gravité | Signature | SID |
|---|---|---|---|
| 264 | 3 | ET REMOTE_ACCESS NetSupport Remote Admin Checkin | 2035892 |
| 264 | 2 | ET INFO HTTP traffic on port 443 (POST) | 2013926 |
| 30 | 3 | SURICATA HTTP Response excessive header repetition | 2221036 |
| 2 | 3 | ET REMOTE_ACCESS NetSupport Remote Admin Response | 2035895 |
| 1 | 3 | ET INFO Microsoft Connection Test | 2031071 |

Événements Suricata par type :

- `dns` : 809
- `flow` : 795
- `alert` : 561
- `dcerpc` : 380
- `smb` : 328
- `http` : 308
- `fileinfo` : 307
- `tls` : 152
- `ldap` : 122
- `quic` : 40
- `anomaly` : 30
- `krb5` : 16
- `mdns` : 3
- `stats` : 1
- `dhcp` : 1

## Zeek — volume par journal

| Journal | Lignes |
|---|---|
| `capture_loss.log` | 19 |
| `conn.log` | 848 |
| `dce_rpc.log` | 280 |
| `dhcp.log` | 2 |
| `dns.log` | 568 |
| `files.log` | 310 |
| `http.log` | 308 |
| `kerberos.log` | 127 |
| `known_hosts.log` | 2 |
| `known_services.log` | 19 |
| `ldap.log` | 61 |
| `ldap_search.log` | 61 |
| `loaded_scripts.log` | 551 |
| `notice.log` | 23 |
| `ocsp.log` | 29 |
| `packet_filter.log` | 1 |
| `quic.log` | 8 |
| `smb_files.log` | 15 |
| `smb_mapping.log` | 26 |
| `software.log` | 6 |
| `ssl.log` | 160 |
| `stats.log` | 54 |
| `weird.log` | 18 |
| `x509.log` | 13 |

### Connexions par service

- `dns` : 365
- `ssl` : 152
- `-` : 104
- `dce_rpc` : 47
- `krb,gssapi,dce_rpc` : 34
- `krb,gssapi,ldap_tcp` : 32
- `ldap_tcp,krb,gssapi` : 29
- `ldap_udp` : 24
- `http` : 19
- `gssapi,smb,krb` : 19
- `quic,ssl` : 8
- `krb_tcp` : 8
- `gssapi,smb,krb,dce_rpc` : 5
- `dhcp` : 2

### Destinations les plus contactées

| Connexions | Destination | Port |
|---|---|---|
| 260 | 10.2.28.2 | 53 |
| 86 | 10.2.28.2 | 389 |
| 63 | 10.2.28.255 | 138 |
| 51 | 10.2.28.255 | 137 |
| 51 | 10.2.28.2 | 137 |
| 41 | 10.2.28.2 | 135 |
| 38 | 10.2.28.2 | 49671 |
| 24 | 10.2.28.2 | 445 |
| 14 | 150.171.28.11 | 443 |
| 13 | 10.2.28.2 | 123 |
| 8 | 23.192.223.17 | 443 |
| 8 | 10.2.28.2 | 88 |
| 8 | 10.2.28.2 | 3 |
| 7 | 239.255.255.250 | 1900 |
| 6 | 23.41.251.53 | 443 |

### Noms résolus (DNS)

- `wpad.mshome.net` (NXDOMAIN) : 78
- `wpad.easyas123.tech` (NXDOMAIN) : 78
- `EASYAS123` (-) : 59
- `-` (YXDOMAIN) : 51
- `edge.microsoft.com` (NOERROR) : 30
- `login.microsoftonline.com` (NOERROR) : 17
- `login.microsoftonline.com` (-) : 14
- `v10.events.data.microsoft.com` (NOERROR) : 13
- `settings-win.data.microsoft.com` (NOERROR) : 13
- `settings-win.data.microsoft.com` (-) : 12
- `www.msn.com` (NOERROR) : 11
- `www.bing.com` (NOERROR) : 10
- `_ldap._tcp.default-first-site-name._sites.dc._msdcs.easyas123.tech` (NOERROR) : 10
- `v10.events.data.microsoft.com` (-) : 9
- `windows.msn.com` (NOERROR) : 8
- `DESKTOP-TEYQ2NR` (-) : 8
- `easyas123-dc.easyas123.tech` (NOERROR) : 7
- `assets.msn.com` (NOERROR) : 7
- `th.bing.com` (NOERROR) : 6
- `self.events.data.microsoft.com` (NOERROR) : 5

### Serveurs TLS (SNI)

- `login.microsoftonline.com` : 18
- `v10.events.data.microsoft.com` : 16
- `edge.microsoft.com` : 16
- `ecs.office.com` : 16
- `settings-win.data.microsoft.com` : 14
- `self.events.data.microsoft.com` : 9
- `windows.msn.com` : 8
- `odc.officeapps.live.com` : 7
- `mobile.events.data.microsoft.com` : 7
- `www.msn.com` : 6
- `www.bing.com` : 5
- `assets.msn.com` : 5
- `th.bing.com` : 4
- `api.msn.com` : 4
- `client.wns.windows.com` : 3
- `srtb.msn.com` : 2
- `services.gfe.nvidia.com` : 2
- `img-s-msn-com.akamaized.net` : 2
- `edge-consumer-static.azureedge.net` : 2
- `assets.adobedtm.com` : 2

### Requêtes HTTP (hôte, méthode, agent)

- 264 × `45.131.214.85` · POST · `NetSupport Manager/1.3`
- 25 × `msedge.b.tlu.dl.delivery.mp.microsoft.com` · GET · `Microsoft BITS/7.8`
- 9 × `ctldl.windowsupdate.com` · GET · `Microsoft-CryptoAPI/10.0`
- 5 × `msedge.b.tlu.dl.delivery.mp.microsoft.com` · HEAD · `Microsoft BITS/7.8`
- 2 × `ocsp.digicert.com` · GET · `Microsoft-CryptoAPI/10.0`
- 1 × `www.msftconnecttest.com` · GET · `Microsoft NCSI`
- 1 × `edge.microsoft.com` · GET · `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0`
- 1 × `acroipm2.adobe.com` · GET · `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)`

### Notices Zeek

- 23 × `SSL::Invalid_Server_Cert` — SSL certificate validation failed with (unable to get local issuer certificate)

## Balisement — connexions (conn.log)

conn.log · 848 connexions lues · 115 paires · 8 évaluées (>= 20 connexions sur >= 300 s)

| Score | Niveau | Source | Destination | Port | Service | Conn. | Intervalle médian | Gigue | Octets médians | Inédite |
|---|---|---|---|---|---|---|---|---|---|---|
| 1.0 | très régulier | 10.2.28.88 | 10.2.28.2 | 137 | dns | 51 | 310.1 s | 0.0 % | 0 | — |
| 1.0 | très régulier | 10.2.28.88 | 10.2.28.255 | 137 | dns | 51 | 310.1 s | 0.0 % | 0 | — |
| 0.835 | régulier | 10.2.28.88 | 10.2.28.255 | 138 | - | 63 | 310.0 s | 9.4 % | 1536 | — |
| 0.783 | régulier | 10.2.28.88 | 10.2.28.2 | 445 | gssapi,smb,krb,gssapi,smb,krb,dce_rpc | 24 | 725.2 s | 24.1 % | 6343 | — |
| 0.663 | peu probant | 10.2.28.88 | 10.2.28.2 | 49671 | dce_rpc,krb,gssapi,dce_rpc | 38 | 335.7 s | 66.5 % | 5504 | — |
| 0.626 | peu probant | 10.2.28.88 | 10.2.28.2 | 135 | -,dce_rpc | 41 | 312.5 s | 78.0 % | 1140 | — |
| 0.257 | peu probant | 10.2.28.88 | 10.2.28.2 | 389 | -,krb,gssapi,ldap_tcp,ldap_tcp,krb,gssapi,ldap_udp | 86 | 0.1 s | 95.1 % | 6114 | — |
| 0.246 | peu probant | 10.2.28.88 | 10.2.28.2 | 53 | dns | 260 | 0.7 s | 100.0 % | 278 | — |

## Balisement — requêtes HTTP (http.log)

http.log · 308 requêtes lues · 12 paires · 1 évaluées (>= 20 requêtes sur >= 300 s)

| Score | Niveau | Source | Destination | Port | Service | Req. | Intervalle médian | Gigue | Octets médians | Inédite |
|---|---|---|---|---|---|---|---|---|---|---|
| 1.0 | très régulier | 10.2.28.88 | 45.131.214.85 | 443 | http POST | 264 | 60.1 s | 0.0 % | 36 | — |

## Verdict

> À écrire à la main, en confrontant ce résumé au compte rendu publié avec la capture :
>
> - **Vu par Suricata** — quelles signatures, sur quelle partie de l'infection.
> - **Vu par Zeek et le balisement** — quelle conversation, quel score, quel indice.
> - **Vu par personne** — ce que le compte rendu décrit et qu'aucun outil n'a remonté.

**Vu par Suricata : oui, sur le contenu.** 264 × « ET REMOTE_ACCESS NetSupport Remote Admin
Checkin » (2035892) : une alerte par rappel, autant que de requêtes dans `http.log`. 2 ×
« NetSupport Remote Admin Response » (2035895) : les deux seules réponses du serveur, à
19:55:51–52. 264 × « ET INFO HTTP traffic on port 443 (POST) » (2013926) : générique, mais
juste — du HTTP en clair sur le port du HTTPS (T1571). Les 30 « excessive header
repetition » (2221036) viennent des serveurs de mise à jour d'Edge (`23.218.232.x`) : bruit.
Aucune de ces alertes ne dépend d'un nom : l'implant joint le C2 **par son adresse**.

**Vu par Zeek / balisement : oui, au niveau des requêtes seulement.** `http.log` : 264 `POST
http://45.131.214.85/fakeurl.htm`, agent `NetSupport Manager/1.3`. Enregistrement à 19:55:51
(deux échanges : 22 → 69 o, 244 → 153 o), puis **260 rappels identiques de 36 o, sans aucune
réponse HTTP**, jusqu'à 00:16:28. `conn.log` : une seule connexion de 15 637 s porte le tout
(`missed_bytes` = 0, capture complète). **Balisement `conn.log` : pas vu** — une connexion
ne fait pas une série ; en tête sortent des paires internes à 1,0 (NetBIOS vers le
contrôleur de domaine et la diffusion, toutes les 310 s), du Windows normal. **Balisement
`http.log` : 1,0**, seule paire évaluée — 264 requêtes toutes les 60,1 s, gigue 0 %.
Le domaine `easyas123.tech` cité avec la capture est l'Active Directory de la victime
(contrôleur `easyas123-dc` → `10.2.28.2`) : pas un indicateur.

**Vu par personne :** rien du canal ne manque — sur ces 4 h 20, le serveur n'envoie aucun
ordre après l'enregistrement. L'infection initiale (avant 19:55) n'est pas dans la capture.
