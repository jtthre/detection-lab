# Analyse — normal-2026-10-14 (résumé public)

Trafic **normal** de la VM Windows du lab : référence de faux positifs pour Suricata, pour le
balisement et pour les règles locales. C'est du trafic personnel : la capture, `resume.md`,
`eve.json` et les journaux Zeek restent dans la sonde (voir `.gitignore`). Ce résumé, écrit à la
main, ne reprend ni les noms résolus, ni les serveurs TLS, ni la navigation.

| Champ | Valeur |
|---|---|
| Capture | `normal-2026-10-14.pcapng` (1 932 694 968 o, non versionnée) |
| SHA-256 | `cc2e1080b1bbb7dc93a7f11a87a9ee4e3c7d762f762e03aa11aff299f0b1b607` |
| Capteur | `pktmon start --capture --comp nics --pkt-size 0 --file-size 2048` dans la VM, puis `pktmon etl2pcap` |
| Analyse | 2026-10-14_215134 — Suricata 8.0.7, Zeek 9.0.0, 53 133 règles ET Open (13/10/2026) |
| Période capturée (UTC) | 2026-10-14 10:00:24 → 11:36:27 (1 h 36) — 1 248 072 paquets |
| Particularité | Dernier bloc pcapng tronqué : conversion interrompue par un écran bleu de la VM (disque de l'hôte plein) |

## Suricata — 160 692 alertes, aucune malveillante

| Nombre | Gravité | Signature | SID | Explication |
|---|---|---|---|---|
| 79 948 | 3 | SURICATA IPv4 invalid checksum | 2200073 | Artefact de capture (somme calculée par la carte après `pktmon`) |
| 77 880 | 3 | SURICATA TCPv4 invalid checksum | 2200074 | Idem |
| 2 011 | 3 | SURICATA UDPv4 invalid checksum | 2200075 | Idem |
| 419 | 3 | SURICATA UDPv6 invalid checksum | 2200078 | Idem |
| 200 | 3 | SURICATA IPv4 total length smaller than header size | 2200002 | Artefact de capture (segmentation déléguée à la carte) |
| 156 | 3 | ET INFO Windows Update P2P Activity | 2027766 | Optimisation de livraison (port 7680) |
| 69 | 3 | SURICATA Applayer Wrong direction first data | 2260001 | Anomalie de flux banale |
| 4 | 3 | SURICATA STREAM excessive retransmissions | 2210054 | Idem |
| 3 | 3 | ET INFO Packed Executable Download | 2014819 | Mises à jour de Defender (`/msdownload/update/software/defu/…`) |
| 1 | 3 | ET INFO Microsoft Connection Test | 2031071 | Test de connectivité de Windows |
| 1 | 2 | ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response | 2021076 | Mise à jour Defender `am_delta_…exe` servie par un cache Windows Update joint par IP (`85.208.10.203`) |

## Règles locales (`regles/local.rules`, `-S`)

**0 alerte** pour 1000001 et 1000002 sur les 1 248 072 paquets.

## Balisement — connexions (`conn.log`)

1 258 connexions · 135 paires · 12 évaluées. Paires au-dessus de 0,70, toutes **internes** :

| Score | Destination | Port | Conn. | Intervalle médian | Gigue | Nature |
|---|---|---|---|---|---|---|
| 1,0 | 192.168.64.2 (passerelle NAT) | 137/udp | 52 | 120,0 s | 0,0 % | NetBIOS |
| 0,867 | 192.168.64.1 (hôte) | 7680/tcp | 156 | 40,2 s | 0,6 % | Optimisation de livraison Windows Update |
| 0,72 | 224.0.0.251 | 5353/udp | 57 | 120,8 s | 1,9 % | mDNS (IPv4) |
| 0,72 | ff02::fb | 5353/udp | 57 | 120,8 s | 1,9 % | mDNS (IPv6) |

Avec `--externes-seulement` : meilleure paire externe à **0,507** (serveur Microsoft, 29
connexions en rafale).

## Balisement — requêtes HTTP (`http.log`)

4 444 requêtes · 10 paires · 2 évaluées.

| Score | Destination | Req. | Intervalle médian | Gigue | Octets médians | Nature |
|---|---|---|---|---|---|---|
| 0,797 | 85.208.10.201:80 | 728 | 1,5 s | 42,1 % | 262 144 | Cache Windows Update joint par IP : téléchargement par morceaux de 256 Ko |
| 0,299 | 199.232.82.172:80 | 3 589 | 0,3 s | 95,8 % | 262 144 | `*.delivery.mp.microsoft.com`, `*.download.windowsupdate.com` |

**Seuil retenu : 0,85.** Aucune paire du trafic normal ne l'atteint ; le C2 NetSupport sort à
1,0 et « destination inédite » face à cette référence.

## Verdict

**Faux positifs Suricata :** aucun qui imite une infection. 99,9 % des alertes sont des
artefacts d'une capture faite sur la machine elle-même ; les 161 alertes ET restantes sont
toutes reliées à Windows Update, Defender ou au test de connectivité. Une seule de gravité 2,
expliquée.

**Faux positifs du balisement :** uniquement du trafic interne Windows (NetBIOS, mDNS,
optimisation de livraison) et un téléchargement par morceaux de taille fixe. `--externes-seulement`
et le seuil de 0,85 les écartent tous.

**Limite :** 1 h 36 d'un poste qui rattrape ses mises à jour. Référence à refaire sur plusieurs
heures, VM à jour, avec un fichier plus grand.
