# Sources des captures

La vérité terrain est notée **avant** l'analyse : on écrit ce qui doit être trouvé, on regarde
les outils ensuite.

| Étiquette | Source | Fichier | Taille | SHA-256 (calculé dans la sonde) | Empreinte publiée | Famille / C2 documenté |
|---|---|---|---|---|---|---|
| `lumma-2026-01-31` | [Exercice MTA du 2026-01-31](https://malware-traffic-analysis.net/2026/01/31/index.html) | `2026-01-31-traffic-analysis-exercise.pcap` | 27 242 609 o | `f755444d0b6eac847e07b73dea0774084b232d8577f536547a12f39b959d7833` | non (taille de l'archive conforme : 21 724 195 o) | **Lumma Stealer** — C2 `153.92.1[.]49:80` (HTTP clair), domaine `whitepepper[.]su` ; victime `10.1.21.58` (DESKTOP-ES9F3ML, `gwyatt`) ; alerte d'origine « ET MALWARE Lumma Stealer Victim Fingerprinting Activity », 2026-01-27 23:05 UTC |
| `netsupport-2026-02-28` | [Exercice MTA du 2026-02-28](https://malware-traffic-analysis.net/2026/02/28/index.html) | `2026-02-28-traffic-analysis-exercise.pcap` | 6 581 991 o | `3dc470f5490ec15b4024c513e87c67e0b17caeae2a2ce3d83541be24ef407e61` | non (taille de l'archive conforme : 5 167 384 o) | **NetSupport Manager RAT** — C2 `45.131.214[.]85`, TCP 443, à partir du 2026-02-28 19:55 UTC ; réseau `10.2.28.0/24`, domaine Active Directory `easyas123.tech` (interne, pas un indicateur — vérifié dans `dns.log`) |
| `natureforce-2026-10-01` | [Exercice MTA du 2026-10-01 « Natureforce »](https://www.malware-traffic-analysis.net/2026/10/01/index.html) | `2026-10-01-traffic-analysis-exercise.pcap` | 36 838 132 o | `287d6dee90cfef71f98a97c42e30444608de2cf59d2f7392a0a6df8dbbc8274b` | non (taille de l'archive conforme : 33 137 313 o) | **RAT « CNCmachineRMS »** — C2 publié `195.64.128[.]106:443`, **observé `195.63.128[.]106:443`** (voir remarques) ; exécutable `runner_ilove.exe` livré en HTTP depuis `107.175.82[.]242:9000` (SHA-256 `b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061`) ; victime `10.10.1.128` (DESKTOP-4VGYQX7, MAC `00:22:fb:ec:7e:e7`, `bdiaz`) ; réseau `10.10.1.0/24`, AD `natureforce.com`, contrôleur `10.10.1.10` |
| `normal-2026-10-14` | VM Windows du lab, `pktmon --comp nics --pkt-size 0`, fichier circulaire 2 Go, converti par `pktmon etl2pcap` | `normal-2026-10-14.pcapng` (**jamais versionné**) | 1 932 694 968 o | `cc2e1080b1bbb7dc93a7f11a87a9ee4e3c7d762f762e03aa11aff299f0b1b607` (identique dans la VM et dans la sonde) | — | **Trafic normal**, aucune campagne de test ; 10:00:24 → 11:36:27 UTC ; dernier bloc pcapng tronqué (conversion interrompue) |

## Remarques sur la vérité terrain

- **Le compte rendu du 31/01 contient deux coquilles** : la victime y est écrite `10.1.28.58`
  puis `10.1.21.58`, et le C2 `153.92.1.49` puis `154.92.1.49` sous une illustration. La plage
  réseau annoncée par le même document (`10.1.21.0/24`) et les indices tranchent pour
  `10.1.21.58` et `153.92.1.49`. **Même la vérité terrain se recoupe** — Zeek confirmera.
- **Une empreinte n'est pas une preuve d'intégrité si l'on n'a pas vérifié la taille.** Une
  première extraction ratée (mauvais mot de passe) a laissé un fichier de 0 octet, dont le
  SHA-256 est `e3b0c442…b855` — l'empreinte bien connue d'un fichier vide. On contrôle la taille
  avant de reporter l'empreinte.
- **Le compte rendu du 01/10 contient lui aussi une coquille** : le C2 y est écrit
  `195.64.128[.]106`. Aucune trace de cette adresse dans la capture ; le seul flux qui
  correspond (début 8 s après la livraison de l'exécutable, 37 min, port 443) va vers
  `195.63.128[.]106`. Deuxième vérité terrain corrigée par les journaux, après Lumma.
- **L'empreinte de l'exécutable se vérifie sans l'extraire** : Zeek calcule le SHA-256 des
  fichiers qu'il voit passer (`files.log`), et celui de `runner_ilove.exe` (1 646 592 o) est
  identique à celui du compte rendu.
