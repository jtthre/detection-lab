# Sources des captures

La vérité terrain est notée **avant** l'analyse : on écrit ce qui doit être trouvé, on regarde
les outils ensuite.

| Étiquette | Source | Fichier | Taille | SHA-256 (calculé dans la sonde) | Empreinte publiée | Famille / C2 documenté |
|---|---|---|---|---|---|---|
| `lumma-2026-01-31` | [Exercice MTA du 2026-01-31](https://malware-traffic-analysis.net/2026/01/31/index.html) | `2026-01-31-traffic-analysis-exercise.pcap` | 27 242 609 o | `f755444d0b6eac847e07b73dea0774084b232d8577f536547a12f39b959d7833` | non (taille de l'archive conforme : 21 724 195 o) | **Lumma Stealer** — C2 `153.92.1[.]49:80` (HTTP clair), domaine `whitepepper[.]su` ; victime `10.1.21.58` (DESKTOP-ES9F3ML, `gwyatt`) ; alerte d'origine « ET MALWARE Lumma Stealer Victim Fingerprinting Activity », 2026-01-27 23:05 UTC |
| `netsupport-2026-02-28` | [Exercice MTA du 2026-02-28](https://malware-traffic-analysis.net/2026/02/28/index.html) | `2026-02-28-traffic-analysis-exercise.pcap` | 6 581 991 o | `3dc470f5490ec15b4024c513e87c67e0b17caeae2a2ce3d83541be24ef407e61` | non (taille de l'archive conforme : 5 167 384 o) | **NetSupport Manager RAT** — C2 `45.131.214[.]85`, TCP 443, à partir du 2026-02-28 19:55 UTC ; réseau `10.2.28.0/24`, domaine Active Directory `easyas123.tech` (interne, pas un indicateur — vérifié dans `dns.log`) |

## Remarques sur la vérité terrain

- **Le compte rendu du 31/01 contient deux coquilles** : la victime y est écrite `10.1.28.58`
  puis `10.1.21.58`, et le C2 `153.92.1.49` puis `154.92.1.49` sous une illustration. La plage
  réseau annoncée par le même document (`10.1.21.0/24`) et les indices tranchent pour
  `10.1.21.58` et `153.92.1.49`. **Même la vérité terrain se recoupe** — Zeek confirmera.
- **Une empreinte n'est pas une preuve d'intégrité si l'on n'a pas vérifié la taille.** Une
  première extraction ratée (mauvais mot de passe) a laissé un fichier de 0 octet, dont le
  SHA-256 est `e3b0c442…b855` — l'empreinte bien connue d'un fichier vide. On contrôle la taille
  avant de reporter l'empreinte.
