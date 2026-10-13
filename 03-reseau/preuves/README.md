# preuves/

**Aucune capture ici.** Les pcaps restent dans la VM sonde, hors du dépôt (`~/pcaps/`).

Ce dossier contient `sources.md` : pour chaque capture analysée, de quoi la retrouver et
prouver que c'est bien celle-là.

| Colonne | Contenu |
|---|---|
| Étiquette | le nom court utilisé dans `rapports/` |
| Source | URL de la page qui publie la capture et son compte rendu |
| Fichier | nom exact du pcap une fois extrait |
| SHA-256 | empreinte calculée dans la VM (`sha256sum`) |
| Empreinte publiée | oui / non — si la source publie une empreinte, elle doit correspondre |
| Famille / C2 documenté | ce que le compte rendu dit de l'infection : c'est la vérité terrain |

## Pourquoi pas les pcaps eux-mêmes

1. Ils contiennent du trafic de maliciels réels, et souvent les binaires téléchargés pendant
   l'infection. Un dépôt public n'a pas à les redistribuer.
2. La capture de trafic **normal** contient la navigation de la VM : elle reste privée.
3. Les sorties de Suricata et Zeek dans `rapports/` suffisent à vérifier chaque verdict, et la
   source + l'empreinte suffisent à rejouer l'analyse.
