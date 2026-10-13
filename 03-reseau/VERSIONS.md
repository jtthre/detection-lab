# Versions de l'outillage — module 03

Une analyse n'est reproductible que si l'on sait avec quoi elle a été menée. Suricata et Zeek
publient plusieurs versions par an, et le jeu de règles ET Open change **chaque jour** : le
même pcap analysé à un mois d'écart ne donne pas les mêmes alertes.

**À remplir après installation**, avec ce que les binaires affichent.

| Outil | Commande de vérification | Version installée | Date d'installation |
|---|---|---|---|
| Ubuntu Server | `lsb_release -d` | | |
| Suricata | `suricata -V` | | |
| Règles ET Open | `ls -l /var/lib/suricata/rules/suricata.rules` (date) et nombre de règles `alert` | | |
| Zeek | `zeek --version` | | |
| Python | `python3 --version` | | |
| jq | `jq --version` | | |

## Repères au moment de l'écriture (octobre 2026)

- **Suricata** : branche 8 en cours (8.0.7 publiée en septembre 2026, correctifs de sécurité) ;
  branche 7 en fin de vie.
- **Zeek** : 9.0 est la version LTS depuis le 14 septembre 2026 ; la LTS précédente est 8.0.
- Ces repères servent à interpréter une différence de comportement, pas à remplacer la ligne
  du tableau : on note ce qui est installé.

## Le jeu de règles est une version comme une autre

`suricata-update` télécharge la dernière version d'ET Open à chaque lancement. Pour qu'une
analyse soit comparable à la suivante :

- noter la **date** du fichier `suricata.rules` dans chaque `resume.md` (le script note déjà la
  version de Suricata) ;
- ne **pas** relancer `suricata-update` au milieu d'une série d'analyses ;
- pour mesurer l'effet du temps (une règle publiée après la capture), c'est au contraire
  l'expérience à faire : même pcap, deux versions des règles, comparaison.

## Emplacements retenus

| Quoi | Chemin dans la sonde |
|---|---|
| Dépôt | `~/detection-lab` |
| Captures (hors dépôt) | `~/pcaps` |
| Règles Suricata assemblées | `/var/lib/suricata/rules/suricata.rules` |
| Configuration Suricata | `/etc/suricata/suricata.yaml` |
| Zeek | `/opt/zeek/bin` |
