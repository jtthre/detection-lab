# rapports/

Un dossier par analyse, produit par `scripts/analyser-pcap.sh` :

```
<date>_<etiquette>/
├── resume.md          à lire en premier : chiffres, principales lignes, section Verdict
├── balisement.md      sortie de balisement.py sur le conn.log (rythme des connexions)
├── balisement-http.md sortie de balisement.py sur le http.log (rythme des requêtes)
├── suricata/
│   ├── eve.json       tous les événements Suricata (alertes, flux, DNS, TLS, HTTP…)
│   └── fast.log       les alertes seules, une ligne chacune
└── zeek/
    ├── conn.log       une ligne par connexion — l'entrée du balisement
    ├── dns.log, http.log, ssl.log, x509.log, files.log, notice.log, weird.log…
```

## La section Verdict n'est pas optionnelle

Le script mesure. Le verdict confronte la mesure au compte rendu publié avec la capture :
ce que Suricata a vu, ce que Zeek et le balisement ont vu, **ce que personne n'a vu**. Un
rapport sans verdict ne compte pas comme une analyse.
