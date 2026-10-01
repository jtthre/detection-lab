# rapports/

Sorties d'analyse et rapports de test, produits automatiquement.

| Fichier | Producteur | Contenu |
|---|---|---|
| `*_<etiquette>.md` | `Invoke-TestAtomique.ps1` | Rapport du test, avec section **Verdict** à compléter |
| `*_<etiquette>_chainsaw.json` | Chainsaw | Alertes de **vos** règles Sigma |
| `*_<etiquette>_hayabusa.csv` | Hayabusa | Alertes du jeu de règles curaté |
| `*_<etiquette>_bilan.json` | `Invoke-Analyse.ps1` | Codes de sortie et chemins — sert au débogage |

## La section Verdict n'est pas optionnelle

Le script mesure : combien d'événements, lesquels, vus par quel outil. Il ne conclut pas.

Un rapport dont le verdict est vide ne compte pas comme un test réalisé. C'est la phrase de
justification qui a de la valeur, pas le tableau de chiffres — un recruteur lit la première
et survole le second.
