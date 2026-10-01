# Matrice de couverture — module 02

Ce fichier est le livrable du module. Pas les règles, pas les scripts : **ce tableau**.

Une règle Sigma prouve qu'on sait écrire du YAML. Une matrice remplie prouve qu'on sait
mesurer ce qu'on détecte et, surtout, **nommer ce qu'on ne détecte pas**. C'est la
différence entre un dépôt d'étudiant et un dépôt d'analyste.

---

## Tableau principal

Une ligne par règle. À remplir après chaque test, depuis le rapport produit par
`Invoke-TestAtomique.ps1`.

| # | Règle | Technique | Atomique | Évts produits | Chainsaw | Hayabusa | Verdict | Latence |
|---|---|---|---|---|---|---|---|---|
| 01 | Accès mémoire LSASS | T1003.001 | | | | | | |
| 02 | PowerShell encodé | T1059.001 | | | | | | |
| 03 | Tâche planifiée | T1053.005 | | | | | | |
| 04 | Clé de démarrage | T1547.001 | | | | | | |
| 05 | Thread distant | T1055.x | | | | | | |
| 06 | Rundll32 détourné | T1218.011 | | | | | | |
| 07 | LOLBin sortant | T1105 | | | | | | |
| 08 | Service suspect | T1543.003 | | | | | | |
| 09 | Clichés instantanés | T1490 | | | | | | |
| 10 | Exécution WMI | T1047 | | | | | | |

**Conventions de remplissage :**

- *Chainsaw* / *Hayabusa* : `oui` si l'outil a remonté une alerte sur le test, `non` sinon.
- *Verdict* : `validée`, `à corriger` ou `donnée absente`. Pas de quatrième valeur.
- *Latence* : secondes entre l'action et l'écriture de l'événement. Utile au module 04,
  quand le SIEM entrera dans la chaîne.

---

## Le tableau qui compte vraiment

Celui-ci n'existe pas dans les dépôts d'étudiants, et c'est exactement pour ça qu'il faut
le tenir.

| Constat | Règle(s) concernée(s) | Pourquoi | Ce que ça coûterait de corriger |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

On y consigne les quatre situations qu'un recruteur cherche à voir nommées :

1. **La règle n'a pas déclenché et c'est normal.** L'atomique choisi implémente la technique
   autrement. Exemple attendu sur `T1055` : toutes les variantes d'injection ne créent pas
   de thread distant.
2. **La règle a déclenché sur le mauvais critère.** Elle remonte, mais pour une raison qui
   n'est pas celle qu'on visait. C'est le défaut le plus dangereux : la règle semble bonne
   et ne l'est pas.
3. **Chainsaw et Hayabusa divergent.** Si Hayabusa remonte et pas vous, vos règles ont un
   angle mort. Si vous remontez et pas Hayabusa, ce n'est pas forcément un faux positif —
   votre configuration Sysmon collecte peut-être une donnée que leur jeu de règles n'attend
   pas.
4. **La donnée n'existait pas.** L'événement n'a jamais été écrit. Le défaut est dans la
   configuration, pas dans la règle — et il se corrige dans `sysmon-config.xml`.

---

## Mesure de bruit au repos

Sans ce chiffre, la matrice ne vaut rien : une règle qui détecte tout détecte aussi tout le
reste.

```powershell
.\scripts\Invoke-TestAtomique.ps1 -Etiquette bruit-repos -SansAtomique -Attente 3600
```

| Fenêtre | Durée | Évts Sysmon | Alertes Chainsaw | Alertes Hayabusa |
|---|---|---|---|---|
| VM au repos | 60 min | | | |

**Toute alerte sur une machine au repos est un faux positif.** Elle se documente dans le
champ `falsepositives` de la règle concernée, avec la date et ce qui l'a déclenchée — pas
une formule générale.

---

## Synthèse de fin de module

À remplir une fois les dix lignes closes. Trois phrases, pas plus — c'est ce paragraphe
qu'on lit en entretien.

**Règles validées :** ⬚ / 10

**Règles à corriger :** ⬚ — lesquelles et pourquoi :

**Données absentes :** ⬚ — quel groupe de `sysmon-config.xml` est en cause :

**Faux positifs au repos :** ⬚ sur 60 minutes

**Ce que la campagne a changé dans le dépôt :**
