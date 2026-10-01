# preuves/

Exports EVTX horodatés du journal `Microsoft-Windows-Sysmon/Operational`, un par test.

Nommage produit par `Invoke-TestAtomique.ps1` :

```
AAAA-MM-JJ_HHMMSS_<etiquette>.evtx
```

## Pourquoi on garde le journal entier et pas seulement la fenêtre du test

Un filtre XPath mal échappé retire silencieusement des événements : l'export réussit, le
fichier est plus petit, et l'analyse conclut à une règle muette. En lab le volume est
faible — on exporte tout, on filtre à l'analyse.

## Pourquoi ces fichiers sont versionnés

Un EVTX est la seule preuve qu'un test a eu lieu et ce qu'il a produit. Sans lui, la matrice
de couverture n'est qu'une affirmation.

Si le volume devient gênant, compressez par campagne plutôt que de supprimer :

```powershell
Compress-Archive -Path .\preuves\2026-09-2*.evtx -DestinationPath .\preuves\campagne-2026-09.zip
```

## Avant toute restauration d'instantané

`git push` d'abord. Un instantané restauré emporte ce dossier avec lui.
