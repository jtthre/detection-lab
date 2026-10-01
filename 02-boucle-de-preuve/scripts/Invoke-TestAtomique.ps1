<#
.SYNOPSIS
    Orchestre un test atomique : marqueur, exécution, collecte, analyse, rapport.

.DESCRIPTION
    La boucle de preuve du module 02, en un seul appel :

      1. releve le dernier RecordId du journal Sysmon (le marqueur)
      2. lance le test atomique demande
      3. attend que le capteur ait fini d'ecrire
      4. compte les evenements produits APRES le marqueur, par identifiant
      5. exporte le journal complet en EVTX dans preuves\
      6. passe Chainsaw (vos regles) et Hayabusa (second avis) dessus
      7. ecrit un rapport Markdown pret a coller dans la matrice de couverture

    Le script ne decide rien. Il mesure. Le verdict — regle validee, regle a
    corriger, donnee absente — reste votre travail.

.PARAMETER Technique
    Identifiant ATT&CK, par exemple T1003.001.

.PARAMETER NumeroTest
    Numero de l'atomique dans le catalogue, obtenu avec -ShowDetailsBrief.

.PARAMETER Etiquette
    Nom court du test pour les fichiers de sortie, par exemple "01-lsass".

.PARAMETER Nettoyer
    Lance la procedure de nettoyage du framework apres la mesure.

.PARAMETER SansAtomique
    N'execute aucun test : se contente de mesurer une fenetre. Sert a la mesure
    de bruit au repos, qui est le vrai critere d'echec d'une regle.

.EXAMPLE
    .\Invoke-TestAtomique.ps1 -Technique T1003.001 -NumeroTest 2 -Etiquette 01-lsass

.EXAMPLE
    # Mesure du bruit : une heure de VM au repos, aucun test lance
    .\Invoke-TestAtomique.ps1 -Etiquette bruit-repos -SansAtomique -Attente 3600
#>

[CmdletBinding()]
param(
    [string] $Technique,
    [int]    $NumeroTest,
    [Parameter(Mandatory)] [string] $Etiquette,
    [int]    $Attente = 20,
    [switch] $Nettoyer,
    [switch] $SansAtomique,
    [string] $JournalSysmon = 'Microsoft-Windows-Sysmon/Operational'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$racine  = Split-Path -Parent $PSScriptRoot
$preuves = Join-Path $racine 'preuves'
$rapports = Join-Path $racine 'rapports'
foreach ($d in @($preuves, $rapports)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
}

$horodatage = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$etiquetteFichier = "${horodatage}_${Etiquette}"

# --- Garde-fou d'isolation ------------------------------------------------------
# Refus d'executer si la VM a une route sortante. Le module 02 execute du code
# reellement malveillant : ce test n'est pas une formalite.
$routeSortante = $false
try {
    $routeSortante = Test-NetConnection -ComputerName '8.8.8.8' -Port 53 `
                                        -InformationLevel Quiet -WarningAction SilentlyContinue
}
catch { $routeSortante = $false }

if ($routeSortante -and -not $SansAtomique) {
    throw 'ARRET : la VM atteint Internet. Coupez la carte reseau avant tout test atomique.'
}

# --- 1. Marqueur ----------------------------------------------------------------
$debut = Get-Date
$marqueur = $null
try {
    $marqueur = (Get-WinEvent -LogName $JournalSysmon -MaxEvents 1 -ErrorAction Stop).RecordId
}
catch {
    Write-Warning 'Journal Sysmon vide — le marqueur part de zero.'
    $marqueur = 0
}
Write-Host "Marqueur : RecordId $marqueur a $($debut.ToString('HH:mm:ss'))" -ForegroundColor Cyan

# --- 2. Exécution ---------------------------------------------------------------
$detailAtomique = 'aucun (mesure de fenetre)'
if (-not $SansAtomique) {
    if (-not $Technique -or -not $NumeroTest) {
        throw 'Precisez -Technique et -NumeroTest, ou utilisez -SansAtomique.'
    }
    if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
        throw 'Invoke-AtomicTest introuvable. Importez le module Atomic Red Team dans cette session.'
    }

    $detailAtomique = "$Technique n°$NumeroTest"
    Write-Host "Lancement : $detailAtomique" -ForegroundColor Yellow
    Invoke-AtomicTest $Technique -TestNumbers $NumeroTest
}

# --- 3. Attente -----------------------------------------------------------------
# Le capteur ecrit de maniere asynchrone. Mesurer trop tot, c'est conclure a une
# regle muette alors que l'evenement n'est simplement pas encore la.
Write-Host "Attente de $Attente s (ecriture du capteur)..." -ForegroundColor DarkGray
Start-Sleep -Seconds $Attente
$fin = Get-Date

# --- 4. Comptage ----------------------------------------------------------------
$nouveaux = @()
try {
    $nouveaux = @(Get-WinEvent -FilterHashtable @{
                      LogName   = $JournalSysmon
                      StartTime = $debut
                  } -ErrorAction Stop |
                  Where-Object { $_.RecordId -gt $marqueur })
}
catch {
    Write-Warning 'Aucun evenement sur la fenetre.'
}

$parIdentifiant = $nouveaux |
    Group-Object -Property Id |
    Sort-Object -Property Count -Descending |
    Select-Object @{n='Evenement';e={[int]$_.Name}}, Count

Write-Host ''
Write-Host "Evenements produits : $($nouveaux.Count)" -ForegroundColor Green
if ($parIdentifiant) { $parIdentifiant | Format-Table -AutoSize }

# --- 5. Export EVTX -------------------------------------------------------------
# On exporte le journal entier plutot qu'une fenetre : en lab le volume est
# faible, et un filtre XPath mal echappe est une source d'erreur silencieuse.
$cheminEvtx = Join-Path $preuves "$etiquetteFichier.evtx"
& wevtutil epl $JournalSysmon $cheminEvtx /ow:true
if (Test-Path $cheminEvtx) {
    $tailleKo = [math]::Round((Get-Item $cheminEvtx).Length / 1KB)
    Write-Host "EVTX exporte : $cheminEvtx ($tailleKo Ko)" -ForegroundColor Green
}

# --- 6. Analyse -----------------------------------------------------------------
$analyse = $null
try {
    $analyse = & (Join-Path $PSScriptRoot 'Invoke-Analyse.ps1') -Evtx $cheminEvtx -Etiquette $Etiquette
}
catch {
    Write-Warning "Analyse non realisee : $($_.Exception.Message)"
}

# --- 7. Nettoyage optionnel -----------------------------------------------------
if ($Nettoyer -and -not $SansAtomique) {
    Write-Host 'Nettoyage du framework...' -ForegroundColor DarkGray
    Invoke-AtomicTest $Technique -TestNumbers $NumeroTest -Cleanup
}

# --- 8. Rapport -----------------------------------------------------------------
$lignesCompte = if ($parIdentifiant) {
    ($parIdentifiant | ForEach-Object { "| $($_.Evenement) | $($_.Count) |" }) -join "`n"
} else {
    '| — | 0 |'
}

# On prepare les cellules du tableau AVANT le here-string. Une expression
# compliquee a l'interieur d'un here-string, ou l'apostrophe inverse est deja le
# caractere d'echappement, est une source d'erreur silencieuse : le script se
# parse, et c'est le rapport qui sort faux.
$accent = [char]0x60   # apostrophe inverse, pour les extraits de code Markdown

$etatChainsaw   = if ($analyse) { $analyse.Chainsaw } else { 'non execute' }
$etatHayabusa   = if ($analyse) { $analyse.Hayabusa } else { 'non execute' }
$fichierChainsaw = if ($analyse -and $analyse.SortieChainsaw) {
    "$accent$($analyse.SortieChainsaw)$accent"
} else { '—' }
$fichierHayabusa = if ($analyse -and $analyse.SortieHayabusa) {
    "$accent$($analyse.SortieHayabusa)$accent"
} else { '—' }
$cheminEvtxMd   = "$accent$cheminEvtx$accent"
$nettoyageFait  = if ($Nettoyer) { 'oui' } else { 'non' }

$rapport = @"
# Test $Etiquette

| Champ | Valeur |
|---|---|
| Atomique | $detailAtomique |
| Debut | $($debut.ToString('yyyy-MM-dd HH:mm:ss')) |
| Fin | $($fin.ToString('yyyy-MM-dd HH:mm:ss')) |
| Marqueur RecordId | $marqueur |
| Evenements produits | $($nouveaux.Count) |
| EVTX | $cheminEvtxMd |
| Nettoyage lance | $nettoyageFait |

## Evenements par identifiant

| Evenement | Nombre |
|---|---|
$lignesCompte

## Sorties d'analyse

| Outil | Etat | Fichier |
|---|---|---|
| Chainsaw (vos regles) | $etatChainsaw | $fichierChainsaw |
| Hayabusa (second avis) | $etatHayabusa | $fichierHayabusa |

## Verdict

> A completer a la main. Trois issues possibles, et une seule phrase chacune :
>
> - **Regle validee** — la regle a remonte l'evenement attendu, et rien d'autre.
> - **Regle a corriger** — l'evenement est la, la regle ne remonte pas. Le defaut
>   est dans la regle ou dans la couche de traduction (mapping Chainsaw).
> - **Donnee absente** — aucun evenement attendu. Le defaut est dans la
>   configuration Sysmon, pas dans la regle.

**Verdict :**

**Justification :**

**Action :**
"@

$cheminRapport = Join-Path $rapports "$etiquetteFichier.md"
$rapport | Set-Content -Path $cheminRapport -Encoding UTF8
Write-Host ''
Write-Host "Rapport : $cheminRapport" -ForegroundColor Green
Write-Host 'Completez la section Verdict, puis reportez la ligne dans matrice-couverture.md.'
