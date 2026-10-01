<#
.SYNOPSIS
    Passe Hayabusa et Chainsaw sur un fichier EVTX et écrit les deux sorties dans rapports\.

.DESCRIPTION
    Deux outils, deux rôles distincts — c'est tout l'intérêt de les lancer ensemble :

      Chainsaw  execute VOS regles Sigma du module 01. C'est votre detection.
                Un test qui ne remonte pas ici est un echec de votre regle.

      Hayabusa  execute SON jeu de regles curate par Yamato Security. C'est un
                second avis. Un test qui remonte chez Hayabusa mais pas chez
                Chainsaw designe un angle mort de vos regles, pas un faux positif.

    La divergence entre les deux est le resultat le plus interessant de la campagne.

.PARAMETER Evtx
    Chemin du fichier EVTX à analyser.

.PARAMETER Etiquette
    Nom court du test, utilisé pour nommer les fichiers de sortie (ex : "01-lsass").

.EXAMPLE
    .\Invoke-Analyse.ps1 -Evtx ..\preuves\2026-09-23_01-lsass.evtx -Etiquette 01-lsass
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Evtx,
    [Parameter(Mandatory)] [string] $Etiquette
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =============================================================================
#  LA SEULE PARTIE DE CE SCRIPT QUI DEPEND DE VOS VERSIONS
#
#  Hayabusa et Chainsaw changent regulierement le nom de leurs options.
#  Avant la premiere campagne, lancez :
#      hayabusa.exe --help
#      chainsaw.exe hunt --help
#  et corrigez les quatre variables ci-dessous si besoin. Ensuite vous n'y
#  touchez plus. Notez la version retenue dans VERSIONS.md.
# =============================================================================
$CheminHayabusa   = 'C:\Lab\outils\hayabusa\hayabusa.exe'
$CheminChainsaw   = 'C:\Lab\outils\chainsaw\chainsaw.exe'
$RegleschainsawSigma = 'C:\Lab\detection-lab\01-socle-windows\sigma'
$MappingChainsaw  = 'C:\Lab\outils\chainsaw\mappings\sigma-event-logs-all.yml'
# =============================================================================

$racine   = Split-Path -Parent $PSScriptRoot
$rapports = Join-Path $racine 'rapports'
if (-not (Test-Path $rapports)) { New-Item -ItemType Directory -Path $rapports | Out-Null }

if (-not (Test-Path $Evtx)) { throw "EVTX introuvable : $Evtx" }
$Evtx = (Resolve-Path $Evtx).Path

$horodatage = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$base       = Join-Path $rapports "${horodatage}_${Etiquette}"

$bilan = [ordered]@{
    Evtx          = $Evtx
    Etiquette     = $Etiquette
    Horodatage    = $horodatage
    Chainsaw      = 'non execute'
    Hayabusa      = 'non execute'
    SortieChainsaw = $null
    SortieHayabusa = $null
}

# --- Chainsaw : vos règles ------------------------------------------------------
if (Test-Path $CheminChainsaw) {
    $sortie = "${base}_chainsaw.json"
    Write-Host "[Chainsaw] vos regles Sigma -> $sortie" -ForegroundColor Cyan
    try {
        # Out-Host, et pas Out-Null : on veut voir la progression a l'ecran, mais
        # surtout pas la laisser partir dans le pipeline. Sans cela, la sortie
        # texte de l'outil se melange a l'objet de bilan rendu en fin de script,
        # et le script appelant recoit un tableau au lieu d'un objet.
        & $CheminChainsaw hunt $Evtx `
            --sigma  $RegleschainsawSigma `
            --mapping $MappingChainsaw `
            --json --output $sortie | Out-Host

        # Une commande native ne leve pas d'exception : un binaire qui echoue
        # rend simplement un code non nul. Sans ce test, l'echec passe inapercu.
        if ($LASTEXITCODE -ne 0) {
            $bilan.Chainsaw = "ECHEC : code de sortie $LASTEXITCODE"
            Write-Warning $bilan.Chainsaw
        }
        else {
            $bilan.Chainsaw       = 'ok'
            $bilan.SortieChainsaw = $sortie
        }
    }
    catch {
        # Une erreur de mapping se manifeste ici, et c'est presque toujours la
        # couche de traduction qui est en cause — pas la regle. Relisez --mapping
        # avant de soupconner le YAML de la regle.
        $bilan.Chainsaw = "ECHEC : $($_.Exception.Message)"
        Write-Warning $bilan.Chainsaw
    }
}
else {
    $bilan.Chainsaw = "binaire absent ($CheminChainsaw)"
    Write-Warning $bilan.Chainsaw
}

# --- Hayabusa : second avis -----------------------------------------------------
if (Test-Path $CheminHayabusa) {
    $sortie = "${base}_hayabusa.csv"
    Write-Host "[Hayabusa] jeu de regles curate -> $sortie" -ForegroundColor Cyan
    try {
        & $CheminHayabusa csv-timeline --file $Evtx --output $sortie `
            --no-wizard --quiet | Out-Host

        if ($LASTEXITCODE -ne 0) {
            $bilan.Hayabusa = "ECHEC : code de sortie $LASTEXITCODE"
            Write-Warning $bilan.Hayabusa
        }
        else {
            $bilan.Hayabusa       = 'ok'
            $bilan.SortieHayabusa = $sortie
        }
    }
    catch {
        $bilan.Hayabusa = "ECHEC : $($_.Exception.Message)"
        Write-Warning $bilan.Hayabusa
    }
}
else {
    $bilan.Hayabusa = "binaire absent ($CheminHayabusa)"
    Write-Warning $bilan.Hayabusa
}

$cheminBilan = "${base}_bilan.json"
$bilan | ConvertTo-Json -Depth 3 | Set-Content -Path $cheminBilan -Encoding UTF8
Write-Host ''
Write-Host "Bilan ecrit : $cheminBilan" -ForegroundColor Green

# Seule sortie pipeline du script : l'objet de bilan.
Write-Output ([pscustomobject]$bilan)
