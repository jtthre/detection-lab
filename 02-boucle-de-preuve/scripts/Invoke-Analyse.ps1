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
#  CHEMINS DE L'OUTILLAGE
#
#  Trois chemins, et c'est tout. Le fichier de mapping de Chainsaw n'est plus
#  code en dur : il est detecte au lancement, parce que son nom change d'une
#  version a l'autre et qu'un mapping errone ne provoque pas d'erreur — il
#  provoque une regle muette, ce qui est bien pire.
# =============================================================================
$CheminHayabusa      = 'C:\Lab\outils\hayabusa\hayabusa.exe'
$CheminChainsaw      = 'C:\Lab\outils\chainsaw\chainsaw.exe'
$ReglesSigma         = 'C:\Lab\detection-lab\01-socle-windows\sigma'
$DossierMappings     = 'C:\Lab\outils\chainsaw\mappings'
# =============================================================================
#
#  Versions validees le 01/10/2026 :
#    Hayabusa 4.1.0 (Suzumushi) — la commande s'appelle "dfir-timeline".
#        Elle s'appelait "csv-timeline" jusqu'en v3. Si une version ulterieure
#        la renomme encore, c'est ICI que ca se corrige.
#    Chainsaw 2.x  — sous-commande "hunt".
#
#  Verification avant une campagne sur une nouvelle version :
#      hayabusa.exe help dfir-timeline
#      chainsaw.exe hunt --help
# =============================================================================
$CommandeHayabusa = 'dfir-timeline'

$racine   = Split-Path -Parent $PSScriptRoot
$rapports = Join-Path $racine 'rapports'
if (-not (Test-Path $rapports)) { New-Item -ItemType Directory -Path $rapports | Out-Null }

if (-not (Test-Path $Evtx)) { throw "EVTX introuvable : $Evtx" }
$Evtx = (Resolve-Path $Evtx).Path

# --- Detection du mapping Chainsaw ---------------------------------------------
# La couche de traduction : elle dit comment les champs Sigma correspondent aux
# champs du journal Windows. Un mapping absent ou inadapte ne leve aucune erreur,
# il rend simplement toutes vos regles muettes. On le resout explicitement, et on
# affiche celui qui a ete retenu — pour qu'il figure dans la trace de la campagne.
$MappingChainsaw = $null
if (Test-Path $DossierMappings) {
    $candidats = @(
        Get-ChildItem -Path $DossierMappings -Filter '*.yml' -ErrorAction SilentlyContinue |
            Sort-Object -Property @{ Expression = {
                # On privilegie le mapping le plus large, celui qui couvre tous
                # les journaux, puis tout mapping dont le nom mentionne sigma.
                if ($_.Name -like 'sigma-event-logs-all*') { 0 }
                elseif ($_.Name -like 'sigma*')            { 1 }
                else                                        { 2 }
            }}, Name
    )
    if ($candidats.Count -gt 0) { $MappingChainsaw = $candidats[0].FullName }
}

$horodatage = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$base       = Join-Path $rapports "${horodatage}_${Etiquette}"

$bilan = [ordered]@{
    Evtx          = $Evtx
    Etiquette     = $Etiquette
    Horodatage    = $horodatage
    MappingUtilise = $MappingChainsaw
    Chainsaw      = 'non execute'
    Hayabusa      = 'non execute'
    SortieChainsaw = $null
    SortieHayabusa = $null
}

# --- Chainsaw : vos règles ------------------------------------------------------
if (-not $MappingChainsaw) {
    # On refuse de lancer Chainsaw sans mapping explicite. Sans lui, l'outil ne
    # remonterait rien et on conclurait a tort que les regles sont mauvaises.
    $bilan.Chainsaw = "ECHEC : aucun mapping trouve dans $DossierMappings"
    Write-Warning $bilan.Chainsaw
}
elseif (-not (Test-Path $ReglesSigma)) {
    $bilan.Chainsaw = "ECHEC : dossier de regles introuvable ($ReglesSigma)"
    Write-Warning $bilan.Chainsaw
}
elseif (Test-Path $CheminChainsaw) {
    Write-Host "[Chainsaw] mapping retenu : $MappingChainsaw" -ForegroundColor DarkGray
    $sortie = "${base}_chainsaw.json"
    Write-Host "[Chainsaw] vos regles Sigma -> $sortie" -ForegroundColor Cyan
    try {
        # Out-Host, et pas Out-Null : on veut voir la progression a l'ecran, mais
        # surtout pas la laisser partir dans le pipeline. Sans cela, la sortie
        # texte de l'outil se melange a l'objet de bilan rendu en fin de script,
        # et le script appelant recoit un tableau au lieu d'un objet.
        & $CheminChainsaw hunt $Evtx `
            --sigma  $ReglesSigma `
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
        # --clobber : sans lui, la deuxieme campagne echoue parce que le fichier
        # de sortie existe deja. --no-wizard : sinon l'outil attend une reponse
        # au clavier et le script reste bloque indefiniment.
        & $CheminHayabusa $CommandeHayabusa --file $Evtx --output $sortie `
            --no-wizard --quiet --clobber | Out-Host

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
