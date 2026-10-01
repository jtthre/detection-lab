<#
.SYNOPSIS
    Vérifie les cinq préalables avant une campagne de tests atomiques.

.DESCRIPTION
    Aucun test ne se lance tant que ce script ne rend pas cinq OK. Un test sur un
    capteur mal configuré produit un résultat faux, et un résultat faux coûte plus
    cher que pas de résultat du tout.

    Le script ne modifie rien. Il constate.

.EXAMPLE
    .\Test-Preconditions.ps1
#>

[CmdletBinding()]
param(
    [string] $JournalSysmon = 'Microsoft-Windows-Sysmon/Operational'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$resultats = [System.Collections.Generic.List[object]]::new()

function Add-Resultat {
    param(
        [string] $Point,
        [bool]   $Ok,
        [string] $Constat
    )
    # Le $( ) autour du if n'est pas decoratif : PowerShell 5.1, celui livre avec
    # Windows 11, refuse une instruction if directement a droite d'une cle de
    # table de hachage. PowerShell 7 l'accepte. Le $( ) fonctionne sur les deux.
    $etat = $(if ($Ok) { 'OK' } else { 'ECHEC' })
    $script:resultats.Add([pscustomobject]@{
        Point   = $Point
        Etat    = $etat
        Constat = $Constat
    })
}

# --- 1. Isolation réseau -------------------------------------------------------
# On teste une destination publique. TcpTestSucceeded doit être False.
# Un True ici signifie que la VM a une route vers l'extérieur : on s'arrête.
try {
    $reseau = Test-NetConnection -ComputerName '8.8.8.8' -Port 53 `
                                 -InformationLevel Quiet -WarningAction SilentlyContinue
    Add-Resultat -Point 'Isolation reseau' -Ok (-not $reseau) `
                 -Constat $(if ($reseau) { 'La VM atteint Internet — NE PAS TESTER' }
                            else         { 'Aucune route sortante' })
}
catch {
    Add-Resultat -Point 'Isolation reseau' -Ok $true -Constat 'Test impossible (pile reseau coupee) — isolation probable'
}

# --- 2. Service Sysmon ---------------------------------------------------------
# Le service installé par winget s'appelle "sysmon" (et non "Sysmon64").
$service = Get-Service -Name 'sysmon' -ErrorAction SilentlyContinue
if (-not $service) { $service = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue }
Add-Resultat -Point 'Service Sysmon' -Ok ($null -ne $service -and $service.Status -eq 'Running') `
             -Constat $(if ($service) { "$($service.Name) : $($service.Status)" } else { 'Service introuvable' })

# --- 3. Journal accessible et alimenté -----------------------------------------
try {
    $dernier = Get-WinEvent -LogName $JournalSysmon -MaxEvents 1 -ErrorAction Stop
    $age = (Get-Date) - $dernier.TimeCreated
    Add-Resultat -Point 'Journal Sysmon' -Ok $true `
                 -Constat ("dernier evenement il y a {0:N0} min (ID {1})" -f $age.TotalMinutes, $dernier.Id)
}
catch {
    Add-Resultat -Point 'Journal Sysmon' -Ok $false -Constat 'Journal illisible ou vide'
}

# --- 4. Les événements dont dépendent les règles sont bien collectés ------------
# Cinq des dix règles reposent sur un événement désactivé par défaut. Si la config
# du module 01 n'est pas chargée, ces identifiants n'apparaîtront jamais.
$attendus = @{
    1  = 'creation de processus'
    3  = 'connexion reseau'
    8  = 'thread distant'
    10 = 'acces processus'
    13 = 'valeur de registre'
}
$vus = @{}
try {
    $recents = Get-WinEvent -LogName $JournalSysmon -MaxEvents 2000 -ErrorAction Stop
    foreach ($e in $recents) { $vus[$e.Id] = $true }
}
catch { }

# L'absence d'un identifiant sur 2000 evenements n'est pas une preuve de mauvaise
# configuration (evenement 8 sur une machine au repos = 0, c'est normal). On le
# signale sans le compter comme un echec.
$manquants = $attendus.Keys | Where-Object { -not $vus.ContainsKey($_) } | Sort-Object
Add-Resultat -Point 'Couverture evenements' -Ok $true `
             -Constat $(if ($manquants) { "non observes sur 2000 evts : $($manquants -join ', ') — a confirmer par le test" }
                        else            { 'les 5 identifiants utiles sont presents' })

# --- 5. Espace disque pour les exports EVTX -------------------------------------
$disque = Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':')) -ErrorAction SilentlyContinue
$libreGo = if ($disque) { [math]::Round($disque.Free / 1GB, 1) } else { 0 }
Add-Resultat -Point 'Espace disque' -Ok ($libreGo -ge 5) -Constat "$libreGo Go libres"

# --- Rendu ----------------------------------------------------------------------
Write-Host ''
$resultats | Format-Table -AutoSize
Write-Host ''

$echecs = @($resultats | Where-Object { $_.Etat -eq 'ECHEC' })
if ($echecs.Count -gt 0) {
    Write-Host "ARRET : $($echecs.Count) prealable(s) non satisfait(s). Ne lancez aucun test." -ForegroundColor Red
    exit 1
}

Write-Host 'Prealables satisfaits. Verifiez encore a la main :' -ForegroundColor Green
Write-Host '  - instantane "VM outillee hors ligne" present dans l hyperviseur'
Write-Host '  - sysmon -c affiche bien les 12 groupes du module 01'
exit 0
