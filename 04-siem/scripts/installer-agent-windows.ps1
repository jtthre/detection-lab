# installer-agent-windows.ps1 - inscrit la VM Windows du lab dans Fleet (module 04, phase 4).
#
# A lancer DANS la VM, PowerShell administrateur :
#   powershell -ExecutionPolicy Bypass -File C:\Lab\agent\installer-agent-windows.ps1
#
# Prerequis dans C:\Lab\agent (recuperes depuis la siem par scp) :
#   elastic-agent-<version>-windows-x86_64.zip et son .sha512
#   fleet-ca.crt               certificat PUBLIC de l'autorite du lab (verifie Fleet Server)
#   jeton-poste-windows.txt    jeton d'inscription de la politique poste-windows (SECRET)
#
# Le jeton est lu dans le fichier, jamais affiche, puis le fichier est supprime quoi qu'il arrive.
# Pas d'option --insecure : l'agent verifie Fleet Server avec fleet-ca.crt.
# Messages sans accents : PowerShell 5.1 lit les scripts UTF-8 sans BOM comme de l'ANSI.

param(
    [string]$Dossier  = 'C:\Lab\agent',
    [string]$Version  = '9.5.5',
    [string]$Fleet    = '192.168.234.20',
    [int]   $Port     = 8220
)

$ErrorActionPreference = 'Stop'
$zip   = Join-Path $Dossier "elastic-agent-$Version-windows-x86_64.zip"
$sha   = "$zip.sha512"
$ca    = Join-Path $Dossier 'fleet-ca.crt'
$jeton = Join-Path $Dossier 'jeton-poste-windows.txt'
$dest  = Join-Path $Dossier "elastic-agent-$Version-windows-x86_64"

# 0. Droits et fichiers
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Lancer PowerShell en administrateur.' }
foreach ($f in $zip, $sha, $ca, $jeton) {
    if (-not (Test-Path $f)) { throw "Fichier manquant : $f" }
}
Write-Host '[OK] Fichiers presents'

# 0 bis. Le fichier a-t-il l'allure d'un jeton ? (base64 de "identifiant:cle")
# Le 26/10, deux collages ont depose autre chose qu'un jeton (121 et 163 octets, espaces) :
# Fleet a repondu "invalid enrollment token". On refuse avant de lancer l'installation.
$brut = (Get-Content $jeton -Raw).Trim()
$forme = $false
if ($brut -match '^[A-Za-z0-9+/]+={0,2}$') {
    try {
        $decode = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($brut))
        $forme = (($decode.ToCharArray() | Where-Object { $_ -eq ':' }).Count -eq 1)
    } catch { $forme = $false }
}
Remove-Variable brut, decode -ErrorAction SilentlyContinue
if (-not $forme) {
    Remove-Item $jeton -Force
    throw 'Le fichier ne ressemble pas a un jeton d inscription (base64 de id:cle). Fichier supprime : recopier le jeton.'
}
Write-Host '[OK] Forme du jeton (base64, un deux-points une fois decode)'

# 1. Integrite de l'archive avant toute execution
$attendu = ((Get-Content $sha -Raw).Trim() -split '\s+')[0].ToLower()
$obtenu  = (Get-FileHash $zip -Algorithm SHA512).Hash.ToLower()
if ($attendu -ne $obtenu) { throw 'Empreinte SHA-512 differente : archive refusee.' }
Write-Host '[OK] Empreinte SHA-512 de l archive'

# 2. Fleet Server joignable
$tcp = Test-NetConnection $Fleet -Port $Port -WarningAction SilentlyContinue
if (-not $tcp.TcpTestSucceeded) { throw "Fleet Server ${Fleet}:$Port injoignable (reseau Host-only ? siem allumee ?)." }
Write-Host "[OK] Fleet Server ${Fleet}:$Port joignable"

# 3. Decompression
if (-not (Test-Path $dest)) { Expand-Archive $zip -DestinationPath $Dossier }
Write-Host '[OK] Archive decompressee'

# 4. Installation et inscription ; le jeton disparait dans tous les cas
$code = 1
$t = (Get-Content $jeton -Raw).Trim()
try {
    & (Join-Path $dest 'elastic-agent.exe') install --force `
        --url="https://${Fleet}:$Port" `
        --enrollment-token=$t `
        --certificate-authorities=$ca
    $code = $LASTEXITCODE
}
finally {
    Remove-Variable t -ErrorAction SilentlyContinue
    Remove-Item $jeton -Force -ErrorAction SilentlyContinue
    Write-Host '[OK] Jeton efface de la VM'
}
if ($code -ne 0) { throw "Installation en echec (code $code)." }

# 5. Etat de l'agent
Write-Host 'Attente du premier rapport a Fleet (30 s)...'
Start-Sleep -Seconds 30
& 'C:\Program Files\Elastic\Agent\elastic-agent.exe' status
Write-Host ''
Write-Host 'A faire ensuite : supprimer le jeton sur la siem (rm ~/agents/jeton-poste-windows.txt)'
Write-Host 'et le revoquer dans Fleet > Jetons d inscription.'
