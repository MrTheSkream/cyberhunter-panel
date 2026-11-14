#Requires -RunAsAdministrator
<#
  Crée le labo de test CyberHunter - Panel sous Hyper-V :
    - commutateur INTERNE "DockPanelLab" (isolé du LAN) + NAT Windows vers Internet
    - hôte = 192.168.250.1, VM = 192.168.250.10 / .11 / .12 (IP statiques posées ensuite via netplan)
    - VM Gen2 "dockpanel-lab" : 4 vCPU, 8 Go RAM fixe, disque 80 Go dynamique, ISO Ubuntu Server 24.04
    - Secure Boot compatible Linux, checkpoints standard, pas de checkpoint automatique

  Usage (PowerShell administrateur) :
    .\New-DockPanelLab.ps1 -IsoPath F:\ISO\ubuntu-24.04.5-live-server-amd64.iso
  Option : -WhatIfOnly pour seulement afficher les vérifications.
#>
param(
    [Parameter(Mandatory)] [string] $IsoPath,
    [string] $VmName     = 'dockpanel-lab',
    [string] $SwitchName = 'DockPanelLab',
    [string] $NatName    = 'DockPanelLabNat',
    [string] $Prefix     = '192.168.250',
    [string] $VmRoot     = 'F:\HyperV',
    [int]    $Cpu        = 4,
    [int64]  $MemoryGB   = 8,
    [int64]  $DiskGB     = 80,
    [switch] $WhatIfOnly
)
$ErrorActionPreference = 'Stop'
$subnet = "$Prefix.0/24"
$hostIp = "$Prefix.1"

if (-not (Test-Path $IsoPath)) { throw "ISO introuvable : $IsoPath" }
if (Get-VM -Name $VmName -ErrorAction SilentlyContinue) { throw "Une VM '$VmName' existe déjà." }

# --- Vérifications NAT / collisions de sous-réseau (Windows n'autorise qu'un seul NetNat) ---
$nats = @(Get-NetNat -ErrorAction SilentlyContinue)
$ourNat = $nats | Where-Object Name -eq $NatName
$otherNat = $nats | Where-Object Name -ne $NatName
if ($otherNat) {
    Write-Warning "NetNat existant(s) : $($otherNat | ForEach-Object { "$($_.Name)=$($_.InternalIPInterfaceAddressPrefix)" })"
    throw "Un autre NetNat existe déjà ; Windows n'en gère qu'un. Arrêt : à décider ensemble (réutiliser son préfixe ou le supprimer)."
}
$clash = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -like "$Prefix.*" -and $_.InterfaceAlias -ne "vEthernet ($SwitchName)" }
if ($clash) { throw "Le sous-réseau $subnet est déjà utilisé sur : $($clash.InterfaceAlias -join ', '). Relancer avec -Prefix autre." }
"OK : pas de NetNat concurrent, $subnet libre."
if ($WhatIfOnly) { return }

# --- Commutateur interne + IP hôte + NAT ---
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
}
$ifIndex = (Get-NetAdapter -Name "vEthernet ($SwitchName)").ifIndex
if (-not (Get-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $hostIp -ErrorAction SilentlyContinue)) {
    New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $hostIp -PrefixLength 24 | Out-Null
}
if (-not $ourNat) { New-NetNat -Name $NatName -InternalIPInterfaceAddressPrefix $subnet | Out-Null }

# --- VM ---
$vmDir = Join-Path $VmRoot $VmName
New-Item -ItemType Directory -Force -Path $vmDir | Out-Null
New-VM -Name $VmName -Generation 2 -MemoryStartupBytes ($MemoryGB * 1GB) -SwitchName $SwitchName `
       -NewVHDPath (Join-Path $vmDir "$VmName.vhdx") -NewVHDSizeBytes ($DiskGB * 1GB) -Path $VmRoot | Out-Null
Set-VM -Name $VmName -ProcessorCount $Cpu -StaticMemory -AutomaticCheckpointsEnabled $false `
       -CheckpointType Standard -AutomaticStopAction ShutDown
Set-VMFirmware -VMName $VmName -SecureBootTemplate MicrosoftUEFICertificateAuthority
Add-VMDvdDrive -VMName $VmName -Path $IsoPath
Set-VMFirmware -VMName $VmName -FirstBootDevice (Get-VMDvdDrive -VMName $VmName)
# MAC statique : l'IP ne bouge pas même si la carte est recréée
Set-VMNetworkAdapter -VMName $VmName -StaticMacAddress '00155DFA0010'

Get-VM -Name $VmName | Format-List Name, State, Generation, ProcessorCount, MemoryStartup, CheckpointType
@"
Labo prêt. Étapes suivantes :
  1. vmconnect localhost $VmName  puis démarrer la VM et installer Ubuntu Server :
     - Réseau : eth0 en MANUEL -> sous-réseau $subnet, adresse $Prefix.10, passerelle $hostIp, DNS 1.1.1.1
     - Cocher « Install OpenSSH server », ne rien importer d'autre (pas de snaps)
     - Utilisateur : au choix (ex. lab)
  2. Après le redémarrage, éjecter l'ISO :  Get-VMDvdDrive -VMName $VmName | Remove-VMDvdDrive
  3. Prévenir Claude : il ajoutera .11/.12, la clé SSH et le premier checkpoint « os-clean ».
"@
