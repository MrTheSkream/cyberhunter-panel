# Déploie la version compilée du fork dans la VM de labo.
#   .\lab\deploy.ps1                 -> restaure le checkpoint dockpanel-upstream puis déploie
#   .\lab\deploy.ps1 -NoRestore      -> déploie sur l'état courant de la VM
# Prérequis : binaires dans lab\out (lab/build.sh release) et frontend compilé (panel\frontend\dist).
param([switch] $NoRestore, [string] $Checkpoint = 'dockpanel-upstream', [string] $Vm = 'dockpanel-lab',
      [string] $VmIp = '192.168.250.10')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$key  = "$env:USERPROFILE\.ssh\dockpanel_lab"
$ssh  = @('-i', $key, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new')

foreach ($b in 'dockpanel-agent','dockpanel-api','dockpanel') {
  if (-not (Test-Path "$root\lab\out\$b")) { throw "Binaire manquant : lab\out\$b" }
}
if (-not (Test-Path "$root\panel\frontend\dist\index.html")) { throw "Frontend non compilé (panel\frontend\dist)" }

if (-not $NoRestore) {
  Write-Host "Restauration du checkpoint $Checkpoint..."
  Restore-VMSnapshot -VMName $Vm -Name $Checkpoint -Confirm:$false
  if ((Get-VM $Vm).State -ne 'Running') { Start-VM $Vm }
}
$t = Get-Date
while (-not (Test-NetConnection $VmIp -Port 22 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
  if (((Get-Date) - $t).TotalSeconds -gt 120) { throw "SSH injoignable" }; Start-Sleep 3
}

Write-Host "Copie des binaires et du frontend..."
$tar = Join-Path $env:TEMP 'dp-frontend.tar.gz'
tar -czf $tar -C "$root\panel\frontend\dist" .
scp @ssh "$root\lab\out\dockpanel-agent" "$root\lab\out\dockpanel-api" "$root\lab\out\dockpanel" $tar "lab@${VmIp}:/tmp/"
Remove-Item $tar

$remote = @'
set -e
fe=$(grep -rhoP 'root\s+\K/opt/dockpanel/frontend[^;]*' /etc/nginx/ 2>/dev/null | head -1)
[ -n "$fe" ] || fe=/opt/dockpanel/frontend/dist
sudo systemctl stop dockpanel-api dockpanel-agent
sudo install -m 755 /tmp/dockpanel-agent /usr/local/bin/dockpanel-agent
sudo install -m 755 /tmp/dockpanel-api /usr/local/bin/dockpanel-api
sudo install -m 755 /tmp/dockpanel /usr/local/bin/dockpanel
sudo rm -rf "$fe.new" && sudo mkdir -p "$fe.new" && sudo tar -xzf /tmp/dp-frontend.tar.gz -C "$fe.new"
sudo rm -rf "$fe.old" && sudo mv "$fe" "$fe.old" && sudo mv "$fe.new" "$fe"
sudo systemctl start dockpanel-agent dockpanel-api
for i in $(seq 1 30); do curl -sf http://127.0.0.1:3080/api/health >/dev/null && break; sleep 2; done
echo "frontend=$fe"
for i in $(seq 1 30); do systemctl is-active --quiet dockpanel-agent dockpanel-api && break; sleep 2; done
systemctl is-active dockpanel-agent dockpanel-api
for i in $(seq 1 30); do c=$(curl -s -o /dev/null -w '%{http_code}' -k https://127.0.0.1:8443/); [ "$c" = 200 ] && break; sleep 2; done
echo "panel=$c"
[ "$c" = 200 ]
# (dernière ligne : PowerShell y ajoute un \r)
'@
$OutputEncoding = New-Object System.Text.UTF8Encoding $false   # pas de BOM vers bash
$ErrorActionPreference = 'Continue'                              # stderr distant ≠ échec PowerShell
$remote -replace "`r`n", "`n" | ssh @ssh "lab@$VmIp" "sed '1s/^\xEF\xBB\xBF//' | bash -s"   # PS 5.1 préfixe un BOM malgré $OutputEncoding
if ($LASTEXITCODE -ne 0) { throw "Déploiement distant en échec ($LASTEXITCODE)" }
Write-Host "Déployé en $([int]((Get-Date) - $t).TotalSeconds) s."
