# Read-only, local watch snapshot for the Windows host runbooks.
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('AD', 'MSSQL', 'Wkst')]
    [string]$Role,
    [string]$OutputDir = (Join-Path $env:LOCALAPPDATA 'CCDC\Reports'),
    [string]$BaselinePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run in an elevated PowerShell window for a complete local snapshot.'
}

$errorsFound = [System.Collections.Generic.List[string]]::new()
function Read-Section {
    param([string]$Name, [scriptblock]$Body)
    try { return @(& $Body) }
    catch {
        $script:errorsFound.Add(('{0}: {1}' -f $Name, $_.Exception.Message))
        return @()
    }
}
function Get-ReadEvents {
    param([hashtable]$Filter, [int]$MaxEvents = 0)
    try {
        if ($MaxEvents -gt 0) { Get-WinEvent -FilterHashtable $Filter -MaxEvents $MaxEvents -ErrorAction Stop }
        else { Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop }
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        throw
    }
}

$serviceNames = switch ($Role) {
    'AD' { @('NTDS', 'DNS', 'WinRM', 'SplunkForwarder') }
    'MSSQL' { @('MSSQLSERVER', 'LanmanServer', 'SplunkForwarder') }
    'Wkst' { @('SplunkForwarder') }
}
$since = (Get-Date).AddMinutes(-20)
$snapshot = [ordered]@{
    schemaVersion = 1
    role = $Role
    host = $env:COMPUTERNAME
    observedUtc = (Get-Date).ToUniversalTime().ToString('o')
    people = Read-Section 'people' {
        $result = & quser 2>&1
        if ($LASTEXITCODE -ne 0) { throw ($result -join ' ') }
        $result
    }
    listeners = Read-Section 'listeners' {
        Get-NetTCPConnection -State Listen | ForEach-Object {
            $processName = try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { '(unavailable)' }
            '{0}:{1} {2}' -f $_.LocalAddress, $_.LocalPort, $processName
        } | Sort-Object -Unique
    }
    outboundWeb = Read-Section 'outboundWeb' {
        Get-NetTCPConnection -State Established -RemotePort 80,443 | ForEach-Object {
            $processName = try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { '(unavailable)' }
            '{0}:{1} {2}' -f $_.RemoteAddress, $_.RemotePort, $processName
        } | Sort-Object -Unique
    }
    administrators = Read-Section 'administrators' {
        if ($Role -eq 'AD') {
            Get-ADGroupMember 'Domain Admins' | Select-Object -ExpandProperty SamAccountName | Sort-Object
        } else {
            Get-LocalGroupMember Administrators | Select-Object -ExpandProperty Name | Sort-Object
        }
    }
    tasks = Read-Section 'tasks' {
        Get-ScheduledTask | Where-Object TaskPath -notlike '\Microsoft\*' |
            ForEach-Object { '{0}{1} [{2}]' -f $_.TaskPath, $_.TaskName, $_.State } | Sort-Object
    }
    firewall = Read-Section 'firewall' {
        Get-NetFirewallProfile | ForEach-Object { '{0}: enabled={1}, inbound={2}' -f $_.Name, $_.Enabled, $_.DefaultInboundAction } | Sort-Object
    }
    defender = Read-Section 'defender' { (Get-MpComputerStatus).RealTimeProtectionEnabled }
    forwarder = Read-Section 'forwarder' {
        $svc = Get-Service SplunkForwarder -ErrorAction Stop
        '{0}: {1}' -f $svc.Name, $svc.Status
    }
    services = Read-Section 'services' {
        foreach ($name in $serviceNames) {
            $svc = Get-Service $name -ErrorAction SilentlyContinue
            if ($null -eq $svc) { '{0}: missing' -f $name }
            else { '{0}: {1}' -f $name, $svc.Status }
        }
    }
    failedLogons20m = Read-Section 'failedLogons20m' {
        $events = @(Get-ReadEvents -Filter @{ LogName = 'Security'; Id = 4625; StartTime = $since } -MaxEvents 10000)
        if ($events.Count -ge 10000) { '>=10000' } else { $events.Count }
    }
    newServices20m = Read-Section 'newServices20m' {
        Get-ReadEvents -Filter @{ LogName = 'System'; Id = 7045; StartTime = $since } -MaxEvents 100 |
            ForEach-Object { '{0:o} {1}' -f $_.TimeCreated, $_.Message } | Sort-Object
    }
    securityLogCleared = Read-Section 'securityLogCleared' {
        Get-ReadEvents -Filter @{ LogName = 'Security'; Id = 1102 } -MaxEvents 1 |
            ForEach-Object { $_.TimeCreated.ToUniversalTime().ToString('o') }
    }
    diskFreeGB = Read-Section 'diskFreeGB' { [Math]::Round((Get-PSDrive C).Free / 1GB, 2) }
}
if ($Role -eq 'AD') {
    $snapshot['recentDomainUsers30m'] = Read-Section 'recentDomainUsers30m' {
        Get-ADUser -Filter * -Properties whenCreated | Where-Object whenCreated -gt (Get-Date).AddMinutes(-30) |
            Select-Object -ExpandProperty SamAccountName | Sort-Object
    }
}
if ($Role -eq 'MSSQL') {
    $snapshot['smbSessions'] = Read-Section 'smbSessions' {
        Get-SmbSession | ForEach-Object { '{0} {1}' -f $_.ClientComputerName, $_.ClientUserName } | Sort-Object
    }
}
$snapshot['errors'] = @($errorsFound)

if (-not (Test-Path -LiteralPath $OutputDir -PathType Container)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
$name = '{0}-{1}-{2}.json' -f $env:COMPUTERNAME, $Role, (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$outputPath = Join-Path $OutputDir $name
if (Test-Path -LiteralPath $outputPath) { throw "Snapshot already exists: $outputPath" }
$snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $outputPath -Encoding utf8 -NoNewline
Write-Output "Snapshot: $outputPath"
Write-Output "Read errors: $($errorsFound.Count). Review every changed line against the $Role runbook Watch table. A difference is a lead, not an incident."

if ($BaselinePath) {
    $baseline = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
    if ($baseline.schemaVersion -ne 1 -or $baseline.role -ne $Role -or $baseline.host -ne $env:COMPUTERNAME) {
        throw 'Baseline host, role or schema differs; comparison refused.'
    }
    foreach ($key in $snapshot.Keys) {
        if ($key -in @('schemaVersion', 'role', 'host', 'observedUtc', 'errors')) { continue }
        $before = @($baseline.$key | ForEach-Object { [string]$_ })
        $after = @($snapshot[$key] | ForEach-Object { [string]$_ })
        $difference = Compare-Object -ReferenceObject $before -DifferenceObject $after
        foreach ($item in $difference) {
            $direction = if ($item.SideIndicator -eq '=>') { 'ADDED' } else { 'REMOVED' }
            Write-Output ('{0} {1}: {2}' -f $key, $direction, $item.InputObject)
        }
    }
}
