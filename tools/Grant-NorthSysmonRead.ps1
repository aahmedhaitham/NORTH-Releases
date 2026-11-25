[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$AccountSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
)

$ErrorActionPreference = 'Stop'
$channel = 'Microsoft-Windows-Sysmon/Operational'
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$channel"
$descriptor = (Get-ItemProperty -LiteralPath $registryPath -Name ChannelAccess).ChannelAccess
$security = [Security.AccessControl.RawSecurityDescriptor]::new($descriptor)
$sid = [Security.Principal.SecurityIdentifier]::new($AccountSid)
$acl = $security.DiscretionaryAcl

foreach ($entry in $acl) {
    if (
        $entry -is [Security.AccessControl.CommonAce] -and $entry.SecurityIdentifier -eq $sid -and
        $entry.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and
        ($entry.AccessMask -band 1)
    ) {
        Write-Host 'This account already has an explicit read permission for the Sysmon log.'
        return
    }
}

$read = [Security.AccessControl.CommonAce]::new(
    [Security.AccessControl.AceFlags]::None,
    [Security.AccessControl.AceQualifier]::AccessAllowed,
    1, $sid, $false, $null
)
$index = $acl.Count
for ($i = 0; $i -lt $acl.Count; $i++) {
    if ($acl[$i].IsInherited) { $index = $i; break }
}
$acl.InsertAce($index, $read)
$updated = $security.GetSddlForm([Security.AccessControl.AccessControlSections]::All)

if ($PSCmdlet.ShouldProcess($channel, "Grant read-only log access to $AccountSid")) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open Windows PowerShell as Administrator to apply the channel permission.'
    }
    & wevtutil.exe sl $channel "/ca:$updated"
    if ($LASTEXITCODE -ne 0) { throw 'Windows did not apply the Sysmon channel permission.' }
    Write-Host 'Read-only access added to the Sysmon channel. Retest from normal PowerShell.'
}
