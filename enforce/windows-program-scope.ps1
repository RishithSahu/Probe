param([Parameter(Mandatory=$true)][string]$PolicyFile, [switch]$Install)
$ErrorActionPreference = 'Stop'
if ($Install) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Firewall installation requires an elevated administrator window. Run Start-Process pwsh -Verb RunAs, accept the Windows prompt, then rerun this command in the new window.'
    }
}
$policy = Get-Content -LiteralPath $PolicyFile -Raw | ConvertFrom-Json
$fw = New-Object -ComObject HNetCfg.FwPolicy2
foreach ($profile in @(1,2,4)) {
    if (-not $fw.FirewallEnabled($profile)) { throw "Firewall disabled for profile $profile" }
    if ($fw.LocalPolicyModifyState -ne 0) { throw "Local rules are overridden for the current profile" }
}
if ($Install) {
    foreach ($family in @('v4','v6')) {
        $name = "ProbeScope.$($policy.scope_digest).$family"
        $existing = @($fw.Rules | Where-Object { $_.Name -eq $name -and $_.ApplicationName -eq $policy.program })
        if ($existing.Count -eq 0) {
            $rule = New-Object -ComObject HNetCfg.FWRule
            $rule.Name = $name
            $rule.Description = 'Probe discovery helper: deny destinations outside the recorded scope'
            $rule.ApplicationName = $policy.program
            $rule.Direction = 2
            $rule.Action = 0
            $rule.Protocol = 256
            $rule.Profiles = 7
            $rule.RemoteAddresses = $(if ($family -eq 'v4') { $policy.denied_v4 -join ',' } else { '::/1,8000::/1' })
            $rule.Enabled = $true
            try {
                $fw.Rules.Add($rule)
            } catch {
                throw "Could not register the $family Probe firewall rule (remote addresses: $($rule.RemoteAddresses)): $($_.Exception.Message). The scan remains blocked; rerunning this installer preserves already-installed rules."
            }
        }
    }
}
$rules = @($fw.Rules | Where-Object { $_.Name -like "ProbeScope.$($policy.scope_digest).*" -and $_.ApplicationName -eq $policy.program } | ForEach-Object {
    [pscustomobject]@{name=$_.Name; program=$_.ApplicationName; enabled=$_.Enabled; direction=$_.Direction;
        action=$_.Action; protocol=$_.Protocol; profiles=$_.Profiles; remote=$_.RemoteAddresses;
        service=$_.ServiceName; interfaces=$_.InterfaceTypes; local=$_.LocalAddresses;
        local_ports=$_.LocalPorts; remote_ports=$_.RemotePorts; interface_ids=$_.Interfaces}
})
[pscustomobject]@{scope_digest=$policy.scope_digest; rules=$rules; profiles_enabled=$true} | ConvertTo-Json -Depth 5 -Compress
