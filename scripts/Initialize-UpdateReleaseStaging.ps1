[CmdletBinding()]
param()
$ErrorActionPreference='Stop'

function Initialize-ReleaseStagingDirectory([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\') -or $full.Substring(2).Contains(':')) { throw 'Staging requires a local path without alternate streams.' }
    for ($current=$full; $current; $current=[IO.Path]::GetDirectoryName($current)) {
        if ((Test-Path -LiteralPath $current) -and ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Staging ancestor is a reparse point.'
        }
    }
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $trusted=@($sid.Value,'S-1-5-18','S-1-5-32-544')
    if (!(Test-Path -LiteralPath $full)) {
        # Parent must already exist: the caller owns the private LocalApplicationData/Decian parent.
        if (!(Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($full)) -PathType Container)) { throw 'Staging parent is missing.' }
        $acl=[Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true,$false); $acl.SetOwner($sid)
        foreach ($principal in ($trusted | Select-Object -Unique)) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($principal),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        }
        [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($full),$acl)
    }
    if (!(Test-Path -LiteralPath $full -PathType Container)) { throw 'Staging path is not a directory.' }
    $actual=Get-Acl -LiteralPath $full
    if (!$actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Existing staging ownership/inheritance is unsafe; preserve it for review.' }
    $rules=$actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted) { throw 'Existing staging permits an untrusted principal; no repair performed.' }
    }
    return $full
}

if ($MyInvocation.InvocationName -ne '.') {
    $base=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Decian'
    if (!(Test-Path -LiteralPath $base)) { New-Item -ItemType Directory -Path $base | Out-Null }
    Initialize-ReleaseStagingDirectory (Join-Path $base 'UpdateReleaseCandidates')
}
