# --- Step 0: Check AD UPN Suffixes ---
$existingSuffixes = (Get-ADForest).UPNSuffixes
if ($existingSuffixes -notcontains $DomainSuffix) {
    Write-Host "WARNING: The domain suffix '$DomainSuffix' is not configured as a UPN suffix in Active Directory." -ForegroundColor Yellow
    Write-Host "To add it, run the following command as a Domain Admin:" -ForegroundColor Cyan
    Write-Host "  Set-ADForest -Identity (Get-ADForest) -UPNSuffixes @{Add='$DomainSuffix'}" -ForegroundColor White
    Write-Host "After adding, re-run this script." -ForegroundColor Yellow
    exit
} else {
    Write-Host "Verified: '$DomainSuffix' is configured as a UPN suffix in Active Directory." -ForegroundColor Green
}
<#
.SYNOPSIS
    Guides the process of aligning on-prem Active Directory UPNs with Entra ID usernames
    to prepare for Azure AD Connect (Entra Connect).

.DESCRIPTION
    - Connects to Entra ID and Active Directory
    - Compares UPNs
    - Shows mismatches
    - Provides a WhatIf mode that outputs ready-to-run scripts
    - If not WhatIf, executes changes after confirmation
#>

param(
    [string]$DomainSuffix,
    [string[]]$IncludeOUs,
    [string[]]$ExcludeSamPatterns = @("admin","svc_","service","krbtgt","$"), # Patterns to exclude (admin, service, computer accounts)
    [switch]$WhatIf
)

# --- Prompt for required parameters if not provided ---
if (-not $DomainSuffix -or $DomainSuffix -eq "") {
    $DomainSuffix = Read-Host "Enter the target domain suffix (e.g., company.com)"
    if (-not $DomainSuffix -or $DomainSuffix -eq "") {
        Write-Error "Domain suffix is required. Exiting."
        exit
    }
}

if (-not $IncludeOUs -or $IncludeOUs.Count -eq 0) {
    $ouInput = Read-Host "Enter one or more OUs to include (comma-separated distinguished names)"
    if (-not $ouInput -or $ouInput -eq "") {
        Write-Error "At least one OU must be provided. Exiting."
        exit
    }
    $IncludeOUs = $ouInput -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
}

function Confirm-Step($Message) {
    $choice = Read-Host "$Message (Y/N)"
    if ($choice -ne "Y") { Write-Host "Skipping..." -ForegroundColor Yellow; return $false }
    return $true
}

# --- Step 1: Load Modules ---
if (-not (Get-Module ActiveDirectory -ListAvailable)) {
    Write-Error "ActiveDirectory module not found. Run on a domain-joined server with RSAT."
    exit
}
if (-not (Get-Module Microsoft.Graph.Users -ListAvailable)) {
    Write-Host "Loading Microsoft Graph PowerShell..."
    try { Import-Module Microsoft.Graph.Users -ErrorAction Stop }
    catch { Write-Error "Please install Microsoft Graph PowerShell: Install-Module Microsoft.Graph" ; exit }
}

# --- Step 2: Connect to Graph ---
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "User.Read.All" | Out-Null


# --- Step 3: Pull AD + Entra ID Users ---
Write-Host "Fetching AD users from specified OUs..." -ForegroundColor Cyan
$ADUsers = @()
foreach ($ou in $IncludeOUs) {
    $ADUsers += Get-ADUser -SearchBase $ou -Filter * -Properties mail, UserPrincipalName, SamAccountName
}

# Exclude admin, service, and system accounts
$FilteredADUsers = $ADUsers | Where-Object {
    $sam = $_.SamAccountName.ToLower()
    ($ExcludeSamPatterns | Where-Object { $sam -like "*$_*" }).Count -eq 0
}

if ($FilteredADUsers.Count -eq 0) {
    Write-Host "No AD users found after filtering. Check your OU and exclusion settings." -ForegroundColor Yellow
    exit
}


Write-Host "Fetching Entra ID users..." -ForegroundColor Cyan
$EntraUsers = Get-MgUser -All -Property UserPrincipalName, Mail

# --- Step 4: Compare Users ---
Write-Host "`nComparing AD vs Entra ID UPNs..." -ForegroundColor Green
$Results = foreach ($ad in $FilteredADUsers) {
    $upn = $ad.UserPrincipalName
    $entra = $EntraUsers | Where-Object { $_.UserPrincipalName -eq $upn -or $_.Mail -eq $upn }
    if ($entra) {
        [PSCustomObject]@{
            ADUser   = $ad.SamAccountName
            ADUPN    = $upn
            EntraUPN = $entra.UserPrincipalName
            Status   = if ($upn -eq $entra.UserPrincipalName) { "MATCH" } else { "MISMATCH" }
        }
    }
    else {
        [PSCustomObject]@{
            ADUser   = $ad.SamAccountName
            ADUPN    = $upn
            EntraUPN = "Not Found"
            Status   = "NO MATCH"
        }
    }
}

$Results | Format-Table -AutoSize


# --- Step 5: Generate/Execute Fix ---
$Mismatches = $Results | Where-Object { $_.Status -ne "MATCH" }

if ($Mismatches.Count -eq 0) {
    Write-Host "`nAll AD UPNs match Entra ID users. You're good to sync!" -ForegroundColor Green
    exit
}

Write-Host "`nFound $($Mismatches.Count) mismatches needing updates." -ForegroundColor Yellow

foreach ($m in $Mismatches) {
    $Sam = $m.ADUser
    $TargetUPN = "$Sam@$DomainSuffix"

    if ($WhatIf) {
        Write-Host "WhatIf: Would run => Set-ADUser $Sam -UserPrincipalName $TargetUPN" -ForegroundColor Cyan
    }
    else {
        if (Confirm-Step "Update $Sam UPN from '$($m.ADUPN)' to '$TargetUPN'?") {
            try {
                Set-ADUser $Sam -UserPrincipalName $TargetUPN
                Write-Host "Updated $Sam to $TargetUPN" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to update $Sam : $_"
            }
        }
    }
}


Write-Host "`nProcess complete. Review mismatches and rerun if needed." -ForegroundColor Green

# --- SAFETY NOTES ---
# This script only processes users from the OUs specified in -IncludeOUs.
# It excludes accounts matching patterns in -ExcludeSamPatterns (e.g., admin, service, computer accounts).
# Review and adjust these parameters for your environment before running in production.
# Always test with a pilot OU and WhatIf mode first!
