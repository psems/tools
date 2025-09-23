# --- Logging Setup ---
$scriptName = $MyInvocation.MyCommand.Name
$logFile = Join-Path $PSScriptRoot ("Prep-EntraConnect-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".log")
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $logFile -Value ("[$timestamp] $Message")
}
Write-Log "Starting $scriptName"

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
        Write-Log "ERROR: Domain suffix not provided. Exiting."
        exit
    }
}

if (-not $IncludeOUs -or $IncludeOUs.Count -eq 0) {
    $ouInput = Read-Host "Enter one or more OUs to include (comma-separated distinguished names)"
    if (-not $ouInput -or $ouInput -eq "") {
        Write-Error "At least one OU must be provided. Exiting."
        Write-Log "ERROR: No OUs provided. Exiting."
        exit
    }
    $IncludeOUs = $ouInput -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
}
Write-Log "DomainSuffix: $DomainSuffix"
Write-Log "IncludeOUs: $($IncludeOUs -join ', ')"

# --- Step 0: Check AD UPN Suffixes ---

$existingSuffixes = (Get-ADForest).UPNSuffixes
Write-Log "Current AD UPN Suffixes: $($existingSuffixes -join ', ')"
if ($existingSuffixes -notcontains $DomainSuffix) {
    $msg = "WARNING: The domain suffix '$DomainSuffix' is not configured as a UPN suffix in Active Directory."
    Write-Host $msg -ForegroundColor Yellow
    Write-Log $msg
    Write-Host "To add it, run the following command as a Domain Admin:" -ForegroundColor Cyan
    Write-Log "Suggest: Set-ADForest -Identity (Get-ADForest) -UPNSuffixes @{Add='$DomainSuffix'}"
    Write-Host "  Set-ADForest -Identity (Get-ADForest) -UPNSuffixes @{Add='$DomainSuffix'}" -ForegroundColor White
    Write-Host "After adding, re-run this script." -ForegroundColor Yellow
    Write-Log "Exiting due to missing UPN suffix."
    exit
} else {
    Write-Host "Verified: '$DomainSuffix' is configured as a UPN suffix in Active Directory." -ForegroundColor Green
    Write-Log "Verified UPN suffix present."
}

function Confirm-Step($Message) {
    $choice = Read-Host "$Message (Y/N)"
    if ($choice -ne "Y") { Write-Host "Skipping..." -ForegroundColor Yellow; return $false }
    return $true
}

# --- Step 1: Load Modules ---

if (-not (Get-Module ActiveDirectory -ListAvailable)) {
    Write-Error "ActiveDirectory module not found. Run on a domain-joined server with RSAT."
    Write-Log "ERROR: ActiveDirectory module not found. Exiting."
    exit
}
if (-not (Get-Module Microsoft.Graph.Users -ListAvailable)) {
    Write-Host "Loading Microsoft Graph PowerShell..."
    Write-Log "Loading Microsoft Graph PowerShell..."
    try { Import-Module Microsoft.Graph.Users -ErrorAction Stop }
    catch {
        Write-Error "Please install Microsoft Graph PowerShell: Install-Module Microsoft.Graph"
        Write-Log "ERROR: Microsoft Graph PowerShell not installed. Exiting."
        exit
    }
}

# --- Step 2: Connect to Graph ---

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Write-Log "Connecting to Microsoft Graph..."
try {
    Connect-MgGraph -Scopes "User.Read.All" | Out-Null
    Write-Log "Connected to Microsoft Graph."
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    Write-Log "ERROR: Failed to connect to Microsoft Graph: $_"
    exit
}


# --- Step 3: Pull AD + Entra ID Users ---

Write-Host "Fetching AD users from specified OUs..." -ForegroundColor Cyan
Write-Log "Fetching AD users from OUs: $($IncludeOUs -join ', ')"
$ADUsers = @()
foreach ($ou in $IncludeOUs) {
    try {
        $ADUsers += Get-ADUser -SearchBase $ou -Filter * -Properties mail, UserPrincipalName, SamAccountName
        Write-Log "Fetched users from $ou: $($ADUsers.Count) total."
    } catch {
        Write-Error "Failed to fetch AD users from $ou: $_"
        Write-Log "ERROR: Failed to fetch AD users from $ou: $_"
    }
}

# Exclude admin, service, and system accounts

$FilteredADUsers = $ADUsers | Where-Object {
    $sam = $_.SamAccountName.ToLower()
    ($ExcludeSamPatterns | Where-Object { $sam -like "*$_*" }).Count -eq 0
}
Write-Log "Filtered AD users: $($FilteredADUsers.Count) remaining after exclusions."
if ($FilteredADUsers.Count -eq 0) {
    Write-Host "No AD users found after filtering. Check your OU and exclusion settings." -ForegroundColor Yellow
    Write-Log "WARNING: No AD users found after filtering. Exiting."
    exit
}



Write-Host "Fetching Entra ID users..." -ForegroundColor Cyan
Write-Log "Fetching Entra ID users..."
try {
    $EntraUsers = Get-MgUser -All -Property UserPrincipalName, Mail
    Write-Log "Fetched $($EntraUsers.Count) Entra ID users."
} catch {
    Write-Error "Failed to fetch Entra ID users: $_"
    Write-Log "ERROR: Failed to fetch Entra ID users: $_"
    exit
}

# --- Step 4: Compare Users ---
Write-Host "`nComparing AD vs Entra ID UPNs..." -ForegroundColor Green
Write-Log "Comparing AD vs Entra ID UPNs..."
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
Write-Log "Comparison results: $($Results.Count) users processed."


# --- Step 5: Generate/Execute Fix ---
$Mismatches = $Results | Where-Object { $_.Status -ne "MATCH" }


if ($Mismatches.Count -eq 0) {
    Write-Host "`nAll AD UPNs match Entra ID users. You're good to sync!" -ForegroundColor Green
    Write-Log "All AD UPNs match Entra ID users. Ready to sync."
    exit
}

Write-Host "`nFound $($Mismatches.Count) mismatches needing updates." -ForegroundColor Yellow
Write-Log "Found $($Mismatches.Count) mismatches needing updates."

foreach ($m in $Mismatches) {
    $Sam = $m.ADUser
    $TargetUPN = "$Sam@$DomainSuffix"

    if ($WhatIf) {
        $msg = "WhatIf: Would run => Set-ADUser $Sam -UserPrincipalName $TargetUPN"
        Write-Host $msg -ForegroundColor Cyan
        Write-Log $msg
    }
    else {
        if (Confirm-Step "Update $Sam UPN from '$($m.ADUPN)' to '$TargetUPN'?") {
            try {
                Set-ADUser $Sam -UserPrincipalName $TargetUPN
                Write-Host "Updated $Sam to $TargetUPN" -ForegroundColor Green
                Write-Log "Updated $Sam to $TargetUPN"
            }
            catch {
                Write-Error "Failed to update $Sam : $_"
                Write-Log "ERROR: Failed to update $Sam : $_"
            }
        } else {
            Write-Log "Skipped update for $Sam."
        }
    }
}



Write-Host "`nProcess complete. Review mismatches and rerun if needed." -ForegroundColor Green
Write-Log "Process complete."

# --- SAFETY NOTES ---
# This script only processes users from the OUs specified in -IncludeOUs.
# It excludes accounts matching patterns in -ExcludeSamPatterns (e.g., admin, service, computer accounts).
# Review and adjust these parameters for your environment before running in production.
# Always test with a pilot OU and WhatIf mode first!
