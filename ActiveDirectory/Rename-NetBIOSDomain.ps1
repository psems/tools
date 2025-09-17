<#
.SYNOPSIS
    Assist with NetBIOS domain rename workflow and verification.

.DESCRIPTION
    Modes:
      - Prep     : Prints an in-depth pre-change verification guide and then runs the rendom preparatory commands.
                   Optionally run automated prechecks with -RunPreChecks.
      - Rename   : Prints Important Notes followed by the exact commands to run during the rename window.
      - Finalize : Prints final cleanup commands and a detailed post-rename verification guide.

.PARAMETER OldNB
    Current NetBIOS name of the domain.

.PARAMETER NewNB
    Desired new NetBIOS name.

.PARAMETER Mode
    One of "Prep","Rename","Finalize"

.PARAMETER RunPreChecks
    If supplied with Prep mode, runs a limited set of non-destructive prechecks automatically.

.PARAMETER AutoProceed
    If supplied with Prep mode, will proceed to run the rendom prepare steps without an interactive Y/N prompt.

.PARAMETER SampleComputersFile
    Optional path to a text file containing computer names (one per line).
    If supplied, verification snippets will only run against these machines instead of sampling the whole domain/OU.

.PARAMETER OU
    Optional distinguishedName of an OU (e.g. "OU=Servers,DC=company,DC=local").
    If provided, verification snippets will query AD for computer objects in this OU.
    Requires RSAT ActiveDirectory module.

.NOTES
    IMPORTANT RECOMMENDATIONS:
    * The verification snippets query Security/System event logs remotely — they require admin rights and WinRM / remote event access.
      If your environment blocks remote event queries, run the snippets on sample machines locally or push a script via SCCM, Intune, PDQ, etc.

    * Use the -RunPreChecks switch only on a machine where you have the necessary privileges and RSAT installed.
      It runs non-destructive checks (dcdiag/repadmin + event-query counts on DCs and a small sample of clients).

    * Always run everything first in a lab that mimics production.
      These verification scripts are examples — modify the sampling size, OU scope, and time windows to suit your estate.
#>

param(
    [Parameter(Mandatory=$true)][string]$OldNB,
    [Parameter(Mandatory=$true)][string]$NewNB,
    [Parameter(Mandatory=$true)]
    [ValidateSet("Prep","Rename","Finalize")]
    [string]$Mode,
    [switch]$RunPreChecks,
    [switch]$AutoProceed,
    [string]$SampleComputersFile,
    [string]$OU
)

# --------------------------------------------------
# Helper functions
# --------------------------------------------------

function Print-ImportantNotes {
    Write-Host ""
    Write-Host "=== IMPORTANT RECOMMENDATIONS ===" -ForegroundColor Yellow
    Write-Host "* The verification snippets query Security/System event logs remotely — they require admin rights and WinRM / remote event access." -ForegroundColor White
    Write-Host "  If blocked, run snippets locally or push via SCCM/Intune/PDQ." -ForegroundColor White
    Write-Host ""
    Write-Host "* Use the -RunPreChecks switch only where RSAT + admin privileges exist." -ForegroundColor White
    Write-Host "  Runs non-destructive checks on DCs and sample clients." -ForegroundColor White
    Write-Host ""
    Write-Host "* Always test first in a lab. Verification snippets are examples — adjust OU scope, sampling, and time windows." -ForegroundColor White
    Write-Host "==================================================================" -ForegroundColor Yellow
}

function Get-SampleComputers {
    param([string]$File,[string]$OU)
    $computers = @()

    # From file
    if ($File -and (Test-Path $File)) {
        $computers += Get-Content $File | Where-Object {$_ -and $_.Trim() -ne ""}
    }

    # From OU
    if ($OU) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $ouComputers = Get-ADComputer -SearchBase $OU -Filter * | Select-Object -Expand Name
            $computers += $ouComputers
        } catch {
            Write-Host "Failed to query OU $OU : $_" -ForegroundColor Red
        }
    }

    # Deduplicate + sort
    $computers = $computers | ForEach-Object { $_.Trim() } | Where-Object {$_ -ne ""} | Sort-Object -Unique
    return $computers
}

function Edit-DomainListXml {
    param(
        [string]$XmlPath,
        [string]$OldNB,
        [string]$NewNB
    )

    if (-not (Test-Path $XmlPath)) {
        throw "Domainlist.xml not found at $XmlPath"
    }

    [xml]$xml = Get-Content $XmlPath -Raw
    $changed = $false

    foreach ($domain in $xml.Forest.Domain) {
        if ($domain.NetBiosName -eq $OldNB) {
            Write-Host "Updating NetBIOS for domain '$($domain.DNSname)': $OldNB -> $NewNB"
            $domain.NetBiosName = $NewNB
            $changed = $true
        }
    }

    if (-not $changed) {
        Write-Warning "No domain entry with NetBIOS '$OldNB' was found in $XmlPath. Please inspect Domainlist.xml manually."
    }
    $xml.Save($XmlPath)
}

function Print-PrecheckGuide {
    Write-Host ""
    Write-Host "=== PRE-CHANGE VERIFICATION GUIDE ===" -ForegroundColor Yellow
    @"
Goal: confirm forest & authentication are healthy BEFORE you change NetBIOS. Follow these steps (examples provided).
Notes:
 - Many commands require (a) the ActiveDirectory PowerShell module (RSAT) and (b) admin credentials.
 - Remote event queries require WinRM / remote event permissions and may be slow for large estates.
"@ | ForEach-Object { Write-Host $_ }

    Write-Host ""
    Write-Host "Step 1 — Basic AD & DC health checks:" -ForegroundColor Cyan
    Write-Host "  - netdom query fsmo"
    Write-Host "  - Get-ADForest | Select ForestMode,DomainMode,Domains"
    Write-Host "  - repadmin /replsummary"
    Write-Host "  - dcdiag /v"

    Write-Host ""
    Write-Host "Step 2 — Verify DC Kerberos activity (Event ID 4768) sample:" -ForegroundColor Cyan
    Write-Host "  Use Get-SampleComputersFile or -OU to limit scope."

    Write-Host ""
    Write-Host "Step 3 — Verify client authentication & reboot events (IDs 4624, 6005) sample:" -ForegroundColor Cyan
    Write-Host "  Use Get-SampleComputersFile or -OU to limit scope."
    Write-Host "  See provided PowerShell examples in script for implementation."

    Write-Host ""
    Write-Host "Step 4 — Test secure channel and GPO application on sample clients:" -ForegroundColor Cyan
    Write-Host "  - Test-ComputerSecureChannel -Verbose"
    Write-Host "  - gpupdate /force"
    Write-Host "  - gpresult /R"

    Write-Host ""
    Write-Host "Step 5 — Functional tests:" -ForegroundColor Cyan
    Write-Host "  - Logon as test users to sample clients"
    Write-Host "  - Access AD-authenticated resources (shares, apps)"
    Write-Host "  - Run 'klist' to verify Kerberos tickets"
}

function Invoke-PreChecks {
    Write-Host "`n--- Automated Pre-Checks ---" -ForegroundColor Cyan
    Write-Host "Running: dcdiag /v" -ForegroundColor Green
    dcdiag /v | Out-File .\dcdiag_output.txt

    Write-Host "Running: repadmin /replsummary" -ForegroundColor Green
    repadmin /replsummary | Out-File .\repadmin_output.txt

    $computers = Get-SampleComputers -File $SampleComputersFile -OU $OU
    if ($computers.Count -eq 0) {
        Write-Host "No SampleComputersFile or OU provided. Skipping client log sampling." -ForegroundColor Yellow
    } else {
        foreach ($c in $computers) {
            Write-Host "Querying $c for logon/auth events..." -ForegroundColor Green
            try {
                Get-WinEvent -ComputerName $c -FilterHashtable @{
                    LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-1)
                } -MaxEvents 10 | Out-File ".\${c}_auth.txt"
            } catch {
                Write-Host "Failed to query $c : $_" -ForegroundColor Red
            }
        }
    }
}

function Print-FinalizeGuide {
    Write-Host ""
    Write-Host "=== POST-RENAME FINAL VERIFICATION GUIDE ===" -ForegroundColor Yellow
    Write-Host "Verify clients & servers have rebooted at least twice since rename and authentication works."
    Write-Host "Use -SampleComputersFile or -OU to limit scope for large estates."
}

# --------------------------------------------------
# Modes
# --------------------------------------------------

if ($Mode -eq "Prep") {
    Write-Host "=== PREP MODE ===" -ForegroundColor Cyan
    Print-ImportantNotes
    Print-PrecheckGuide
    if ($RunPreChecks) { Invoke-PreChecks }

    if (-not $AutoProceed) {
        $answer = Read-Host "Proceed with rendom preparatory commands now? [y/N]"
        if ($answer.ToLower() -ne 'y') {
            Write-Host "Aborting Prep per user input." -ForegroundColor Yellow
            exit 0
        }
    }

    Write-Host "`n1) Generating Domainlist.xml (rendom /list)..."
    rendom /list

    $xmlPath = Join-Path (Get-Location) "Domainlist.xml"
    if (-not (Test-Path $xmlPath)) { throw "Domainlist.xml not found after rendom /list." }

    Edit-DomainListXml -XmlPath $xmlPath -OldNB $OldNB -NewNB $NewNB

    Write-Host "`n2) Previewing planned forest rename (rendom /showforest)..."
    rendom /showforest

    Write-Host "`n3) Uploading rename instructions (rendom /upload)..."
    rendom /upload

    Write-Host "`n4) Preparing DCs (rendom /prepare)..."
    rendom /prepare

    Write-Host "`nPrep complete. Verify DC readiness and backups before proceeding." -ForegroundColor Yellow
}

elseif ($Mode -eq "Rename") {
    Write-Host "=== RENAME MODE ===" -ForegroundColor Cyan
    Print-ImportantNotes
    Write-Host "`n--- Commands to Run ---" -ForegroundColor Cyan
    Write-Host "rendom /list"
    Write-Host "rendom /upload"
    Write-Host "rendom /prepare"
    Write-Host "rendom /execute"
    Write-Host "`nAfter execution, reboot all clients and servers at least twice, then run this script in Finalize mode." -ForegroundColor Yellow
}

elseif ($Mode -eq "Finalize") {
    Write-Host "=== FINALIZE MODE ===" -ForegroundColor Cyan
    Print-ImportantNotes
    Print-FinalizeGuide
    Write-Host "`nFinal cleanup commands (Control Station):" -ForegroundColor Green
    Write-Host "rendom /clean"
    Write-Host "rendom /end"
}
