# PowerShell script to generate MD5 hashes from email addresses in CSV
param(
    [Parameter(Mandatory=$true)]
    [string]$InputCsvPath,
    
    [Parameter(Mandatory=$false)]
    [string]$EmailColumnName = "email"  # Odoo uses lowercase 'email'
)

# Function to generate MD5 hash
function Get-MD5Hash {
    param([string]$InputString)
    
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $inputBytes = [System.Text.Encoding]::UTF8.GetBytes($InputString.ToLower().Trim())
    $hashBytes = $md5.ComputeHash($inputBytes)
    $md5.Dispose()
    
    # Convert bytes to hex string
    $hashString = [System.BitConverter]::ToString($hashBytes) -replace '-', ''
    return $hashString.ToLower()
}

try {
    # Check if input file exists
    if (-not (Test-Path $InputCsvPath)) {
        Write-Error "Input CSV file not found: $InputCsvPath"
        exit 1
    }

    Write-Host "Reading CSV file: $InputCsvPath"
    
    # Generate output file path in same directory as input
    $inputDirectory = Split-Path -Parent $InputCsvPath
    $inputFileName = [System.IO.Path]::GetFileNameWithoutExtension($InputCsvPath)
    $outputCsvPath = Join-Path $inputDirectory "$inputFileName`_md5_hashes.csv"
    
    # Import CSV file
    $csvData = Import-Csv -Path $InputCsvPath
    
    # Check if email column exists (try common variations)
    $emailColumn = $null
    $possibleColumns = @("email", "Email", "EMAIL", "email_address", "Email Address")
    
    foreach ($col in $possibleColumns) {
        if ($csvData | Get-Member -Name $col -MemberType NoteProperty) {
            $emailColumn = $col
            break
        }
    }
    
    if (-not $emailColumn) {
        Write-Error "Email column not found. Available columns: $($csvData | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)"
        exit 1
    }
    
    Write-Host "Using email column: $emailColumn"
    Write-Host "Processing $($csvData.Count) records..."
    
    # Generate MD5 hashes only
    $md5Hashes = @()
    $csvData | ForEach-Object {
        $email = $_.$emailColumn
        if ([string]::IsNullOrWhiteSpace($email)) {
            # Skip empty emails
        } else {
            $md5Hash = Get-MD5Hash -InputString $email
            $md5Hashes += [PSCustomObject]@{ MD5_Hash = $md5Hash }
        }
    }
    
    # Export MD5 hashes to new CSV
    $md5Hashes | Export-Csv -Path $outputCsvPath -NoTypeInformation
    
    Write-Host "Successfully created MD5 hash file: $outputCsvPath" -ForegroundColor Green
    Write-Host "`nSample MD5 hashes:" -ForegroundColor Yellow
    $md5Hashes | Select-Object -First 5 | Format-Table -AutoSize
    
    Write-Host "`nSummary:" -ForegroundColor Cyan
    $totalRecords = $csvData.Count
    $withEmails = ($csvData | Where-Object { -not [string]::IsNullOrWhiteSpace($_.$emailColumn) }).Count
    $withoutEmails = $totalRecords - $withEmails
    $hashCount = $md5Hashes.Count
    
    Write-Host "  Total input records: $totalRecords"
    Write-Host "  Records with emails: $withEmails"
    Write-Host "  Records without emails: $withoutEmails"
    Write-Host "  MD5 hashes generated: $hashCount"

} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}