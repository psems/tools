
# Align UPNs Between Active Directory and Entra ID

This guide explains how to use the `Align-UPN-With-Entra.ps1` script to ensure on-prem Active Directory user principal names (UPNs) match existing Entra ID (Azure AD) usernames. Correct alignment prevents duplicate accounts when enabling Entra Connect (Azure AD Connect).

## Prerequisites

- Domain-joined Windows Server
- RSAT Active Directory module installed
- Microsoft Graph PowerShell SDK installed (`Install-Module Microsoft.Graph`)
- Permissions:
  - **AD:** read and update user accounts
  - **Entra ID:** Global Reader (to compare) and Global Admin (for sync prep)

## Safety & Filtering

- Only users from the OUs specified in the `-IncludeOUs` parameter are processed.
- Accounts matching patterns in `-ExcludeSamPatterns` (e.g., admin, service, computer accounts) are excluded.
- Always test with a pilot OU and `-WhatIf` mode first.

## Script

**File name suggestion:** `Align-UPN-With-Entra.ps1`

**Key features:**
- Connects to AD and Entra ID
- Compares UPNs
- Displays mismatches
- Filters users by specified OUs and excludes admin/service/system accounts
- Has a `-WhatIf` mode to output ready-to-run commands
- Executes changes with confirmation if not run in `-WhatIf` mode
- Logs all actions, errors, and results to a date/time stamped log file
- Handles errors for permissions and connectivity to AD/Graph
- Checks for required privileges before running
- Verifies AD UPN suffix setup and provides a command to fix if missing

## Usage

### Preview changes (safe mode)

Run with `-WhatIf` to see what would change without applying updates. You can also specify OUs and exclusion patterns:

```powershell
.\Align-UPN-With-Entra.ps1 -DomainSuffix "company.com" -IncludeOUs "OU=Users,DC=company,DC=com" -WhatIf
```

All actions and errors will be logged to a file named like `Prep-EntraConnect-YYYYMMDD-HHMMSS.log` in the script directory.

**Example output:**
```
ADUser   ADUPN              EntraUPN             Status
jdoe     jdoe@corp.local    jdoe@company.com     MISMATCH
asmith   asmith@company.com asmith@company.com   MATCH
Found 1 mismatches needing updates.
WhatIf: Would run => Set-ADUser jdoe -UserPrincipalName jdoe@company.com
```

### Execute changes

Run without `-WhatIf` to apply updates. You will be prompted before each change.

```powershell
.\Align-UPN-With-Entra.ps1 -DomainSuffix "company.com" -IncludeOUs "OU=Users,DC=company,DC=com"
```

**Example prompt:**
```
Update jdoe UPN from 'jdoe@corp.local' to 'jdoe@company.com'? (Y/N)
```
If confirmed:
```
Updated jdoe to jdoe@company.com
```

## Verification & Troubleshooting

- After updates, re-run with `-WhatIf` to confirm no mismatches remain.
- In Entra ID portal, verify:
  - Users show **Source:** Windows Server AD
  - UPN equals the email address (`user@company.com`)
- If the script exits with a warning about the AD UPN suffix, run the following command as a Domain Admin:

```powershell
Set-ADForest -Identity (Get-ADForest) -UPNSuffixes @{Add="company.com"}
```

## Notes

- The script only updates UPNs, not groups or service accounts.
- Only users from the OUs specified in `-IncludeOUs` are processed.
- Accounts matching patterns in `-ExcludeSamPatterns` (e.g., admin, service, computer accounts) are excluded.
- All actions and errors are logged to a date/time stamped log file.
- The script checks for required privileges and will exit with instructions if not run as Domain Admin or Global Admin.
- Test with a pilot OU and `-WhatIf` mode before applying broadly.
- Review and adjust parameters for your environment before running in production.