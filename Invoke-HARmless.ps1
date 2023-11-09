<#
.SYNOPSIS
    This script removes sensitive data from the headers of a HAR file and saves the sanitized file with a new name.
.DESCRIPTION
    This PowerShell script takes a HAR (HTTP Archive) file as input and removes sensitive data from its headers. The
    script prompts the user to input the file path if it is not provided as a parameter. The headers to be redacted
    are specified in a hashtable. The script then reads the HAR file, removes the sensitive data from the specified
    headers, and saves the sanitized HAR file with a new name.
.NOTES
    Version: 20231108.01
    Author: Ryan Dunton https://github.com/ryandunton
.EXAMPLE
    Sanitize HAR
    PS C:\> .\Invoke-HARmless.ps1 -FilePath HarToSanitize.har
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $FilePath
)

begin {
    $HeadersToRedact = @{
        "Authorization" = $true
        "Cookie" = $true
    }
    if ($PSVersionTable.PSVersion.Major -lt 6) {Write-Warning "Please use PowerShell v6 or above to avoid HAR formatting issues."}
}

process {
    function Show-Banner {
        $Banner = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(""))
        Write-Host $Banner
    }
    function Remove-SensitiveDataFromHar {
        param (
            [Parameter(Mandatory=$true)]
            [string]
            $FilePath,
            [Parameter(Mandatory=$true)]
            [hashtable]
            $HeadersToRedact
        )
        $HarContents = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        foreach ($HarContent in $HarContents.log.entries) {
            foreach ($Header in $HarContent.request.headers) {
                if ($HeadersToRedact.ContainsKey($Header.name)) {
                    $Header.value = "REDACTED"
                }
            }
        }
        Write-Host "[*] Saving sanitized file to $($FilePath.Replace(".har", "_sanitized.har"))"
        $HarContents | ConvertTo-Json -Depth 100 | Out-File -FilePath $($FilePath.Replace(".har", "_sanitized.har"))
    }
    Show-Banner
    if (!($FilePath)) {$FilePath = Read-Host "[*] Please enter the path to the HAR file to sanitize"}
    Write-Host "[+] Processing HAR file: $FilePath"
    Remove-SensitiveDataFromHar -FilePath $FilePath -HeadersToRedact $HeadersToRedact
}

end {
    Write-host "[+] Done!"
}
