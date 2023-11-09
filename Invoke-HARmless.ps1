<#
.SYNOPSIS
    This script removes sensitive data from the headers of a HAR file and saves the sanitized file with a new name.
.DESCRIPTION
    This PowerShell script takes a HAR (HTTP Archive) file as input and removes sensitive data from its headers. The
    script prompts the user to input the file path if it is not provided as a parameter. The headers to be redacted
    are specified in a hashtable. The script then reads the HAR file, removes the sensitive data from the specified
    headers, and saves the sanitized HAR file with a new name.
.NOTES
    Version: 20231108.02
    Author: Ryan Dunton https://github.com/ryandunton
.EXAMPLE
    Sanitize HAR
    PS C:\> .\Invoke-HARmless.ps1 -HARFile HarToSanitize.har -RedactWithWord "REDACTED"
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $HARFile,
    [Parameter()]
    [string]
    $RedactWithWord = "REDACTED"
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
        Write-Host -ForegroundColor Blue "
        ██╗  ██╗ █████╗ ██████╗ ███╗   ███╗██╗     ███████╗███████╗███████╗
        ██║  ██║██╔══██╗██╔══██╗████╗ ████║██║     ██╔════╝██╔════╝██╔════╝
        ███████║███████║██████╔╝██╔████╔██║██║     █████╗  ███████╗███████╗
        ██╔══██║██╔══██║██╔══██╗██║╚██╔╝██║██║     ██╔══╝  ╚════██║╚════██║
        ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║███████╗███████╗███████║███████║
        ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝"
        Write-Host "             `"Removing bearer tokens and cookies, one byte at a time!`"" -ForegroundColor Red
        Write-Host "                      https://github.com/ryandunton/HARmless
        "
    }
    function Remove-SensitiveDataFromHar {
        param (
            [Parameter(Mandatory=$true)]
            [string]
            $HARFile,
            [Parameter(Mandatory=$true)]
            [hashtable]
            $HeadersToRedact,
            [Parameter()]
            [string]
            $RedactWithWord
        )
        Write-Host "[+] Sanitizing..." -ForegroundColor Green
        $HarContents = Get-Content -Path $HARFile -Raw | ConvertFrom-Json
        foreach ($HarContent in $HarContents.log.entries) {
            foreach ($Header in $HarContent.request.headers) {
                if ($HeadersToRedact.ContainsKey($Header.name)) {
                    $Header.value = "$RedactWithWord"
                    Write-Host "[-] $($Header.name) header in $($HarContent.request.url.split('?')[0])"
                }
            }
        }
        Write-Host "[*] Saving sanitized file to $($HARFile.Replace(".har", "_sanitized.har"))" -ForegroundColor Yellow
        $HarContents | ConvertTo-Json -Depth 100 | Out-File -FilePath $($HARFile.Replace(".har", "_sanitized.har"))
    }
    Show-Banner
    While (!(Test-Path -Path $HARFile)) {$HARFile = $(Write-Host "[*] Please enter the path to the HAR file to sanitize: " -ForegroundColor Yellow -NoNewline;Read-Host)}
    Write-Host "[+] Processing HAR file..." -ForegroundColor Green
    Write-Host "[-] Location: $HARFile"
    Write-Host "[-] Redacting headers `'$($HeadersToRedact.Keys -Join(', '))`' with `'$RedactWithWord`'"
    Remove-SensitiveDataFromHar -HARFile $HARFile -HeadersToRedact $HeadersToRedact -RedactWithWord $RedactWithWord
}

end {
    Write-host "[+] Done!" -ForegroundColor Green
}
