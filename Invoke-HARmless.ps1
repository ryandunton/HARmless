<#
.SYNOPSIS
    This script removes sensitive data from the headers of a session files like HAR or Fiddler SAZ and saves the
    sanitized file with a new name.
.DESCRIPTION
    This PowerShell script takes a HAR (HTTP Archive) or Fiddler SAZ file as input and removes sensitive data from
    its headers. The script prompts the user to input the file path if it is not provided as a parameter. The headers
    to be redacted are specified in a hashtable. The script then reads the HAR file, removes the sensitive data from 
    the specified headers, and saves the sanitized session file with a new name.
.NOTES
    Version: 20231123.01
    Author: Ryan Dunton https://github.com/ryandunton
.EXAMPLE
    Sanitize HAR
    PS C:\> .\Invoke-HARmless.ps1 -SessionFile HarToSanitize.har -RedactWithWord "REDACTED"

    Sanitize Fiddler SAZ
    PS C:\> .\Invoke-HARmless.ps1 -SessionFile SazToSanitize.saz -RedactWithWord "REDACTED"
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $SessionFile,
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
    function Remove-SensitiveDataFromSaz {
        param (
            [Parameter(Mandatory=$true)]
            [string]
            $SAZFile,
            [Parameter(Mandatory=$true)]
            [hashtable]
            $HeadersToRedact,
            [Parameter()]
            [string]
            $RedactWithWord
        )
        Write-Host "[+] Sanitizing..." -ForegroundColor Green
        Expand-Archive -Path $SAZFile -DestinationPath $($SAZFile.Replace(".saz", "")) -Force
        $Files = Get-ChildItem -Path $($SAZFile.Replace(".saz", "")) -Recurse *.* | Select-String -Pattern $($HeadersToRedact.Keys) | Select Path
        foreach ($File in $Files.Path) {
            $TmpContents = Get-Content -Path $File
            # Use regex to replace the Authorization value with an empty string
            foreach ($HeadersToRedactKey in $HeadersToRedact.Keys) {
                $TmpContents = $TmpContents -Replace "(?<=$($HeadersToRedactKey): )([^`"]*)|(?<=`"$($HeadersToRedactKey)`":`")([^`"]*)", "$RedactWithWord"
            }
            # Write the updated content back to the file
            Set-Content -Path "$($File)" -Value $TmpContents
        }
        Write-Host "[*] Saving sanitized file to $($SAZFile.Replace(".saz", "_sanitized.saz"))" -ForegroundColor Yellow
        Compress-Archive -Path $($SAZFile.Replace(".saz", "")) -DestinationPath $($SAZFile.Replace(".saz", "_sanitized.saz")) -CompressionLevel Optimal -Force
        Write-Host "[-] Removing temp folder and files `'$($SAZFile.Replace('.saz', ''))`'"
        Remove-Item -Path $($SAZFile.Replace(".saz", "")) -Recurse -Force
    }
    Show-Banner
    While (!(Test-Path -Path $SessionFile)) {$SessionFile = $(Write-Host "[*] Please enter the path to the session file to sanitize: " -ForegroundColor Yellow -NoNewline;Read-Host)}
    if ($SessionFile -like "*.har") {
        Write-Host "[+] Processing HAR file..." -ForegroundColor Green
        Write-Host "[-] Location: $SessionFile"
        Write-Host "[-] Redacting headers `'$($HeadersToRedact.Keys -Join(', '))`' with `'$RedactWithWord`'"
        Remove-SensitiveDataFromHar -HARFile $SessionFile -HeadersToRedact $HeadersToRedact -RedactWithWord $RedactWithWord
    } elseif ($SessionFile -like "*.saz") {
        Write-Host "[+] Processing SAZ file..." -ForegroundColor Green
        Write-Host "[-] Location: $SessionFile"
        Write-Host "[-] Redacting headers `'$($HeadersToRedact.Keys -Join(', '))`' with `'$RedactWithWord`'"
        Remove-SensitiveDataFromSaz -SAZFile $SessionFile -HeadersToRedact $HeadersToRedact -RedactWithWord $RedactWithWord
    } else {
        Write-Host "[!] Invalid file type. Please use a HAR or SAZ file." -ForegroundColor Red
    }
}
end {
    Write-host "[+] Done!" -ForegroundColor Green
}