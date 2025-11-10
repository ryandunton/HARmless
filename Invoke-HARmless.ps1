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

	Version: 20251110.01
    Author: Ryan Dunton https://github.com/ryandunton
    - Fixed SAML/password detection logic
    - Fixed URL redaction to preserve structure
    - Added response header/body redaction
    - Added case-insensitive header matching
    - Expanded sensitive headers and query params
    - Added comprehensive error handling
    - Added UTF-8 encoding support
    - Improved SAZ file redaction
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
        "Set-Cookie" = $true
        "X-Device-Fingerprint" = $true
        "X-API-Key" = $true
        "X-Auth-Token" = $true
        "X-CSRF-Token" = $true
        "X-Session-Token" = $true
        "X-Access-Token" = $true
        "API-Key" = $true
        "APIKey" = $true
        "Proxy-Authorization" = $true
        "WWW-Authenticate" = $true
        "location" = $true
        "fromLoginToken" = $true
        "serviceToken" = $true
        "v-appId" = $true
    }

    # Sensitive query parameters to redact
    $SensitiveQueryParams = @(
        "token", "access_token", "refresh_token", "id_token",
        "api_key", "apikey", "api-key",
        "session", "sessionid", "session_id", "sid",
        "secret", "client_secret",
        "key", "auth", "authorization",
        "password", "passwd", "pwd"
    )

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

        # Add error handling for JSON parsing
        try {
            $HarContents = Get-Content -Path $HARFile -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            Write-Error "Failed to parse HAR file: $_"
            return
        }

        foreach ($HarContent in $HarContents.log.entries) {
            # Redact REQUEST headers (case-insensitive)
            foreach ($Header in $HarContent.request.headers) {
                foreach ($HeaderToRedact in $HeadersToRedact.Keys) {
                    if ($Header.name -ieq $HeaderToRedact) {
                        $Header.value = "$RedactWithWord"
                        Write-Host "[-] Redacted request header '$($Header.name)' in $($HarContent.request.url.split('?')[0])"
                        break
                    }
                }
            }

            # Redact RESPONSE headers (case-insensitive)
            if ($HarContent.response.headers) {
                foreach ($Header in $HarContent.response.headers) {
                    foreach ($HeaderToRedact in $HeadersToRedact.Keys) {
                        if ($Header.name -ieq $HeaderToRedact) {
                            $Header.value = "$RedactWithWord"
                            Write-Host "[-] Redacted response header '$($Header.name)' in $($HarContent.request.url.split('?')[0])"
                            break
                        }
                    }
                }
            }

            # Redact RESPONSE content for sensitive data
            if ($HarContent.response.content -and $HarContent.response.content.text) {
                $responseText = $HarContent.response.content.text
                $foundSensitive = $false

                # Check for tokens in response body
                if ($responseText -match '(access_token|refresh_token|id_token|bearer|session|api_key)') {
                    $foundSensitive = $true
                }

                if ($foundSensitive) {
                    $HarContent.response.content.text = $RedactWithWord
                    Write-Host "[-] Redacted sensitive data in response body of $($HarContent.request.url.split('?')[0])"
                }
            }

            # Redact POST data parameters
            if ($HarContent.request.postData -ne $null) {
                $sensitiveFields = @("SAMLResponse", "SAMLRequest", "SignatureValue", "token", "password", "client_secret", "access_token", "refresh_token")

                # Redact params array
                if ($HarContent.request.postData.params) {
                    foreach ($param in $HarContent.request.postData.params) {
                        if ($sensitiveFields -contains $param.name) {
                            $param.value = $RedactWithWord
                            Write-Host "[-] Redacted '$($param.name)' field in 'postData.params' of $($HarContent.request.url.split('?')[0])"
                        }
                    }
                }

                # Redact postData.text if it contains sensitive fields (FIXED LOGIC)
                if ($HarContent.request.postData.text) {
                    $textRedacted = $false

                    if ($HarContent.request.postData.text -like '*password*') {
                        $HarContent.request.postData.text = $RedactWithWord
                        Write-Host "[-] Redacted 'password' in 'postData.text' of $($HarContent.request.url.split('?')[0])"
                        $textRedacted = $true
                    }

                    if (-not $textRedacted -and ($HarContent.request.postData.text -like '*SAMLResponse*' -or
                        $HarContent.request.postData.text -like '*SAMLRequest*')) {
                        $HarContent.request.postData.text = $RedactWithWord
                        Write-Host "[-] Redacted SAML data in 'postData.text' of $($HarContent.request.url.split('?')[0])"
                        $textRedacted = $true
                    }

                    if (-not $textRedacted -and ($HarContent.request.postData.text -match '(token|access_token|refresh_token|client_secret|api_key)')) {
                        $HarContent.request.postData.text = $RedactWithWord
                        Write-Host "[-] Redacted sensitive tokens in 'postData.text' of $($HarContent.request.url.split('?')[0])"
                    }
                }
            }

            # Redact sensitive query parameters while preserving URL structure (FIXED)
            foreach ($param in $SensitiveQueryParams) {
                if ($HarContent.request.url -match "$param=") {
                    $originalUrl = $HarContent.request.url.split('?')[0]
                    $HarContent.request.url = $HarContent.request.url -replace "($param=)[^&\s]*", "`$1$RedactWithWord"
                    Write-Host "[-] Redacted '$param=' parameter in URL of $originalUrl"
                }
            }
        }

        Write-Host "[*] Saving sanitized file to $($HARFile.Replace(".har", "_sanitized.har"))" -ForegroundColor Yellow

        try {
            $HarContents | ConvertTo-Json -Depth 100 | Out-File -FilePath $($HARFile.Replace(".har", "_sanitized.har")) -Encoding UTF8
        } catch {
            Write-Error "Failed to save sanitized HAR file: $_"
            return
        }
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

        $extractPath = $SAZFile.Replace(".saz", "")

        try {
            Expand-Archive -Path $SAZFile -DestinationPath $extractPath -Force
        } catch {
            Write-Error "Failed to extract SAZ file: $_"
            return
        }

        # Get all files in the extracted directory
        $AllFiles = Get-ChildItem -Path $extractPath -Recurse -File

        foreach ($File in $AllFiles) {
            try {
                $TmpContents = Get-Content -Path $File.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                if (-not $TmpContents) { continue }

                $modified = $false

                # Redact headers (case-insensitive)
                foreach ($HeadersToRedactKey in $HeadersToRedact.Keys) {
                    # Match both raw header format and JSON format
                    $pattern = "(?i)(?<=$($HeadersToRedactKey): )([^`r`n]*)|(?<=`"$($HeadersToRedactKey)`":`")([^`"]*)"
                    if ($TmpContents -match $pattern) {
                        $TmpContents = $TmpContents -Replace $pattern, "$RedactWithWord"
                        $modified = $true
                        Write-Host "[-] Redacted header '$HeadersToRedactKey' in $($File.Name)"
                    }
                }

                # Redact sensitive query parameters in URLs
                foreach ($param in $SensitiveQueryParams) {
                    if ($TmpContents -match "$param=") {
                        $TmpContents = $TmpContents -replace "(?i)($param=)[^&\s`"']*", "`$1$RedactWithWord"
                        $modified = $true
                        Write-Host "[-] Redacted '$param=' parameter in $($File.Name)"
                    }
                }

                # Redact POST data fields (for both form-encoded and JSON)
                $sensitiveFields = @("SAMLResponse", "SAMLRequest", "SignatureValue", "token", "password", "client_secret", "access_token", "refresh_token")
                foreach ($field in $sensitiveFields) {
                    # Form-encoded format: field=value
                    if ($TmpContents -match "$field=") {
                        $TmpContents = $TmpContents -replace "($field=)[^&\s]*", "`$1$RedactWithWord"
                        $modified = $true
                        Write-Host "[-] Redacted '$field=' field in $($File.Name)"
                    }

                    # JSON format: "field":"value" or "field": "value"
                    if ($TmpContents -match "`"$field`"") {
                        $TmpContents = $TmpContents -replace "(`"$field`"\s*:\s*`")([^`"]*)", "`$1$RedactWithWord"
                        $modified = $true
                        Write-Host "[-] Redacted JSON field '$field' in $($File.Name)"
                    }
                }

                # Write the updated content back to the file if modified
                if ($modified) {
                    Set-Content -Path $File.FullName -Value $TmpContents -Encoding UTF8
                }

            } catch {
                Write-Warning "Failed to process file $($File.FullName): $_"
                continue
            }
        }

        Write-Host "[*] Saving sanitized file to $($SAZFile.Replace(".saz", "_sanitized.saz"))" -ForegroundColor Yellow

        try {
            Compress-Archive -Path $extractPath -DestinationPath $($SAZFile.Replace(".saz", "_sanitized.saz")) -CompressionLevel Optimal -Force
        } catch {
            Write-Error "Failed to compress sanitized SAZ file: $_"
        }

        Write-Host "[-] Removing temp folder and files `'$extractPath`'"
        try {
            Remove-Item -Path $extractPath -Recurse -Force
        } catch {
            Write-Warning "Failed to remove temporary files: $_"
        }
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
