#!/usr/bin/env pwsh
<#
   Copyright 2020 Google LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
#>
Add-Type -TypeDefinition @"
    public enum GoogleOAuthToken {
        Access,
        Refresh,
        Id
    }
"@
$DefaultClientSecret = @"
{
    "installed": {
        "client_id"                   : "32555940559.apps.googleusercontent.com",
        "client_secret"               : "ZmssLNjJy2998hD4CTg2ejr2",
        "project_id"                  : "powershell",
        "auth_uri"                    : "https://accounts.google.com/o/oauth2/auth",
        "token_uri"                   : "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url" : "https://www.googleapis.com/oauth2/v1/certs",
        "redirect_uris"               : [
            "urn:ietf:wg:oauth:2.0:oob",
            "http://localhost"
        ]
    }
}
"@
$BaseScopes = @(
    'https://www.googleapis.com/auth/accounts.reauth',
    'https://www.googleapis.com/auth/userinfo.email'
)
$DefaultScopes = @(
    'https://www.googleapis.com/auth/appengine.admin',
    'https://www.googleapis.com/auth/compute',
    'https://www.googleapis.com/auth/cloud-platform'
) |
Sort-Object

Function ConvertFrom-gOAuthUnixTimestamp {
    Param(
        [Int32]
        $Timestamp,
        [switch]
        $UTC
    )
    $UTC.IsPresent ?
    [System.TimeZone]::CurrentTimeZone.ToUniversalTime([datetime]::UnixEpoch.AddSeconds($Timestamp)) :
    [System.TimeZone]::CurrentTimeZone.ToLocalTime([datetime]::UnixEpoch.AddSeconds($Timestamp))
}
function Get-gOAuthDecodeJwt {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ProjectId,
        [string]
        $Token = ( Get-gOAuthToken -Projectid $Projectid -Token Id -Verbose:$False )
    )
    If ( -not $Token ) {
        throw 'ID token is empty'
    }
    $p = $Token.Split('.')[1].replace('-', '+').replace('_', '/')
    switch ($p.Length % 4) {
        1 { $p = $p.Substring(0, $p.Length - 1) }
        2 { $p = $p + "==" }
        3 { $p = $p + "=" }
    }
    $t = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
    $t.iat = ConvertFrom-gOAuthUnixTimestamp -Timestamp $t.iat
    $t.exp = ConvertFrom-gOAuthUnixTimestamp -Timestamp $t.exp
    If ( $VerbosePreference ) {
        $t | ConvertTo-Json | Write-Verbose -Verbose:$VerbosePreference
    }
    $t
}
Function Get-gOAuthToken {
    [cmdletbinding()]
    Param(
        [string]
        $ProjectId = $(throw [System.ArgumentException]"ProjectId is required"),
        [GoogleOAuthToken]
        $Token,
        [switch]
        $All
    )
    Process {
        $t = If ( $All.IsPresent ) {
            [GoogleOAuthToken]::GetValues([GoogleOAuthToken])
        }
        Else {
            $Token
        }
        $t | % {
            $authorization = switch ($_.ToString()) {
                'Refresh' {
                    Get-gOAuthAuthorization -ProjectId $ProjectId
                }
                Default {
                    Get-gOAuthAuthorizationRefreshed -ProjectId $ProjectId
                }
            }
            If ( $VerbosePreference ) {
                $authorization | ConvertTo-Json -Depth 99 | Write-Verbose -Verbose:$true
            }
            $v = $authorization."$($_)_token"
            if ($VerbosePreference -and $_ -eq [GoogleOAuthToken]::Id ) {
                [void](Get-gOAuthDecodeJwt -ProjectId $ProjectId -Token $v -Verbose)
            }
            $v
        }
    }
}

Function Open-gOAuthUri {
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]] $Uri
    )
    begin {
        $allUris = @()
    }
    process {
        $allUris += switch -regex ($Uri) {
            '^[a-z]+:' { $_ } # protocol scheme present, use as-is
            default { 'http://' + $_ } # default to http://
        }
    }
    end {
        if ($env:OS -eq 'Windows_NT') {
            # use Start-Process
            # Note: Start-Process accepts neither pipeline input nor multiple
            #       paths to start.
            $allUris | ForEach-Object { Start-Process -FilePath $_ }
        }
        elseif ((uname) -eq 'Darwin') {
            # macOS: use native `open` CLI
            open $allUris
        }
        else {
            $b = '/mnt/c/Program Files (x86)/Google/Chrome/Application/chrome.exe'
            If ( Test-Path $b ) {
                $allUris | % { &$b $_ }
            }
            else {
                # Linux: assume that xdg-open is available
                $allUris | Write-Host
                xdg-open $allUris
            }
        }
    }
}
Function Test-gOAuthCommand {
    Param (
        [string]
        $Command
    )
    $beforePreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {
        if (Get-Command $Command) {
            $True
        }
    }
    Catch {
        $False
    }
    Finally {
        $ErrorActionPreference = $beforePreference
    }
}
Function Start-gOAuthApiConsole {
    Open-gOAuthUri -Uri https://console.developers.google.com/
}
Function Set-gOAuthClientSecret {
    [CmdletBinding()]
    param (
        [string[]]
        $Json,
        $ProjectId
    )
    $value = $Json -join ' '
    $value | Write-Verbose -Verbose:$VerbosePreference
    $p = $ProjectId ?? ( $value |
        ConvertFrom-Json | % {
            $_.installed; $_.web
        } |
        Select-Object -First 1 |
        Select-Object -ExpandProperty project_id
    )
    If ( -not $p ) {
        throw 'ProjectId is missing'
    }
    $facility = 'gOAuth-' + $p.ToLowerInvariant()
    Set-gSecret -Facility $facility -Name Client -Value $Value -Verbose:$VerbosePreference
}
function Set-gOAuthClientSecretFromFile {
    [CmdletBinding()]
    param (
        [Parameter(
            Position = 0,
            Mandatory = $True,
            HelpMessage = "Enter file name of downloaded JSON secrets file",
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias("name", "file", "path")]
        [string[]]$PSPath,
        $ProjectId
    )
    Process {
        Set-gOAuthClientSecret -ProjectId $ProjectId -Json (@( Get-Content $PSPath ) -join ' ')
    }
}
Function Get-gOAuthClientSecret {
    [CmdletBinding()]
    param(
        [string]
        $ProjectId
    )
    $value = If ( $ProjectId -and ($ProjectId -ne 'powershell')) {
        Get-gSecret -Facility ( 'gOAuth-' + $ProjectId.ToLowerInvariant() ) -Name Client -Verbose:$VerbosePreference
    }
    Else {
        $DefaultClientSecret
    }
    If ( $Value ) {
        $value | Write-Verbose -Verbose:$VerbosePreference
        $value | ConvertFrom-Json | % { $_.installed; $_.web } | Select-Object -First 1
    }
    Else {
        throw [System.ArgumentException]"Use Set-gOAuthClientSecret to import the credentials downloaded from https://console.developers.google.com/apis/credentials?project=$ProjectId"
    }
}

Function Invoke-gOAuthLogin {
    [cmdletbinding()]
    Param(
        [string]
        $LoginHint = $null,
        $ProjectId = 'powershell',
        [string[]]
        $Scopes = $DefaultScopes,
        [string[]]
        $Base = $BaseScopes
    )
    $i = Get-gOAuthClientSecret -ProjectId $ProjectId -Verbose:$VerbosePreference
    $codeChallenge = [System.Guid]::NewGuid().ToString().Replace('-', '')
    $r = ( $i.redirect_uris ?? $i.javascript_origins ) | Select-Object -First 1
    $requestUri = $i.auth_uri +
    '?redirect_uri=' + [System.Uri]::EscapeDataString($r) +
    '&client_id=' + [System.Uri]::EscapeDataString($i.client_id) +
    '&scope=' + [System.Uri]::EscapeDataString((($Base + $Scopes | Sort-Object) -join ' ')) +
    '&project_id=' + [System.Uri]::EscapeDataString($i.project_id) +
    '&code_challenge=' + [System.Uri]::EscapeDataString($codeChallenge) +
    '&code_challenge_method=plain' +
    '&prompt=select_account' +
    '&response_type=code' +
    '&include_granted_scopes=true' +
    '&access_type=offline'
    if ( $LoginHint ) {
        $requestUri += '&login_hint=' + [System.Uri]::EscapeDataString($LoginHint)
    }
    if ( Test-gOAuthCommand Set-Clipboard ) {
        Set-Clipboard -Value $requestUri
    }
    $requestUri | Write-Verbose -Verbose:$VerbosePreference
    Open-gOAuthUri $requestUri -Verbose:$VerbosePreference
    $Code = Read-Host -Prompt 'Paste the code from the Webpage here, if the browser does not start, uri is on the clipboard!'
    $body = @{
        code          = $Code;
        client_id     = $i.client_id;
        client_secret = $i.client_secret;
        redirect_uri  = $i.redirect_uris[0];
        grant_type    = "authorization_code";
        code_verifier = $codeChallenge;
    };
    Set-gOAuthAuthorization `
        -ProjectId $ProjectId `
        -AuthorizationResponse (Invoke-RestMethod -Uri $i.token_uri -Method POST -Body $body -Verbose:$VerbosePreference)
}
Function Set-gOAuthAuthorization {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]
        $ProjectId,
        $AuthorizationResponse
    )
    $value = $AuthorizationResponse | ConvertTo-Json -Depth 99
    Set-gSecret -Facility ('gOAuth-' + $ProjectId.ToLowerInvariant()) -Name AuthorizationResponse -Value $value -Verbose:$VerbosePreference
    Set-gSecret -Facility ('gOAuth-' + $ProjectId.ToLowerInvariant()) -Name AuthorizationRefreshed -Value $value -Verbose:$VerbosePreference
}
Function Set-gOAuthAuthorizationRefreshed {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]
        $ProjectId,
        $AuthorizationResponse
    )
    $value = $AuthorizationResponse | ConvertTo-Json -Depth 99
    Set-gSecret -Facility ('gOAuth-' + $ProjectId.ToLowerInvariant()) -Name AuthorizationRefreshed -Value $value -Verbose:$VerbosePreference
}
Function Get-gOAuthAuthorization {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]
        $ProjectId
    )
    Get-gSecret -Facility ('gOAuth-' + $ProjectId.ToLowerInvariant()) -Name AuthorizationResponse -Verbose:$VerbosePreference | % {
        If ( [string]::IsNullOrEmpty($_)) {
            throw ('Authorization does not exist, please login with project {0}!' -f $ProjectId)
        }
        $_
    } |
    ConvertFrom-Json -Depth 99
}
Function Get-gOAuthAuthorizationRefreshed {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]
        $ProjectId
    )
    Get-gSecret -Facility ('gOAuth-' + $ProjectId.ToLowerInvariant()) -Name AuthorizationRefreshed -Verbose:$VerbosePreference | % {
        If ( [string]::IsNullOrEmpty($_)) {
            throw ('Authorization does not exist, please login with project {0}!' -f $ProjectId)
        }
        $_
    } |
    ConvertFrom-Json -Depth 99
}
Function Get-gOAuthAccessToken {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]
        $ProjectId,
        [switch]
        $Refresh = (Get-gOAuthDecodeJwt -ProjectId $ProjectId).exp -lt (Get-Date).AddSeconds(300)
    )
    if ( $Refresh.IsPresent ) {
        $client = Get-gOAuthClientSecret -Project $ProjectId -Verbose:$VerbosePreference
        'Refreshing access token for {0}' -f $client.client_id | Write-Verbose -Verbose:$VerbosePreference
        $body = @{
            client_id     = $client.client_id;
            client_secret = $client.client_secret;
            grant_type    = "refresh_token";
            refresh_token = ( Get-gOAuthToken -ProjectId $ProjectId -Token Refresh )
        };
        Set-gOAuthAuthorizationRefreshed `
            -ProjectId $ProjectId `
            -AuthorizationResponse (Invoke-RestMethod -Uri $client.token_uri -Method POST -Body $body -Verbose:$VerbosePreference)
    }
    Get-gOAuthToken -Projectid $ProjectId -Token Access -Verbose:$VerbosePreference
}
Function Get-gOAuthAccessTokenSDK {
    (gcloud auth application-default print-access-token --format json | ConvertFrom-Json).access_token
}
Function Invoke-gOAuthRestMethod {
    [cmdletbinding()]
    Param(
        [string]
        $ProjectId = $(throw [System.ArgumentException]"ProjectId is required"),
        [System.Uri]
        $Uri = $(throw [System.ArgumentException]"Uri is required"),
        $RetryCount = 1,
        $ContentType = 'application/json',
        $Body = $null,
        $Method = $null,
        [switch]
        $UseGoogleCloudSDK
    )
    $AccessToken = $UseGoogleCloudSDK.IsPresent ? (Get-gOAuthAccessTokenSDK) :  (Get-gOAuthAccessToken -ProjectId $ProjectId)
    $m = $Method ?? ( $Body ? 'Post' : 'Get' )
    'Method: {0}' -f $m | Write-Verbose -Verbose:$VerbosePreference
    if ( $Body ) {
        Try {
            $b = ConvertTo-Json -InputObject $Body -Depth 100 -EscapeHandling Default
        }
        catch {
            throw 'Unable to convert body to JSON'
        }
    }
    do {
        $Retry = $false
        try {
            if ( $Body ) {
                If ( $VerbosePreference ) {
                    $b | Write-Verbose -Verbose:$VerbosePreference
                }
                Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken" } -Uri $Uri -Method $m -ContentType $ContentType -Body $b -Verbose:$VerbosePreference
            }
            else {
                Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken" } -Uri $Uri -Method $m -Verbose:$VerbosePreference
            }
        }
        catch [System.Net.WebException], [System.Net.Http.HttpRequestException] {
            $_ | Write-Verbose -Verbose:$VerbosePreference
            if ( $_.Exception.Response.StatusCode -ne 401 ) {
                throw
            }
            $Retry = $RetryCount-- -gt 0
            if (-not $Retry ) {
                throw
            }
            $AccessToken = $UseGoogleCloudSDK.IsPresent ? (Get-gOAuthAccessTokenSDK) :  (Get-gOAuthAccessToken -ProjectId $ProjectId -Refresh)
        }
    } while ( $Retry )
}
Function Invoke-gOAuthRestMethodPaged {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory)]
        [string]
        $ProjectId,
        [Parameter(Mandatory)]
        [System.Uri]
        $Uri,
        $Body = $null,
        $Method = $null,
        $Filter,
        [string]
        $Item = 'items',
        [int]
        $MaxResults = 99,
        [int]
        $RetryCount = 1,
        [string]
        $ContentType = 'application/json',
        [switch]
        $UseGoogleCloudSDK
    )
    Begin {
        $results = @()
        $nextPageToken = $false
    }
    Process {
        do {
            $pagedUri =
            $Uri.AbsoluteUri + ( $Uri.Query ? '&' : '?' ) +
            "maxResults=$maxResults" +
            ($nextPageToken ? ('&pageToken={0}' -f [System.Uri]::EscapeDataString($nextPageToken)) : '') +
            ($Filter ? ('&filter={0}' -f [System.Uri]::EscapeDataString($Filter)) : '')
            $pagedUri | Write-Verbose -Verbose:$VerbosePreference
            $result = Invoke-gOAuthRestMethod `
                -ProjectId $ProjectId `
                -Uri $pagedUri `
                -RetryCount $RetryCount `
                -ContentType $ContentType `
                -Body $Body `
                -Method $Method `
                -UseGoogleCloudSDK:$UseGoogleCloudSDK `
                -Verbose:$VerbosePreference
            If ($VerbosePreference) {
                $result | ConvertTo-Json | Write-Verbose -Verbose:$VerbosePreference
            }
            $results += $result.$Item
            $nextPageToken = $result.nextPageToken
            'nextPageToken: {0}' -f $nextPageToken | Write-Verbose -Verbose:$VerbosePreference
        } while ( $nextPageToken )
    }
    End {
        $results
    }
}

# SIG # Begin signature block
# MIIdEQYJKoZIhvcNAQcCoIIdAjCCHP4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU6Rmn5fzS+2maTefGv6kbJy38
# Fi2gghiiMIIFNTCCAx2gAwIBAgIQT/hgdSzRMK1Ptmol1X/K6zANBgkqhkiG9w0B
# AQsFADAOMQwwCgYDVQQDEwNnb2QwIBcNMTYwOTA4MTUxOTE5WhgPMjA1OTExMDIy
# MjE2MzNaMA4xDDAKBgNVBAMTA2dvZDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAJKirTyUVPFLWIgo8xg/YiWwYZyKxwqJ/TdOI4sX61Xm8gzxxOxPc7H1
# mqIG0ZSZQ6hSWb/JmGBm9BVctD78dDIEMMxkIfhsZQVF3wPLwc150zFpRFXSxnMR
# ivQeULzpS7aNhVhaHxX/H0YSIPUn7MU8vbGQWozheo9gljHTfjcAsHhZ94kuPFI1
# 3p5A5TfQf4AWBb21CSniqoUlfu8iYrUebYQTAvU3Lm55uOy5lVHcwlekFq40plRG
# jIPaoZT97L2LBxu+NaP9or8SXSUhKxhHiVAgYSD2trWVVDMuwsyDRmn61ORtMQDT
# TMZ9W+HoujUiATMxNDhUawlZNM8fn6d5SirqP97jrzUpZKmnKOHzWGbdz6xjDwm8
# eEKXj770zdfOQhuxh1gxfrUzf5Wa/NwV3Sj40pHfRO0dOj3llIMldpIyo5pMb+3W
# yea7FJfBf3KeTf+SQmgS0e1d2OEHKTalkThnUVUpgES2QqmWJ0iL4RgQor7EwajN
# g5qsR1QqQX1Q8A9NycxwA/YxT7pQhropEyhddVEjEWOONL5YLH8/4tN5FgrxOMwE
# u0+q+hCphttRBFAbEjGexhTjENmNMmgTIHb9jCkIFwTkWqUv1/0g8+UzRmC5vWf9
# G9gSmPACzY/ATZRsUA+Z+EQaiCVU5je0ZMOXV4QpZJ8BxDFfjTujAgMBAAGjgYww
# gYkwEwYJKwYBBAGCNxQCBAYeBABDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQF
# MAMBAf8wHQYDVR0OBBYEFOnDw0HoRV9Yspg5xBYu0pfyshkUMBAGCSsGAQQBgjcV
# AQQDAgECMCMGCSsGAQQBgjcVAgQWBBR85TAn1w27aOhVU80oamRgW9vkajANBgkq
# hkiG9w0BAQsFAAOCAgEAPoHPAzHnLZaoQFetJbyK/iZdGCCc8DXGViMbhBsNH6rM
# mk97uunVWQ0JZ/vTbfjYFe9tlDrk6HnYholJG8RqaMHcQEST/0iReP6DFXHIMkVX
# qy/z54EMgk15NIV1qhPCrORQdz+1HauDta/S0rin1K2jndFhSTddtpr3ky1NLr2G
# JPFDP7TZqSsnZCjqoWvp+s2ETtbreg28hh+RF7/lHnesWgMqbhMbBQMeR2D/Q+5B
# L58ul1T6QNWzcrhR7LkI15AYjH8WNot9wBS7HM7cYOwhRN/vj1QdFAqX/6+/cGO7
# RqeELL12SzZibkmDsF2vGKxeANxuRMg/3RxMaBpAdnw4loSFW+lFb1rHHcvl7baM
# D60iW/zNx+6rccVL/Mvclv20FvsrbWq7gTZjjjKLEzmYcCA9260glnQAdh6coZ9d
# RbPmKFmcrHos5n8MSdk2ca/CAKLrKj1b01iYUHVG70/1Yb8tr9OaIB5SLTq23Bqf
# ztcxtKNyqV6Jv0o40kxfTUmGqyWzoBgdEzxhxHUYDTOaSLg/igSGzzOnpjWXMKUU
# DNBL/+cBXbwECtYQwMHS39bjfDrd9q8R3pmu3rAljXOCyVnjUQznecK2hpxThPCy
# EHF2OMTd9Y2X9/DwhIsHt0+F1k1TkiHbpvJeIpiVlR4cDMzHL7ebPbMyKCkrcMIw
# ggYmMIIEDqADAgECAhMiAAADPr7I+iou2FbsAAIAAAM+MA0GCSqGSIb3DQEBCwUA
# MA4xDDAKBgNVBAMTA2dvZDAeFw0xOTEyMjYyMjI5MTRaFw0zOTEyMjEyMjI5MTRa
# MBgxFjAUBgNVBAMTDURhdmlkIEt1YmVsa2EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
# DwAwggEKAoIBAQDClmZJB+vLBNeC9nHtVnNDR0BwPYd4PY+gMAKguycRavMNfsBq
# v0X5nobE/PBH/F5wwHHXYCYw7CqHLd93xLo9xSzxeOMVZvAoxxh3MtLSW6ljLYYw
# 40azaTOd1Geio47FJFIWjNca0hBFBrp/bpNmBUiXjZTXC/fcqGzSMnfB8zhGF1NC
# m9bKwzzhQN39mvHsJCUuw4Y7WSN4eF7445tznnptAIYV91cu4gBHVGHebiNCRA9X
# s9yBPXfA5aDxteAOEdMiALt6T/iEKi5Y/3bcca2MPaoO2N4UBttpaa71QLJuJy8v
# mS7J/x69jPKAy6GxKcyPralTCpYZP+Ny3GQlAgMBAAGjggJxMIICbTA+BgkrBgEE
# AYI3FQcEMTAvBicrBgEEAYI3FQiC69dxgsC2J4GdlwiB9vE6hLrhc4EMgqDXS4ak
# szsCAWUCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwCwYDVR0PBAQDAgeAMBsGCSsG
# AQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFFxbLr96KqbNM28qgUFO
# zlDF6OHoMB8GA1UdIwQYMBaAFOnDw0HoRV9Yspg5xBYu0pfyshkUMIHJBgNVHR8E
# gcEwgb4wgbuggbiggbWGgbJsZGFwOi8vL0NOPWdvZCxDTj1kYzUsQ049Q0RQLENO
# PVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3Vy
# YXRpb24sREM9a2lya2xhbmQsREM9a3ViZWxrYSxEQz1vcmc/Y2VydGlmaWNhdGVS
# ZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBv
# aW50MIHBBggrBgEFBQcBAQSBtDCBsTCBrgYIKwYBBQUHMAKGgaFsZGFwOi8vL0NO
# PWdvZCxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2Vydmlj
# ZXMsQ049Q29uZmlndXJhdGlvbixEQz1raXJrbGFuZCxEQz1rdWJlbGthLERDPW9y
# Zz9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1
# dGhvcml0eTAcBgNVHREEFTATgRFkYXZpZEBrdWJlbGthLmNvbTANBgkqhkiG9w0B
# AQsFAAOCAgEAd3dIoAhEkFVhNMwSOk1ANilSvTAaAX67KPwraPvC7UfNszX7hcRr
# h4I8TsZSvhtPNP6nMobnHyLFdXEJRQzY6i9FEwqdH7V+GhAdSnayuSiJIfYtExgo
# SmNdtyBhka6s8y/4VBaYbhq5bm6YQFMzH+k9+YbnQgENoJ4NumQ2KU/qY/s814G4
# yJ0lO5AlD1PZ/nnYL5JVF3e90LLWbZSYOP7xfKf+CVQpe+FtujS7EDID/s5MP1Pk
# 5geEGT0kOQxbyzjt/vRkm41bvhcQfyxu2mbAjY8MCYJ6EX4ekge2TOBsC3Z+er0i
# rCfKnbfacGNj07AdA8HiV3yLQht7KgU3/hW49J7s3mLbTxZn1Uk5U5CCSJpUw+JV
# wlV2sI/0jTb4ET8h2K3LtF7l+C3brPi/c/c7kd9vlsk3uZtmlRzTi5d/Aj/83+oq
# NVjQUd3TCUFBOXjycK06Ku8e91weLBrHpex1rf09dUE2GbWNlrxRvnUCn6KNg2WW
# EREK089DfGtPF6SAfs2GV1A7UOL3rllNbaIIg/3CUx7Wt7usmCKYnEB/tDorqGZP
# a0A1P2/BT7M4niJogBBB9eMoEtdfsFr26qb8NQR8CA4OKF84ReIjb1AR7yA4HoOU
# Oy5MiYVVVnP0jpneeKeUXNqyMBQ8f9ayz9oHdg5uPyb9IqrllD76PokwggZqMIIF
# UqADAgECAhADAZoCOv9YsWvW1ermF/BmMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMTAeFw0x
# NDEwMjIwMDAwMDBaFw0yNDEwMjIwMDAwMDBaMEcxCzAJBgNVBAYTAlVTMREwDwYD
# VQQKEwhEaWdpQ2VydDElMCMGA1UEAxMcRGlnaUNlcnQgVGltZXN0YW1wIFJlc3Bv
# bmRlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKNkXfx8s+CCNeDg
# 9sYq5kl1O8xu4FOpnx9kWeZ8a39rjJ1V+JLjntVaY1sCSVDZg85vZu7dy4XpX6X5
# 1Id0iEQ7Gcnl9ZGfxhQ5rCTqqEsskYnMXij0ZLZQt/USs3OWCmejvmGfrvP9Enh1
# DqZbFP1FI46GRFV9GIYFjFWHeUhG98oOjafeTl/iqLYtWQJhiGFyGGi5uHzu5uc0
# LzF3gTAfuzYBje8n4/ea8EwxZI3j6/oZh6h+z+yMDDZbesF6uHjHyQYuRhDIjegE
# YNu8c3T6Ttj+qkDxss5wRoPp2kChWTrZFQlXmVYwk/PJYczQCMxr7GJCkawCwO+k
# 8IkRj3cCAwEAAaOCAzUwggMxMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAA
# MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIIBvwYDVR0gBIIBtjCCAbIwggGhBglg
# hkgBhv1sBwEwggGSMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5j
# b20vQ1BTMIIBZAYIKwYBBQUHAgIwggFWHoIBUgBBAG4AeQAgAHUAcwBlACAAbwBm
# ACAAdABoAGkAcwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMAdABp
# AHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAg
# AEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAvAEMAUABTACAAYQBuAGQAIAB0AGgAZQAg
# AFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAg
# AHcAaABpAGMAaAAgAGwAaQBtAGkAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBu
# AGQAIABhAHIAZQAgAGkAbgBjAG8AcgBwAG8AcgBhAHQAZQBkACAAaABlAHIAZQBp
# AG4AIABiAHkAIAByAGUAZgBlAHIAZQBuAGMAZQAuMAsGCWCGSAGG/WwDFTAfBgNV
# HSMEGDAWgBQVABIrE5iymQftHt+ivlcNK2cCzTAdBgNVHQ4EFgQUYVpNJLZJMp1K
# Knkag0v0HonByn0wfQYDVR0fBHYwdDA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEQ0EtMS5jcmwwOKA2oDSGMmh0dHA6Ly9j
# cmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRENBLTEuY3JsMHcGCCsG
# AQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29t
# MEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRBc3N1cmVkSURDQS0xLmNydDANBgkqhkiG9w0BAQUFAAOCAQEAnSV+GzNNsiaB
# XJuGziMgD4CH5Yj//7HUaiwx7ToXGXEXzakbvFoWOQCd42yE5FpA+94GAYw3+pux
# nSR+/iCkV61bt5qwYCbqaVchXTQvH3Gwg5QZBWs1kBCge5fH9j/n4hFBpr1i2fAn
# PTgdKG86Ugnw7HBi02JLsOBzppLA044x2C/jbRcTBu7kA7YUq/OPQ6dxnSHdFMoV
# XZJB2vkPgdGZdA0mxA5/G7X1oPHGdwYoFenYk+VVFvC7Cqsc21xIJ2bIo4sKHOWV
# 2q7ELlmgYd3a822iYemKC23sEhi991VUQAOSK2vCUcIKSK+w1G7g9BQKOhvjjz3K
# r2qNe9zYRDCCBs0wggW1oAMCAQICEAb9+QOWA63qAArrPye7uhswDQYJKoZIhvcN
# AQEFBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJl
# ZCBJRCBSb290IENBMB4XDTA2MTExMDAwMDAwMFoXDTIxMTExMDAwMDAwMFowYjEL
# MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
# LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJRCBDQS0x
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6IItmfnKwkKVpYBzQHDS
# nlZUXKnE0kEGj8kz/E1FkVyBn+0snPgWWd+etSQVwpi5tHdJ3InECtqvy15r7a2w
# cTHrzzpADEZNk+yLejYIA6sMNP4YSYL+x8cxSIB8HqIPkg5QycaH6zY/2DDD/6b3
# +6LNb3Mj/qxWBZDwMiEWicZwiPkFl32jx0PdAug7Pe2xQaPtP77blUjE7h6z8rwM
# K5nQxl0SQoHhg26Ccz8mSxSQrllmCsSNvtLOBq6thG9IhJtPQLnxTPKvmPv2zkBd
# XPao8S+v7Iki8msYZbHBc63X8djPHgp0XEK4aH631XcKJ1Z8D2KkPzIUYJX9BwSi
# CQIDAQABo4IDejCCA3YwDgYDVR0PAQH/BAQDAgGGMDsGA1UdJQQ0MDIGCCsGAQUF
# BwMBBggrBgEFBQcDAgYIKwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDCDCCAdIG
# A1UdIASCAckwggHFMIIBtAYKYIZIAYb9bAABBDCCAaQwOgYIKwYBBQUHAgEWLmh0
# dHA6Ly93d3cuZGlnaWNlcnQuY29tL3NzbC1jcHMtcmVwb3NpdG9yeS5odG0wggFk
# BggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUAIABvAGYAIAB0AGgAaQBz
# ACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQAZQBz
# ACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBD
# AGUAcgB0ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBp
# AG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBo
# ACAAbABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBl
# ACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAg
# AHIAZQBmAGUAcgBlAG4AYwBlAC4wCwYJYIZIAYb9bAMVMBIGA1UdEwEB/wQIMAYB
# Af8CAQAweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5k
# aWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4
# oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJv
# b3RDQS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dEFzc3VyZWRJRFJvb3RDQS5jcmwwHQYDVR0OBBYEFBUAEisTmLKZB+0e36K+Vw0r
# ZwLNMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqGSIb3DQEB
# BQUAA4IBAQBGUD7Jtygkpzgdtlspr1LPUukxR6tWXHvVDQtBs+/sdR90OPKyXGGi
# nJXDUOSCuSPRujqGcq04eKx1XRcXNHJHhZRW0eu7NoR3zCSl8wQZVann4+erYs37
# iy2QwsDStZS9Xk+xBdIOPRqpFFumhjFiqKgz5Js5p8T1zh14dpQlc+Qqq8+cdkvt
# X8JLFuRLcEwAiR78xXm8TBJX/l/hHrwCXaj++wc4Tw3GXZG5D2dFzdaD7eeSDY2x
# aYxP+1ngIw/Sqq4AfO6cQg7PkdcntxbuD8O9fAqg7iwIVYUiuOsYGk38KiGtSTGD
# R5V3cdyxG0tLHBCcdxTBnU8vWpUIKRAmMYID2TCCA9UCAQEwJTAOMQwwCgYDVQQD
# EwNnb2QCEyIAAAM+vsj6Ki7YVuwAAgAAAz4wCQYFKw4DAhoFAKB4MBgGCisGAQQB
# gjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHon3M+L
# lo31bmAJaOvcDa6tRKyRMA0GCSqGSIb3DQEBAQUABIIBABkcnpSCqCLr7Da7gp8y
# KalxsXJJOyXpPcmhqGDndbjv+5Z3mSmwqnALPrF4DTNfb4ITBVKBDwp+27n0/0Wq
# Mh2ssDo0yT+aNrHjivk3GRCFhtNKHNJbOIboxPByO56K4zzF22XrRWub3wrZfc7Z
# wyyfXqsrFIMxdXQnM41gRH5OIlhbyzlLUzunXJDNN6ZAf693ze5RsCTOsVjlqPUF
# VxiSWaPY9036XSfA4qSOPXn47dR9khqRDSNyIqXAxsyRlUbn2WuAtNV8ALC7A4t4
# S/V/SksQ7wnrYWKWA41beGN5QAwrYDOP37xFzScK4gZFaTbw4CyCaxjwlXxFy8qc
# B6ihggIPMIICCwYJKoZIhvcNAQkGMYIB/DCCAfgCAQEwdjBiMQswCQYDVQQGEwJV
# UzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQu
# Y29tMSEwHwYDVQQDExhEaWdpQ2VydCBBc3N1cmVkIElEIENBLTECEAMBmgI6/1ix
# a9bV6uYX8GYwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEw
# HAYJKoZIhvcNAQkFMQ8XDTIwMDYyNjE2MzEwMFowIwYJKoZIhvcNAQkEMRYEFNYD
# pbgDcbusDyAO9YKqM7YJlc01MA0GCSqGSIb3DQEBAQUABIIBAG28ZH6PhmK3bSTP
# lGKy6pCiuwCoqWauuSk9JfxUgCfYoqyWqXrLmgL/gqL0qT9NsRL6uIA+BXaLZFIu
# gTnSrpso1jZUrNsmUZIHCRz3ZLALhrAoXD7R6lQ4SRXc4vm3T8pZLZnfuL169V/u
# VLWfyzmPzpx5K6Pq+qP+f044p+btsnUuPm5qk/ZfTXeP8c0GhOktm+dARMpkIrW5
# wbb2lYZTItp9uFou2RX4jn/SLZCVCEXGomt5OglVTHYGeLCeH9RNvU5HsRHo3vvJ
# wnHPBYEd6iF8IpS0zsQK/qwQiLInfvKyT95Sgk/dqmOdXMVR12buXLZn1K/UJIFJ
# afNzE5c=
# SIG # End signature block
