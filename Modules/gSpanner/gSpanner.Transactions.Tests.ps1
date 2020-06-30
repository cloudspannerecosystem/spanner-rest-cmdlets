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
Import-Module pester -Version 4.10.1
$scriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleName = (Get-Item $scriptFolder).Name
Import-Module -Force "$scriptFolder\$moduleName.psm1" -Verbose:$VerbosePreferences
$ProjectId = 'kubelka-cloud'
Describe 'Transactions' {
    $database = $null
    BeforeAll {
        $instanceId = 'gspanner-instance-id-' + [System.Guid]::NewGuid().GetHashCode().ToString('x8')
        $databaseId = 'gspanner-database-id-' + [System.Guid]::NewGuid().GetHashCode().ToString('x8')
        $instanceConfig = Get-gSpannerInstanceConfig -ProjectId $ProjectId | ? displayName -eq 'europe-west4'
        $instance = Add-gSpannerInstance -Id $instanceId -Config $instanceConfig
        $database = Add-gSpannerDatabase -Instance $instance -Id $databaseId
        # $instance = @{ name = 'projects/kubelka-cloud/instances/demo' }
        # $database = @{ name = 'projects/kubelka-cloud/instances/demo/databases/db' }
        $testCases = @(
            @{
                Database = $database;
                Instance = $instance
            }
        )
    }
    AfterAll {
        Get-gSpannerSession -Database $database | Remove-gSpannerSession
        Remove-gSpannerInstance -Instance @{ name = (($database.name -split '/' | Select-Object -First 4 ) -join '/') } -Confirm:$false
        Write-Warning 'AfterAll done!'
    }
    It -TestCases $testCases 'Commit read only transaction' {
        Param ( $Database, $Instance )
        $s = New-gSpannerSession -Database $database
        $t = New-gSpannerTransaction -Session $s -TransactionMode readOnly
        { Publish-gSpannerTransaction -Session $s -Transaction $t } | Should Throw
        Remove-gSpannerSession -Session $s
    }
    It -TestCases $testCases 'Test Transaction Options' {
        Param ( $Database, $Instance )
        $t = Get-Date
        $s = $t - ($t.AddSeconds(-3700))
        $rs = '{0}s' -f $s.TotalSeconds
        (Get-gSpannerTransactionOptions).options.readOnly | Should BeOfType PSCustomObject
        (Get-gSpannerTransactionOptions -TransactionMode readWrite ).options.readOnly | Should Be $null
        (Get-gSpannerTransactionOptions -TransactionMode readWrite ).options.readWrite | Should BeOfType PSCustomObject
        (Get-gSpannerTransactionOptions -Strong ).options.readOnly.strong | Should Be $true
        (Get-gSpannerTransactionOptions -ReturnReadTimestamp -Strong ).options.readOnly.returnReadTimestamp | Should Be $true
        (Get-gSpannerTransactionOptions -ReturnReadTimestamp -MinReadTimestamp $t ).options.readOnly.minReadTimestamp | Should Be $t
        (Get-gSpannerTransactionOptions -ReturnReadTimestamp -ReadTimestamp $t ).options.readOnly.readTimestamp | Should Be $t
        (Get-gSpannerTransactionOptions -ReturnReadTimestamp -MaxStaleness $s ).options.readOnly.maxStaleness | Should Be $rs
        (Get-gSpannerTransactionOptions -ReturnReadTimestamp -ExactStaleness $s ).options.readOnly.exactStaleness | Should Be $rs
    }
    It -TestCases $testCases 'Read with Timestamp' {
        Param ( $Database, $Instance )
        class Timestamps { [int]$Number; [datetime]$At }
        $row = [Timestamps]@{ Number = 1; At = (get-date) }
        $row | Add-gSpannerTable -Database $Database | Should BeOfType PSCustomObject
        $s = New-gSpannerSession -Database $Database
        'delete from Timestamps where 1 = 1',
        'select count(*) Count from Timestamps' |
        Invoke-gSpannerSql -Session $s -TransactionMode readWrite -Commit |
        Select-Object -Last 1 |
        Select-Object -ExpandProperty resultSet |
        Select-Object -ExpandProperty Count | Should Be 0
        $r1 = 'select * from Timestamps' | Invoke-gSpannerSql -Session $s -ReturnReadTimestamp -SingleUse
        $tsBefore = $r1.executeSql.metadata.transaction.readTimestamp
        $tBefore = New-gSpannerTransaction -Session $s -TransactionMode readOnly -ReturnReadTimestamp -ReadTimestamp $tsBefore
        $r2 = $row | Add-gSpannerItems -Database $database -SkipSchemaCreation
        $tsAfter = $r2.commit.commitTimestamp
        $tAfter = New-gSpannerTransaction -Session $s -TransactionMode readOnly -ReturnReadTimestamp -ReadTimestamp $tsAfter
        ('select count(*) Count from Timestamps' | Invoke-gSpannerSql -Session $s -Transaction $tBefore ).resultSet.Count | Should Be 0
        ('select count(*) Count from Timestamps' | Invoke-gSpannerSql -Session $s -Transaction $tAfter ).resultSet.Count | Should Be 1
        ('select count(*) Count from Timestamps' | Invoke-gSpannerSql -Session $s -ReadTimestamp $tsAfter.AddTicks(-1) ).resultSet.Count | Should Be 0
        ('select count(*) Count from Timestamps' | Invoke-gSpannerSql -Session $s -MinReadTimestamp $tsAfter.AddTicks(-1) -SingleUse ).resultSet.Count | Should Be 1
        Remove-gSpannerSession -Session $s
        Remove-gSpannerTable -Table @{ name = 'Timestamps'; database = $database } -Confirm:$false | Should BeOfType PSCustomObject
    }
}
# SIG # Begin signature block
# MIIdEQYJKoZIhvcNAQcCoIIdAjCCHP4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxDEmVov7G9lNH18q5GUQnuSV
# XxigghiiMIIFNTCCAx2gAwIBAgIQT/hgdSzRMK1Ptmol1X/K6zANBgkqhkiG9w0B
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFPJQb5Ze
# nmOTgQAVaKC3TnQxvP52MA0GCSqGSIb3DQEBAQUABIIBALSZGR+PnhMVUBLpi9rb
# Yzvk6f8InSlfHP9+F85Y5jyu6LdwUWBs1pfo+r/iJFB2xKf3cJKWSKnp5PvrawBa
# wMEuFpKSeUP/jkapPisIuN5JxMZfWW9jTMDq0bCZAAtw80bBB8hsvmOScxNNNZ+5
# o0h1rP2skWKu1DRKoZsKH83JS1XKMHsvHuRt7HhXGe4mzZkZr2eZ7SZUpWUzyApU
# m5K8O2kMiJ17phqgEV0rgAShdLAfQFkjXcRb1NaCLL0NrLlOkLQaaWKjYzvjZOKW
# /CVnbNUxt/CQTx1dQvBQGrI1iAxtq9nWabf11ptXsNMx4pXVAwfLWRdfdVRMeXWn
# vSGhggIPMIICCwYJKoZIhvcNAQkGMYIB/DCCAfgCAQEwdjBiMQswCQYDVQQGEwJV
# UzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQu
# Y29tMSEwHwYDVQQDExhEaWdpQ2VydCBBc3N1cmVkIElEIENBLTECEAMBmgI6/1ix
# a9bV6uYX8GYwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEw
# HAYJKoZIhvcNAQkFMQ8XDTIwMDYyNDE5NTM1OVowIwYJKoZIhvcNAQkEMRYEFDKz
# Vq+zNrjfQid5PgEQKr7SkfDHMA0GCSqGSIb3DQEBAQUABIIBAExFAyTn7WUGmAVA
# aFOHd4bUoCpbwjfzegtzcj5o5u+kkpigc7CxVBpK20fKqOZlXWlfYDg9/OqGGRAq
# Bci+4sqaulydhzdpygdME01IiEtIYSbI/Dtn7cvhFau6LJj1eYk2WeAUP2Pi6QeK
# uG31fJLU1d289Od7WBbcQCAIXGmzGXxlcngVvjKTZLmOSgwoA6UG6S4ZaymVABzx
# 0askYUhCNpeLKYCf1wCQ6m4w7aPo0R9YrbzLQyd454/qr++yqkUoNuL7xVnC1gbf
# f2YDisfnI6vOjesciuQRP2We+SuJ218ch/pa+SAy70d6E4kuLFTNk0xqhmzt6XOd
# 2Xt3P2Q=
# SIG # End signature block
