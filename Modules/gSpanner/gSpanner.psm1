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

Demo:
    $p = '<your projectid>'
    $ic = Get-gSpannerInstanceConfig -ProjectId $p | ? name -like *regional-europe-west4
    $i = Add-gSpannerInstance -Id spanner -Config $ic
    $db = Add-gSpannerDatabase -Instance $i -Id db
    Get-Process | Add-gSpannerItems -Database $db
    Get-gSpannerSchema -Database $db
    $s = New-gSpannerSession -Database $db
    Invoke-gSpannerSql -Session $s -SingleUse -Sql 'select * from System_Diagnostics_Process' |
        Select-Object -Expand resultSet | Out-GridView
    Invoke-gSpannerSql -Session $s -SingleUse -Sql "select processname from System_Diagnostics_Process where workingset > $(200mb)" |
        Select-Object -Expand resuktSet | Export-Csv t.csv
    Remove-gSpannerInstance -Instance $i

#>
Function Set-gSpannerAliases {
    Set-Alias -Scope Global -Force -Name asdb -Value Add-gSpannerDatabase
    Set-Alias -Scope Global -Force -Name asi  -Value Add-gSpannerItems
    Set-Alias -Scope Global -Force -Name ast  -Value Add-gSpannerTable
    Set-Alias -Scope Global -Force -Name gsdb -Value Get-gSpannerDatabase
    Set-Alias -Scope Global -Force -Name gsdo -Value Get-gSpannerDatabaseOperation
    Set-Alias -Scope Global -Force -Name gsi  -Value Get-gSpannerInstance
    Set-Alias -Scope Global -Force -Name gsic -Value Get-gSpannerInstanceConfig
    Set-Alias -Scope Global -Force -Name gsio -Value Get-gSpannerInstanceOperation
    Set-Alias -Scope Global -Force -Name gss  -Value Get-gSpannerSession
    Set-Alias -Scope Global -Force -Name gssc -Value Get-gSpannerSchema
    Set-Alias -Scope Global -Force -Name gst  -Value Get-gSpannerTable
    Set-Alias -Scope Global -Force -Name isb  -Value Invoke-gSpannerBatchDml
    Set-Alias -Scope Global -Force -Name iss  -Value Invoke-gSpannerSql
    Set-Alias -Scope Global -Force -Name nss  -Value New-gSpannerSession
    Set-Alias -Scope Global -Force -Name nstr -Value New-gSpannerTransaction
    Set-Alias -Scope Global -Force -Name pstr -Value Publish-gSpannerTransaction
    Set-Alias -Scope Global -Force -Name rsdb -Value Remove-gSpannerDatabase
    Set-Alias -Scope Global -Force -Name rsdo -Value Remove-gSpannerDatabaseOperation
    Set-Alias -Scope Global -Force -name rsi -Value Remove-gSpannerInstance
    Set-Alias -Scope Global -Force -name rsio -Value Remove-gSpannerInstanceOperation
    Set-Alias -Scope Global -Force -Name rss  -Value Remove-gSpannerSession
    Set-Alias -Scope Global -Force -Name rst  -Value Remove-gSpannerTable
    Set-Alias -Scope Global -Force -Name ssdp -Value Set-gSpannerDefaultProjectId
    Set-Alias -Scope Global -Force -Name sss  -Value Start-gSpannerStreamingSql
    Set-Alias -Scope Global -Force -Name sssh -Value Set-gSpannerSchema
    Set-Alias -Scope Global -Force -Name ustr -Value Undo-gSpannerTransaction
}
Set-gSpannerAliases
Function Set-gSpannerDefaultProjectId {
    Param(
        $ProjectId
    )
    $Global:PSDefaultParameterValues['*-gSpanner*:ProjectId'] = $ProjectId
}

$version1 = 'https://spanner.googleapis.com/v1'
Add-Type -TypeDefinition @"
    public enum SpannerTransactionMode {
        readWrite,
        readOnly,
        partitionedDml
    }
"@
$PsDefaultParameterValues['*-gOAuth*:ProjectId'] = 'powershell'
Function Invoke-gSpannerLogin {
    [CmdletBinding()]
    Param()
    Invoke-gOAuthLogin -Verbose:$VerbosePreference
    [void](Get-gOAuthAccessToken -Refresh -Verbose:$VerbosePreference)
}
Function Get-gSpannerInstanceConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ProjectId
    )
    (Invoke-gOAuthRestMethod -Uri "$version1/projects/$ProjectId/instanceConfigs" -Verbose:$VerbosePreference).instanceConfigs
}
Function Get-gSpannerInstance {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ProjectId,
        $Id,
        [switch]
        $Default
    )
    $Id ?
    (Invoke-gOAuthRestMethod  -Uri "$version1/projects/$ProjectId/instances/$Id" -Verbose:$VerbosePreference) :
    (Invoke-gOAuthRestMethod  -Uri "$version1/projects/$ProjectId/instances" -Verbose:$VerbosePreference).instances |
    % {
        If ( $Default.IsPresent ) {
            $Global:PSDefaultParameterValues['*-gSpanner*:Instance'] = $_
        }
        $_
    }

}
Function Add-gSpannerInstance {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Id,
        [Parameter(Mandatory)]
        $Config,
        [string]
        $DisplayName = $Id,
        [Parameter()]
        [int]
        $NodeCount = 1
    )
    $projectId = ($Config.name -split '/')[1]
    $b = @{
        instanceId = $Id;
        instance   = @{
            config      = $Config.name;
            nodeCount   = $NodeCount;
            displayName = $DisplayName
        }
    }
    $o = Invoke-gOAuthRestMethod -Uri "$version1/projects/$projectId/instances" -Body $b -Verbose:$VerbosePreference
    While ( -not $o.done) {
        Start-Sleep -Milliseconds 30
        $o = Get-gSpannerInstanceOperation -Operation $o -Verbose:$VerbosePreference
        If ( $VerbosePreference ) {
            $o | ConvertTo-Json | Write-Verbose -Verbose:$VerbosePreference
        }
    }
    If ( $o.error.code) {
        throw $o.error
    }
    $o.response
}
Function Remove-gSpannerInstance {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $Instance
    )
    Process {
        $i = $_ ?? $Instance
        if ($PSCmdlet.ShouldProcess(('Spanner instance {0} from project' -f $i.name), "remove")) {
            $r = Invoke-gOAuthRestMethod -Uri "$version1/$($i.name)" -Method DELETE -Verbose:$VerbosePreference
            If ( $VerbosePreference ) {
                $r | ConvertTo-Json -Depth 99 | Write-Verbose -Verbose:$VerbosePreference
            }
        }
        Else {
            'Remove Spanner instance {0} from project' -f $db.name | Write-Information
        }
    }
}
Function Get-gSpannerDatabase {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Instance,
        $Id,
        [switch]
        $Default
    )
    $Id ?
    (Invoke-gOAuthRestMethod -Uri "$version1/$($Instance.name)/databases/$Id" -Verbose:$VerbosePreference) :
    (Invoke-gOAuthRestMethod -Uri "$version1/$($Instance.name)/databases" -Verbose:$VerbosePreference).databases |
    % {
        If ( $Default.IsPresent ) {
            $Global:PSDefaultParameterValues['*-gSpanner*:Database'] = $_
        }
        $_
    }
}
Function Add-gSpannerDatabase {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Instance,
        [Parameter(Mandatory)]
        $Id
    )
    $b = @{
        createStatement = 'CREATE DATABASE `{0}`' -f $Id;
        extraStatements = @()
    }
    $o = Invoke-gOAuthRestMethod  -Uri "$version1/$($Instance.name)/databases" -Body $b -Verbose:$VerbosePreference
    If ( $VerbosePreference ) {
        $o | ConvertTo-Json | Write-Verbose -Verbose:$VerbosePreference
    }
    While ( -not $o.done) {
        Start-Sleep -Milliseconds 30
        $o = Get-gSpannerDatabaseOperation -Operation $o -Verbose:$VerbosePreference
        If ( $VerbosePreference ) {
            $o | ConvertTo-Json | Write-Verbose -Verbose:$VerbosePreference
        }
    }
    If ( $o.error.code) {
        throw $o.error
    }
    $o.response
}
Function Get-gSpannerDatabaseDdl {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $Database
    )
    Process {
        $db = $_ ?? $Database
        Invoke-gOAuthRestMethod  -Uri "$version1/$($db.name)/ddl" -Verbose:$VerbosePreference
    }
}
Function Remove-gSpannerDatabase {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $Database
    )
    Process {
        $db = $_ ?? $Database
        if ($PSCmdlet.ShouldProcess(('database {0} from Spanner instance' -f $db.name), "remove")) {
            Invoke-gOAuthRestMethod -Uri "$version1/$($db.name)" -Method DELETE -Verbose:$VerbosePreference
        }
        Else { 
            'Remove database {0} from Spanner instance' -f $db.name | Write-Information
        }
    }
}
Function Get-gSpannerTable {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Database,
        $Like,
        [scriptblock]
        $Filter = { $_.TABLE_SCHEMA -eq '' }
    )
    $s = New-gSpannerSession -Database $Database -Verbose:$VerbosePreference
    try {
        $sql = $Pattern ?
        'select * from INFORMATION_SCHEMA.TABLES where TABLE_NAME like "{0}"' -f $Like :
        'select * from INFORMATION_SCHEMA.TABLES'
        Invoke-gSpannerSql -Session $s -SingleUse -Sql $sql -Verbose:$VerbosePreference |
        Select-Object -ExpandProperty resultSet |
        Where-Object $Filter |
        Select-Object -ExpandProperty TABLE_NAME | % {
            [PSCustomObject]@{
                name     = $_;
                database = $Database
            }
        }
    }
    finally {
        Remove-gSpannerSession -Session $s
    }
}
Function Remove-gSpannerTable {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $Table
    )
    Begin {
        $tables = @()
    }
    Process {
        $tables += $_ ?? $Table
    }
    End {
        If ( $tables.Count -gt 0 ) {
            $tables |
            Sort-Object -Property database |
            Group-Object -Property database | % {
                $statements = @()
                $db = $null
                $_.Group | % {
                    if ($PSCmdlet.ShouldProcess(('table {0} from database' -f $_.name), "drop")) {
                        $statements += 'DROP TABLE `{0}`' -f $_.name
                        $db = $_.database
                    }
                    else {
                        'Drop table {0} from database' -f $_ | Write-Information
                    }
                }
                If ( $statements.Count -gt 0 ) {
                    $statements | Set-gSpannerSchema -Database $db -Verbose:$VerbosePreference
                }
            }
        }
    }
}
Function Get-gSpannerSchema {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Database
    )
    (Invoke-gOAuthRestMethod -Uri "$version1/$($Database.name)/ddl").statements
}
Function New-gSpannerSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Database,
        [switch]
        $Default
    )
    Invoke-gOAuthRestMethod -Uri "$version1/$($Database.name)/sessions" -Body @{ } -Verbose:$VerbosePreference |
    % {
        If ( $Default.IsPresent) {
            $Global:PSDefaultParameterValues['*-gSpanner*:Session'] = $_
        }
        $_
    }
}
Function Remove-gSpannerSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline, Position = 1)]
        $Session
    )
    Begin { }
    Process {
        $s = $_ ?? $Session
        If ( $s ) {
            [void](Invoke-gOAuthRestMethod -Uri "$version1/$($s.name)" -Method DELETE -Verbose:$VerbosePreference)
        }
    }
    End { }
}
Function Get-gSpannerSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Database,
        [switch]
        $Default
    )
    (Invoke-gOAuthRestMethod -Uri "$version1/$($Database.name)/sessions" -Verbose:$VerbosePreference).sessions |
    % {
        If ( $Default.IsPresent) {
            $Global:PSDefaultParameterValues['*-gSpanner*:Session'] = $_
        }
        $_
    }
}
Function Get-gSpannerInstanceOperation {
    [CmdletBinding()]
    param (
        #[Parameter(Mandatory)]
        $Operation,
        $Instance
    )
    $Operation ?
    (Invoke-gOAuthRestMethod  -Uri "$version1/$($Operation.name)" -Verbose:$VerbosePreference) : 
    (Invoke-gOAuthRestMethod  -Uri "$version1/$($Instance.name)/operations" -Verbose:$VerbosePreference).operations
}
Function Remove-gSpannerInstanceOperation {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        $Operation
    )
    Process {
        $o = $_ ?? $Operation
        If ( $o ) {
            [void](Invoke-gOAuthRestMethod -Uri "$version1/$($o.name)" -Method DELETE -Verbose:$VerbosePreference)
        }
    }
}
Function Get-gSpannerDatabaseOperation {
    [CmdletBinding()]
    param (
        #[Parameter(Mandatory)]
        $Operation,
        $Database,
        $Instance
    )
    $Operation ?
    (Invoke-gOAuthRestMethod  -Uri "$version1/$($Operation.name)" -Verbose:$VerbosePreference) :
    $Database ?
    (Invoke-gOAuthRestMethod  -Uri "$version1/$($Database.name)/operations" -Verbose:$VerbosePreference).operations :
    (Invoke-gOAuthRestMethod  -Uri "$version1/$($Instance.name)/databaseOperations" -Verbose:$VerbosePreference).operations
}
Function Remove-gSpannerDatabaseOperation {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        $Operation
    )
    Process {
        $o = $_ ?? $Operation
        If ( $o ) {
            Try {
                [void](Invoke-gOAuthRestMethod -Uri "$version1/$($o.name)" -Method DELETE -Verbose:$VerbosePreference)
            }
            Catch {
                $m = $_.ErrorDetails.Message | ConvertFrom-Json
                If ( 'UNIMPLEMENTED' -eq $m.error.status ) {
                    $m.error.message | Write-Warning
                }
                Else {
                    Throw
                }
            }
        }
    }
}
Function Set-gSpannerSchema {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $Statements,
        [Parameter(Mandatory)]
        $Database
    )
    Begin {
        $s = @()
    }
    Process {
        $s += [string]($_ ?? $Statements)
    }
    End {
        If ( $s.Count -eq 0 ) {
            throw 'No statements have been given...'
        }
        $operation = 'id_' + [System.Guid]::NewGuid().ToString().Replace('-', '')
        $body = @{
            statements  = $s;
            operationId = $operation
        }
        $o = Invoke-gOAuthRestMethod -Uri "$version1/$($Database.name)/ddl" -Method PATCH -Body $body -Verbose:$VerbosePreference
        If ( $VerbosePreference ) {
            $o | ConvertTo-Json | Write-Verbose -Verbose:$VerbosePreference
        }
        While ( -not $o.done ) {
            Start-Sleep -Milliseconds 30
            $o = Get-gSpannerInstanceOperation -Operation $o -Verbose:$VerbosePreference
            If ( $VerbosePreference ) {
                $o | ConvertTo-Json | Write-Verbose -Verbose:$VerbosePreference
            }
        }
        If ( $o.error.code) {
            throw $o.error
        }
        $o
    }
}
Function Invoke-gSpannerBatchDml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]
        $Statements,
        [Parameter(Mandatory)]
        $Session,
        $Transaction,
        [int64]
        $SeqNo = 1,
        [switch]
        $Commit,
        [SpannerTransactionMode]
        $TransactionMode = [SpannerTransactionMode]::readWrite,
        $RetryCount = 3
    )
    Begin {
        $s = @()
    }
    Process {
        $s += $_ ?? $Statements
    }
    End {
        If ($VerbosePreference) {
            $s | Write-Verbose -Verbose:$VerbosePreference
        }
        $tp = @{ }
        foreach ( $p in $PSBoundParameters.GetEnumerator() ) {
            $v = switch ( $p.Key ) {
                'Statements' { }
                'Session' { }
                'SeqNo' { }
                'Commit' { }
                'RetryCount' { }
                default { $p }
            }
            If ( $v ) {
                $tp.Add($v.Key, $v.Value)
            }
        }
        $to = Get-gSpannerTransactionOptions @tp
        $body = [PSCustomObject]@{
            transaction = [pscustomobject]@{
                $to.key = $to.options
            }
            statements  = @( $s | % { @{ sql = [string]$_ } } );
            seqno       = $SeqNo.ToString()
        }
        $o = Invoke-gOAuthRestMethod -Uri "$version1/$($Session.Name):executeBatchDml" -Body $body -Verbose:$VerbosePreference
        If ( $VerbosePreference ) {
            $o | ConvertTo-Json -Depth 99 | Write-Verbose -Verbose:$VerbosePreference
        }
        If ( $o.status.code ) {
            throw $o.status
        }
        $r = [PSCustomObject]@{
            executeBatchDml = $o;
            commit          = $null;
        }
        If ( $Commit.IsPresent ) {
            $r.executeBatchDml.resultSets | Select-Object -First 1 | % {
                $r.commit = Publish-gSpannerTransaction -Session $Session -Transaction ($_.metadata.transaction ?? $Transaction ) -RetryCount $RetryCount
            }
            If ( $VerbosePreference ) {
                $r.commit | ConvertTo-Json -Depth 99 | Write-Verbose -Verbose:$VerbosePreference
            }
        }
        If ( $VerbosePreference ) {
            $r | ConvertTo-Json -Depth 99 | Write-Verbose -Verbose:$VerbosePreference
        }
        $r
    }
}
Function Get-gSpannerTransactionOptions {
    [CmdletBinding()]
    param (
        $Transaction,
        [SpannerTransactionMode]
        $TransactionMode = [SpannerTransactionMode]::readOnly,
        [switch]
        $ReturnReadTimestamp,
        [switch]
        $Strong,
        [datetime]
        $MinReadTimestamp,
        [timespan]
        $MaxStaleness,
        [datetime]
        $ReadTimestamp,
        [timespan]
        $ExactStaleness,
        [switch]
        $SingleUse
    )
    If ( $VerbosePreference ) {
        $PSBoundParameters | ConvertTo-Json -Depth 99 | Write-Verbose -Verbose:$VerbosePreference
    }
    $b = If ( $Transaction ) { 
        [PSCustomObject]@{
            key     = 'id'
            options = $transaction.id
        }
    }
    else {
        switch ($TransactionMode.ToString()) {
            'readWrite' {
                [PSCustomObject]@{
                    key     = 'begin'
                    options = [PSCustomObject]@{
                        readWrite = [PSCustomObject]@{ }
                    }
                }
                break
            }
            'readOnly' {
                $o = [PSCustomObject]@{
                    readOnly = [PSCustomObject]@{ }
                }
                $r = $o.readOnly
                $b = If ( $SingleUse.IsPresent -or ( -not ($PSBoundParameters.ContainsKey('TransactionMode') ))) {
                    [PSCustomObject]@{
                        key     = 'singleUse'
                        options = $o
                    }
                }
                Else {
                    [PSCustomObject]@{
                        key     = 'begin'
                        options = $o
                    }
                }
                If ( $ReturnReadTimestamp) {
                    Add-Member -InputObject $r -MemberType NoteProperty -Name returnReadTimestamp -Value $true
                }
                If ( $Strong ) {
                    Add-Member -InputObject $r -MemberType NoteProperty -Name strong -Value $true
                }
                If ( $MinReadTimestamp ) {
                    Add-Member -InputObject $r -MemberType NoteProperty -Name minReadTimestamp -Value ('{0:o}' -f $MinReadTimestamp.ToUniversalTime())
                }
                If ( $MaxStaleness ) {
                    Add-Member -InputObject $r -MemberType NoteProperty -Name maxStaleness -Value ('{0}s' -f ( $MaxStaleness.Ticks / 10000000 ))
                }
                If ( $ReadTimestamp ) {
                    Add-Member -InputObject $r -MemberType NoteProperty -Name readTimestamp -Value ('{0:o}' -f $ReadTimestamp.ToUniversalTime())
                }
                If ( $ExactStaleness ) {
                    Add-Member -InputObject $r -MemberType NoteProperty -Name exactStaleness -Value ('{0}s' -f ( $ExactStaleness.Ticks / 10000000 ))
                }
                $b
                break
            }
            'partitionedDml' {
                [PSCustomObject]@{
                    key     = 'begin'
                    options = [PSCustomObject]@{
                        partitionedDml = [PSCustomObject]@{ } 
                    }
                };
                break
            }
        }
    }
    If ( $VerbosePreference ) {
        $b | ConvertTo-Json | Write-Verbose -Verbose:$VerbosePreference
    }
    $b
}
Function New-gSpannerTransaction {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [SpannerTransactionMode]
        $TransactionMode,
        [Parameter(Mandatory)]
        $Session,
        [switch]
        $ReturnReadTimestamp,
        [switch]
        $Strong,
        [datetime]
        $MinReadTimestamp,
        [timespan]
        $MaxStaleness,
        [datetime]
        $ReadTimestamp,
        [timespan]
        $ExactStaleness,
        [switch]
        $SingleUse,
        [switch]
        $Default
    )
    $tp = @{ }
    foreach ( $p in $PSBoundParameters.GetEnumerator() ) {
        $v = switch ( $p.Key ) {
            'Session' { }
            'Default' { }
            default { $p }
        }
        If ( $v ) {
            $tp.Add($v.Key, $v.Value)
        }
    }
    $to = Get-gSpannerTransactionOptions @tp
    $b = [pscustomobject]@{
        options = $to.options
    }
    Invoke-gOAuthRestMethod -Uri "$version1/$($Session.Name):beginTransaction" -Body $b -Verbose:$VerbosePreference |
    % {
        If ( $Default.IsPresent ) {
            $Global:PSDefaultParameterValues['*-gSpanner*:Transaction'] = $_
        }
        $_
    }
}
Function Start-gSpannerStreamingSql {
    [CmdletBinding(DefaultParameterSetName = 'ReadOnly')]
    param (
        [Parameter(ValueFromPipeline, Mandatory, Position = 1)]
        [string]
        $Sql,
        [Parameter(Mandatory)]
        $Session,
        [int]
        $SeqNo = 1,
        [Parameter(ParameterSetName = 'Custom')]
        $Transaction,
        [switch]
        $Commit,
        [Parameter(ParameterSetName = 'SingleUse')]
        [switch]
        $SingleUse,
        [Parameter(ParameterSetName = 'ReadWrite')]
        [Parameter(ParameterSetName = 'ReadOnly')]
        [Parameter(ParameterSetName = 'SingleUse')]
        [SpannerTransactionMode]
        $TransactionMode = [SpannerTransactionMode]::readOnly,
        [Parameter(ParameterSetName = 'ReadOnly')]
        [Parameter(ParameterSetName = 'SingleUse')]
        [switch]
        $ReturnReadTimestamp,
        [Parameter(ParameterSetName = 'ReadOnly')]
        [Parameter(ParameterSetName = 'SingleUse')]
        [switch]
        $Strong,
        [Parameter(ParameterSetName = 'ReadOnly')]
        [Parameter(ParameterSetName = 'SingleUse')]
        [datetime]
        $MinReadTimestamp,
        [Parameter(ParameterSetName = 'SingleUse')]
        [timespan]
        $MaxStaleness,
        [Parameter(ParameterSetName = 'ReadOnly')]
        [Parameter(ParameterSetName = 'SingleUse')]
        [datetime]
        $ReadTimestamp,
        [Parameter(ParameterSetName = 'ReadOnly')]
        [Parameter(ParameterSetName = 'SingleUse')]
        [timespan]
        $ExactStaleness
    )
    $tp = @{ }
    foreach ( $p in $PSBoundParameters.GetEnumerator() ) {
        $v = switch ( $p.Key ) {
            'Sql' { }
            'Session' { }
            'SeqNo' { }
            'Commit' { }
            default { $p }
        }
        If ( $v ) {
            $tp.Add($v.Key, $v.Value)
        }
    }
    $to = Get-gSpannerTransactionOptions @tp
    $body = @{
        transaction = [pscustomobject]@{
            $to.key = $to.options
        }
        sql         = $Sql;
        seqno       = $SeqNo.ToString();
        queryMode   = 'PROFILE'
    }
    $o = Invoke-gOAuthRestMethod -Uri "$version1/$($Session.Name):executeStreamingSql" -Body $body -Verbose:$VerbosePreference
    If ( $VerbosePreference) {
        $o | ConvertTo-Json | Write-Verbose -Verbose:$VerbosePreference
    }
    $r = [PSCustomObject]@{
        executeStreamingSql = $o
        transaction         = $o.metadata.transaction ?? $Transaction
    }
    If ( $Commit ) {
        $o = Publish-gSpannerTransaction -Session $Session -Transaction $r.transaction -Verbose:$VerbosePreference
        Add-Member -InputObject $r -MemberType NoteProperty -Name commit -Value $o
    }
    If ( $VerbosePreference ) {
        $r | ConvertTo-Json -Depth 99 | Write-Verbose -Verbose:$VerbosePreference
    }
    Get-gSpannerResultSet -ResultSet $r.executeStreamingSql -Streaming
}
Function Invoke-gSpannerSql {
    [CmdletBinding(DefaultParameterSetName = 'ReadOnly')]
    param (
        [Parameter(ValueFromPipeline, Mandatory, Position = 1)]
        [string]
        $Sql,
        [Parameter(Mandatory)]
        $Session,
        [int]
        $SeqNo = 1,
        [Parameter(ParameterSetName = 'Custom')]
        $Transaction,
        [switch]
        $Commit,
        [Parameter(ParameterSetName = 'SingleUse')]
        [switch]
        $SingleUse,
        [Parameter(ParameterSetName = 'ReadWrite')]
        [Parameter(ParameterSetName = 'ReadOnly')]
        [Parameter(ParameterSetName = 'SingleUse')]
        [SpannerTransactionMode]
        $TransactionMode = [SpannerTransactionMode]::readOnly,
        [Parameter(ParameterSetName = 'ReadOnly')]
        [Parameter(ParameterSetName = 'SingleUse')]
        [switch]
        $ReturnReadTimestamp,
        [Parameter(ParameterSetName = 'ReadOnly')]
        [Parameter(ParameterSetName = 'SingleUse')]
        [switch]
        $Strong,
        [Parameter(ParameterSetName = 'ReadOnly')]
        [Parameter(ParameterSetName = 'SingleUse')]
        [datetime]
        $MinReadTimestamp,
        [Parameter(ParameterSetName = 'SingleUse')]
        [timespan]
        $MaxStaleness,
        [Parameter(ParameterSetName = 'ReadOnly')]
        [Parameter(ParameterSetName = 'SingleUse')]
        [datetime]
        $ReadTimestamp,
        [Parameter(ParameterSetName = 'ReadOnly')]
        [Parameter(ParameterSetName = 'SingleUse')]
        [timespan]
        $ExactStaleness,
        [switch]
        $ExpandResultset
    )
    Begin {
        $tp = @{ }
        foreach ( $p in $PSBoundParameters.GetEnumerator() ) {
            $v = switch ( $p.Key ) {
                'Sql' { }
                'Session' { }
                'SeqNo' { }
                'Commit' { }
                'ExpandResultset' { }
                default { $p }
            }
            If ( $v ) {
                $tp.Add($v.Key, $v.Value)
            }
        }
        $to = Get-gSpannerTransactionOptions @tp
    }
    Process {
        $s = $_ ?? $Sql;
        $s | Write-Verbose -Verbose:$VerbosePreference
        $body = [pscustomobject]@{
            transaction = [pscustomobject]@{
                $to.key = $to.options
            }
            sql         = $s.PSObject.BaseObject;
            seqno       = $SeqNo.ToString();
            queryMode   = 'PROFILE'
        }
        If ( $VerbosePreference ) {
            $body | ConvertTo-Json -Depth 1 | Write-Verbose -Verbose:$VerbosePreference
        }
        $o = Invoke-gOAuthRestMethod -Uri "$version1/$($Session.Name):executeSql" -Body $body -Verbose:$VerbosePreference
        $r = [pscustomobject]@{
            executeSql  = $o;
            transaction = $o.metadata.transaction ?? $Transaction
            commit      = $null;
        } |
        Add-Member -Name resultSet -MemberType ScriptProperty -Value { @( Get-gSpannerResultSet -ResultSet $this.executeSql ) } -PassThru
        If ( $Commit.IsPresent ) {
            $r.commit = Publish-gSpannerTransaction -Session $Session -Transaction $r.transaction -Verbose:$VerbosePreference
            If ( $VerbosePreference ) {
                $r.commit | ConvertTo-Json -Depth 99 | Write-Verbose -Verbose:$VerbosePreference
            }
        }
        If ( $ExpandResultset.IsPresent ) {
            $r | Select-Object -ExpandProperty resultSet
        }
        Else {
            $r
        }
    }
    End {
    }
}
Function Get-gSpannerColumnHeader {
    Param(
        [Parameter(Mandatory)]
        $ResultSet,
        [Parameter(Mandatory)]
        [int]
        $Index
    )
    ( $ResultSet.metadata.rowType.fields ? $ResultSet.metadata.rowType.fields[$Index].name : $null ) ?? 'Column{0:00#}' -f $Index
}
Function Get-gSpannerResultSet {
    Param (
        $ResultSet,
        [switch]
        $Streaming
    )
    If ( $Streaming ) {
        $i = 0
        $r = New-Object PSCustomObject
        $ResultSet.values | % {
            $name = Get-gSpannerColumnHeader -ResultSet $ResultSet -Index $i
            Add-Member -InputObject $r -MemberType NoteProperty -Name $name -Value $_
            $i = ++$i % $ResultSet.metadata.rowType.fields.Length
            If ( $i -eq 0) {
                $r
                $r = New-Object PSCustomObject
            }
        }
    }
    Else {
        $ResultSet.rows | % {
            $i = 0
            $r = New-Object PSCustomObject
            $_ | % {
                $name = Get-gSpannerColumnHeader -ResultSet $ResultSet -Index $i
                Add-Member -InputObject $r -MemberType NoteProperty -Name $name -Value $_
                $i += 1
            }
            $r
        }
    }
}
Function Publish-gSpannerTransaction {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Session,
        [Parameter(Mandatory)]
        $Transaction,
        $RetryCount = 3
    )
    $body = @{
        transactionId = $Transaction.id
    }
    $retry = $false
    do {
        Try {
            Invoke-gOAuthRestMethod -Uri "$version1/$($Session.Name):commit" -Body $body -Verbose:$VerbosePreference
        }
        catch {
            If ( $RetryCount -lt 1) {
                throw
            }
            $json = $_.ErrorDetails.Message
            $message = $json | ConvertFrom-Json
            If ( $message.error.status -eq 'ABORTED') {
                $message.error.details |
                ? { $_.'@type' -eq 'type.googleapis.com/google.rpc.RetryInfo' } |
                Select-Object -First 1 | % {
                    try {
                        $delay = [timespan]::FromSeconds([double]::parse($_.retryDelay.TrimEnd('s')))
                    }
                    catch {
                        If ( $VerbosePreference) {
                            'Unable to parse retry delay {0}. Exception: {1}' -f $_.retryDelay, $json | Write-Warning
                        }
                        throw
                    }
                    $Retry = $RetryCount-- -gt 0
                    if (-not $Retry ) {
                        If ( $VerbosePreference) {
                            'No more retries, abandon publish transaction: {0}' -f $json | Write-Warning
                        }
                        throw
                    }
                    If ( $VerbosePreference) {
                        'Retry in {0} milliseconds to publish transaction: {1}' -f $delay.TotalMilliseconds, $json | Write-Warning
                    }
                    Start-Sleep -Milliseconds $delay.TotalMilliseconds
                }
            }
            Else {
                If ( $VerbosePreference) {
                    'Abandon publish transaction: {0}' -f $json | Write-Warning
                }
                throw
            }
        }
    } while ( $retry )
}
Function Undo-gSpannerTransaction {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Transaction,
        [Parameter(Mandatory)]
        $Session
    )
    $body = @{
        transactionId = $Transaction.id
    }
    [void](Invoke-gOAuthRestMethod -Uri "$version1/$($Session.Name):rollback" -Body $body -Verbose:$VerbosePreference)
}
Function Get-gSpannerDataType {
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]
        $DataType
    )
    try {
        $dt = [type]$DataType
    }
    catch {
        $dt = 'System.Management.Automation.' + $DataType
    }
    '{0} became {1}' -f $DataType, $dt.FullName | Write-Verbose -Verbose:$VerbosePreference
    switch ( $dt.FullName ) {
        'System.String' {
            'STRING(MAX)'
        }
        'System.DateTime' {
            'TIMESTAMP'
        }
        'System.TimeSpan' {
            'INT64'
        }
        'System.INT64' {
            'INT64'
        }
        'System.INT32' {
            'INT64'
        }
        'System.INT16' {
            'INT64'
        }
        'System.Boolean' {
            'BOOL'
        }
        default {
            'STRING(MAX)'
        }
    }
}
Function Get-gSpannerValue {
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [object]
        $Value,
        [switch]
        $JSON
    )
    if ( $null -ne $Value  ) {
        switch ( $Value.GetType().ToString()) {
            'System.DateTime' {
                If ( $JSON ) {
                    [Math]::Floor(1000 * (Get-Date -Date $Value -UFormat %s))
                }
                Else {
                    $v = $Value.Kind -eq [System.DateTimeKind]::Unspecified ? [Datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) : $Value
                    "TIMESTAMP '{0:o}'" -f $v.ToUniversalTime()
                }
            }
            'System.TimeSpan' {
                $Value.Ticks
            }
            'System.String' {
                If ( $JSON ) {
                    "'{0}'" -f [System.Web.HttpUtility]::JavaScriptStringEncode([System.Web.HttpUtility]::JavaScriptStringEncode($Value))
                }
                Else {
                    "'{0}'" -f [System.Web.HttpUtility]::JavaScriptStringEncode($Value)
                }
            }
            'System.Boolean' {
                $Value.ToString().ToLowerInvariant()
            }
            'System.Int64' {
                $Value
            }
            'System.Int32' {
                $Value
            }
            'System.Int16' {
                $Value
            }
            'System.Management.Automation.PSCustomObject' {
                "'{0}'" -f [System.Web.HttpUtility]::JavaScriptStringEncode(($Value | ConvertTo-Json))
            }
            default {
                If ( $JSON ) {
                    #"'{0}'" -f [System.Web.HttpUtility]::JavaScriptStringEncode([System.Web.HttpUtility]::JavaScriptStringEncode($Value))
                    $null
                }
                Else {
                    "'{0}'" -f [System.Web.HttpUtility]::JavaScriptStringEncode($Value)
                }
            }
        }
    }
    else {
        'null'
    }
}
Function Get-gSpannerColumns {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [object]
        $Value
    )
    Begin {
        $v = @()
    }
    Process {
        $v += $Value
    }
    End {
        $v |
        Get-Member -MemberType Properties |
        ? {
            switch ($_.MemberType) {
                'Property' { $true }
                'NoteProperty' { $true }
                'ScriptProperty' { $true }
                default { $false }
            }
        } |
        Sort-Object -Property TypeName, Name -Unique |
        ? {
            If ( $_.Name -match '^[a-z][a-z,0-9,_,\p{Zs}]*$' ) {
                $True
            }
            else {
                If ( $_.Name -inotlike '__*') {
                    'Name invalid, ignoring {0}.{1}' -f $_.TypeName, $_.Name | Write-Warning
                }
            }
        } |
        % {
            Add-Member -InputObject $_ -Name __ColumnHeader -MemberType NoteProperty -Value ( $_.Name.Replace(' ', '_')) -PassThru
        }
    }
}
Function Get-gSpannerColumnsFromType {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [type]
        $Type
    )
    Begin {
        $v = @()
    }
    Process {
        $v += $Type
    }
    End {
        $v |
        % {
            $_.GetMembers()
        } |
        ? {
            $_.MemberType -eq 'Property'
        } |
        Sort-Object -Property ReflectedType, Name -Unique |
        ? {
            If ( $_.Name -match '^[a-z][a-z,0-9,_,\p{Zs}]*$' ) {
                $True
            }
            else {
                If ( $_.Name -inotlike '__*') {
                    'Name invalid, ignoring {0}.{1}' -f $_.TypeName, $_.Name | Write-Warning
                }
            }
        } |
        % {
            Add-Member -InputObject $_ -Name __ColumnHeader -MemberType NoteProperty -Value ( $_.Name.Replace(' ', '_')) -Force -PassThru
        }
    }
}
Function Add-gSpannerTableFromType {
    param (
        [Parameter(ValueFromPipeline)]
        [type]
        $Type,
        [Parameter(Mandatory)]
        $Database,
        [switch]
        $JSON,
        [switch]
        $Header,
        $Key
    )
    Begin {
        $values = @()
    }
    Process {
        $values += If ( $Value ) {
            $Value
        }
        Else {
            $_
        }
    }
    End {
        $values |
        Get-gSpannerColumnsFromType |
        Group-Object -Property ReflectedType | % {
            $t = $_.Name -split '\.' | Select-Object -Last 1
            $v = If ($Header.IsPresent) {
                @(
                    '`g_Id`    STRING(32)'
                    '`g_Load`  TIMESTAMP'
                )
                $Key = 'g_id'
            }
            Else {
                @()
            }
            If ( $JSON ) {
                $v += '`g_Value`  STRING(MAX)'
            }
            Else {
                $v += @(
                    $_.Group |
                    % {
                        '`{0}` {1}' -f $_.__ColumnHeader, (Get-gSpannerDataType -DataType $_.PropertyType )
                    }
                )
            }
            $vs = $v -join ', '
            @(
                'CREATE TABLE {0}(' -f $t
                $vs
                ') PRIMARY KEY(`{0}`)' -f $Key
            ) -join ' '
        } |
        Set-gSpannerSchema -Database $Database -Verbose:$VerbosePreference
    }
}
Function Add-gSpannerTable {
    param (
        [Parameter(ValueFromPipeline)]
        [object]
        $Value,
        [Parameter(Mandatory)]
        $Database,
        $Name,
        [switch]
        $SkipLoadHeader,
        [switch]
        $JSON,
        [string[]]
        $Key = @( 'g_Id', 'g_Load')
    )
    Begin {
        $values = @()
    }
    Process {
        $values += If ( $Value ) {
            $Value
        }
        Else {
            $_
        }
    }
    End {
        $values |
        Get-gSpannerColumns |
        Group-Object -Property TypeName | % {
            $t = $Name ?? ( $_.Name -split '\.' | Select-Object -Last 1 )
            'Table: {0}' -f $t | Write-Verbose -Verbose:$VerbosePreference
            $v = @()
            If ( -not $SkipLoadHeader.IsPresent ) {
                $v += @(
                    '`g_Id`    STRING(32)'
                    '`g_Load`  TIMESTAMP'
                )
            }
            If ( $JSON ) {
                $v += '`g_Value`  STRING(MAX)'
            }
            Else {
                $v += @(
                    $_.Group |
                    % {
                        '`{0}` {1}' -f $_.__ColumnHeader, (Get-gSpannerDataType -DataType ( $_.Definition -Split ' ' | Select-Object -First 1 ) )
                    }
                )
            }
            $vs = $v -join ', '
            @(
                'CREATE TABLE {0}(' -f $t
                $vs
                ') PRIMARY KEY('
                @(
                    $Key | % { '`{0}`' -f $_ }
                ) -Join ','
                ')' -f $t
            ) -join ' '
        } |
        Set-gSpannerSchema -Database $Database -Verbose:$VerbosePreference
    }
}
Function Add-gSpannerItemsSelectUnionAll {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [object]
        $Value,
        [Parameter(Mandatory)]
        $Database,
        [switch]
        $SkipSchemaCreation,
        [switch]
        $JSON,
        [System.DateTime]
        $Load = [System.DateTime]::UtcNow,
        [int]
        $PageSize = 200
    )
    Begin {
        $values = @()
    }
    Process {
        $values += $_
    }
    End {
        If ( -not $SkipSchemaCreation.IsPresent ) {
            $values | Add-gSpannerTable -Database $Database -JSON:$JSON
        }
        $s = @()
        $values |
        % {
            $tn = ( $_ | Get-Member | Select-Object -First 1).TypeName
            $_ | Add-Member -MemberType NoteProperty -Name __TypeName -Value $tn -Force -PassThru
        } |
        Sort-Object -Property __TypeName |
        Group-Object __TypeName |
        % {
            $v = $_
            $members = $values | Get-gSpannerColumns | ? TypeName -eq $v.Name
            $rows = $_ | Select-Object -ExpandProperty Group
            1..[int][Math]::Ceiling(($rows | Measure-Object).Count / $PageSize) |
            % {
                $page = ([int]::Parse($_) - 1)
                $l = @(
                    'INSERT INTO {0} (' -f ( $v.Name -split '\.' | Select-Object -Last 1 )
                    @(
                        '`g_Id`'
                        '`g_Load`'
                        If ( $JSON) {
                            '`g_Value`'
                        }
                        Else {
                            $members |
                            % {
                                '`{0}`' -f $_.__ColumnHeader
                            }
                        }
                    ) -join ', '
                    ')'
                    $u = @()
                    $rows |
                    Select-Object -Skip ( $page * $PageSize ) -First $PageSize |
                    % {
                        $c = $_
                        $u += @(
                            'SELECT'
                            @(
                                Get-gSpannerValue -Value ([System.Guid]::NewGuid().ToString().Replace('-', ''))
                                Get-gSpannerValue -Value $Load
                                @(
                                    $members |
                                    % {
                                        $n = $_.Name
                                        $o = $c.$n
                                        If ( $JSON ) {
                                            If ( $o ) {
                                                $ov = Get-gSpannerValue -Value $o -JSON:$JSON
                                                If ( $ov ) {
                                                    "'{0}': {1}" -f $n, $ov
                                                }
                                            }
                                        }
                                        Else {
                                            Get-gSpannerValue -Value $o
                                        }
                                    }
                                ) -Join ', ' |
                                % {
                                    If ( $JSON ) {
                                        '"{' + $_ + '}"'
                                    }
                                    Else {
                                        $_
                                    }
                                }
                            ) -join ', '
                        ) -join ' '
                    }
                    $u -join ' UNION ALL '
                ) -join ' '
                $s += $l
            }
        }
        $session = New-gSpannerSession -Database $Database
        Invoke-gSpannerBatchDml -Session $session -Statements $s -Commit -Verbose:$VerbosePreference
    }
}
Function Add-gSpannerItems {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [object]
        $Value,
        [Parameter(Mandatory)]
        $Database,
        [switch]
        $SkipLoadHeader,
        [switch]
        $SkipSchemaCreation,
        [switch]
        $JSON,
        [System.DateTime]
        $Load = [System.DateTime]::UtcNow,
        $TableName,
        [string[]]
        $Key = @( 'g_Id', 'g_Load'),
        [int]
        $PageSize = 200
    )
    Begin {
        $values = @()
    }
    Process {
        $values += $_
    }
    End {
        If ( -not $SkipSchemaCreation.IsPresent ) {
            $values | Add-gSpannerTable -Database $Database -JSON:$JSON -Name $TableName -Key $Key -SkipLoadHeader:$SkipLoadHeader
        }
        $s = @()
        $values |
        % {
            $tn = ( $_ | Get-Member | Select-Object -First 1).TypeName
            $_ | Add-Member -MemberType NoteProperty -Name __TypeName -Value $tn -Force -PassThru
        } |
        Sort-Object -Property __TypeName |
        Group-Object __TypeName |
        % {
            $v = $_
            $members = $values | Get-gSpannerColumns | ? TypeName -eq $v.Name
            $rows = $_ | Select-Object -ExpandProperty Group
            1..[int][Math]::Ceiling(($rows | Measure-Object).Count / $PageSize) |
            % {
                $page = ([int]::Parse($_) - 1)
                $l = @(
                    'INSERT INTO {0} (' -f ($TableName ?? (( $v.Name -split '\.' | Select-Object -Last 1 )))
                    @(
                        If ( -not $SkipLoadHeader.IsPresent ) {
                            '`g_Id`'
                            '`g_Load`'
                        }
                        If ( $JSON) {
                            '`g_Value`'
                        }
                        Else {
                            $members |
                            % {
                                '`{0}`' -f $_.__ColumnHeader
                            }
                        }
                    ) -join ', '
                    ') VALUES '
                    $u = @()
                    $rows |
                    Select-Object -Skip ( $page * $PageSize ) -First $PageSize |
                    % {
                        $c = $_
                        $u += @(
                            '('
                            @(
                                If ( -not $SkipLoadHeader.IsPresent ) {
                                    Get-gSpannerValue -Value ([System.Guid]::NewGuid().ToString().Replace('-', ''))
                                    Get-gSpannerValue -Value $Load
                                }
                                @(
                                    $members |
                                    % {
                                        $n = $_.Name
                                        $o = $c.$n
                                        If ( $JSON ) {
                                            If ( $o ) {
                                                $ov = Get-gSpannerValue -Value $o -JSON:$JSON
                                                If ( $ov ) {
                                                    "'{0}': {1}" -f $n, $ov
                                                }
                                            }
                                        }
                                        Else {
                                            Get-gSpannerValue -Value $o
                                        }
                                    }
                                ) -Join ', ' |
                                % {
                                    If ( $JSON ) {
                                        '"{' + $_ + '}"'
                                    }
                                    Else {
                                        $_
                                    }
                                }
                            ) -join ', '
                            ')'
                        ) -join ' '
                    }
                    $u -join ', '
                ) -join ' '
                $s += $l
            }
        }
        $session = New-gSpannerSession -Database $Database
        Invoke-gSpannerBatchDml -Session $session -Statements $s -TransactionMode readWrite -Commit -Verbose:$VerbosePreference
    }
}
# SIG # Begin signature block
# MIIdEQYJKoZIhvcNAQcCoIIdAjCCHP4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUl3xa4eHk00bOW2FwsfM3YruK
# TAKgghiiMIIFNTCCAx2gAwIBAgIQT/hgdSzRMK1Ptmol1X/K6zANBgkqhkiG9w0B
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFBP7+WMt
# Z922NhI2tnyOPE+ouwnAMA0GCSqGSIb3DQEBAQUABIIBADfK721eSWXeZoxgu7yJ
# 9PB0Vc9JeDyCTyihOQuemBNWkaTZs/PYxBmx/6xO90epQ07+bCsuYpvV3ZTMGNOy
# gLnjHh+fe0k79nHXikvciu5MJybPoVnnsqchbmnIUolRp1DVASDZyE9BlF/ph60O
# q/P73ztC3pafXNEmLitVtC3V2Y6V5nsBuMd2WpPA+Zuv3DjiLTRXywNpA9LcCe5v
# 3Br/U33oLnDKbD7vLELElABs4qAOPcHPc0jn1Pvdtitz12+jc5wQmiYC1/3y7QZK
# QV/2zZ9bRl+JgVUT4cylmeMi1Kv1gbM9O/mfrs9Tv0dDP6uJzK3wFz4Ou++87NSA
# t9mhggIPMIICCwYJKoZIhvcNAQkGMYIB/DCCAfgCAQEwdjBiMQswCQYDVQQGEwJV
# UzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQu
# Y29tMSEwHwYDVQQDExhEaWdpQ2VydCBBc3N1cmVkIElEIENBLTECEAMBmgI6/1ix
# a9bV6uYX8GYwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEw
# HAYJKoZIhvcNAQkFMQ8XDTIwMDcwNTA2MDMxN1owIwYJKoZIhvcNAQkEMRYEFBgE
# 6Dapa9UUAXY1ACAlZPCsHTLHMA0GCSqGSIb3DQEBAQUABIIBAIGvz4aDN7niIED1
# Gbr/fizA6kS1VCjL6lei6NuOf5x+FpXBmfozWIjl+l6Bf3KMC55FhnVcJNuV4qoW
# x9DQBbH4KWQxLhthBnrchXcPsGL8GPjM7T6/JzGa6NKHuprrRxJgr9zHiEucX5nD
# lsdjaLXO/SdtTcoHCjsrtgl9duOsKcpnCVTGqtLCYP30crvcrZfEMuPJee3FLDay
# TeyQQkmSUSLT1ybhCctZPtL/kwWYrq3TKRQUiHfPFFqwlNXq5tzIRzUbiOi2n2jK
# BXSQt5VUIMHtNxgI/+kVN/ijm13MS7VOeQAveCxkyFvh3GvJc2djjqt/MyMW5NIS
# LvtvHvc=
# SIG # End signature block
