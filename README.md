# Spanner Rest Cmdlets

The Spanner Rest Cmdlets are a PowerShell wrapper for the [Google Cloud Spanner REST Api](https://cloud.google.com/spanner/docs/reference/rest) including authentication. It exposes most Api calls through Powershell functions. The exposed Spanner entities are:

* [Instance Configuration](https://cloud.google.com/spanner/docs/reference/rest/v1/projects.instanceConfigs)

* [Instance](https://cloud.google.com/spanner/docs/reference/rest/v1/projects.instances)

* [Database](https://cloud.google.com/spanner/docs/reference/rest/v1/projects.instances.databases)

* [Session](https://cloud.google.com/spanner/docs/reference/rest/v1/projects.instances.databases.sessions)

* [Transaction](https://cloud.google.com/spanner/docs/reference/rest/v1/Transaction)

Operations are not exposed, asynchronous operations are waited upon so they don't need to be exposed. Asynchronicity can be achieved with PowerShell's "Job" or "ThreadJob" commands.

## Installation

Refer to [Github](https://github.com/PowerShell/Powershell) for download and installation instruction of PowerShell Core for the desired platform.

You can install the gSpanner, gOAuth and gSecret modules using one of the following methods.

1) From the PowerShell Gallery like so:

``` Powershell
Install-Module gSpanner
```

2) XCopy deployment to any of the folders referenced by $ENV:PSModulePath

3) Extract the module anywhere on the filesystem, and import them explicitly, using Import-Module

## Design

The design goal was not to make Spanner look like every other relational database, but to stay close to the REST Api structure of Spanner. Only small deviations for convenience in Powershell have been taken so that the results can easily be used with other PowerShell functions like ConvertTo-Csv etc.

The **Spanner Rest Cmdlets** have a dependency on the module gOAuth for authentication and on the module gSecret to store tokens (both modules are included). On Linux and Mac OS, tokens are stored in files and names are hashed for obscurity. On Windows the data protection API (DPAPI) is used to encrypt the tokens in the registry. Having stated these dependencies, the **Spanner Rest Cmdlets** do not depend on any binaries, only human readable scripts which should make the use in enterprise environments so much easier because nothing has to be installed.

The module name for the Spanner Cmdlets is gSpanner. All function names adhere to the pattern \<Verb\>-gSpanner\<Object\>, Example: Get-gSpannerInstanceConfig. Also look at:

``` Powershell
Get-Command -Module gSpanner -Syntax
```

The **Spanner Rest Cmdlets** have been tested with the Open Source version of Powershell Core 7.0.2 on Windows, Linux, Mac OS and the Google Cloud Shell. It even runs on a Raspberry Pi. On headless systems, the initial token has to be pasted from a browser on a different system.

## Testing

Pester is used for unit testing. The files named *.test.ps1 are to be used with Invoke-Pester.

``` PowerShell
Import-Module pester -Version 4.10.1
Import-Module gSpanner
Invoke-Pester (Get-Item (Get-Module gSpanner).Path).DirectoryName
```

The modules have been tested with version 4.10.1 of Pester, later version should work. Information on Pester can be found on [Github](https://github.com/pester/Pester).

## Tutorial

Let's assign the id of an existing project on Google Cloud that has billing enabled to the PowerShell variable $p. If you are using the **Spanner Rest Cmdlets**  for the first time, you need to authenticate.

``` PowerShell
$p = 'david-kubelka-gcp'
# Only the first time or if you get the following error message
# Authorization does not exist, please login with project powershell!
Invoke-gSpannerLogin
```

Let's have a look at the Spanner instance configurations that are available for this project.

``` PowerShell
$ Get-gSpannerInstanceConfig -ProjectId $p | ft displayName

displayName
-----------
Europe (Belgium/Netherlands)
United States, Europe, and Asia (Iowa/Oklahoma/Belgium/Taiwan)
United States (Northern Virginia/South Carolina)
United States (Iowa/South Carolina/Oregon/Los Angeles)
asia-east1
asia-east2
asia-northeast1
asia-northeast2
asia-northeast3
asia-south1
asia-southeast1
australia-southeast1
europe-north1
europe-west1
europe-west2
europe-west3
europe-west4
europe-west6
northamerica-northeast1
southamerica-east1
us-central1
us-east1
us-east4
us-west1
us-west2
us-west3
us-west4
```

 Let's select one close by and assign it to the PowerShell variable named $ic.

``` PowerShell
$ic = Get-gSpannerInstanceConfig -ProjectId $p | ? displayName -eq europe-west4
```

Now that we have selected an instance configuration, we can standup a Spanner instance, set and it's id to "cluster", add it to the project and assign it's reference to the PowerShell variable $i.

``` PowerShell
$i = Add-gSpannerInstance -Id cluster -Config $ic
```

An instance without a database doesn't have much value, so let's add a database called banking to the Spanner instance and assign it's reference to the powershell variable $db

``` PowerShell
$db = Add-gSpannerDatabase -Id banking -Instance $i
```

Now that we have a database, we can create a table to put some tuples in. For that we
create a class that will represent the table and its properties will be used as columns.
We then instantiate 1000 objects of this class, initialize its properties, create the table
and insert the objects with a few lines of script.

``` PowerShell
class Accounts { [int64]$Number; [string]$Name; [datetime]$Created}
1..1000 |
    %{ [Accounts]@{Number=$_; Name = ('Customer {0}' -f $_); Created = (Get-Date) }} |
    Add-gSpannerItems -Database $db
```

If we want to have a look on what table was created, we can ask Spanner for the statements to recreate the schema of this instance.

``` PowerShell
$ Get-gSpannerDatabaseDdl -Database $db | fl *

statements : {CREATE TABLE Accounts (
               g_Id STRING(32),
               g_Load TIMESTAMP,
               Created TIMESTAMP,
               Name STRING(MAX),
               Number INT64,
             ) PRIMARY KEY(g_Id)}
```

Note that the columns g_id and g_load where created by the Add-gSpannerItems function.
g_Id is a GUID used as a surrogate key, created at statement generation time. g_Load is
the same timestamp for all tuples and identifies the load process. If the -Key parameter is used to specify a primary key for the table, -SkipLoadHeader can be used so that the columns g_id and g_load are not created.

To execute Sql statements we need a session and maybe a transaction if we don't want
one created implicitly. The session reference will be assigned to the PowerShell variable $s.

``` PowerShell
$s = New-gSpannerSession $db
```

Let's have a look how many tuples we have in Accounts.

``` PowerShell
$ 'Select count(*) Count from Accounts' | Invoke-gSpannerSql -Session $s -SingleUse | fl *

executeSql  : @{metadata=; stats=; rows=System.Object[]}
transaction : @{singleUse=}
commit      :
resultSet   : @{Count=1000}
```

What we can see here is that executing a sql statement will return a PSCustomObject including the result
from the executeSql REST call, the transaction options (in our case singleUse) or the transactionId and in case of
a readWrite transaction that is published with the -Commit switch, it will also include the result for the commit REST call.
The resultSet is formatted in a way that it can be piped easily into other PowerShell commands for example Out-GridView. Also the switch '-ExpandResultSet' will make it easier to process the incoming rows.

To create a CSV file from the first 10 tuples the command would look like this:

``` PowerShell
'Select * from Accounts order by Number Limit 10' |
Invoke-gSpannerSql -Session $s -SingleUse -ExpandResultSet |
ConvertTo-Csv |
Set-Content First10.csv
```

To verify what you actually got, you can use Out-GridView if you are not on a headless system.

``` PowerShell
Get-Content First10.csv |
ConvertFrom-Csv |
Out-GridView
```

This tutorial only shows a subset of the total functionality of the Spanner-Rest-Cmdlets, further details can be learned from the source code.

To avoid incurring unwanted charges, you should remove your Spanner cluster from your Google Cloud project like this.

``` PowerShell
Remove-gSpannerInstance -Instance $i
```

Enjoy!
