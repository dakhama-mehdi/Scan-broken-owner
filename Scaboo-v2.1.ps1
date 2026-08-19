<#
   .SYNOPSIS
   Detects Active Directory objects (users, computers, groups, OUs) whose Owner attribute
   does not match Microsoft's recommended baseline, and generates an HTML report.

   .DESCRIPTION
   This script scans Active Directory to detect broken/inconsistent owners on user accounts,
   computers, groups, and Organizational Units, based on Microsoft's recommendations.
   It generates a standalone HTML report and requires no external module.

   .EXAMPLE
   .\Scaboo-V2.ps1
   Launches the interactive menu to scan the whole domain or a specific OU.

   .NOTES
   ===========================================================================
   Version      : 2.1
   Created      : June 2022
   Updated      : August 2026
   Created by   : Dakhama Mehdi
   Contribution : Baomar Adham
   Thanks       : It-Connect.fr
   Company      : Rylel.com
   Tool Name    : Broken-Owner (Scaboo)
   ===========================================================================

   .HOW TO USE
   - Must be run from a machine joined to the AD domain
   - Can be launched with a standard AD user account (no admin rights required)
   - No PowerShell module required
#>

# Test connection and ldap request on DC

$testdomain = $env:username

$testldap = ([adsisearcher]"(&(objectCategory=User)(samaccountname=$testdomain))").findone()  

if (!$testldap) {
cls
Write-Host 'cannot contact AD domain, or user havent right' -ForegroundColor Yellow
Start-Sleep -Seconds 5
break;

 }

#Get Privilege groups domain for filter
$skipdefaultgroups = $null
$skipdefaultgroups = @()	

$skipdefaultgroups += ([adsisearcher]"(&(groupType:1.2.840.113556.1.4.803:=1)(!(objectSID=S-1-5-32-546))(!(objectSID=S-1-5-32-545)))").findall().Properties.name
$skipdefaultgroups += ([adsisearcher] "(&(objectCategory=group)(admincount=1)(iscriticalsystemobject=*))").FindAll().Properties.name


$varoptionalgroup = [ADSI]("LDAP://" + (([ADSI]"LDAP://RootDSE").schemaNamingContext))
$varoptionalgroup.PsBase.ObjectSecurity.Access.identityreference.value | select -Unique | ForEach-Object {

$skipdefaultgroups += $_.Split("\")[1]
}
# Add groups or objects to skip from result and uncomment the below line 
# Exemple for skip MDT-account, replace only "MDT-account" from your user name or groups
# $skipdefaultgroups += "MDT-account"

#creating arrays that will contain noncompiding objects    
$brokenusers = $Object = $brokenpc = $null
$script:brokenusers = [System.Collections.ArrayList]@() 
$script:brokenpc = [System.Collections.ArrayList]@()
$script:brokengroups = [System.Collections.ArrayList]@()
$script:brokenou = [System.Collections.ArrayList]@()
$script:nbrbrokenusers = $script:NbrsbrokenPC = $script:nbrbrokengroups = $script:nbrscanobject = $script:nbrbrokenou = 0

#Search computer or user from all domain (search from specific OU will be added later)
#You can stop by ctrl+c script any times

#region Menu

$ScriptVersion = "2.1"

function Show-Banner {
    $width = 64
    $line = "=" * $width

    Write-Host $line -ForegroundColor Yellow
    Write-Host "  Scan Active Directory - Broken Owner" -ForegroundColor White
    Write-Host "  v$ScriptVersion  |  Dakhama Mehdi  |  Rylel.com" -ForegroundColor White
    Write-Host $line -ForegroundColor Yellow
}

do
 {
    Clear-Host
    Show-Banner
    Write-Host ""
    Write-Host "  1) Scan all domain" -ForegroundColor Green
    Write-Host "  2) Scan a specific OU" -ForegroundColor Green
    Write-Host ""
    $selection = Read-Host "Your choice"

    switch ($selection)   {

    '1' {  'You chose option #1' 
    $selection = 'q'
    #$conditions = ([adsisearcher]"(|(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))(objectCategory=User)(groupType:1.2.840.113556.1.4.803:=2)(objectCategory=organizationalUnit))").findall().properties
    Write-Host "Searching objects across the whole domain, please wait..." -ForegroundColor Yellow
    $startTime = Get-Date
    $searcherAll = [adsisearcher]"(|(&(objectCategory=computer))(objectCategory=User)(objectCategory=group)(objectCategory=organizationalUnit))"
    $searcherAll.PageSize = 1000
    $searcherAll.PropertiesToLoad.AddRange(@(
        'name','samaccountname','distinguishedname','whencreated',
        ,'objectcategory','operatingsystem',
        'userprincipalname','cn','description'
    ))
    $conditions = $searcherAll.findall().properties
    }
    
    '2' {    
    $Ouname = Read-Host "enter name of OU"
    
    $searcherOU = [adsisearcher]"(&(objectCategory=organizationalUnit)(ou=$Ouname*))"
    $searcherOU.PageSize = 1000
    $OUpath= $searcherOU.findall().properties.distinguishedname | Out-GridView -PassThru -Title "Select OU" -ErrorAction Stop 
    
    if (!$OUpath) {
    Write-Host -ForegroundColor Red "Pls retest OU name not found`n" 
    pause
    } else {
    $startTime = Get-Date
    Write-Host "Searching objects in the selected OU, please wait..." -ForegroundColor Yellow
    $searcherScope = New-Object -TypeName adsisearcher -ArgumentList ([adsi] ("LDAP://" + $OUpath)), '(|(&(objectCategory=computer))(objectCategory=User)(objectCategory=group)(objectCategory=organizationalUnit))'
    $searcherScope.PageSize = 1000
    $searcherScope.PropertiesToLoad.AddRange(@(
        'name','samaccountname','distinguishedname','whencreated',
        ,'objectcategory','operatingsystem',
        'userprincipalname','cn','description'
    ))
    $conditions = $searcherScope.FindAll().Properties
    $selection = 'q'
    }

    } default {
      Write-Host "pls chose 1 or 2, and q for quit" -ForegroundColor DarkGray
      sleep -Seconds 3
    }
    }
 }
 until ($selection -eq 'q')

#endregion menu

#region function create table

 function add-valueobject  {
    
    param (
        [string] $name,
        [string] $samaccountname,
		[string] $distinguishedname,
		[string] $whencreated,
		[string] $OS,
		[string] $owner,
        [string] $cat,
        [string] $listetype
     )

		 
     $Hash = [ordered]@{
        Name              = $name
        SamAccountName    = $samaccountname
        DistinguishedName = $distinguishedname
        Created           = $whencreated
        $cat              = $OS
        Owner             = $owner
   }

if ($listetype -eq 'brokenou')
{
  $Hash.remove('SamAccountName')
}

$Object = [PSCustomObject]$Hash


    switch ($listetype) {
    
    'brokenpc'     { $script:brokenpc += $Object ; $script:NbrsbrokenPC++ }
    'brokenusers'  { $script:brokenusers += $Object; $script:nbrbrokenusers++ }
    'brokengroups' { $script:brokengroups += $Object; $script:nbrbrokengroups++ }
    'brokenou'     { $script:brokenou += $Object;  $script:nbrbrokenou++ }

    }

    }

#endregion function create table

#region Scan 

Write-Host "Found $($conditions.Count) object(s) to scan." -ForegroundColor Green

#$conditions | ForEach-Object {

#region Scan
$scanIndex = 0
$totalToScan = $conditions.Count

foreach ($item in $conditions) {

    $scanIndex++
    if (($scanIndex % 1000) -eq 0 -or $scanIndex -eq $totalToScan) {
        Write-Progress -Activity "Scanning AD objects" -Status "$scanIndex / $totalToScan" -PercentComplete (($scanIndex / $totalToScan) * 100)
    }
    
$name = $item.samaccountname

if (!$name) { $name = $item.name }

$getowner = [ADSI]("LDAP://" + $item.distinguishedname)

#check if owner is different from the array
if ($skipdefaultgroups -notcontains $getowner.PsBase.ObjectSecurity.Owner.Split("\")[1]) { 
        
      #Convert Binary SID     
      #$sid = $item["objectsid"][0] 
      #if ($sid) { $sidstring = (New-Object System.Security.Principal.SecurityIdentifier($sid, 0)).Value }
                   
       if ($item["objectcategory"][0] -match "Computer") { 
       
       add-valueobject $item["name"][0] $item["samaccountname"][0] $item["distinguishedname"][0] $item["whencreated"][0] $item["operatingsystem"][0] $getowner.PsBase.ObjectSecurity.Owner.Split("\")[1] OS brokenpc                                                                         
       
       } elseif ($item["objectcategory"][0] -match "Person") {

       add-valueobject $item["name"][0] $item["samaccountname"][0] $item["distinguishedname"][0] $item["whencreated"][0] $item["userprincipalname"][0] $getowner.PsBase.ObjectSecurity.Owner.Split("\")[1] UPN brokenusers
              
       } elseif ($item["objectcategory"][0] -match "Group") {
       
       add-valueobject $item["name"][0] $item["samaccountname"][0] $item["distinguishedname"][0] $item["whencreated"][0] $item["CN"][0] $getowner.PsBase.ObjectSecurity.Owner.Split("\")[1] CN brokengroups
              
       } else {

       add-valueobject $item["name"][0] ' ' $item["distinguishedname"][0] $item["whencreated"][0] $item["description"][0]  $getowner.PsBase.ObjectSecurity.Owner.Split("\")[1] Description brokenou
      }

    $name = $getowner = $null 
}
  
    $nbrscanobject++
}

Write-Progress -Activity "Scanning AD objects" -Completed
$endTime = Get-Date
$elapsed = ($endTime - $startTime).ToString('hh\:mm\:ss')
Write-Host "Scan completed in $elapsed" -ForegroundColor Green
#endregion Scan

$htmltest = $null

#region CreateHTML

$head = @"
<style>
    :root {
        --bg: #f4f6f8;
        --card-bg: #ffffff;
        --text: #1f2937;
        --muted: #6b7280;
        --accent: #2563eb;
        --danger: #dc2626;
        --border: #e5e7eb;
        --header-bg: #111827;
    }
    * { box-sizing: border-box; }
    body {
        background-color: var(--bg);
        font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
        color: var(--text);
        margin: 0;
        padding: 0 0 40px 0;
    }
    header.banner {
        background-color: var(--header-bg);
        color: white;
        padding: 24px 32px;
    }
    header.banner h1 { font-size: 20px; margin: 0; }
    header.banner p { margin: 4px 0 0 0; color: #9ca3af; font-size: 13px; }

    .summary {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 16px;
        padding: 24px 32px 0 32px;
    }
    .summary .card {
        background: var(--card-bg);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 16px;
        text-align: center;
    }
    .summary .card .num {
        font-size: 28px;
        font-weight: 700;
        color: var(--danger);
    }
    .summary .card .label {
        font-size: 13px;
        color: var(--muted);
        margin-top: 4px;
    }

    section.table-section {
        margin: 32px 32px 0 32px;
        background: var(--card-bg);
        border: 1px solid var(--border);
        border-radius: 10px;
        overflow: hidden;
    }
    section.table-section h2 {
        font-size: 15px;
        margin: 0;
        padding: 14px 18px;
        background-color: #f9fafb;
        border-bottom: 1px solid var(--border);
    }
    .table-wrap {
        max-height: 420px;
        overflow-y: auto;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
    }
    th, td {
        padding: 8px 12px;
        text-align: left;
        border-bottom: 1px solid var(--border);
        white-space: nowrap;
    }
    th {
        position: sticky;
        top: 0;
        background-color: var(--accent);
        color: white;
        font-weight: 600;
    }
    tr:hover { background-color: #f3f4f6; }
    tr:nth-child(even) { background-color: #fafafa; }

    input.filter-box {
        margin: 12px 18px;
        padding: 8px 12px;
        border: 1px solid var(--border);
        border-radius: 6px;
        width: calc(100% - 60px);
        font-size: 13px;
    }
</style>
"@

$date = Get-Date

# Build one fragment per table, each with its own filter input + scrollable wrapper
function New-ReportSection {
    param (
        [string] $title,
        [string] $tableId,
        [array]  $data
    )

    if ($data.Count -eq 0) {
        $tableHtml = "<p style='padding:14px 18px;color:var(--muted);'>No broken object found.</p>"
    } else {
        $fragment = $data | ConvertTo-Html -Fragment
        $tableHtml = "<input type='text' class='filter-box' placeholder='Filter rows...' onkeyup=""filterTable(this, '$tableId')"">"
        $tableHtml += "<div class='table-wrap'>" + ($fragment -replace '<table>', "<table id='$tableId'>") + "</div>"
    }

    return "<section class='table-section'><h2>$title ($($data.Count))</h2>$tableHtml</section>"
}

$summaryHtml = @"
<div class="summary">
    <div class="card"><div class="num" style="color:#16a34a;">$nbrscanobject</div><div class="label">Scanned Objects</div></div>
    <div class="card"><div class="num">$nbrbrokenusers</div><div class="label">Broken Users</div></div>
    <div class="card"><div class="num">$NbrsbrokenPC</div><div class="label">Broken PC</div></div>
    <div class="card"><div class="num">$nbrbrokengroups</div><div class="label">Broken Groups</div></div>
    <div class="card"><div class="num">$nbrbrokenou</div><div class="label">Broken OU</div></div>
</div>
"@

$bodyHtml = "<header class='banner'>"
$bodyHtml += "<h1>Scan Active Directory Broken Owner - v$ScriptVersion</h1>"
$bodyHtml += "<p>By: Dakhama Mehdi - Baomar Adham &nbsp;|&nbsp; Rapport Date : $date &nbsp; | Elapsed : $elapsed </p>"
$bodyHtml += "</header>"
$bodyHtml += $summaryHtml
$bodyHtml += New-ReportSection -title "Broken Users" -tableId "tbl-users" -data $brokenusers
$bodyHtml += New-ReportSection -title "Broken PC" -tableId "tbl-pc" -data $brokenpc
$bodyHtml += New-ReportSection -title "Broken Groups" -tableId "tbl-groups" -data $brokengroups
$bodyHtml += New-ReportSection -title "Broken OU" -tableId "tbl-ou" -data $brokenou

$scriptTag = @"
<script>
function filterTable(input, tableId) {
    const filter = input.value.toLowerCase();
    const rows = document.getElementById(tableId).getElementsByTagName('tr');
    for (let i = 1; i < rows.length; i++) {
        rows[i].style.display = rows[i].textContent.toLowerCase().includes(filter) ? '' : 'none';
    }
}
</script>
"@

$htmltest = ConvertTo-Html -Head $head -Body $bodyHtml -Title "Scan-AD-Broken-Owner Report"
$htmltest = $htmltest -replace '</body>', "$scriptTag</body>"

#endregion CreateHTML

$htmltest | Out-File report-brokenowner.html
start .\report-brokenowner.html

# You can list result on consol if you use ISE, or use out-gridview
# exemples to list all brokenusers or computers on out-gridview
#$brokenusers + $brokenpc | Out-GridView -Title SCABOO -OutputMode Single 

# SIG # Begin signature block
# MIItjAYJKoZIhvcNAQcCoIItfTCCLXkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBsTBT8oJi0twz4
# //sMuHcSC2SOPdciJzw5svwqU8hg+KCCEtUwggXJMIIEsaADAgECAhAbtY8lKt8j
# AEkoya49fu0nMA0GCSqGSIb3DQEBDAUAMH4xCzAJBgNVBAYTAlBMMSIwIAYDVQQK
# ExlVbml6ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYDVQQLEx5DZXJ0dW0gQ2Vy
# dGlmaWNhdGlvbiBBdXRob3JpdHkxIjAgBgNVBAMTGUNlcnR1bSBUcnVzdGVkIE5l
# dHdvcmsgQ0EwHhcNMjEwNTMxMDY0MzA2WhcNMjkwOTE3MDY0MzA2WjCBgDELMAkG
# A1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xJzAl
# BgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEkMCIGA1UEAxMb
# Q2VydHVtIFRydXN0ZWQgTmV0d29yayBDQSAyMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAvfl4+ObVgAxknYYblmRnPyI6HnUBfe/7XGeMycxca6mR5rlC
# 5SBLm9qbe7mZXdmbgEvXhEArJ9PoujC7Pgkap0mV7ytAJMKXx6fumyXvqAoAl4Va
# qp3cKcniNQfrcE1K1sGzVrihQTib0fsxf4/gX+GxPw+OFklg1waNGPmqJhCrKtPQ
# 0WeNG0a+RzDVLnLRxWPa52N5RH5LYySJhi40PylMUosqp8DikSiJucBb+R3Z5yet
# /5oCl8HGUJKbAiy9qbk0WQq/hEr/3/6zn+vZnuCYI+yma3cWKtvMrTscpIfcRnNe
# GWJoRVfkkIJCu0LW8GHgwaM9ZqNd9BjuiMmNF0UpmTJ1AjHuKSbIawLmtWJFfzcV
# WiNoidQ+3k4nsPBADLxNF8tNorMe0AZa3faTz1d1mfX6hhpneLO/lv403L3nUlbl
# s+V1e9dBkQXcXWnjlQ1DufyDljmVe2yAWk8TcsbXfSl6RLpSpCrVQUYJIP4ioLZb
# MI28iQzV13D4h1L92u+sUS4Hs07+0AnacO+Y+lbmbdu1V0vc5SwlFcieLnhO+Nqc
# noYsylfzGuXIkosagpZ6w7xQEmnYDlpGizrrJvojybawgb5CAKT41v4wLsfSRvbl
# jnX98sy50IdbzAYQYLuDNbdeZ95H7JlI8aShFf6tjGKOOVVPORa5sWOd/7cCAwEA
# AaOCAT4wggE6MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLahVDkCw6A/joq8
# +tT4HKbROg79MB8GA1UdIwQYMBaAFAh2zcsH/yT2xc3tu5C84oQ3RnX3MA4GA1Ud
# DwEB/wQEAwIBBjAvBgNVHR8EKDAmMCSgIqAghh5odHRwOi8vY3JsLmNlcnR1bS5w
# bC9jdG5jYS5jcmwwawYIKwYBBQUHAQEEXzBdMCgGCCsGAQUFBzABhhxodHRwOi8v
# c3ViY2Eub2NzcC1jZXJ0dW0uY29tMDEGCCsGAQUFBzAChiVodHRwOi8vcmVwb3Np
# dG9yeS5jZXJ0dW0ucGwvY3RuY2EuY2VyMDkGA1UdIAQyMDAwLgYEVR0gADAmMCQG
# CCsGAQUFBwIBFhhodHRwOi8vd3d3LmNlcnR1bS5wbC9DUFMwDQYJKoZIhvcNAQEM
# BQADggEBAFHCoVgWIhCL/IYx1MIy01z4S6Ivaj5N+KsIHu3V6PrnCA3st8YeDrJ1
# BXqxC/rXdGoABh+kzqrya33YEcARCNQOTWHFOqj6seHjmOriY/1B9ZN9DbxdkjuR
# mmW60F9MvkyNaAMQFtXx0ASKhTP5N+dbLiZpQjy6zbzUeulNndrnQ/tjUoCFBMQl
# lVXwfqefAcVbKPjgzoZwpic7Ofs4LphTZSJ1Ldf23SIikZbr3WjtP6MZl9M7JYjs
# NhI9qX7OAo0FmpKnJ25FspxihjcNpDOO16hO0EoXQ0zF8ads0h5YbBRRfopUofbv
# n3l6XYGaFpAP4bvxSgD5+d2+7arszgowggZHMIIEL6ADAgECAhA12OBytW+cTayv
# VHUpRhwLMA0GCSqGSIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhB
# c3NlY28gRGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNp
# Z25pbmcgMjAyMSBDQTAeFw0yNTExMTYxMTAwMTlaFw0yNjExMTYxMTAwMThaMG0x
# CzAJBgNVBAYTAkZSMQ8wDQYDVQQHDAZUb3Vsb24xHjAcBgNVBAoMFU9wZW4gU291
# cmNlIERldmVsb3BlcjEtMCsGA1UEAwwkT3BlbiBTb3VyY2UgRGV2ZWxvcGVyLCBE
# QUtIQU1BIE1FSERJMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp6Ku
# m/VmkWCqAaF/3zHh9f1FuJYY2ozbXOu7mo1/Q8i1c0fE0TXpkZXLY2GZbfpj9BmH
# AAFM0IhOsPR2vdxq3jOUJUb9TICneFor6YaPpySsXR3WSE7X42kgpkkmPELovm1Y
# hwSzhJ4a+E+NWL/MU8h5JpmGVlqPJ02/ZTlMj5kcpIQtq8hoQMcUEDkGFt9IcamE
# 1yN4IHkBA5nm4jJPaos0IuS77t805992JSGWhxBxWARH+2vyltv8Rmq1pZV1lE6n
# JgrWT7Ichjw2X/A+OP68ooTzQwCIpzXb4UuUcwHEfrmP3HGMQJoj//SNC4QPMao+
# 3Z8zbevl73E3d6Kfvra1S+pWM2Ze5YCsIqAd98GUHgi5E6GiG8FQq/+d6msL7l8B
# UASCqXlcAKIjRNMHp8BrUaaW6HS9Kpc+3O3t/LUmK6X3FFiW8QsWoh4K+7YSpopa
# CQbNXmEI4xftctwBOJrEU2oqRnYiwchfjqBNlrGwVGPK1rmM0iTt5KiLTus7AgMB
# AAGjggF4MIIBdDAMBgNVHRMBAf8EAjAAMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6
# Ly9jY3NjYTIwMjEuY3JsLmNlcnR1bS5wbC9jY3NjYTIwMjEuY3JsMHMGCCsGAQUF
# BwEBBGcwZTAsBggrBgEFBQcwAYYgaHR0cDovL2Njc2NhMjAyMS5vY3NwLWNlcnR1
# bS5jb20wNQYIKwYBBQUHMAKGKWh0dHA6Ly9yZXBvc2l0b3J5LmNlcnR1bS5wbC9j
# Y3NjYTIwMjEuY2VyMB8GA1UdIwQYMBaAFN10XUwA23ufoHTKsW73PMAywHDNMB0G
# A1UdDgQWBBSXTmfHi9BD9GDRwk5/doNtKHBXYzBLBgNVHSAERDBCMAgGBmeBDAEE
# ATA2BgsqhGgBhvZ3AgUBBDAnMCUGCCsGAQUFBwIBFhlodHRwczovL3d3dy5jZXJ0
# dW0ucGwvQ1BTMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDAN
# BgkqhkiG9w0BAQsFAAOCAgEAe+khGqwUUkFYuFRsrvenX2/a+PIt2Tu9d3VoW6Or
# MX3YLpe7S2CgFkXwEi2Siq5KiD1labP9jsh/3G1ZQwwlnPv8dB7ocl/nOrQ9OZex
# GVE1r7IO6VYVa5F7XuJ/KadKLEbQSs1BpBVhESo1ZYr6w9NCLuO9q2Sh3H5MktET
# D6sB+g1TFOYMdwYl8eAawgI2kGPe3dRQSoumP0mHkm3x5SIwRCW+08md5uyzCIui
# 85WmcNPtM1QCqjkSpfdFGYPsnf/BO9NATpZkqFxhXwa9+PqseX+mofCIL49guCXG
# kU4RpeRHcUie14oYkxvBw7VUO4MT6wYbS2C3j2nyoAV4XqqNMfrhZIBJG5haj2RB
# V46bMJ+DsW6hxlm3lIlCaJT2pLbbk79OP+Bk0HIdC9mAbKzcqaZpBpn4+ljrcx7/
# X7OHv4XTCCDWwlZbaogy4Wci6TiSjjfpfXK5N/eJTEEh2w4qoYTTrR61ptkVnTUT
# vGRfPnVtS/3aOm2v4UahtOc/ygcL0A/J85r1e6CEeOaTm9eJbHoNdwNIYaZ81VlX
# /V/MoJgFCtioYOKiTf2Rdq7XrEEHLU2YGwCqJyKYz9tz10yXBcMW6/+gX+PGqAYz
# eKg5jbKLdi9lVrKspQUXAPHdcl6VJMXy799J0lbsQeJNgBVy6HWxOWvdLBGX3hPE
# 3aYwgga5MIIEoaADAgECAhEAmaOACiZVO2Wr3G6EprPqOTANBgkqhkiG9w0BAQwF
# ADCBgDELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVz
# IFMuQS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEk
# MCIGA1UEAxMbQ2VydHVtIFRydXN0ZWQgTmV0d29yayBDQSAyMB4XDTIxMDUxOTA1
# MzIxOFoXDTM2MDUxODA1MzIxOFowVjELMAkGA1UEBhMCUEwxITAfBgNVBAoTGEFz
# c2VjbyBEYXRhIFN5c3RlbXMgUy5BLjEkMCIGA1UEAxMbQ2VydHVtIENvZGUgU2ln
# bmluZyAyMDIxIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnSPP
# BDAjO8FGLOczcz5jXXp1ur5cTbq96y34vuTmflN4mSAfgLKTvggv24/rWiVGzGxT
# 9YEASVMw1Aj8ewTS4IndU8s7VS5+djSoMcbvIKck6+hI1shsylP4JyLvmxwLHtSw
# orV9wmjhNd627h27a8RdrT1PH9ud0IF+njvMk2xqbNTIPsnWtw3E7DmDoUmDQiYi
# /ucJ42fcHqBkbbxYDB7SYOouu9Tj1yHIohzuC8KNqfcYf7Z4/iZgkBJ+UFNDcc6z
# okZ2uJIxWgPWXMEmhu1gMXgv8aGUsRdaCtVD2bSlbfsq7BiqljjaCun+RJgTgFRC
# tsuAEw0pG9+FA+yQN9n/kZtMLK+Wo837Q4QOZgYqVWQ4x6cM7/G0yswg1ElLlJj6
# NYKLw9EcBXE7TF3HybZtYvj9lDV2nT8mFSkcSkAExzd4prHwYjUXTeZIlVXqj+ea
# YqoMTpMrfh5MCAOIG5knN4Q/JHuurfTI5XDYO962WZayx7ACFf5ydJpoEowSP07Y
# aBiQ8nXpDkNrUA9g7qf/rCkKbWpQ5boufUnq1UiYPIAHlezf4muJqxqIns/kqld6
# JVX8cixbd6PzkDpwZo4SlADaCi2JSplKShBSND36E/ENVv8urPS0yOnpG4tIoBGx
# VCARPCg1BnyMJ4rBJAcOSnAWd18Jx5n858JSqPECAwEAAaOCAVUwggFRMA8GA1Ud
# EwEB/wQFMAMBAf8wHQYDVR0OBBYEFN10XUwA23ufoHTKsW73PMAywHDNMB8GA1Ud
# IwQYMBaAFLahVDkCw6A/joq8+tT4HKbROg79MA4GA1UdDwEB/wQEAwIBBjATBgNV
# HSUEDDAKBggrBgEFBQcDAzAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vY3JsLmNl
# cnR1bS5wbC9jdG5jYTIuY3JsMGwGCCsGAQUFBwEBBGAwXjAoBggrBgEFBQcwAYYc
# aHR0cDovL3N1YmNhLm9jc3AtY2VydHVtLmNvbTAyBggrBgEFBQcwAoYmaHR0cDov
# L3JlcG9zaXRvcnkuY2VydHVtLnBsL2N0bmNhMi5jZXIwOQYDVR0gBDIwMDAuBgRV
# HSAAMCYwJAYIKwYBBQUHAgEWGGh0dHA6Ly93d3cuY2VydHVtLnBsL0NQUzANBgkq
# hkiG9w0BAQwFAAOCAgEAdYhYD+WPUCiaU58Q7EP89DttyZqGYn2XRDhJkL6P+/T0
# IPZyxfxiXumYlARMgwRzLRUStJl490L94C9LGF3vjzzH8Jq3iR74BRlkO18J3zId
# mCKQa5LyZ48IfICJTZVJeChDUyuQy6rGDxLUUAsO0eqeLNhLVsgw6/zOfImNlARK
# n1FP7o0fTbj8ipNGxHBIutiRsWrhWM2f8pXdd3x2mbJCKKtl2s42g9KUJHEIiLni
# 9ByoqIUul4GblLQigO0ugh7bWRLDm0CdY9rNLqyA3ahe8WlxVWkxyrQLjH8ItI17
# RdySaYayX3PhRSC4Am1/7mATwZWwSD+B7eMcZNhpn8zJ+6MTyE6YoEBSRVrs0zFF
# IHUR08Wk0ikSf+lIe5Iv6RY3/bFAEloMU+vUBfSouCReZwSLo8WdrDlPXtR0gicD
# nytO7eZ5827NS2x7gCBibESYkOh1/w1tVxTpV2Na3PR7nxYVlPu1JPoRZCbH86gc
# 96UTvuWiOruWmyOEMLOGGniR+x+zPF/2DaGgK2W1eEJfo2qyrBNPvF7wuAyQfiFX
# LwvWHamoYtPZo0LHuH8X3n9C+xN4YaNjt2ywzOr+tKyEVAotnyU9vyEVOaIYMk3I
# eBrmFnn0gbKeTTyYeEEUz/Qwt4HOUBCrW602NCmvO1nm+/80nLy5r0AZvCQxaQ4x
# ghoNMIIaCQIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0
# YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAy
# MSBDQQIQNdjgcrVvnE2sr1R1KUYcCzANBglghkgBZQMEAgEFAKB8MBAGCisGAQQB
# gjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC4Bc5uQHYtvVEVT4In
# 6cSYnLB2sX7mrVQ9bpIReIyj2jANBgkqhkiG9w0BAQEFAASCAYBThbzTRoHpTAbX
# yVg3g1hvKLBQpnxwNUb0uQ/hZyoWXjW7d2K1TND0PLKfiTkaOIQ/XdJR4eO1sHqp
# yeMLA+rRCI5QbNuC0N/nysHwu2VvIpWC9fbOLxP2goGIM1YMy7Xy5sZWgnVMIxLz
# 0tb/8UR4WWgFcWuQi23wmO5TijMlh6Bij7XXV0lwUfvXDXvx9kiGQhUhSyFP2veJ
# ZP6HcNkdu+6uOriBxmjSPD4mjO55eGWYI4KYvuCLWIr2JTqLjo5CaiTNm7ePKBwC
# IuNiJfxJCpcasHi2L+KphwQjtsPda4JLn9mxDWd3Vz9h+Ww83D4Ji9c5vRNvK+bx
# qBBtrcwL1VvJccxzIDyR9TFQLeRvrdudWSzlEKLq2peEsXx40jBPVORsC5eUAHoL
# diRbJYIiF9nOWIvAZ9YfWry1hw0GW/gYBqAwMKxvGoF1VvDZyYG+ZdVU5sDCEHdi
# YZU4Yw8rn+RGZybMztY+5YQYgNl8PrrnEaumrqNcGubX9xHExcmhghd2MIIXcgYK
# KwYBBAGCNwMDATGCF2IwghdeBgkqhkiG9w0BBwKgghdPMIIXSwIBAzEPMA0GCWCG
# SAFlAwQCAQUAMHcGCyqGSIb3DQEJEAEEoGgEZjBkAgEBBglghkgBhv1sBwEwMTAN
# BglghkgBZQMEAgEFAAQgRiEkL8adumwQDSOXD7tf4M6k9fmC+lQWqYfWzf/diwEC
# ED3K6m6sqvnPlQoPFw+J8fkYDzIwMjYwODE5MTI0MzI4WqCCEzowggbtMIIE1aAD
# AgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQg
# VHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEw
# HhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1
# NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfM
# GUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFP
# JIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMU
# Ng7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjK
# s3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8o
# dbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK4
# 0uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk
# 12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2
# hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6Ct
# juuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT
# 3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A
# 9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx
# 7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtO
# MA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYB
# BQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0
# MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP
# 2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8w
# v2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75
# ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihs
# QyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQ
# JmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz
# 0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8
# MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjF
# BtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJ
# VxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFl
# Txq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMIIGtDCCBJyg
# AwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUw
# NTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2N
# DZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qft
# JYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0t
# rj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX
# 0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEp
# NVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coW
# J+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdk
# DjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0Xb
# Qcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sf
# uZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7v
# QTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwb
# tmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/n
# upiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3Bggr
# BgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0g
# BBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAX
# zvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQ
# a8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd
# 6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FH
# aoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOc
# zgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFb
# qrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z
# 4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT
# 70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43es
# aUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif
# /sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+
# VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBY0wggR1oAMCAQICEA6b
# GI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEk
# MCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAw
# MDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERp
# Z2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMY
# RGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2u
# exuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKv
# aJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/gh
# YZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOt
# yU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCR
# cKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8
# oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m
# 1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y
# 1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkl
# iWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/E
# IFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOC
# ATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/n
# upiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB
# /wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
# LmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqg
# OKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEA
# cKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU
# 9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0Sb
# QyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1Rmpp
# VLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxY
# oA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0Vys
# GMNNn3O3AamfV6peKOK5lDGCA3wwggN4AgEBMH0waTELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVk
# IEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN
# 8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZI
# hvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MDgxOTEyNDMyOFowKwYLKoZIhvcN
# AQkQAgwxHDAaMBgwFgQU3WIwrIYKLTBr2jixaHlSMAf7QX4wLwYJKoZIhvcNAQkE
# MSIEINAIzhECWzsAgd+QBYwgyfA5weIhqviQJBY6W3ZzsH/LMDcGCyqGSIb3DQEJ
# EAIvMSgwJjAkMCIEIEqgP6Is11yExVyTj4KOZ2ucrsqzP+NtJpqjNPFGEQozMA0G
# CSqGSIb3DQEBAQUABIICALhImPmBr+aV2DX4w3x3EzkXk/vHofhhzSC4szl/GX4E
# UZSBXoaVHVivrYT02fVp8ZS9F7SdDGPK+hpOUlAJGFLKYyGs06uIYWimQvqynqNX
# 0I6TUK9yPXS8sXEHxg1eEI9tqM1Oz3bz9rmwg6GNcbknCQ44m7vGpLvh/uS0+mSS
# swn1LZWKGM7xTkupAv+dQ2qWkt4FUFx0Wirv0OAkIbdKtUWoySpPkxpLa+c3rR4R
# JapOfQX3TrqRs5WAtt3AijD84KEOPEymOco71CFCREcSsGKY6IN2WTJlOtCstFR4
# zAg7YbGiipA2hlWKP44Ug9jUHvuRj9o3XDJGEqfFTfu3F+76qCwpS1p2PxDRXWp7
# NpjZejKPmyx/tnvOjH+fkEFYv5/8DqfcOdKbuS3Mk/1OuM5InYFKlCczstjPTQuD
# StpzoPlRPefBpycRatWPYlUtqt2RFm8J3layqmSUSDpujqKkQJ7u8Cx8/Se9Npor
# WYNcs+DnS9c46vV2agZWuaDQGnx62TBAgxvbSv8jjUgytAAQ7rhxB8To2j4LaATr
# 3LmXVR9MQTsd4OE6Rzd8QVvifLWMSIrzTQVNZJxyoHBMR9QWpA47i0bzhVqsfDpT
# e6fB1eDpPSbBIpGbHFQaoUvnvekEv3J8+cVkR4RgvVsSzHVNixCuBzMgKIFVRcS5
# SIG # End signature block
