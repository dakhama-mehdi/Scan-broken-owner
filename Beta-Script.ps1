
<#	
   .NOTES
   ===========================================================================
   Version      : 1
   Updated      : Juin, 2022
   Created by   : Dakhama Mehdi
   Contribution : Souin Matthiew
                  Boamar Adham
   Organization : CADIM.org
   Filename:      Scan-AD-Broken-object-Owner
   Tool Name :    Broken-Owner
   ===========================================================================
  .DESCRIPTION
  This script, help to detect broken owners/representing a risk of (user accounts, Computers, Groups and Organizational Units), Based on Microsoft recommandation
  It generates an HTML page, and does not require any module.
  .How to use 
  Must be turned on machine in domain AD
  Lanuched with user from AD (no right admin or privilege groups is required)
			
#>



#Get Privilege groups domain for filter

$skipdeaultgroups = $null
$skipdeaultgroups = @()	
$skipdeaultgroups += ([adsisearcher]"(&(groupType:1.2.840.113556.1.4.803:=1)(!(objectSID=S-1-5-32-546))(!(objectSID=S-1-5-32-545)))").findall().Properties.name
$skipdeaultgroups += ([adsisearcher] "(&(objectCategory=group)(admincount=1)(iscriticalsystemobject=*))").FindAll().Properties.name

#creating arrays that will contain noncompiding objects    
$brokenusers = $Object = $brokenpc = $null
$brokenusers = [System.Collections.ArrayList]@() 
$brokenpc = [System.Collections.ArrayList]@()
$nbrbrokenusers = $NbrsbrokenPC = 0

#Search computer or user from all domain (search from specific OU will be added later)
#You can stop by ctrl+c script any times

([adsisearcher]"(|(objectCategory=computer)(objectCategory=User))").findall().properties | ForEach-Object {

$name = $_.samaccountname

Write-Output -InputObject "We scanne $name"

$getowner = [ADSI]("LDAP://" + $_.distinguishedname)

#check if owner is different from the array
if ($skipdeaultgroups -notcontains $getowner.PsBase.ObjectSecurity.Owner.Split("\")[1]) { 

#Convert Binary SID     
    $sid = $_["objectsid"][0]
    $sidstring = (New-Object System.Security.Principal.SecurityIdentifier($sid, 0)).Value

    if ($_["objectcategory"][0] -match "Computer") { 
        
        $Object = [PSCustomObject]@{
        Name              = $_["name"][0]
        GivenName         = $_["givenname"][0]  
        SamAccountName    = $_["samaccountname"][0]
        DistinguishedName = $_["distinguishedname"][0]
        Created           = $_["whencreated"][0]
        SID               = $sidstring
        OS                = $_["operatingsystem"][0]
        Owner             = $getowner.PsBase.ObjectSecurity.Owner.Split("\")[1]      
    }

    $brokenpc += $Object                                  
    $NbrsbrokenPC++                              
                                  
                                  } else {


        $Object = [PSCustomObject]@{
        Name              = $_["name"][0]
        GivenName         = $_["givenname"][0]  
        SamAccountName    = $_["samaccountname"][0]
        DistinguishedName = $_["distinguishedname"][0]
        Created           = $_["whencreated"][0]
        SID               = $sidstring
        UserPrincipalName = $_["userprincipalname"][0] 
        Owner             = $getowner.PsBase.ObjectSecurity.Owner.Split("\")[1]



                                  }
    $brokenusers += $Object
    $nbrbrokenusers++

}

    $name = $getowner = $null
    
}
}



#Format HTML Head and page 
$head = @"
<style  type="text/css">
body { background-color:#FFFFFF;
       font-family:Calibri;
              font-size:12pt; }

                h1{
        background-color:green;
        color:white;
        text-align: center;
    }

     h2{
        background-color:red;
        color:white;
        text-align: center;
    }


              td, th { border:0px solid black; 
                       border-collapse:collapse;
    }
                       th { color:white;
                            background-color:Dodgerblue; }
                            table, tr, td, th { padding: 2px; margin: 0px }
                            tr:nth-child(odd) {background-color: lightgray}
                            table {
                            width:95%;
                            margin-left:10px; 
                            margin-bottom:20px;
                            }
                            caption 
                            {
                            background-color:#FFFF66;
                            text-align:left;
                            font-weight:bold;
                            font-size:14pt;
                            }
tr:nth-child(n + 20) {
    visibility: hidden;
}
</style>
"@

#Generate HTML page style
( ConvertTo-Html  -PreContent "<h1>Broken PC : $nbrbrokenusers</h1>" -Head $head) + ($brokenusers | ConvertTo-Html -PreContent "<h1> </h1>" -Head $head) +
( ConvertTo-Html -PreContent "<h1>Broken Users : $NbrsbrokenPC</h1>" -Head $head) + ($brokenpc | ConvertTo-Html -PreContent "<h1> </h1>" -Head $head)  | Out-File Servicesoutput.html

start .\Servicesoutput.html

#You can list result on consol if you use ISE, or use out-gridview
# exemples to list all brokenusers or computers on out-gridview
# $brokenusers + $brokenpc | Out-GridView
