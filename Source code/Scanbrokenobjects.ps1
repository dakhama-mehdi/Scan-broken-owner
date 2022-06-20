
# Script on Beta Version

<#
.SYNOPSIS
    Collection of broken owners of user accounts, Computers, Groups and Organizational Units

.DESCRIPTION
    Collection of owners (owners) of user accounts, Computers, Groups and Organizational Units

    When an object is created by a user who is not a member of one of the groups below through delegation or the use of the "Account Operator" group,
    the user who created the object is the owner.
    Groups: Domain Admins
                Company administrators
                BUILTIN\Administrators
                NT AUTHORITY\System

    If a filter is performed via the name of the groups, this must be adapted to the installation language of the domain controller on which you operate.
    Therefore, we prefer to use to filter "Well-known SIDs"

    This situation can pose security problems, see : https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution
    If you only have a few objects, it is possible to correct it by hand, but if you have several tens/hundreds, it can take a long time.

   In the case of ANSSI use, the script makes it possible to correct the problem: vuln3_owner
   https://www.cert.ssi.gouv.fr/uploads/guide-ad.html#owner

.NOTES
    Version : 4.0
    Change : Add ADSI queries, rebuild all search method
    Date : 13/06/2022
        Using GenericList instead of Array (faster on big collections)
        Generating report in HTML format
        Using Well-Known SIDs instead of Names for filters
#>

#region Params
<# allows to add common parameters including verbose Mode
[CmdletBinding()]
param (
    [Parameter()]
    [ValidateScript( { if ( -not ( $Computer | Test-Path -PathType leaf ))
            {
                throw 'Le path doit être un path de fichier'
            } } )]
    [String]

    $ReportPath = "$currentpath\ADObjectOwners-Au-$(Get-Date -f 'dd-MM-yyyy').html"

    Contribution : 

    DAKHAMA MEHDI
    OLIVIER THE Frog
    Bouamar Adham
    mdunca83
)
#>

#endregion Params

#region Settings


 $currentpath = Get-Location
 $ReportPath = "$currentpath\ADObjectOwners-Au-$(Get-Date -f 'dd-MM-yyyy').html"


Write-Verbose 'Paramétrage pour utiliser TLS1.2 pour metre à jour les modules sur PowershellGallery à partir du 01/04/2020'
# ref : https://devblogs.microsoft.com/powershell/powershell-gallery-tls-support/
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Verbose 'Paramétrage du comportement par défaut de certaines cmdlets'
$PSDefaultParameterValues = @{
    'New-HTMLSection:HeaderBackGroundColor' = 'Green'
    'New-HTMLSection:CanCollapse'           = $true
}
#endregion Settings

#region Modules
Write-Verbose 'Chargement du module PSWriteHtml'
Function Test-Module ()
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String[]]
        $ModuleName
    )
    if (-not (Get-Module -ListAvailable -Name PSWriteHtml))
    {
        Write-Verbose "Module $ModuleName non installé. Téléchargement..."
        Install-Module -Name PSWriteHtml -Scope CurrentUser -Verbose
    }
}

# Modules necessaires
$Modules = 'PSWriteHtml' # les séparer par "," si plusieurs modules
Test-Module -ModuleName $Modules
Write-Verbose "Chargement des modules : $( $Modules -join(' - ') )"
Import-Module -Name $Modules
#endregion Modules

#region Infos sur le domaine
<#
On préfèrera utiliser une Query WMI pour identifier le Domaine. En effet, si le compte qui exécute le script est membre d'un autre AD,
et dispose de droits sur le domaine courant via une relation d'Approbation, les Cmdlets Get-AD... (ex. : Get-ADDomain, Get-ADUsers,... ) retourneront les info du domaine du compte
au lieu du domaine du DC sur lequel on opère.
#>

    $skipdeaultgroups = $null
	$skipdeaultgroups = @()
	
	$skipdeaultgroups += ([adsisearcher]"(&(groupType:1.2.840.113556.1.4.803:=1)(!(objectSID=S-1-5-32-546))(!(objectSID=S-1-5-32-545)))").findall().Properties.name
	$skipdeaultgroups += ([adsisearcher] "(&(objectCategory=group)(admincount=1)(iscriticalsystemobject=*))").FindAll().Properties.name
    
    $brokenusers = $brkoencomputers = $brokengroups = $brokenou = $null
#endregion Infos sur le domaine

#region Utilisateurs

# Initialisation d'un object GenericList
$brokenusers = [System.Collections.Generic.List[PSCustomObject]]::new()
$nbrsUsers = $NbrsbrokenPC = 0

# Collecte des info de l'AD
Write-Host 'Collecte des infos sur les comptes utilisateurs'
([adsisearcher]"(&(objectCategory=User))").findall().properties | ForEach-Object {

$name = $_.samaccountname

Write-Host on scanne $name `r`n

$getowner = [ADSI]("LDAP://" + $_.distinguishedname)

if ($skipdeaultgroups -notcontains $getowner.PsBase.ObjectSecurity.Owner.Split("\")[1]) { 


c

  $Obj = [PSCustomObject]@{
        Name              = $_["name"][0]
        GivenName         = $_["givenname"][0]  
        SamAccountName    = $_["samaccountname"][0]
        DistinguishedName = $_["distinguishedname"][0]
        ObjectGUID        = $_["ObjectGUID"][0]
        SID               = $sidstring
        UserPrincipalName = $_["userprincipalname"][0] 
        Owner             = $getowner.PsBase.ObjectSecurity.Owner.Split("\")[1]
      
    }

    # Add $Obj to $ResultUsers
   $brokenusers.add($Obj)

    $NbrsbrokenPC++

}

    $name = $getowner = $null
    
    $nbrsUsers++
    # reset des valeurs des variables pour le tour suivant de la boucle
}


$SynthesisUsersAccounts = [PSCustomObject]@{
    'Nombre total de comptes Utilisateurs'                           = $nbrsUsers
    'Nombre total de comptes Utilisateurs Après filtrage à corriger' = $NbrsbrokenPC
}
Write-Verbose 'Synthèse des info Utilisateurs'

#endregion Utilisateurs

#region Ordinateurs

# Initialisation d'un object GenericList
$brkoencomputers = [System.Collections.Generic.List[PSCustomObject]]::new()
$nbrsPC = $NbrsbrokenPC = 0

# Collecte des info de l'AD
Write-Host 'Collecte des infos sur les comptes Ordinateurs'
([adsisearcher]"(&(objectCategory=computer))").findall().properties | ForEach-Object {

$getowner = $null

$name = $_.samaccountname

Write-Host on scanne $name `r`n

$getowner = [ADSI]("LDAP://" + $_.distinguishedname)


if ($skipdeaultgroups -notcontains $getowner.PsBase.ObjectSecurity.Owner.Split("\")[1]) { 
    

    $sid = $_["objectsid"][0]
    $sidstring = (New-Object System.Security.Principal.SecurityIdentifier($sid, 0)).Value

  $Obj = [PSCustomObject]@{
        Name              = $_["name"][0]
        DistinguishedName = $_["Enabled"][0]
        Enabled           = $_["samaccountname"][0]
        SID               = $_["distinguishedname"][0]
        SamAccountName    = $_["whencreated"][0] 
        ObjectGUID        = $sidstring
        OperatingSysteme  = $_["operatingsystem"][0]
        Owner             = $getowner.PsBase.ObjectSecurity.Owner.Split("\")[1]
      
    }

    # Add $Obj to $ResultUsers
    $brkoencomputers.add($Obj)

    $NbrsbrokenPC++
}
    $nbrsPC++
  
}


#$NoGoodComputers = $ResultComputers.Where({ $Computer.SID -notin $Filter })
Write-Verbose "Comptes Ordinateurs filtrés des groupes/comptes Builtin  qui doivent être corrigés : $NbrsbrokenPC "

$SynthesisComputersAccounts = [PSCustomObject]@{
    'Nombre total de comptes Ordinateurs'                           = $nbrsPC
    'Nombre total de comptes Ordinateurs Après Filtrage à Corriger' = $NbrsbrokenPC
}
Write-Verbose 'Synthèse des info Ordinateur'

#endregion Ordinateurs


#region export in html
Write-Verbose 'Génération du rapport ...'

New-HTML -FilePath $ReportPath -Online -ShowHTML {

    # 1er Onglet Utilisateurs
    New-HTMLTab -Name "Comptes Utilisateurs" {

        # Ici on va mettre les informations qu'on a préalablement mis dans la variable $SynthesisUsersAccounts
        New-HTMLTable -DataTable $SynthesisUsersAccounts {
            New-TableContent -ColumnName 'Nombre total de comptes Utilisateurs' -Alignment center -BackGroundColor BrightGreen
            New-TableContent -ColumnName 'Nombre total de comptes Utilisateurs Après filtrage à corriger' -Alignment center -BackGroundColor BurntOrange
        } # end-HewhtmlTable

        # Ici on va mettre les informations qu'on a préalablement mis dans la variable $NoGoodUsers
        New-HTMLTable -DataTable $brokenusers {
            New-TableContent -ColumnName 'Name' -Alignment center
            New-TableContent -ColumnName 'Owner' -Alignment center -Color white -BackGroundColor BrightRed
        } # end-HewhtmlTable

    } # end New-HtmlTab

    # 2ème Onglet Ordinateurs
    New-HTMLTab -Name "Comptes Ordinateurs" {

        # Ici on va mettre les informations qu'on a préalablement mis dans la variable $SynthesisComputersAccounts
        New-HTMLTable -DataTable $SynthesisComputersAccounts {
            New-TableContent -ColumnName 'Nombre total de comptes Ordinateurs' -Alignment center -BackGroundColor BrightGreen
            New-TableContent -ColumnName 'Nombre total de comptes Ordinateurs Après Filtrage à Corriger' -Alignment center -BackGroundColor BurntOrange
        } # end-HewhtmlTable

        # Ici on va mettre les informations qu'on a préalablement mis dans la variable $NogoosComputers
        New-HTMLTable -DataTable $brkoencomputers {
            New-TableContent -ColumnName 'Name' -Alignment center
            New-TableContent -ColumnName 'Owner' -Alignment center -Color white -BackGroundColor BrightRed
        } # end-HewhtmlTable

    }  # end New-HtmlTab

}

#endregion export in html
