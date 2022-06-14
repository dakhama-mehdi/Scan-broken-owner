

<#
.SYNOPSIS
    Collecte des propriétaires (owners) cassées des comptes utilisateurs, Ordinateurs, Groupes et Unités d'Organisation

.DESCRIPTION
    Collecte des propriétaires (owners) des comptes utilisateurs, Ordinateurs, Groupes et Unités d'Organisation

    Quand un objet est créé par un utilisateur non membre d’un des groupes ci-après par le biais d’une délégation ou de l’utilisation du groupe « Opérateur de compte »,
    c’est l’utilisateur qui a créé l’objet qui en est le propriétaire.
    Groupes :   Administrateurs du domaine
                Administrateurs de l’entreprise
                BUILTIN\Administrateurs
                AUTORITE NT\Système

    Si un filtre est effectué via le nom des groupes, celui-ci doit être adapté à la langue d'installation du contrôleur de domaine sur lequel vous opérez.
    C'est pourquoi, on préfèrera utiliser pour filtrer les "Well-known SIDs"

    Cette situation peut poser des problèmes de sécurité, cf : https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution
    Si vous avez seulement quelques objets, il est possible de le corriger à la main, mais si vous en avez plusieurs dizaines/centaines, cela peut prendre beaucoup de temps.

   Dans le cas d'utilisation ANSSI, le script permet de corriger le probleme : vuln3_owner
   https://www.cert.ssi.gouv.fr/uploads/guide-ad.html#owner

.NOTES
    Version : 3.0
    Date : 13/06/2022
        Utilisation de GenericList au lieu d'Array (plus rapide sur grosses collections)
        Génération rapport au format HTML
        Uitlisation des Well-Known SID au lieu des Names pour les filtres
#>

#region Params
<# permet d'ajouter les paramètres communs dont le verbose Mode
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
Import-Module .\sources\Microsoft.ActiveDirectory.Management.dll
Import-Module .\sources\Microsoft.ActiveDirectory.Management.resources.dll

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

    $genericgroups = $skipdeaultgroups = $conditions = $null
	$genericgroups = $skipdeaultgroups = @()
	
	$dom = (Get-ADDomain)
	$domsid = $dom.domainsid.tostring()
	$domain = $dom.DistinguishedName

	$skipdeaultgroups += (Get-ADGroup -filter 'SID -ne "S-1-5-32-545" -and SID -ne "S-1-5-32-546"' -Searchbase (Get-ADObject -Filter 'name -eq "Builtin"')).name
	$skipdeaultgroups += (Get-ADGroup -Filter { AdminCOunt -eq 1 -and iscriticalsystemobject -like "*" }).Name
	$skipdeaultgroups += (Get-ADGroup ($domsid + '-522')).name
    
    $brokenusers = $brkoencomputers = $brokengroups = $brokenou = $null
#endregion Infos sur le domaine

#region Utilisateurs

# Initialisation d'un object GenericList
$brokenusers = [System.Collections.Generic.List[PSCustomObject]]::new()
$nbrsUsers = $NbrsbrokenPC = 0

# Collecte des info de l'AD
Write-Host 'Collecte des infos sur les comptes utilisateurs'
Get-ADUser -Filter * | ForEach-Object {

$var = $null

$name = $_.name

$var= [ADSI](([ADSISearcher]"(name=$name)").Findall().Path)

if ($skipdeaultgroups -notcontains $var.PsBase.ObjectSecurity.Owner.Split("\")[1]) { 


  $Obj = [PSCustomObject]@{
        Name              = $_.name
        GivenName         = $_.givenname   
        SamAccountName    = $_.samaccountname    
        DistinguishedName = $_.distinguishedname
        ObjectGUID        = $_.ObjectGUID
        SID               = $_.sid
        UserPrincipalName = $_.userprincipalname 
        Owner             = $var.PsBase.ObjectSecurity.Owner.Split("\")[1]
      
    }

    # Add $Obj to $ResultUsers
   $brokenusers.add($Obj)

    $NbrsbrokenPC++

}
    
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
Get-ADComputer -Filter * | ForEach-Object {

$var = $name = $null

$name = $_.SamAccountName

$var= [ADSI](([ADSISearcher]"(SamAccountName=$name)").Findall().Path)


if ($genericgroups -notcontains $var.PsBase.ObjectSecurity.Owner -and $skipdeaultgroups -notcontains $var.PsBase.ObjectSecurity.Owner.Split("\")[1]) { 


  $Obj = [PSCustomObject]@{
        Name              = $_.name
        DistinguishedName = $_.distinguishedname
        Enabled           = $_.Enabled
        SID               = $_.sid
        SamAccountName    = $_.samaccountname 
        ObjectGUID        = $_.ObjectGUID
        Owner             = $var.PsBase.ObjectSecurity.Owner.Split("\")[1]
      
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

#region Groupes
# Initialisation d'un object GenericList
$brokengroups = [System.Collections.Generic.List[PSCustomObject]]::new()
$nbrgroups = $nbrbrokengrp = 0

# Collect AD infos
Write-Host 'Collecte des infos sur les groupes'
Get-ADGroup -Filter * | ForEach-Object {

$var = $null

$name = $_.SamAccountName 

$var= [ADSI](([ADSISearcher]"(SamAccountName=$name)").Findall().Path)


if ($genericgroups -notcontains $var.PsBase.ObjectSecurity.Owner -and $skipdeaultgroups -notcontains $var.PsBase.ObjectSecurity.Owner.Split("\")[1]) { 


  $Obj = [PSCustomObject]@{
        Name              = $_.name
        DistinguishedName = $_.distinguishedname
        GroupCategory     = $_.GroupCategory
        GroupScope        = $_.GroupScope
        SamAccountName    = $_.samaccountname    
        ObjectGUID        = $_.ObjectGUID
        SID               = $_.sid
        Owner             = $var.PsBase.ObjectSecurity.Owner.Split("\")[1]
      
    }

    # Add $Obj to $ResultUsers
    $brokengroups.add($Obj)

    $nbrbrokengrp++

    }

    $nbrgroups++

}



$SynthesisGroupsAccounts = [PSCustomObject]@{
    'Nombre total de Groupes'                           = $nbrgroups
    'Nombre total de Groupes Après filtrage à corriger' = $nbrbrokengrp
}
Write-Verbose 'Synthèse des info sur les Groupes'

#endregion Groupes

#region Unités d'Organisation
# Initialisation d'un object GenericList
$BrokenOU = [System.Collections.Generic.List[PSCustomObject]]::new()
$nbrsOU = $nbrbrokenou = 0

# Collect AD infos
Write-Host 'Collecte des infos sur les OUs'
Get-ADOrganizationalUnit -Filter * | ForEach-Object {

$var = $null

$name = $_.DistinguishedName

$var= [ADSI](([ADSISearcher]"(DistinguishedName=$name)").Findall().Path)

if ($genericgroups -notcontains $var.PsBase.ObjectSecurity.Owner -and $skipdeaultgroups -notcontains $var.PsBase.ObjectSecurity.Owner.Split("\")[1]) { 


  $Obj = [PSCustomObject]@{
        Name              = $_.name
        DistinguishedName = $_.distinguishedname
        City              = $_.City
        Country           = $_.Country
        ManagedBy         = $_.ManagedBy   
        ObjectGUID        = $_.ObjectGUID
        Owner             = $var.PsBase.ObjectSecurity.Owner.Split("\")[1]
               
   }

    # Add $Obj to $ResultUsers
    $NoGoodOU.add($Obj)

    $nbrbrokenou++

}

    $nbrsOU++
}


$SynthesisOUsAccounts = [PSCustomObject]@{
    "Nombre total des OUs"  = $nbrsOU
    "Nombre total des OUs Après filtrage à corriger" = $nbrbrokenou
}



#endregion Unités d'Organisation

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

    # 3ème Onglet Groupes
    New-HTMLTab -Name "Groupes" {

        # Ici on va mettre les informations qu'on a préalablement mis dans la variable $SynthesisGroupssAccounts
        New-HTMLTable -DataTable $SynthesisGroupsAccounts {
         New-TableContent -ColumnName 'Nombre total de Groupes' -Alignment center -BackGroundColor BrightGreen
         New-TableContent -ColumnName 'Nombre total de Groupes Après filtrage à corriger' -Alignment center -Color white -BackGroundColor BurntOrange
        } # end-HewhtmlTable

        # Ici on va mettre les informations qu'on a préalablement mis dans la variable $NoGoodGroups
        New-HTMLTable -DataTable $brokengroups {
            New-TableContent -ColumnName 'Name' -Alignment center
            New-TableContent -ColumnName 'Owner' -Alignment center -Color white -BackGroundColor BrightRed
        } # end-HewhtmlTable

    }  # end New-HtmlTab

    # 4ème Onglet Groupes
    New-HTMLTab -Name "OU" {

        # Ici on va mettre les informations qu'on a préalablement mis dans la variable $SynthesisGroupssAccounts
        New-HTMLTable -DataTable $SynthesisOUsAccounts {
         New-TableContent -ColumnName 'Nombre total des OUs' -Alignment center -BackGroundColor BrightGreen
         New-TableContent -ColumnName 'Nombre total des OUs Après filtrage à corriger' -Alignment center -BackGroundColor BurntOrange
        } # end-HewhtmlTable

        # Ici on va mettre les informations qu'on a préalablement mis dans la variable $NoGoodGroups
        New-HTMLTable -DataTable $NoGoodOU {
            New-TableContent -ColumnName 'Name' -Alignment center
            New-TableContent -ColumnName 'Owner' -Alignment center -Color white -BackGroundColor BrightRed
        } # end-HewhtmlTable

    }  # end New-HtmlTab

    }  # end New-HtmlTab


#endregion export in html
