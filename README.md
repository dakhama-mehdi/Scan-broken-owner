# Scan-AD-broken-owner 

![Scboo](Picture/2.png "Scaboo")

(Project in building)


# Description : 
This script aims to help companies audit and have a clean AD, to reduce lateral movement vulnerabilities due to the different risks of kerberos delegation attacks

Script scan and collect broken owners/representing a risk of (user accounts, Computers, Groups and Organizational Units).


# Objective : 

Clean AD and prevent various attacks as well as reduce CT vulnerabilities on objects

# About : 

When an user is specified as the owner of an object, that principal can always change permissions on the object, implicitly, regardless of its permissions. In practice, this means that if you are the owner, you cannot deny yourself access to it. Although you can create explicit deny permission (ACE) entries even for yourself, you can always delete them later as long as you are the owner of the object. Even if the ACL contains no permission entries, the owner can still modify the permissions. Primary owner behavior is implied.

# Recommandation : 

Microsoft recommends placing a Domain Admin privileged group or groups memebers on objects at risk to protect them from various vulnerabilities.

Links : https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd125370(v=ws.10)?redirectedfrom=MSDN

# Why to Use script : 

This script help to list these object who do not possess the legitimate properties recommanded

Prevent Attack : Kerberos Resource-based Constrained Delegation on Computer Object Takeover

# How to use : 

 Script will be available in two version PS1 or GUI (with EXE files signed) 
 
 the PS1 can be used with a AD lite module (if Rsat is not installed in the machine)
 
 if you have RSAT you dont need the source files.
 
 PS : Required PSWriteHtml module to output HMTL format (no needed if use GUI)
 
 # Thanks to All contributors, specified :  
 
 
 DAKHAMA MEHDI
 Souin Mattieuw 
 Adham Bouomar
 
 # Demo : 
 
 ![Scan-broken-owners](https://user-images.githubusercontent.com/49924401/175139428-13175605-2c31-44fe-9b65-e15ba3230097.gif)
 
