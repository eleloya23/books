# BOOK

* **Title**: Hardening Linux
* **Authors**: JAMES TURNBULL
* **Link**: http://www.worldcat.org/oclc/517751119
* **Publication**: 2005
* **Tags**: SECURITY, LINUX

# SUMMARY

## Basic Security Tenants

1. **Be minimalistic**
2. **Defense in Depth**
3. **Vigilance**

### Be minimalistic, and minimize risk

- The safest way to reduce risk is to not introduce them in the first place.
- Keep the security solution simple. 
- Eliminate anything you don't need: users, files, servers, configuration, services and software.

### Defense in Depth

- Do not rely on a single layer of defense for your hosts.
- Protect and defend your systems in multiple layers: 
  - at the outer layer / firewall
  - at the application layer
  - at the operating system layer
  - at the kernel layer
  - at the bios/firmware layer
  - at the physical layer
  
### Vigilance

- Even our systems/software are subject to entropy.
- As time goes on, your system becomes less and less secure.
- The solution is monitoring. 
- Define a baseline for normal behaviour. Monitor for anything abnormal.
- Truly vigilant test. Periodically perform penetration testing of your systems using automated tools like Nessus or other commercial tools.
- Keep up-to-date with vulnerabilities, threats, and exploits. Subscribe to the security newsletter your vendors and dependencias have.

## Chapter 1 - Basics

1. **Install the distribution/os securely**
  - Always verify the signature and checksum of the operating system and packages you will install.
  - Use the minimal system available.
  - Remove X-Windows and all packages that are unnecesary to your production system.
  - Try to make the installation offline from the internet.
  - Recommended to use a central system to download and verify packages and updates.
2. **Secure the bootloader**
  - Do not leave older kernel versions hanging around in your system. Specially if you just upgraded for security reasons! An attacker can and will reboot your system using an older kernel version.
  - Password protect the bootloader. GRUB and LILO for example can be configured to ask for a password before entering single-mode or changing kernels at boot time.
3. **Init, Starting Services and Boot Sequencing**
  - Limit shutdown to specific users (or root only). Protect against a simple DoS.
  - The book argues to reduce the number of virtual terminals available. Specially if you don't have multiple users in it.
  - The starting services have a boot sequence. Make sure the order/sequence of the services does not leave them unprotected for brief periods of time. E.g. Your firewall must load before your webserver.
  - Ensure proper file permissions on the init files. An attacker may modified them and reboot your system to gain additional access.
  - Allow root only one terminal. Modify /etc/securetty for that. This limits root to only 1 login at a time.
  - Lock and password protect virtual terminals with vlock. The same way you lock your GUI Desktop System. It is also important to keep your ttys locked when you are not present.
  - Remove identifiable information from the loginscreen /etc/issue. Don't show system name, operating system, software or location to potential attackers.
4. **Users and Groups**
  - User wihtout shell access commonly have */bin/false* or */bin/nologin* on */etc/passwd*. Replace it with a binary that supports the detection of access to disabled accounts. E.g. **NoShell** from titantools does that by logging the attempt.
  - List and remove unnecessary users and groups from your system. This may break some packages, so you must test it beforehand.
  - Use a better hashing (SHA512) than DES or MD5 for the local users password on /etc/shadow. This is done on the password module in /etc/pam.d/.
  - Enforce secure password policies in the system. This usually done on the passwd module in /etc/pam.d/. It will at least protect yourself against your own lazyness.
  - Recommended to also enforce password aging. Entropy again.
  - On production systems there is no need for users to have unrestricted access to sudo. Users with administrative roles should be given restricted access to sudo (only certain commands).
5. **Process Accounting**
  - Keep a log of the programs/commands run by your users.
  - You may use a package like acct to achieve this.
  - Allows you query who used what and when.
6. **PAM**
  - When a PAM-aware application doesn't find or doesn't have a module. It defaults to the /etc/pam.d/other configuration. Default behaviour should be to deny.
  - PAM helps you to limit resources on logged-in users. The configuration here depends on your specific use cases.
  - For example, you may limit remote access to specific days and hours. May help you protect against those Russians on a different timezone trying to hack you at 3 a.m. while you're sleeping :p .
  - Also, you can also configure it to send login alerts on specific users.
7. **File Integrity**
  - Learn to verify checksums and signatures. Verify always before installing packets.
  - Remove Compilers and Development Tools You can also just restrict them to root only. Development tools are helpful for you, but also to your attackers!.
8. **Hardening the Kernel**
    - You *should* use hardened kernel.
    - Review different hardened kernels before choosing one. OPENWALL/GRSEC/LIDS/SELINUX/etc.
    - Test that your applications/services still work in a hardened kernel.
    - Hardened kernels may give you usefull protections like:
      - Protection against buffer overflows. 
      - Protection against linking attacks.
      - Protection against untrusted named pipes.
      - Restricts access to /proc. Users can only see their own processes.
      - Many more

## Chapter 2 - Firewalling Your Hosts

- In addition to firewalling the perimeter of your network. You must also protect individual hosts. Firewalls give you protection from unwanted incoming and outoging traffic.
- Any access should be the exception, not the rule.
- Change default iptables policy from ACCEPT to DROP.
- The best way to determine what rules to implement is to monitor/log normal activity in your network. After that you can extract the rules needed for the system to work.
- Be very specific with what you allow. E.g.
  - This rule ```ipables -A INPUT -i eth0 -p tcp --dport 80 -m state--state NEW,ESTABLISHED -j ACCEPT``` is more secure than this rule ```ipables -A INPUT --dport 80 -j ACCEPT```
  - Why? Because an attacker may put a rootkit listening on port 80 udp. Or on port 80 on a different interface. This is why you have to be very specific about your exceptions.
- *Mostly* only allow ESTABLISHED or RELATED connections for outgoing traffic. This helps you protect against data exfiltration or lateral movement inside your network. E.g.
  - ```iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT```. This for example will prevent an attacker already in your system from initiating new ssh connections to the inside of your network (lateral movement). The only outgoing traffic allowed on port 22 is for already established connections.
- Use the firewall to log malicious or suspicious traffic. It can provide early warning from an attack.
- Implement rules to drop [common malicious and bogus traffic](https://security.blogoverflow.com/2011/08/base-rulesets-in-iptables/). ICMP attacks, DDoS attacks, Spoofing, Invalid packets, etc.
- In addition to the firewall, you can also further secure your system by configuring some kernel parameters. 
  - Disable ipforward if you dont need it. /proc/sys/net/ipv4/ip_forward
  - Disable ICMP redirects. /proc/sys/net/ipv4/conf/all/accept_redirects
  - Disable source-routed packets. /proc/sys/net/ipv4/conf/all/accept_source_route
  - Enable log_martians. This logs packets with invalid addresses. /proc/sys/net/ipv4/conf/all/log_martians
  - Enable reverse path filtering. Enforces that the packets ipaddressess and interfaces must match with what you have on your routing table. Otherwise they are rejected. Prevents some spoofing attacks. /proc/sys/net/ipv4/conf/all/rp_filter
  - Enable icmp_echo_ignoreall. This parameters makes your system ignore ping echo requests from the internet. /proc/sys/net/ipv4/icmp_echo_ignore_all
  - Enable icmp_echo_ignore_broadcasts. Prevents smurf attacks. /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
  - Enable tcp_syncookies. To protect against SYN Flooding attacks. /proc/sys/net/ipv4/tcp_syncookies

## Chapter 3 - Securing Connections and Remote Administration

- It is recommended to implement a VPN like IPSEC to access your systems.
- IPSEC for example encrypts the data at the ip packet level. Which means you can use it on-top of SSL even. Giving you two layers with two different crypto algorithms.
- Recommended to disable ssh agent forwading. You may not want your private key being forwarded to the memory of a potentially compromised system.
- Prefer public key authentication over password authentication.
- Enable StrictHostKeyChecking for OpenSSL. Protects you against dns spoofing attacks.
- Enable UsePriviledgeSeparation for OpenSSL. This way OpenSSL uses an unpriviledged sshd deamon to handle authentication. This protects you against zero-days on the sshd deamon (given that it usually runs as root always).
- Whitelist the users that can login to the system with ssh. It should be restricted on a production system.
- You can protect unencrypted administrative services by encaptsulating them on an SSL Tunnel using STUNNEL. 

## Chapter 4 - Securing Files and File Systems

- Increase default umask from 022 to 077. UMASK changes the default permissions on new files. On production systems it is recommend that only the file owner has access to the file. 
- Find files that have world write permissions & AUDIT them ```find / -perm -o=w ! -typle l -ls```
  - Remember that an unprivileged attacker will look for ways to use them.
- Use sticky bit to restrict file deletion to only the file owner. ```chmod +t /tmp/file_undeletable_by_others```
- Find unowned files & AUDIT them, they are a red flag. ```find / -nouser -o -nogroup -ls```
- Inmutable files is a powerful feature of ext2 and ext3 filesystems.
  - Activate the inmutable flag to disallow modification, deletion, renaming and hard linking by anyone (even the owner) ```chattr -V +l /etc/password``` You may also use the attribute a for modification in append mode only (useful for logs)
  - This is specially good for configuration files that should be inmutable. You don't want an attacker modifying them!
  - On hardened systems, ideally, all binaries should be immutable to avoid replacement. Obviously, you would have to remove the flag before upgrading the system.
- You may add capabilities to the system using the lcap package. It can remove capabilities to certain users (even root!). This limits the amount of damage that can be done to the system. Changing capabilities requiere a full restart. [Read](http://lukehinds.com/2016/02/07/linux-capabilities.html) about [them](https://linux.die.net/man/7/capabilities).
- Configure mount options to further secure certain areas of your system (readonly,noexec,nodev, etc)
  - For example, if your application has a folder where users can upload stuff. It better be mounted with noexec privileges. Inmutable configuration files may be mounted using the special readonly mounting option. This way no normal users can change them. Read about them and use this features!
- You can manually make encrypted volumes to secure information using tools like EncFS or Loop-AES.
- Use a file monitor like TripWire. It allows you to set rules for specific files.
  - This is very good if you want alerts whenever someone:
    - Modifies a specific file
    - Deletes a specific file
    - Tries to replace something (checksum monitoring)

## Chapter 5 - Logging

- If you want to centralize logging. Don't use syslogd. Use an alternative.
- Put logs in a non-root partision to prevent the system from crashing in the event it grows to saturation levels (possible because of an DoS attack).
- The important thing before analyzing the logs is to think "What am I even looking for". You have to test the system, try to break it, do abnormal stuff. Put attention to "what got" logged on your attempts to break it. Look for patterns that you can later search for when your systems fails or are compromised.
- An interesting log monitor is SEC. It is a flexible log analyzer that can spawn commands when certain criteria is met. Or it can just further log or alert you based on custom triggers. 
- You can use a tool like logrotate to manage the rotation of your logs.

## Chapter 6 - Using Tools for Security Testing

- The basic takeaway from this chapter is that **you must always test your security, and do it periodically**.
- You should check for rootkits in the system. Attackers generally want to secure later access to a compromised system. Use tools like RkHunter or ChkRootkit for this. 
- Use NMAP to periodically check which services are running on your networks.
- Use NESSUS to periodically verify that public exploits don't break your system.
- In the event your system was compromised. Record everything you can before pulling the plug.
  - puppy# script -a penetration_log.txt
  - puppy# (date; uname -a)
  - puppy# (ps -aux; ps -auxeww; lsof) > current_procs.txt
  - puppy# tar -cvpf proc_directory.tar /proc/[0-9]*
  - puppy# (date; uname -a; netstat -p; netstat -rn; arp -v) > network_status.txt
  - Finally, take a snapshot of the currently active and kernel memory
  - puppy# dd bs=1024 < /dev/mem > mem
  - puppy# dd bs=1024 < /dev/kmem > kmem
  - It is recommended to also take a snapsho of the disk for future forensic work. 
  - puppy# dd if=/dev/hda1 bs=1024 > hda1 


####Chapter 7 - Securing Your Mail Server
####Chapter 8 - Authenticating and Securing Your Mail
####Chapter 9 - Hardening Remote Access to E-Mail
####Chapter 10 - Securing a FTP Server
####Chapter 11- Hardening DNS and BIND

I didn't read these last 5 chapters because I didn't have use for them. I'm not planning on hosting mail, ftp or dns server anytime soon. You may contribute, I'm happy to accept a pull request.

