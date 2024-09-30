

## Posts

-   Aug 31, 2024

    ### [HTB: Skyfall](/htb-skyfall.md)

    #ctf #hackthebox #htb-skyfall #nmap #feroxbuster #ffuf #subdomain
    #ssrf #minio #nginx-flask-parse #burp #burp-repeater #cve-2023-28432
    #cve-2023-28434 #hashicorp-vault #fuse #go-fuse #memfs #sshfs

    ![](/img/skyfall-cover.png)

    Skyfall is all about enumerating technolories like MinIO and Vault.
    I'll start with a demo website that has a MinIO status page blocked
    by nginx. I'll abuse a parser breakdown between nginx and flask to
    get access to the page, and learn the MinIO domain. From there, I'll
    exploit a vulnerability in MinIO that leaks the admin username and
    password. With access to the MinIO cluster, I'll find a home
    directory backup where a previous version contained a sensitive
    Vault token in the Bash configuration file. I'll use that to get
    access to the Vault instance and SSH access. From there, I'll have
    the ability to run a script the unseal the Vault as root. This
    generates a log file that I can't read. I'll abuse FUSE to generate
    an in-memory filesystem that allows for root to write to it but that
    I can still read.

-   Aug 24, 2024

    ### [HTB: Runner](/htb-runner.md)

    #htb-runner #ctf #hackthebox #nmap #ffuf #subdomain #teamcity
    #ubuntu #feroxbuster #cve-2023-42793 #authentication-bypass #docker
    #hsql #hypersql #portainer #hashcat #cve-2024-21626

    ![](/img/runner-cover.png)

    Runner is all about exploiting a TeamCity server. I'll start with an
    authentication bypass vulnerability that allows me to generate an
    API token. There's two ways to exploit this, by enabling debug more
    and running system commands in the TeamCity container, or creating
    an admin user and getting a backup from the TeamCity GUI. Either
    way, I get access to the TeamCity data, where I can find password
    hashes and an SSH key. I'll use the SSH key to get a shell on the
    host. There I'll abuse a vulnerable runc binary. To exploit this,
    I'll have to work through Portainer, which is a neat challenge as
    all the POCs for this vulnerability assume the user is working from
    the Docker group, but I am not.

-   Aug 22, 2024

    ### [HTB Sherlock: Reaper](/htb-sherlock-reaper.md)

    #ctf #htb-sherlock #hackthebox #forensics #sherlock-reaper #dfir
    #ntml #net-ntlmv2 #ntlmrelayx #ntlm-relay #win-event-4624
    #win-event-5140 #pcap #wireshark #llmnr #jq evtx-dump

    ![](/img/sherlock-reaper.png)

    Reaper is the investigation of an NTLM relay attack. The attacker
    works from within the network to poison an LLMNR response when a
    victim has a typo in the host in a share path. This results in the
    victim authenticating to the attacker, who relays the authentication
    to another workstation to get access there. I'll show how this all
    happened using the given PCAP and Windows Security Log.

-   Aug 17, 2024

    ### [HTB: FormulaX](/htb-formulax.md)

    #htb-formulax #hackthebox #ctf #nmap #ubuntu #express #nodejs
    #python #socket-io #xss #simple-git #git #cve-2022-24433
    #cve-2022-24066 #cve-2022-25912 #cve-2022-25860 #command-injection
    #librenms #mongo #hashcat #bcrypt #snmp-trap #libreoffice
    #apache-uno #file-read #formula-injection #htb-corporate #htb-visual

    ![](/img/formulax-cover.png)

    FormulaX is a long box with some interesting challenges. I'll start
    with a XSS to read from a SocketIO instance to get the
    administrator's chat history. That reveals new subdomain to
    investigate, where I'll find a site using simple-git to generate
    reports on repositories. I'll exploit a command injection CVE in
    simple-git to get a foothold. I'll find creds for the next user by
    cracking a hash in the Mongo database. I'll pivot to the next user
    by exploiting an SNMP trap vulnerability that leads to XSS in
    LibreNMS, and then to the next user abusing a shared password in the
    LibreNMS configuration. For root, I'll abuse the LibreOffice Calc
    API to execute commands. In Beyond Root I'll show some unintended
    paths, first using a weird permissions setting on the LibreNMS
    directory to skip the SNMP trap exploitation, and then using the
    LibreOffice Calc API to write formulas into a worksheet that read
    files from the file system, which I'll turn into a nice Python
    script to get arbitrary file read.

-   Aug 10, 2024

    ### [HTB: Usage](/htb-usage.md)

    #htb-usage #ctf #hackthebox #nmap #ubuntu #ffuf #subdomain #laravel
    #sqli #sqlmap #blindsql #hashcat #laravel-admin #cve-2023-24249
    #webshell #monit #wildcard #7z

    ![](/img/usage-cover.png)

    Usage starts with a blind SQL injection in a password reset form
    that I can use to dump the database and find the admin login. The
    admin panel is made with Laravel-Admin, which has a vulnerability in
    it that allows uploading a PHP webshell as a profile picture by
    changing the file extension after client-side validation. I'll find
    a password in a monit config, and then abuse a wildcard
    vulnerability in 7z to get file read as root.

-   Aug 3, 2024

    ### [HTB: IClean](/htb-iclean.md)

    #hackthebox #htb-iclean #ctf #nmap #ubuntu #flask #feroxbuster #burp
    #burp-repeater #xss #ssti #crackstation #qpdf #file-read #pdf-parser
    #pdf #youtube

    ![](/img/iclean-cover.png)

    IClean starts out with a simple cross-site scripting cookie theft,
    followed by exploiting a server-side template injection in an admin
    workflow. I'll abuse that to get a shell on the box, and pivot to
    the next user by getting their hash from the website DB and cracking
    it. For root, the user can run the a command-line PDF software as
    root. I'll use that to attach files to PDF documents for file read
    as well. In Beyond Root, I'll go through the structure of the PDF
    documents and use tools to pull the attachments out without opening
    the document.

-   Jul 27, 2024

    ### [HTB: WifineticTwo](/htb-wifinetictwo.md)

    #hackthebox #htb-wifinetictwo #ctf #nmap #ubuntu #openplc #c #flask
    #flask-unsign #cve-2021-31630 #c-reverse-shell #wifi #oneshot
    #pixie-dust #wpa #wps #open-wrt #chisel #tunnel

    ![](/img/wifinetictwo-cover.png)

    WifineticTwo is another Wifi-themed box. I'll start with a host
    running OpenPLC. I'll log into the web interface using default creds
    and exploit it by writing a C reverse shell into the hardware code.
    From there, I'll identify a wireless interface that isn't connected
    to anything. I'll scan for access points, and perform a Pixie Dust
    attack on the AP to get it's password. Then I can connect to the
    network and find an Open-WRT router. The root account has no
    password, so I can get access to the web interface and run cron
    jobs, add SSH keys, or just SSH in as root with no password.

-   Jul 26, 2024

    ### [HTB Sherlock: Campfire-2](/htb-sherlock-campfire-2.md)

    #htb-sherlock #forensics #sherlock-campfire-2 #ctf #hackthebox #dfir
    #eventlogs #evtx-dump #win-event-4769 #win-event-4768
    #win-event-5140 #as-rep-roasting #jq

    ![](/img/sherlock-campfire-2.png)

    The second in the Campfire Sherlock series about active directory
    attacks is about AS-REP-Roasting, an attack against users configured
    to not require preauthentication when interaction with Kerberos.
    I'll examine the event logs to show which user account was
    compromised in the attack, as well as the workstation that was
    compromised to perform the attack.

-   Jul 23, 2024

    ### [HTB Sherlock: Tracer](/htb-sherlock-tracer.md)

    #htb-sherlock #sherlock-tracer #forensics #ctf #hackthebox #dfir
    #psexec #prefetch #ntfs-journal #pecmd #evtxecmd #mftecmd
    #event-logs #win-event-7045 #named-pipe #win-event-17 #win-event-11

    ![](/img/sherlock-tracer.png)

    Tracer is all about a forensics investigation where the attacker
    used PSExec to move onto a machine. I'll show how PSExec creates a
    service on the machine, creates named pipes to communicate over, and
    eventually drops a .key file. I'll identify the machine that sourced
    the attack as well.

-   Jul 20, 2024

    ### [HTB: Headless](/htb-headless.md)

    #ctf #hackthebox #htb-headless #nmap #debian #flask #python #burp
    #burp-repeater #xss #feroxbuster #ffuf #filter #cookies
    #command-injection #bash #cyberchef

    ![](/img/headless-cover.png)

    Headless is a nice introduction to cross site scripting, command
    injection, and understanding Linux and Bash. I'll start with a
    simple website with a contact form. When I put any HTML tags into
    the message, there's an alert saying that my request headers have
    been forwarded for analysis. I'll embed a XSS payload into request
    headers and steal a cookie from the admin. As an admin user, I get
    access to the dashboard, where a simple form has command injection.
    To escalate, I'll abuse a system check script that tries to run
    another script with a relative path. In Beyond Root, I'll look at
    understanding and attacking the cookie used by the site, and some
    odd status codes I noticed during the solution.

-   Jul 13, 2024

    ### [HTB: Corporate](/htb-corporate.md)

    #htb-corporate #hackthebox #ctf #nmap #ffuf #subdomain #sso #csp
    #content-security-policy #csp-evaluator #feroxbuster .md-injection
    #xss #meta-redirect #jwt #python-jwt #openvpn #vpn #idor #burp
    #burp-repeater #brute-force #default-creds #debian #ubuntu #netexec
    #docker #docker-sock #sssd #linux-ldap #autofs #nfs #firefox
    #firefox-history #bitwarden #firefox-bitwarden
    #bitwarden-pin-brute-force #snappy #rust #cargo #moz-idb-edit #jq
    #gitea #jwt-forge #docker-image-upload #proxmox #pve

    ![](/img/corporate-cover.png)

    Corporate is an epic box, with a lot of really neat technologies
    along the way. I'll start with a very complicated XSS attack that
    must utilize two HTML injections and an injection into dynamic
    JavaScript to bypass a content security policy and steal a a cookie.
    With that cookie, I'll enumerate users and abuse an insecure direct
    object reference vulnerability to get access to a welcome PDF that
    contains a default password syntax that includes the user's
    birthday. I'll brute force through the user's profiles, collecting
    their email and birthday, and checking for any users that still use
    the default password. Each user also has an OpenVPN connection
    config. I'll connect and find a remote VM that I can SSH into as
    these users. On that host, I'll find a dynamic home directory system
    that mounts NFS shares on login as different users. I'll find a
    Bitwarden Firefox extension in one user's home directory, and
    extract that to get their time-based one time password to the local
    Gitea instance. This instance has the source to the websites, and
    I'll find the JWT secret in an old commit, which allows me to
    generate tokens as any user and reset passwords without knowing the
    old one. I'll use that to get access to the VM as an user with
    access to the Docker socket, and escalate to root on that VM. I'll
    target sysadmin users and find an SSH key that works to get onto the
    main host. From there, I'll abuse a Proxmox backup to generate a
    cookie and use the API to reset the root user's password.

-   Jul 6, 2024

    ### [HTB: Perfection](/htb-perfection.md)

    #htb-perfection #hackthebox #ctf #ubuntu #nmap #ruby #ruby-sinatra
    #ruby-webrick #ssti #ssti-ruby #feroxbuster #newline-injection
    #filter #burp #burp-repeater #ffuf #erb #hashcat #hashcat-mask
    #htb-clicker

    ![](/img/perfection-cover.png)

    Perfection starts with a simple website designed to calculate
    weighted averages of grades. There is a filter checking input, which
    I'll bypass using a newline injection. Then I can exploit a Ruby
    server-side template injection to get execution. I'll find a
    database of hashes and a hint as to the password format used
    internally, and use hashcat rules to crack them to get root access.
    In Beyond Root, I'll look at the Ruby webserver and the SSTI
    vulnerability.

-   Jun 29, 2024

    ### [HTB: Jab](/htb-jab.md)

    #hackthebox #ctf #htb-jab #windows #nmap #jabber #xmpp #openfire
    #netexec #pidgin #xmpp-console #as-rep-roast #hashcat #bloodhound
    #bloodhound-py #dcom-execution #dcom #dcomexec.py #openfire-plugin

    ![](/img/jab-cover.png)

    Jab starts with getting access to a Jabber / XMPP server. I'll use
    Pidgin to enumerate other users, and find over two thousand! I'll
    AS-REP-Roast these users and find three that have the disable
    preauth bit set, and one with a crackable password. Logging into the
    chat server as that user, I'll find a private chat discussing a
    pentest, and creds for another account. That account has DCOM
    access. I'll abuse that to get a shell on the box. From there, I'll
    access the Openfire admin panel and upload a malicious plugin to get
    execution as system.

-   Jun 24, 2024

    ### [HTB Sherlock: Campfire-1](/htb-sherlock-campfire-1.md)

    #htb-sherlock #ctf #dfir #hackthebox #forensics #sherlock-campfire-1
    #eventlogs #prefetch #evtx-dump #pecmd #win-event-4769
    #kerberoasting #jq #win-event-4104 #powerview

    ![](/img/sherlock-campfire-1.png)

    Campfire-1 is the first in a series of Sherlocks looking at
    identifying critical active directory vulnerabilities. This
    challenge requires looking at event log and prefetch data to see an
    attack run PowerView and the Rubeus to perform a Kerberoasting
    attack.

-   Jun 22, 2024

    ### [HTB: Office](/htb-office.md)

    #htb-office #ctf #hackthebox #nmap #windows #netexec #joomla
    #feroxbuster #cve-2023-23752 #kerbrute #pcap #wireshark #hashcat
    #joomla-webshell #runascs #libreoffice #chisel #phishing #macros
    #cve-2023-2255 #cmd-key #saved-credentials #dpapi #mimikatz #gpo
    #sharp-gpo-abuse #htb-devvortex #htb-access

    ![](/img/office-cover.png)

    Office starts with a Joomla instance that leaks a password. I'll
    brute force usernames over Kerberos and then password spray to find
    where the password is reused. that use has access to an SMB share
    where I find a PCAP that includes a Kerberos authentication
    exchange. I'll build a hash from that and crack it to get another
    password. This one also works for the Joomla admin account. I'll add
    a webshell to a template and get a foothold on the box. There's an
    internal site that takes resume submissions. I'll abuse LibreOffice
    two ways, first by a CVE and then by editing the registry to enable
    macros. The next user has saved credentials, which I'll decrypt with
    Mimikatz. Finally, I'll abuse GPO access to get administrative
    access.

-   Jun 15, 2024

    ### [HTB: Crafty](/htb-crafty.md)

    #htb-crafty #hackthebox #ctf #windows #minecraft #feroxbuster #nmap
    #wireshark #log4shell #log4j #minecraft-client #cve-2021-44228 #java
    #jd-gui #virus-total #runascs #web.config #htb-logforge

    ![](/img/crafty-cover.png)

    Crafty is all about exploiting a Minecraft server. Minecraft was
    notoriously vulnerable to Log4Shell due to its use of the Java Log4J
    package. I'll use a free Minecraft command line client to connect
    and send a Log4Shell payload to get a shell on the box. From there,
    I'll find a plugin for the Minecraft server and reverse it to find
    the administrator password. In Beyond Root, I'll examine and
    understand the web.config file for the static website.

-   Jun 13, 2024

    ### [HTB Sherlock: Noted](/htb-sherlock-noted.md)

    #htb-sherlock #forensics #sherlock-noted #dfir #ctf #hackthebox
    #notepad++ #sherlock-cat-dfir

    ![](/img/sherlock-noted.png)

    Noted is a quick Sherlock analysing the AppData directory associated
    with Notepad++. I'll use the artifacts to recover the contents of
    two files, including a Java script used to collect files from the
    host for exfil. I'll get the password for the pastes site containing
    the attacker information and some idea of the timeline over which
    the activity occurred.

-   Jun 8, 2024

    ### [HTB: Pov](/htb-pov.md)

    #ctf #htb-pov #hackthebox #subdomain #ffuf #aspx #feroxbuster
    #viewstate #file-read #directory-traversal #deserialization
    #ysoserial.net #powershell-credential #clixml #certutil #runascs
    #sedebugprivilege #metasploit #meterpreter #psgetsys #chisel
    #evil-winrm

    ![](/img/pov-cover.png)

    Pov offers only a web port. I'll abuse a file read and directory
    traversal in the web page to read the ASP.NET secrets used for
    VIEWSTATE, and then use ysoserial.net to make a malicious
    serlialized .NET payload to get execution. I'll pivot on a
    PowerShell credential, and then abuse SeDebugPrivilege through both
    Metasploit and via a PowerShell script, psgetsys.ps1.

-   Jun 5, 2024

    ### [HTB Sherlock: Constellation](/htb-sherlock-constellation.md)

    #htb-sherlock #forensics #sherlock-constellation #hackthebox #dfir
    #ctf #sherlock-cat-threat-intelligence #unfurl #url-forensics
    #exiftool #osint #linkedin #url-discord #url-google

    ![](/img/sherlock-constellation.png)

    Constellation is a fun Sherlock challenge largely focuced on
    forensics against URLs. Two URLs, from Discord and Google are
    shared, and I'll use Unfurl to pull timestamps and other information
    from them to make a timeline of an insider threat interaction.

-   Jun 1, 2024

    ### [HTB: Analysis](/htb-analysis.md)

    #ctf #htb-analysis #hackthebox #nmap #windows #netexec #ffuf
    #subdomain #feroxbuster #upload #webshell #hta #ldap #ldap-injection
    #python #python-async #python-httpx #autologon-credentials #web-logs
    #evil-winrm #snort #snort-dynamic-preprocessor #msfvenon
    #htb-support

    ![](/img/analysis-cover.png)

    Analysis starts with a PHP site that uses LDAP to query a user from
    active directory. I'll use LDAP injection to brute-force users, and
    then to read the description field of a shared account, which has
    the password. That grants access to the admin panel, where I'll
    abuse an upload feature two ways - writing a webshell and getting
    execution via an HTA file. I'll find credentials for the next user
    in autologon registry values and in web logs. To get administrator,
    I'll abuse the Snort dynamic preprocessor feature writing a
    malicious DLL to where Snort will load it.

-   May 30, 2024

    ### [HTB Sherlock: Nubilum-1](/htb-sherlock-nubilum-1.md)

    #htb-sherlock #dfir #ctf #hackthebox #sherlock-nubilum-1
    #sherlock-cat-cloud #forensics #cloud #aws #cloudtrail #catscale
    #youtube #container #docker #python #s3 #ec2 #splunk #poshc2

    ![](/img/sherlock-nubilum-1.png)

    Nublium-1 is all about cloud forensics, specifically a compromised
    AWS account that leads to multiple EC2 VM instances, including one
    acting as a PoshC2 server. I'll work through the CloudTrail logs in
    a Splunk instance (run via Docker with video on setup), as well as
    CatScale logs and other forensic collection to show where the threat
    actor got credentials for the account, what they did in the cloud,
    and even identify a victim machine.

-   May 25, 2024

    ### [HTB: Bizness](/htb-bizness.md)

    #htb-bizness #ctf #hackthebox #nmap #debian #ofbiz #feroxbuster
    #cve-2023-49070 #ysoserial #java #hashcat #ij #derby #dbeaver
    #cyberchef

    ![](/img/bizness-cover.png)

    Bizness is all about an Apache OFBiz server that is vulnerable to
    CVE-2023-49070. I'll exploit this pre-authentication remote code
    execution CVE to get a shell. To esclate, I'll find the Apache Derby
    database and exfil it to my machine. I'll show how to enumerate it
    using the ij command line too, as well as DBeaver. Once I find the
    hash, I'll need to reformat it to something hashcat can process,
    crack it, and get root.

-   May 22, 2024

    ### [HTB Sherlock: Bumblebee](/htb-sherlock-bumblebee.md)

    #htb-sherlock #forensics #dfir #ctf #sherlock-bumblebee
    #sherlock-cat-dfir #hackthebox #sqlite #phpbb #access-log
    #credential-theft

    ![](/img/sherlock-bumblebee.png)

    Bumblebee is a fun introductory level Sherlock. All the data needed
    to solve the challenge is in a sqlite database for a phpBB instance
    and an access log file. No fancy tools, just SQLite and Bash
    commands. I'll show how a user created a malicious post and got the
    admin to send their credentials to the attacker. Then they used the
    creds to log in as admin, give their own account administrator
    privileges, and export the database.

-   May 18, 2024

    ### [HTB: Ouija](/htb-ouija.md)

    #hackthebox #ctf #htb-ouija #nmap #feroxbuster #burp #burp-proxy
    #subdomain #gitea #haproxy #cve-2021-40346 #request-smuggling
    #integer-overflow #burp-repeater #file-read #proc #hash-extender
    #hash-extension #youtube #python #reverse-engineering #php-module
    #gdb #peda #ghidra #bof #arbitrary-write #htb-intense #htb-extension

    ![](/img/ouija-cover.png)

    Ouija starts with a requests smuggling vulnerability that allows me
    to read from a dev site that's meant to be blocked by HA Proxy.
    Access to the dev site leaks information about the API, enough that
    I can do a hash extension attack to get a working admin key for the
    API and abuse it to read files from the system. I'll read an SSH key
    and get a foothold. From there, I'll abuse a custom PHP module
    written in C and compiled into a .so file. There's an integer
    overflow vulnerability which I'll abuse to overwrite variables on
    the stack, providing arbitrary write as root on the system.

-   May 16, 2024

    ### [HTB Sherlock: Logjammer](/htb-sherlock-logjammer.md)

    #htb-sherlock #ctf #sherlock-logjammer #sherlock-cat-dfir #forensics
    #dfir #hackthebox #evtxecmd #windows #event-logs #win-event-4624 #jq
    #win-event-2004 #win-event-2005 #win-event-2006 #win-event-2010
    #win-event-2033 #win-event-2051 #win-event-4719 #win-event-4698
    #win-event-1116 #win-event-1117 #win-event-4103 #win-event-4104
    #win-event-1102 #win-event-104

    ![](/img/sherlock-logjammer.png)

    Logjammer is a neat look at some Windows event log analysis. I'll
    start with five event logs, security, system, Defender, firewall,
    and PowerShell, and use EvtxECmd.exe to convert them to JSON. Then
    I'll slice them using JQ and some Bash to answer 12 questions about
    a malicious user on the box, showing their logon, uploading
    Sharphound, modifying the firewall, creating a scheduled task,
    running a PowerShell script, and clearing some event logs.

-   May 11, 2024

    ### [HTB: Monitored](/htb-monitored.md)

    #hackthebox #htb-monitored #ctf #nmap #nagios #nagiosxi #ldapsearch
    #snmpwalk #nagios-api #api-fuzz #feroxbuster #burp #burp-repeater
    #cve-2023-40931 #sqli #sqlmap #symbolic-link

    ![](/img/monitored-cover.png)

    Monitored is all about a Nagios XI monitoring system. I'll abuse it
    over and over to slowly escalate privileges ending up at root. I'll
    find initial creds from SNMP, but the account is disabled. I'll
    abuse the API to get a token that provides authentication to the
    site. From there I'll exploit a SQL injection to get the
    administrator's API key. With that key, I'll add a new admin user,
    and get admin access to the site. From there, I'll create a command
    that runs on the host to get a shell. To escalate to root, I'll show
    two ways to abuse sudo privileges that Nagios gives the nagios user.

-   May 9, 2024

    ### [Einladen mso.dll Reverse Engineering](/htb-sherlock-einladen-malware-re.md)

    #htb-sherlock #sherlock-einladen #hackthebox #ctf #forensics #dfir
    #malware #decoy-document #dll-side-loading #authenticode
    #virus-total #zulip-chat #youtube #ghidra #python

    ![](/img/einladen-malware-cover.png)

    In the Einladen Sherlock, there's an HTA file that drops a Microsoft
    signed legit executable, two DLLs, and a PDF. I'm able to use the
    PCAP and Procmon data to figure out where to go next, without
    reverse-engineering the malware. In the embedded YouTube video, I'll
    dive into the DLL side-load, how the binary loads winint.dll
    secretly, decrypts stack strings, and contacts the C2, with a
    summary of the analysis in this post.

-   May 7, 2024

    ### [Go Binary Analysis with gftrace](/gftrace.md)

    #htb-napper #go #gftrace #elastic #reverse-engineering #hook
    #source-code

    ![](/img/gftrace-cover.png)

    gftrace is a command line Windows tool that will run a Go binary and
    log all the Windows API calls made as it runs. Having just finished
    solving Napper from HackTheBox a few days before learning of this
    tool, it seems obvious to try to apply it to the Go binary from that
    box. I'll also give a brief overview of how it works, walking
    through the source code from GitHub. Overall, the tool is a bit raw,
    but a useful on to keep in my toolbox and something to keep an eye
    on.

-   May 4, 2024

    ### [HTB: Napper](/htb-napper.md)

    #htb-napper #ctf #hackthebox #nmap #windows #iis #subdomain #ffuf
    #hugo #feroxbuster #burp #burp-repeater #naplistener-malware
    #malware #csharp #dotnet #dotnet-reverse-shell #mcs #laps
    #elasticsearch #chisel #tunnel #smbserver #ghidra #go #youtube #uac
    #runascs #scheduled-tasks #dotpeek #htb-haystack

    ![](/img/napper-cover.png)

    Napper presents two interesting coding challenges wrapping in a
    story of real malware and a custom LAPS alternative. I'll start by
    finding a username and password in a blog post, and using it to get
    access to an internal blog. This blog talks about a real IIS
    backdoor, Naplistener, and mentions running it locally. I'll find it
    on Napper, and write a custom .NET binary that will run when passed
    to the backdoor to get a shell. On the box, I'll find a draft blog
    post about a new internally developed solution to replace LAPS,
    which stores the password in a local Elastic Search DB. I'll write a
    Go program to fetch the seed and the encrypted blob, generate the
    key from the seed, and use the key to decrypt the blob, resulting in
    the password for a user with admin access. I'll use RunasCs.exe to
    bypass UAC and get a shell with administrator privileges. In Beyond
    Root, I'll explore the automations for the box, including the both
    how the password is rotated every 5 minutes, and what changes are
    made to the real malware for HTB.

-   May 2, 2024

    ### [HTB Sherlock: Einladen](/htb-sherlock-einladen.md)

    #sherlock-einladen #htb-sherlock #sherlock-cat-dfir #hackthebox #ctf
    #forensics #dfir #malware #phishing .md #hta #decoy-document
    #dll-side-loading #authenticode #virus-total #wireshark #pcap
    #tshark #zulip-chat #aws #procmon #javascript #polyglot #batch
    #any-run #sandbox #youtube #lolbas #dotpeek #dotnet #aes #cyberchef
    #dnspy #pbkdf2 #anti-debug #scheduled-task

    ![](/img/sherlock-einladen.png)

    Einladen starts with a ton of artifacts. I'll work through a
    phishing HTML page that downloads a Zip with an HTA that creates
    three executables and a PDF, then runs one of the executables. The
    one it runs is a legit Microsoft binary, but the DLLs are malware,
    side-loaded by the legit binary. That binary connects to a chat
    service as C2. There's also a JavaScript / bat polyglot that
    presumably is downloaded and run by the malware that starts another
    infection chain, this time running another RAT that is written in
    .NET. I'll figure out how to decrypt it's settings (both dynamically
    and with some really fun CyberChef foo), and understand how it
    works.

-   Apr 27, 2024

    ### [HTB: DevVortex](/htb-devvortex.md)

    #hackthebox #ctf #htb-devvortex #nmap #ubuntu #ffuf #subdomain
    #joomla #cve-2023-23752 #mass-assignment #information-disclosure
    #joomla-webshell #joomla-plugin #joomla-template #youtube
    #apport-cli #apport #cve-2023-1326 #pager-exploit #less #htb-sau

    ![](/img/devvortex-cover.png)

    DevVortex starts with a Joomla server vulnerable to an information
    disclosure vulnerability. I'll leak the users list as well as the
    database connection password, and use that to get access to the
    admin panel. Inside the admin panel, I'll show how to get execution
    both by modifying a template and by writing a webshell plugin. I'll
    pivot to the next user after cracking their hash from the DB. For
    root, I'll abuse a pager vulnerability in apport-cli that allows
    escaping to a root shell when run with sudo.

-   Apr 23, 2024

    ### [HTB Sherlock: Meerkat](/htb-sherlock-meerkat.md)

    #hackthebox #htb-sherlock #ctf #dfir #forensics #sherlock-meerkat
    #sherlock-cat-soc #pcap #wireshark #suricata #bonitasoft
    #cve-2022-25237 #tshark #credential-stuffing #pastes-io #jd-gui #jq

    ![](/img/sherlock-meerkat.png)

    In Meerkat, I'll look at some Suricata alert data and a PCAP and see
    how an actor performs a credential stuffing attack against a
    Bonitasoft BPM server. Once authenticated, they exploit a CVE to get
    access as a privileged user and upload a malicious extension to run
    commands on the host opterating system. Using that access, they
    download a Bash script from a pastes site and run it, downloading a
    public key and putting it into a user's authorized keys file to
    backdoor the system. In Beyond Root, I'll find the script the actor
    was using, and do some basic reverse engineering on the Java plugin.

-   Apr 20, 2024

    ### [HTB: Surveillance](/htb-surveillance.md)

    #hackthebox #ctf #htb-surveillance #nmap #ubuntu #feroxbuster
    #craftcms #cve-2023-41892 #arbitrary-object-instantiation
    #image-magick #hashcat #zoneminder #cve-2023-26035
    #command-injection #zmupdate #zmdc #htb-intentions #htb-clicker

    ![](/img/surveillance-cover.png)

    Surveillance is one of those challenges that has gotten
    significantly easier since it's initial release. It features
    vulnerabilities that had descriptions but not public POCs at the
    time it was created, which made for an interesting challenge. It
    starts with an instance of Craft CMS. I'll exploit an arbitrary
    object injection vulnerability to get RCE and a shell. I'll find a
    password hash for another user in a database backup and crack it.
    That user can log into a ZoneMinder instance running on localhost,
    and I'll exploit a vulnerability in it to get access as the
    zoneminder user. For root, I'll show two ways to abuse the
    zoneminder user's sudo privileges - through the ZoneMinder
    LD_PRELOAD option, and via command injection in one of their
    scripts.

-   Apr 18, 2024

    ### [HTB Sherlock: Subatomic](/htb-sherlock-subatomic.md)

    #ctf #hackthebox #htb-sherlock #forensics #sherlock-subatomic
    #sherlock-cat-malware-analysis #malware #dfir #nullsoft #electron
    #nsis #authenticode #imphash #python-pefile #virus-total #7z #nsi
    #asar #npm #nodejs #vscode #nodejs-debug #deobfuscation #duvet
    #discord #browser #htb-atom #htb-unobtainium

    ![](/img/sherlock-subatomic.png)

    Subatomic looks at a real piece of malware written in Electron,
    designed as a fake game installer that will hijack the system's
    Discord installation as well as exfil data about the machine, and
    Discord tokens, and tons of browser data. I'll take apart the
    malware to see what it does and answer the questions for the
    challenge.

-   Apr 17, 2024

    ### [HTB Sherlock: BFT](/htb-sherlock-bft.md)

    #ctf #dfir #forensics #sherlock-bft #sherlock-cat-dfir #hackthebox
    #htb-sherlock #mft #mftecmd #timeline-explorer
    #alternative-data-streams #zone-identifier #malware #bat #python

    ![](/img/sherlock-bft.png)

    BFT is all about analysis of a Master File Table (MFT). I'll use
    Zimmerman tools MFTECmd and Timeline Explorer to find where a Zip
    archive was downloaded from Google Drive. It is then unzipped to get
    another zip, which is unzipped to get another zip. That final zip
    has a Windows Bat file in it. Because the Bat file is small, I'm
    able to recover the full file from the MFT and see that it uses a
    PowerShell cradle to download and run PowerShell from a malicious
    C2.

-   Apr 13, 2024

    ### [HTB: Hospital](/htb-hospital.md)

    #ctf #htb-hospital #hackthebox #nmap #windows #ubuntu #netexec
    #roundcube #upload #feroxbuster #ffuf #burp #burp-repeater #php
    #webshell #php-disable-functions #dfunc-bypasser #p0wny-shell
    #weevely #vm #htb-moderators #hashcat #gameoverlay #cve-2023-2640
    #cve-2023-32629 #youtube #cve-2023-35001 #shadow #phishing
    #ghostscript #cve-2023-3664 #xampp #htb-rebound #qwinsta
    #meterpreter #metasploit #msfvenom #espia #meterpreter-screenshot
    #meterpreter-key-sniff #htb-updown

    ![](/img/hospital-cover.png)

    Hospital is a Windows box with an Ubuntu VM running the company
    webserver. I'll bypass upload filters and disable functions to get a
    PHP webshell in the VM and execution. I'll escalate using kernel
    exploits, showing both CVE-2023-35001 and GameOver(lay). As root on
    the webserver, I'll crack the password hashes for a user, and get
    credentials that are also good on the Windows host and the RoundCube
    webmail. In the mail, I'll reply to another user who is waiting for
    a EPS file to exploit a vulnerability in Ghostscript and get
    execution. To escalate, I'll show four ways, including the intended
    path which involves using a keylogger to get the user typing the
    admin password into RoundCube. In Beyond Root, I'll look at the
    automations for the Ghostscript phishing step.

-   Apr 11, 2024

    ### [HTB Sherlock: Unit42](/htb-sherlock-unit42.md)

    #ctf #dfir #forensics #sherlock-unit42 #sherlock-cat-dfir
    #hackthebox #htb-sherlock #event-logs #sysmon #jq #malware
    #time-stomping #evtxecmd

    ![](/img/sherlock-unit42.png)

    Unit42 is based off a real malware campaign noted by Unit 42.I'll
    work with Sysmon logs to see how the malware was downloaded through
    Firefox from Dropbox, run by the user, and proceeded to install
    itself using Windows tools. It makes network connections including
    DNS queries and connection to a probably malicious IP before killing
    itself.

-   Apr 9, 2024

    ### [HTB Sherlock: Brutus](/htb-sherlock-brutus.md)

    #ctf #dfir #forensics #sherlock-brutus #sherlock-cat-dfir
    #hackthebox #htb-sherlock #auth-log #wtmp #btmp #utmp #utmpdump
    #ssh-brute-force

    ![](/img/sherlock-brutus.png)

    Brutus is an entry-level DFIR challenge that provides a auth.log
    file and a wtmp file. I'll use these two artifacts to identify where
    an attacker performed an SSH brute force attack, eventually getting
    success with a password for the root user. I'll see how the user
    comes back in manually and connects, creating a new user and adding
    that user to the sudo group. Finally, that user connects and runs a
    couple commands using sudo.

-   Apr 6, 2024

    ### [HTB: Codify](/htb-codify.md)

    #ctf #hackthebox #htb-codify #nmap #ubuntu #nodejs #express #js-vm2
    #cve-2023-37903 #cve-2023-37466 #cve-2023-32314 #cve-2023-30547
    #sqlite #hashcat #bash #bash-glob #python #brute-force

    ![](/img/codify-cover.png)

    The website on Codify offers a JavaScript playground using the vm2
    sandbox. I'll abuse four different CVEs in vm2 to escape and run
    command on the host system, using that to get a reverse shell. Then
    I'll find a hash in a sqlite database and crack it to get the next
    user. For root, I'll abuse a script responsible for backup of the
    database. I'll show two ways to exploit this script by abusing a
    Bash glob in an unquoted variable compare.

-   Mar 30, 2024

    ### [HTB: Rebound](/htb-rebound.md)

    #ctf #htb-rebound #hackthebox #nmap #windows #active-directory
    #domain-controller #netexec #rid-cycle #lookupsid #kerberoast
    #kerberoast-without-auth #hashcat #password-spray #bloodhound
    #powerview #powerview-py #windows-acl #bloodyad #shadow-credential
    #certipy #qwinsta #cross-session #remotepotato0 #krbrelay #gmsa
    #gmsapasswordreader #delegation #constrained-delegation #rbcd
    #kerberos #s4u2self #s4u2proxy #secretsdump #htb-absolute
    #htb-outdated #adcs

    ![](/img/rebound-cover.png)

    Rebound is a monster Active Directory / Kerberos box. I'll start off
    with a RID-cycle attack to get a list of users, and combine
    AS-REP-Roasting with Kerberoasting to get an crackable hash for a
    service account. That password is shared by a domain user, and I'll
    find a bad ACL that allows that user control over an important
    group. With access to that group, I can change the password of or
    get a shadow credential for another user with WinRM access. I'll
    perform a cross-session relay attack with both RemotePotato0 and
    KrbRelay to get a hash for the next user, who can read the GMSA
    password for another service account. This account has a constrained
    delegation, and I'll need to abuse both that delegation as well as
    RBCD to get a ticket as the DC machine account, and dump hashes for
    the domain. This one is heavey into Active Directory and Kerberos!

-   Mar 23, 2024

    ### [HTB: Analytics](/htb-analytics.md)

    #ctf #htb-analytics #hackthebox #nmap #ffuf #subdomain #feroxbuster
    #metabase #cve-2023-38646 #burp #burp-repeater #docker #env
    #gameoverlay #cve-2023-2640 #cve-2023-32629 #youtube

    ![](/img/analytics-cover.png)

    Analytics starts with a webserver hosting an instance of Metabase.
    There's a pre-auth RCE exploit that involves leaking a setup token
    and using it to start the server setup, injecting into the
    configuration to get code execution. Inside the Metabase container,
    I'll find creds in environment variables, and use them to get access
    to the host. From there I'll exploit the GameOver(lay) vulnerability
    to get a shell as root, and include a video explaining the exploit.

-   Mar 21, 2024

    ### [SMB Enumeration Cheatsheet](/smb-cheat-sheet.md)

    #pwk #hackthebox #smb #oscp #methodology #cheat-sheet #netexec
    #smbclient #impacket #nmap #manspider #htb-manager

    ![](/img/smb_cheat-cover.png)

    SMB enumeration is a key part of a Windows assessment, and it can be
    tricky and finicky. When I was doing OSCP back in 2018, I wrote
    myself an SMB enumeration checklist. Five years later, this is the
    updated version with newer tools and how I approach SMB today. It's
    also worth noting that this list is for a Linux attack box.

-   Mar 16, 2024

    ### [HTB: Manager](/htb-manager.md)

    #ctf #htb-manager #hackthebox #nmap #windows #ffuf #iis #feroxbuster
    #netexec #lookupsid #rid-cycle #ldapsearch #ldapdomaindump #kerbrute
    #password-spray #mssql #mssqlclient #xp-dirtree #certipy #adcs #esc7
    #evil-winrm

    ![](/img/manager-cover.png)

    Manager starts with a RID cycle or Kerberos brute force to find
    users on the domain, and then a password spray using each user's
    username as their password. When the operator account hits, I'll get
    access to the MSSQL database instance, and use the xp_dirtree
    feature to explore the file system. I'll find a backup archive of
    the webserver, including an old config file with creds for a user.
    As that user, I'll get access to the ADCS instance and exploit the
    ESC7 misconfiguration to get access as administrator.

-   Mar 9, 2024

    ### [HTB: Appsanity](/htb-appsanity.md)

    #hackthebox #ctf #htb-appsanity #nmap #tls #ffuf #vhosts #subdomain
    #windows #aspx #dotnet #feroxbuster #hidden-input #cookies
    #shared-cookie #jwt #ssrf #filter #upload #burp #burp-repeater
    #ssrf-fuzz #aspx #webshell #dotpeek #reverse-engineering #ghidra
    #x64dbg #procmon

    ![](/img/appsanity-cover.png)

    Appsanity starts with two websites that share a JWT secret, and thus
    I can get a cookie from one and use it on the other. On the first,
    I'll register an account, and abuse a hidden input vulnerability to
    get evelated privilieges as a doctor role. Then I'll use that cookie
    on the other site to get access, where I find a serverside request
    forgery, as well as a way to upload PDFs. I'll bypass a filter to
    upload a webshell, and use the SSRF to reach the internal management
    page and trigger a reverse shell. From there, I'll find the location
    of credentials in a .NET application, and extract a password from
    the registry to get another shell. Finally, I'll reverse a C++
    binary using ProcMon, Ghidra, and x64dbg to figure out a location
    where I could write a DLL and trigger it's being loaded, giving
    shell as administrator.

-   Mar 2, 2024

    ### [HTB: CozyHosting](/htb-cozyhosting.md)

    #hackthebox #ctf #htb-cozyhosting #nmap #ubuntu #java #spring-boot
    #spring-boot-actuator #feroxbuster #command-injection #bash-ifs
    #bash-brace-expansion #whitespace-filter #burp #burp-repeater
    #postgresql #jar #jd-gui #hashcat #gtfobins #ssh-proxycommand

    ![](/img/cozyhosting-cover.png)

    CozyHosting is a web hosting company with a website running on Java
    Spring Boot. I'll find a Spring Boot Actuator path that leaks the
    session id of a logged in user, and use that to get access to the
    site. Once there, I'll find command injection in a admin feature to
    get a foothold. I'll pull database creds from the Java Jar file and
    use them to get the admin's hash on the website from Postgres, which
    is also the user's password on the box. From there, I'll abuse sudo
    ssh with the ProxyCommand option to get root.

-   Feb 24, 2024

    ### [HTB: Visual](/htb-visual.md)

    #hackthebox #htb-visual #ctf #nmap #windows #php #xampp #feroxbuster
    #visual-studio #csharp #gitea #docker #dotnet #dotnet-linux
    #php-webshell #webshell #fullpowers #seimpersonate #godpotato
    #htb-keeper

    ![](/img/visual-cover.png)

    Visual is all about abusing a Visual Studio build process. There's a
    website that takes a hosted Git URL and loads a Visual Studio
    project from the URL and compiles it. I'll stand up a Gitea server
    in a container and host a project with a pre-build action that runs
    a command and gets a shell. From there, I'll drop a webshell into
    the XAMPP web root to get a shell as local service. This service is
    running without SeImpersonate privileges, but I'll use the FullPower
    executable to recover this, and then GodPotato to get System.

-   Feb 17, 2024

    ### [HTB: Drive](/htb-drive.md)

    #hackthebox #htb-drive #ctf #ubuntu #nmap #django #idor #feroxbuster
    #ffuf #gitea #sqlite #sqli #sqlite-injection #sqlite-rce #hashcat
    #ghidra #reverse-engineering #format-string #canary #bof #pwntools
    #filter #gdb #peda #ropper

    ![](/img/drive-cover.png)

    Drive has a website that provides cloud storage. I'll abuse an IDOR
    vulnerability to get access to the administrator's files and leak
    some creds providing SSH access. From there I'll access a Gitea
    instance and use the creds to get access to a backup script and the
    password for site backups. In these backups, I'll find hashes for
    another use and crack them to get their password. For root, there's
    a command line client binary that has a buffer overflow. I'll show
    that, as well as two ways to get RCE via an unintended SQL
    injection.

-   Feb 12, 2024

    ### [HTB: Builder](/htb-builder.md)

    #ctf #hackthebox #htb-builder #cve-2024-23897 #file-read #jenkins
    #jenkins-cli #youtube #hashcat #bcrypt #jenkins-credentials
    #jenkins-sshagent #jenkins-pipeline #htb-jeeves #htb-object

    ![](/img/builder-cover.png)

    Builder is a neat box focused on a recent Jenkins vulnerability,
    CVE-2024-23897. It allows for partial file read and can lead to
    remote code execution. I'll show how to exploit the vulnerability,
    explore methods to get the most of a file possible, find a password
    hash for the admin user and crack it to get access to Jenkins. From
    in Jenkins, I'll find a saved SSH key and show three paths to
    recover it. First, dumping an encrypted version from the admin
    panel. Second, using it to SSH into the host and finding a copy
    there. And third by having the pipeline leak the key back to me.

-   Feb 10, 2024

    ### [HTB: Keeper](/htb-keeper.md)

    #htb-keeper #hackthebox #ctf #nmap #request-tracker #default-creds
    #keepass #cve-2022-32784 #dotnet #dotnet-linux #docker #chatgpt
    #kpcli #putty #puttygen

    ![](/img/keeper-cover.png)

    Keeper is a relatively simple box focused on a helpdesk running
    Request Tracker and with an admin using KeePass. I'll use default
    creds to get into the RT instance and find creds for a user in their
    profile. That user is troubleshooting a KeePass issue with a memory
    dump. I'll exploit CVE-2022-32784 to get the master password from
    the dump, which provides access to a root SSH key in Putty format.
    I'll convert it to OpenSSH format and get root access.

-   Feb 3, 2024

    ### [HTB: RegistryTwo](/htb-registrytwo.md)

    #htb-registrytwo #ctf #hackthebox #nmap #ubuntu #ffuf #vhosts #nginx
    #java #war #feroxbuster #docker #docker-registry #youtube
    #dockerregistrygrabber #catalina #tomcat #jd-gui #reverse-enginering
    #rmi #java-rmi #breaking-parser-logic #tomcat-examples
    #tomcat-session #file-read #mass-assignment #null-byte
    #update-alternatives #docker-host-network #idea-ide #java-jar #pspy
    #recaf #python #clamav #ipv6 #htb-registry

    ![](/img/registrytwo-cover.png)

    RegistryTwo is a very difficult machine focusing on exploiting Java
    applications. At the start, there's a Docker Registry and auth
    server that I'll use to get an image and find a Java War file that
    runs the webserver. Enumeration and reversing show multiple
    vulnerabilities including nginx/Tomcat issues, mass assignment, and
    session manipulation. I'll chain those together to get a foothold in
    the production container. From there, I'll create a rogue Java RMI
    client to get file list and read on the host, where I find creds to
    get a shell. To escalate to root, I'll wait for the RMI server to
    restart, and start a rogue server to listen on the port before it
    can. My server will abuse a process for scanning files with ClamAV
    and get file read and eventually a shell. In Beyond Root, I'll go
    over some unintended paths, and look at the nginx configuration that
    allows for dynamic creation of different website virtual hosts.

-   Jan 27, 2024

    ### [HTB: Clicker](/htb-clicker.md)

    #htb-clicker #hackthebox #ctf #nmap #ubuntu #ffuf #php #feroxbuster
    #nfs #source-code #mass-assignment #newline-injection #sqli #burp
    #burp-proxy #burp-repeater #webshell #directory-traversal
    #reverse-engineering #ghidra #perl-debug #ld-preload #http-proxy
    #environment-variables #sudo-setenv #xxe

    ![](/img/clicker-cover.png)

    Clicker has a website that presents a game that is a silly version
    of Universal Paperclips. I'll find an mass assignment vulnerability
    that allows me to change my role to admin after bypassing a filter
    two different ways (newline injection and SQLI). Then I'll exploit a
    file write vulnerability to get a webshell and execution on the box.
    To escalate, I'll find a SetUID binary for the next user and abuse
    it to read their SSH key. To get root, I'll exploit a script the
    user can run with sudo, showing three different ways (playing with
    Perl environment variables, setting myself as the proxy and adding
    an XXE attack, and abusing LD_PRELOAD).

-   Jan 20, 2024

    ### [HTB: Bookworm](/htb-bookworm.md)

    #ctf #htb-bookworm #hackthebox #nmap #ubuntu #nodejs #express #xss
    #idor #javascript #python #feroxbuster #csp #content-security-policy
    #insecure-upload #flask #directory-traversal #file-read #netexec
    #calibre-ebook-convert #symlink #sqli #postscript
    #postscript-injection #arbitrary-write #ps2pdf
    #express-query-strings

    ![](/img/bookworm-cover.png)

    Bookworm starts with a gnarly exploit chain combining cross-site
    scripting, insecure upload, and insecure direct object reference
    vulnerabilities to identify an HTTP endpoint that allows for file
    download. In this endpoint, I'll find that if multiple files are
    requested, one can attack a directory traversal to return arbitrary
    files in the returned Zip archive. I'll use that to leak database
    creds that also work for SSH on the box. The next user is running a
    dev webserver that manages ebook format conversion. I'll abuse this
    with symlinks to get arbitrary write, and write an SSH public key
    and get access. For root, I'll abuse a SQL injection in a label
    creating script to do PostScript injection to read and write files
    as root. In Beyond Root, I'll look at the Express webserver from the
    foothold and how it was vulnerable and where it wasn't.

-   Jan 13, 2024

    ### [HTB: Zipping](/htb-zipping.md)

    #ctf #htb-zipping #hackthebox #nmap #ubuntu #php #feroxbuster #zip
    #file-read #symlink #youtube #python #python-zipfile #filter
    #php-regex #sqli #sqli-union #sqli-file #lfi #shared-object
    #null-byte #7z #phar #htb-broker

    ![](/img/zipping-cover.png)

    Zipping has a website with a function to upload resumes as PDF
    documents in a Zip archive. I'll abuse this by putting symlinks into
    the zip and reading back files from the host file system. I'll get
    the source for the site and find a filter bypass that allows SQL
    injection in another part of the site. I'll use that injection to
    write a webshell, and include it exploiting a LFI vulnerability to
    get execution. For root, I'll abuse a custom binary with a malicious
    shared object. In Beyond Root, I'll show two unintended foothold
    paths. The first arises from the differences between how PHP and 7z
    handle a file in a zip with a null byte in its name. The second uses
    the PHAR PHP filter to bypass the file_exists check and execute a
    webshell from an archive.

-   Jan 6, 2024

    ### [HTB: Sau](/htb-sau.md)

    #ctf #hackthebox #htb-sau #nmap #request-baskets #feroxbuster
    #cve-2023-27163 #ssrf #mailtrail #command-injection #systemctl #less
    #pager-exploit

    ![](/img/sau-cover.png)

    Sau is an easy box from HackTheBox. I'll find and exploit an SSRF
    vulnerability in a website, and use it to exploit a command
    injection in an internal Mailtrack website. From there, I'll abuse
    how the Less pager works with systemctl to get shell as root.

-   Jan 6, 2024

    ### [2023 SANS Holiday Hack Challenge: A Holiday Odyssey \| Featuring 6: Geese A-Lei\'ing!](/holidayhack2023/)

    #ctf #sans-holiday-hack

    ![](/img/hh23-cover.png)

    The 2023 challenge, *A Holiday Odyssey, Featuring 6: Geese
    A-Lei'ing!*, takes place in the Geese Islands, where Santa has moved
    his operation on the advice of his new AI, ChatNPT. I'll work
    through a series of technical (and physical) challenges to find that
    it's Jack Frost behind the AI, working from space, trying to destroy
    Christmas. In the end, I'll hack into his space system and redirect
    his missile away from Earth into the sun. The SANS Holiday Hack is
    something I look forward to each year, and 2023 did not disappoint.

-   Jan 2, 2024

    ### [Hackvent 2023 - Easy](/hackvent2023/easy)

    #ctf #hackvent #qrcode #python #flask #geek-code #grille-cipher
    #ghidra #reverse-engineering #kdenlive #deepskystacker #video-noise
    #volatility #stegnaography #stegsolve #transfer-encoding

    ![](/img/hackvent2023-easy-cover.png)

    Hackvent 2023 was a ton of fun, and this year I made it through 22
    of the 24 challenges (25 of 27 counting hidden challenge), only
    running out of time on two of the final three. The first seven plus
    a hidden challenge had QRcodes, Geek Codes, a Grille Cipher, a very
    simple RE challenge, image editing, memory analysis, steg, and a
    flag hidden in HTTP chunk metadata.

-   Jan 2, 2024

    ### [Hackvent 2023 - Medium](/hackvent2023/medium)

    #ctf #hackvent #bash #bash-glob #python #bruteforce #pcap #wireshark
    #tshark #jinja2 #ssti #python #flask #regex #steganography
    #python-pil #cryptography #mersenne-twister #randcrack
    #mersenne-twiters-seed-recover #hashing #firmware #gdb #core-dump
    #ghidra #reverse-enginnering #nettle #cyberchef #pwntools
    #htb-spider

    ![](/img/hackvent2023-medium-cover.png)

    The seven medium challenges presented challenges across the Web
    Security, Fun, Network Security, Forensic, Crypto, and Reverse
    Engineering categories. While I'm not always a fan of cryptography
    challenges, both day 13 and 14 were fantastic, the former having me
    abuse a weak hash algorithm to bypass signing requirements, and the
    latter having me recover an encrypted file and key from a core dump.
    There's also a Bash webserver with an unquoted variable, a PCAP with
    a flag in the TCP source ports, Jinja2 (Flask) template injection,
    steganography, and recovering the seed used for Python's random
    function.

-   Jan 2, 2024

    ### [Hackvent 2023 - Hard](/hackvent2023/hard)

    #ctf #hackvent #linux-forensics #backdoor #dpkg #dpkg-verify
    #virus-total #ghidra #reverse-engineering #docker #gdb #debugging
    #bof #python #pwntools #format-string #libc #ropgadget #rsa
    #exiftool #python-pil #arduino #atmel-avr #minecraft #log4j
    #log4shell #cve-2021-44228 #setuid #setresuid #dotnet #dotpeek
    #bruteforce #csharp #visual-studio

    ![](/img/hackvent2023-hard-cover.png)

    The hard challenges really took it up a level. My favorite was a
    .NET web application where I have to crack a licence key. There's
    also finding and reversing a backdoored passwd binary, some binary
    exploitation where I have to crash the server to preserve the flag
    and read it from the dump, RSA via an image, USB forensics, and
    exploiting a Minecraft server with Log4Shell.

-   Jan 2, 2024

    ### [Hackvent 2023 - Leet](/hackvent2023/leet)

    #ctf #hackvent #crypto #sagemath #rsa #bruteforce

    ![](/img/hackvent2023-leet-cover.png)

    I only got to solve one of the three leet challenges. It was a
    cryptography challenge where I can brute force two parameters known
    to be between 0 and 1000 and then work backwards to figure out q
    based on a hint leaked in the output. From there, it's simple RSA.

-   Dec 16, 2023

    ### [HTB: Coder](/htb-coder.md)

    #ctf #htb-coder #hackthebox #nmap #windows #smb #netexec #smbclient
    #adcs #teamcity #reverse-engineering #dotnet #dotpeek #youtube
    #visual-studio #keepass #kpcli #authenticate #2fa #totp #source-code
    #javascript #cicd #git-diff #evil-winrm #bloodhound
    #bloodhound-python #CVE-2022-26923 #secretsdump

    ![](/img/coder-cover.png)

    Coder starts with an SMB server that has a DotNet executable used to
    encrypt things, and an encrypted file. I'll reverse engineer the
    executable and find a flaw that allows me to decrypt the file,
    providing a KeePass DB and file. I'll use the file as a key to get
    in, and find the domain, creds, and a 2FA backup to a TeamCity
    server. I'll reverse the Chrome plugin to understand how the backup
    works, and brute force the password to recover the TOTP seed. With
    that and the creds, I can log into the server and upload a diff that
    gets executed as part of a CI/CD pipeline. I'll find Windows
    encrypted creds for the next user in a diff files stored with the
    TeamCity files. For root, I'll abuse CVE-2022-26923 by registering a
    fake computer with a malicious DNS hostname to trick ADCS into
    thinking it's the DC. From there, I can dump the hashes for the
    domain and get a shell as administrator.

-   Dec 14, 2023

    ### [HTB Sherlock: Tick Tock](/htb-sherlock-tick-tock.md)

    #ctf #dfir #forensics #sherlock-tick-tock #sherlock-cat-dfir
    #hackthebox #kape #teamviewer #event-logs #evtxecmd #time-stomping
    #merlin-c2 #defender #mft #mftecmd #htb-sherlock

    ![](/img/sherlock-tick-tock.png)

    A new employee gets a call from the "IT department", who is actually
    a malicious actor. They get a TeamViewer connection and launch a
    Merlin C2 agent. I'll see through the logs the processes it runs,
    where Defender catches it, and how it tries to mess with forensics
    by constantly changing the system time.

-   Dec 9, 2023

    ### [HTB: Authority](/htb-authority.md)

    #ctf #htb-authority #hackthebox #nmap #windows #iis #smb #netexec
    #smbclient #dig #dns #feroxbuster #pwm #ansible #ansible-vault
    #ansible2john #hashcat #wireshark #responder #evil-winrm #adcs
    #certipy #esc1 #ms-ds-machineaccountquota #powerview #addcomputer-py
    #pass-the-cert #silver-ticket #htb-absolute #htb-escape #htb-support

    ![](/img/authority-cover.png)

    Authority is a Windows domain controller. I'll access open shares
    over SMB to find some Ansible playbooks. I'll crack some encrypted
    fields to get credentials for a PWM instance. The PWM instance is in
    configuration mode, and I'll use that to have it try to authenticate
    to my box over LDAP with plain text credentials. With those creds,
    I'll enumerate active directory certificate services to find they
    are vulnerable to ESC1, with a twist. Rather than any user being
    able to enroll with the template, it's any domain computer. I'll add
    a fake computer to the domain and use that to get a certificate for
    the DC. That certificate doesn't work directly, but I can use a
    pass-the-cert attack to dump hashes and get access as administrator.

-   Dec 4, 2023

    ### [HTB Sherlock: Knock Knock](/htb-sherlock-knock-knock.md)

    #ctf #dfir #forensics #sherlock-knock-knock #sherlock-cat-dfir
    #hackthebox #pcap #zeek #pcap-nmap #pcap-password-spray
    #port-knocking #knockd #pcap-port-knocking #ansible #gonnacry
    #htb-sherlock

    ![](/img/sherlock-knock-knock.png)

    Knock Knock is a Sherlock from HackTheBox that provides a PCAP for a
    ransomware incident. I'll find where the attacker uses a password
    spray to compromise a publicly facing FTP server. In there, the
    attacker finds a configuration file for a port-knocking setup, and
    uses that to get access to an internal FTP server. On that server,
    they find lots of documents, including a reference to secrets on the
    company GitHub page. In that repo, the attacker found SSH creds, and
    used an SSH session to download GonnaCry ransomware using wget.

-   Dec 2, 2023

    ### [HTB: CyberMonday](/htb-cybermonday.md)

    #htb-cybermonday #ctf #hackthebox #nmap #debian #php #laravel
    #feroxbuster #off-by-slash #nginx #ffuf #gitdumper #source-code
    #mass-assignment #burp #burp-repeater #api #jwt #jwks #python-jwt
    #jwt-tool #jwt-algorithm-confusion #jwt-asymmetric #ssrf #ssrf-redis
    #redis #crlf-injection #laravel-deserialization #deserialization
    #redis-migrate #redis-blind #laravel-decrypt #phpggc #docker
    #container #escape #pivot #chisel #docker-registry #snyk
    #directory-traversal #file-read #docker-compose #docker-capabilities
    #docker-apparmor #docker-shocker #shocker #youtube #htb-pikaboo
    #htb-seal #htb-monitors #htb-talkative

    ![](/img/cybermonday-cover.png)

    CyberMonday is a crazy difficult box, most of it front-loaded before
    the user flag. I'll start with a website, and abuse an off-by-slash
    nginx misconfiguration to read a .env file and the Git source repo.
    I'll find a mass assignment vulnerability in the site allowing me to
    get admin access, which provides a new subdomain for a webhooks API.
    I'll enumerate that API to find it uses JWTs and asymmetric crypto.
    I'll abuse that to forge a token and get admin access to the API,
    where I can create webhooks. One of webhooks allows me to get the
    server to issue web requests, like an SSRF. I'll abuse that, with a
    CRLF injection to interact with the Redis database that's caching
    the Laravel session data. I'll abuse that to get code execution in
    the web container. From there, I'll find a Docker Registry
    container, and pull the API container image. Source code review
    shows additional API endpoints with an additional header required.
    I'll abuse those to get file read on the API container, and leak the
    password of a user that works for SSH. To get to root, I'll abuse a
    script designed to allow a user to run docker compose in a safe way.
    I'll show a couple ways to do this, most of which center around
    giving the container privileges. In Beyond Root, I look at where the
    Python JWT library prevented me from forging a JWT, and edit it to
    allow me. I'll also look at the off-by-slash vulnerability in the
    nginx config.

-   Nov 25, 2023

    ### [HTB: Pilgr![![image*](/htb-pilgrimage.md)

    #htb-pilgrimage #ctf #hackthebox #nmap #debian #git #gitdumper
    #feroxbuster #cve-2022-44268 #image-magick #pngcrush #sqlite
    #inotifywait #binwalk #cve-2022-4510 #file-read #htb-scriptkiddie

    ![](/img/pilgrimage-cover.png)

    Pilgrimage starts with a website that reduces image size. I'll find
    an exposed Git repo on the site, and use it to see it's using a
    version of Image Magick to do the image reduction that has a file
    read vulnerability. I'll use that to enumerate the host and pull the
    SQLite database. That database gives a plaintext password that works
    for SSH. There's a script run by root that's monitor file uploads
    using inotifywait. When there's a file, it runs binwalk on the file
    to look for executables. I'll abuse a vulnerability in binwalk to
    get execution as root.

-   Nov 18, 2023

    ### [HTB: Sandworm](/htb-sandworm.md)

    #htb-sandworm #ctf #hackthebox #nmap #ubuntu #gpg #pgp #feroxbuster
    #python #flask #ssti #crypto #firejail #httpie #cargo #rust
    #source-code #cve-2022-31214 #htb-cerberus

    ![](/img/sandworm-cover.png)

    Sandworm offers the website for a secret intelligence agency. The
    website takes PGP-encrypted messages, and there's a demo site that
    allows people to test their encrypting, decrypting, and signing.
    There's a server-side template injection vulnerability in the
    verification demo, and I'll abuse that to get a foothold on
    Sandworm. That access runs inside a Firejail jail. I'll find creds
    for the next user in a httpie config. Then I'll modify a Rust
    program running on a cron as the first user to get back to that
    user, this time outside the jail. With that access, I can exploit
    CVE-2022-31214 in Firejail to get root access. In Beyond Root, I'll
    look at the Flask webserver and how works, and the Firejail config.

-   Nov 17, 2023

    ### [HTB Sherlock: i-like-to](/htb-sherlock-i-like-to.md)

    #ctf #dfir #forensics #sherlock-cat-dfir #sherlock-i-like-to
    #hackthebox #htb-sherlock #moveit #cve-2023-34362 #sqli
    #deserialization #metasploit #source-code #kape #memory-dump
    #iis-logs #powershell-history #event-logs #sql-dump #webshell
    #awen-webshell #asp #aspx #mftexplorer #mftecmd #mft #evtxecmd #jq
    #win-event-4624 #win-event-4724

    ![](/img/sherlock-i-like-to.png)

    i-like-to is the first Sherlock to retire on HackTheBox. It's a
    forensics investigation into a compromised MOVEit Transfer server. I
    start with a memory dump and some collection from the file system,
    and I'll use IIS logs, the master file table (MFT), PowerShell
    History logs, Windows event logs, a database dump, and strings from
    the memory dump to show that the threat actor exploited the SQL
    injection several times using the Metasploit exploit to run commands
    via deserialization, changing the password of the moveitsvc user and
    connecting over remote desktop, and then again to upload a webshell.
    The first attempt to upload the webshell was quarantined by
    Defender, but a different copy of the awen webshell was successful.

-   Nov 11, 2023

    ### [HTB: Download](/htb-download.md)

    #ctf #hackthebox #htb-download #nmap #ubuntu #express #cookies
    #crypto #hamc #sha1 #signature #feroxbuster #file-read #burp
    #burp-repeater #prisma #orm #orm-injection #npm #cyberchef
    #bruteforce #python #hashcat #systemd #psql #postgresql #pspy
    #tty-pushback #ioctl #ioctl-tiocsti

    ![](/img/download-cover.png)

    Download starts off with a cloud file storage solution. I'll find a
    subtle file read vulnerability that allows me to read the site's
    source. With that source, I'll identify an ORM injection that allows
    me to access other user's files, and to brute force items from the
    database. With a password hash that is crackable, I'll get SSH on
    the box. From there, I'll identify a root cron that's dropping to
    the postgres user to make database queries. I'll exploit TTY
    pushback to get execution as root. In Beyond Root, I'll dig more
    into the TTY pushback, and look at the file read vuln.

-   Nov 9, 2023

    ### [HTB: Broker](/htb-broker.md)

    #ctf #hackthebox #htb-broker #ubuntu #nmap #activemq #cve-2023-46604
    #deserialization #java #nginx #shared-object #ldpreload #sudo-nginx

    ![](/img/broker-cover.png)

    Broken is another box released by HackTheBox directly into the
    non-competitive queue to highlight a big deal vulnerability that's
    happening right now. ActiveMQ is a Java-based message queue broker
    that is very common, and CVE-2023-46604 is an unauthenticated remote
    code execution vulnerability in ActiveMQ that got the rare 10.0 CVSS
    imact rating. I'll exploit this vulnerability to get a foothold, and
    then escalate to root abusing the right to run nginx as root. I'll
    stand up a rogue server to get file read. Then I'll add PUT
    capabilities and write an SSH key for root. I'll also show a method
    that was used to exploit a similar Zimbra miconfiguration
    (CVE-2022-41347). In this case, I'll poison the LD preload file by
    running nginx with its error logs pointing at that file, and then
    load a malicious shared object.

-   Nov 4, 2023

    ### [HTB: Topology](/htb-topology.md)

    #htb-topology #ctf #hackthebox #nmap #ubuntu #feroxbuster #ffuf
    #subdomain #latex #pdftex #file-read #htaccess #htpasswd #hashcat
    #gnuplot #filter #bypass #htb-chaos

    ![](/img/topology-cover.png)

    Topology starts with a website for a Math department at a university
    with multiple virtual hosts. One has a utility for turning LaTeX
    text into an image. I'll exploit an injection to get file read, and
    get the .htpassword file for a dev site, which has a shared password
    with a user on the box. To get to root, I'll exploit a cron running
    gnuplot. In Beyond Root, I'll look at an unintended filter bypass
    that allows for getting a shell as www-data by writing a webshell
    using LaTeX, as well as how one of the images that gnuplot is
    creating got broken and how to fix it.

-   Oct 28, 2023

    ### [HTB: Gofer](/htb-gofer.md)

    #ctf #hackthebox #htb-gofer #nmap #debian #samba #netexec #smbclient
    #smtp #ffuf #feroxbuster #subdomain #burp #burp-proxy #burp-repeater
    #ssrf #filter #smtp-over-gopher #gopher #phishing #odt #libreoffice
    #macros #tcpdump #sniffing #heap #binary-exploitation #path-hijack
    #youtube #ghidra #htb-travel #htb-laser #htb-jarmis #htb-attended
    #htb-re #htb-rabbit

    ![](/img/gofer-cover.png)

    Gofer starts with a proxy that requires auth. I'll bypass this using
    different HTTP verbs, and get access to the proxy that allows for
    gopher protocol. I'll use that to interact with an internal SMTP
    server and send a phishing email to one of the users with a
    LibreOffice Writer (like Word) attachment. With a shell, I'll use
    tcpdump to sniff traffic and catch the next user logging into the
    proxy. That password is shared on the system. This user has access
    to a simple notes program running as root. I'll identify and exploit
    a use after free vulnerability and a path hijack just by playing
    with it. Then in Beyond Root, I'll open it with Ghidra and see what
    it is doing, and take a look at the filter rules on the proxy.

-   Oct 21, 2023

    ### [HTB: Jupiter](/htb-jupiter.md)

    #ctf #htb-jupiter #hackthebox #nmap #ffuf #feroxbuster #grafana
    #postgresql #cve-2019-9193 #burp #burp-repeater #pspy
    #shadow-simulation #jupyter-notebook #sattrack #arftracksat

    ![](/img/jupiter-cover.png)

    Jupiter starts with a Grafana dashboard. I'll find an endpoint in
    Grafana that allows me to send raw SQL queries that are executed by
    the PostgreSQL database, and use that to get code execution on the
    host. Then I'll exploit a cron running Shadow Simulator to pivot to
    the next user. Then, I'll get access to a Jupyter Notebook, and use
    it to pivot again. To get a shell as root, I'll exploit a satellite
    tracking program.

-   Oct 14, 2023

    ### [HTB: Intentions](/htb-intentions.md)

    #htb-intentions #ctf #hackthebox #nmap #ubuntu #php #laravel
    #feroxbuster #image-magick #sqli #second-order #second-order-sqli
    #sqli-union #sqli-no-spaces #sqlmap #sqlmap-second-order #ssrf
    #arbitrary-object-instantiation #msl #scheme #webshell #upload #git
    #capabilities #bruteforce #python #youtube #file-read #htb-extension
    #htb-earlyaccess #htb-nightmare

    ![](/img/intentions-cover.png)

    Intentions starts with a website where I'll find and exploit a
    second order SQL injection to leak admin hashes. I'll find a version
    of the login form that hashes client-side and send the hash to get
    access as admin. As admin, I have access to new features to modify
    images. I'll identify this is using ImageMagick, and abuse arbitrary
    object instantiation to write a webshell. With a foothold, I'll find
    credentials in an old Git commit, and pivot to the next user. This
    user can run a hashing program as root to look for copywritten
    material. I'll abuse it's ability to specify a length to give myself
    file read as root by brute-forcing one byte at a time. In Beyond
    Root, I'll look at some oddities of the file scanner.

-   Oct 11, 2023

    ### [\[HTB Blog\] Exploiting Looney Tunables](/exploiting-the-looney-tunables-vulnerability-on-htb-cve-2023-4911-htb-blog.md)

    #hackthebox #htb-twomillion #cve-2023-4911 #looney-tunables #glibc
    #gnu-loader #glibc-tunables #syslog

    ![](/img/looney-tunables-cover.png)

    I wrote a blog post for the HackTheBox blog, [Exploiting the Looney
    Tunables Vulnerability on HTB
    (CVE-2023-4911)](https://www.hackthebox.com/blog/exploiting-the-looney-tunables-vulnerability-cve-2023-4911).
    In the post, I'll give an overview of the vulnerability and how
    exploitation works (at a high level), and then show how to run one
    of the proof of concept (POC) exploits against the HackTheBox
    [TwoMillion](https://www.hackthebox.com/machines/TwoMillion)
    machine. I'll also look at how to detect Looney Tunables
    exploitation in Linux log files.

-   Oct 7, 2023

    ### [HTB: PC](/htb-pc.md)

    #ctf #htb-pc #hackthebox #nmap #ubuntu #grpc #grpcurl #sqlite #sqli
    #sqlite-injection #pyload #cve-2023-0297 #youtube

    ![](/img/pc-cover.png)

    PC starts with only SSH and TCP port 50051 open. I'll poke at 50051
    until I can figure out that it's GRPC, and then use grpcurl to
    enumerate the service. I'll find an SQL injection in the SQLite
    database and get some creds that I can use over SSH. To escalate,
    I'll find an instance of pyLoad running as root and exploit a 2023
    CVE to get execution. In Beyond Root, a video exploring the Python
    GRPC application to see how it works.

-   Sep 30, 2023

    ### [HTB: Format](/htb-format.md)

    #htb-format #hackthebox #ctf #nmap #ffuf #subdomain #debian
    #feroxbuster #gitea #source-code #php #file-read #arbitrary-write
    #webshell #burp #burp-repeater #nginx #redis #proxy-pass
    #password-reuse #python #ssti #wfuzz

    ![](/img/format-cover.png)

    Format hosts a primitive opensource microblogging site. I'll abuse
    post creation to get arbitrary read and write on the host, and use
    that along with a proxy_pass bug to poison Redis, giving my account
    "pro" status. With the upgraded status, I can access a writable
    directory that I can drop a webshell into and get a foothold on the
    box. To pivot to the user, I'll get shared credentials out of the
    Redis database. To get to root, I'll exploit a template injection in
    a Python script to leak the secret. In Beyond Root, I'll look at two
    unintended solutions that were patched (mostly) ten days after
    release.

-   Sep 28, 2023

    ### [HTB: Aero](/htb-aero.md)

    #ctf #hackthebox #htb-aero #nmap #windows #windows11 #iis-arr
    #feroxbuster #themebleed #cve-2023-38146 #msstyles #dll #youtube
    #visual-studio #cpp #cff-explorer #dll-reverse-shell #cve-2023-28252
    #nokoyawa #filesystemwatcher #htb-helpline

    ![](/img/aero-cover.png)

    The Aero box is a non-competitive release from HackTheBox meant to
    showcase two hot CVEs right now, ThemeBleed (CVE-2023-38146) and a
    Windows kernel exploit being used by the Nokoyawa ransomware group
    (CVE-2023-28252). To exploit these, I'll have to build a reverse
    shell DLL other steps in Visual Studio. In Beyond Root, I'll look at
    a neat automation technique I hadn't seen before using
    FileSystemWatcher to run an action on file creation.

-   Sep 23, 2023

    ### [HTB: Snoopy](/htb-snoopy.md)

    #ctf #hackthebox #htb-snoopy #ubuntu #linux #nmap #bind #dns
    #feroxbuster #ffuf #subdomain #mattermost #password-reset
    #zone-transfer #directory-traversal #file-read #filter #youtube
    #python #python-zipfile #php #tsig-dns #python-aiosmtpd
    #quoted-printable-encoding #ssh-honeypot #cowrie #git #git-apply
    #cve-2023-23946 #git-diff #clamav #clamscan #cve-2023-20052 #dmg
    #xxe #binary-edit #htb-encoding

    ![](/img/snoopy-cover.png)

    Snoopy starts off with a website that has a file read / directory
    traversal vulnerability. I'll use that to read a bind DNS
    configuration, and leak the keys necessary to make changes to the
    configuration. Once that's updated, I can direct password reset
    emails for accounts on snoopy.htb to my server, and get access to a
    MatterMost instance. In there, I'll abuse a slash command intended
    to provisions servers to have it connect to my SSH honeypot, and use
    those creds to get on the box. The next two steps both involve CVEs
    that didn't have public exploits or even much documentation at the
    time Snoopy released. First I'll exploit a CVE in git for how the
    apply command allows overwriting arbitrary files. Then I'll exploit
    an XXE vulnerability in ClamAV's clamscan utility to read root's SSH
    key. In Beyond Root, I'll reconfigure the box back before a patch
    from HackTheBox and show two unintended exploits that no longer
    work.

-   Sep 16, 2023

    ### [HTB: Wifinetic](/htb-wifinetic.md)

    #hackthebox #ctf #htb-wifinetic #nmap #openwrt #wpa #reaver #wps
    #wps-bruteforce #wash

    ![](/img/wifinetic-cover.png)

    Wifinetic is a realitively simple box, but based on some cool tech
    Felemos did to virtualize a wireless network. I'll start with
    anonymous access to an FTP server that contains a backup file with a
    WPA wireless config. That config has a pre-shared key (password) in
    it, that also works over SSH. On the box, I'll find a few wireless
    interfaces configured, and the reaver WPA WPS pin crackign tool.
    This tool allows me to brute force leak the pre-shared key for the
    wireless network, which happens to be the root password. In Beyond
    Root, I'll look at the wash command, and why it doesn't work well on
    this box despite being in almost all of the reaver tutorials.

-   Sep 9, 2023

    ### [HTB: PikaTwoo](/htb-pikatwoo.md)

    #htb-pikatwoo #hackthebox #ctf #nmap #debian #express #feroxbuster
    #modsecurity #waf #apisix #uri-blocker-apisix #openstack
    #openstack-swift #openstack-keystone #android #cve-2021-38155 #ffuf
    #apktool #apk #flutter #flutter-obfuscate #genymotion #adb #burp
    #burp-proxy #burp-repeater #certificate-pinning #frida #sqli
    #chat-gpt #rsa #cve-2021-43557 #bypass #api #swagger #nginx
    #cve-2021-35368 #youtube #nginx-temp-files #kubernetes #minikube
    #kubectl #podman #cve-2022-24112 #cr8escape #cve-2022-0811 #crio
    #kernel-parameters #crashdump #htb-dyplesher #htb-canape
    #htb-pikaboo #htb-routerspace #htb-encoding #htb-pollution
    #htb-vessel

    ![](/img/pikatwoo-cover.png)

    PikaTwoo is an absolute monster of an insane box. I'll start by
    abusing a vulnerability in OpenStack's KeyStone to leak a username.
    With that username, I'll find an Android application file in the
    OpenStack Swift object storage. The application is a Flutter
    application built with the obfuscate option, making it very
    difficult to reverse. I'll set up an emulator to proxy the
    application traffic, using Frida to bypass certificate pinning. I'll
    find an SQL injection in the API, and leak an email address. I'll
    exploit another vulenrability in the APISIX uri-block WAF to get
    access to private documents for another API. There, I'll reset the
    password for the leaked email, and get authenticated access. I'll
    exploit a vulnerability in the modsecurity core rule set to bypass
    the WAF and get local file include in that API. From there, I'll
    abuse nginx temporary files to get a reverse shell in the API pod.
    I'll leak an APISIX secret from the Kubernetes secrets store, and
    use that with another vulnerability to get execution in the APISIX
    pod. I'll find creds for a user in a config file and use them to SSH
    into the host. From there, I'll abuse the Cr8Escape vulnerability to
    get execution as root.

-   Sep 2, 2023

    ### [HTB: MonitorsTwo](/htb-monitorstwo.md)

    #htb-monitorstwo #hackthebox #ctf #nmap #ubuntu #cacti
    #cve-2022-46169 #command-injection #metasploit #wfuzz #burp-repeater
    #burp #docker #john #cve-2021-41091 #cve-2021-41103 #htb-monitors

    ![](/img/monitorstwo-cover.png)

    MonitorsTwo starts with a Cacti website (just like Monitors).
    There's a command injection vuln that has a bunch of POCs that don't
    work as of the time of MonitorsTwo's release. I'll show why, and
    exploit it manually to get a shell in a container. I'll pivot to the
    database container and crack a hash to get a foothold on the box.
    For root, I'll exploit a couple of Docker CVEs that allow for
    creating a SetUID binary inside the container that I can then run as
    root on the host.

-   Aug 26, 2023

    ### [HTB: OnlyForYou](/htb-onlyforyou.md)

    #hackthebox #htb-onlyforyou #ctf #nmap #ffuf #subdomain #flask
    #ubuntu #source-code #file-read #directory-traversal #burp
    #burp-repeater #python-re #command-injection #filter #chisel
    #foxyproxy #gogs #neo4j #cypher-injection #cypher #crackstation #pip
    #setup-py #htb-opensource

    ![](/img/onlyforyou-cover.png)

    OnlyForYou is about exploiting Python and Neo4J. I'll start by
    exploiting a Flask website file disclosure vulnerability due to a
    misunderstanding of the `os.path.join` function to get the source
    for another site. In that source, I'll identify a command injection
    vulnerability, and figure out how bypass the filtering with a
    misunderstanding of the `re.match` function. Exploiting this returns
    a shell. I'll pivot to the next user by abusing a Cypher Injection
    in Neo4J, and then escalate to root by exploiting an unsafe sudo
    rule with pip.

-   Aug 19, 2023

    ### [HTB: Mailroom](/htb-mailroom.md)

    #htb-mailroom #hackthebox #ctf #nmap #ubuntu #debian #feroxbuster
    #wfuzz #gitea #subdomain #execute-after-redirect #xss
    #nosql-injection #nosql-injection-over-xss #xsrf #command-injection
    #filter #keepass #strace #trace #ptrace-scope #youtube #htb-retired
    #htb-fingerprint #htb-previse

    ![](/img/mailroom-cover.png)

    Mailroom has a contact us form that I can use to get cross site
    sripting against an admin user. I'll use this XSS to exploit a NoSQL
    injection vulnerability in a private site, brute forcing the user's
    password and exfiling it back to myself. From this foothold, I'll
    exploit into the container running the site and find more
    credentials, pivoting to another user. This user is opening their
    KeePass database, and I'll use strace to watch them type their
    password into KeePass CLI, which I can use to recover the root
    password. In Beyond Root, a quick dive into how the KeePass password
    was automated.

-   Aug 12, 2023

    ### [HTB: Busqueda](/htb-busqueda.md)

    #hackthebox #htb-busqueda #ctf #nmap #flask #ubuntu #searchor
    #feroxbuster #python-eval #command-injection #burp #burp-repeater
    #password-reuse #gitea #htb-forgot

    ![](/img/busqueda-cover.png)

    Busqueda presents a website that gives links to various sites based
    on user input. Under the hood, it is using the Python Searchor
    command line tool, and I'll find an unsafe eval vulnerability and
    exploit that to get code execution. On the host, the user can run
    sudo to run a Python script, but I can't see the script. I'll find a
    virtualhost with Gitea, and use that along with different creds to
    eventually find the source for the script, and identify how to run
    it to get arbitrary execution as root.

-   Aug 5, 2023

    ### [HTB: Agile](/htb-agile.md)

    #ctf #hackthebox #htb-agile #nmap #ubuntu #flask #python
    #feroxbuster #file-read #werkzeug #werkzeug-debug #flask-debug-pin
    #youtube #python-venv #pytest #selenium #chrome #chrome-debug
    #sudoedit #cve-2023-22809 #idor #flask-cookie #htb-bagel
    #htb-opensource #htb-rainyday #htb-noter

    ![](/img/agile-cover.png)

    Agile is a box hosting a password manager solution. There's a file
    read vulnerability in the application, and the Flask server is
    running in debug mode. I'll use those to get execution on the box,
    which turns out to be a bit trickier than expected. From there, I'll
    dump a user's password out of the database and get an SSH shell.
    There's a testing version of the app running as well, and I'll abuse
    Chrome debug to get credentials from the testing Chrome instance to
    pivot to the next user. This user can use sudoedit to modify files
    related to the test server. I'll abuse CVE-2023-22809 to write into
    the virtual environment that root is sourcing to get root. In Beyond
    Root, I'll show two unintended vulnerabilities in the web
    application that got patched about a week after release.

-   Jul 29, 2023

    ### [HTB: Cerberus](/htb-cerberus.md)

    #ctf #htb-cerberus #hackthebox #nmap #ttl #wireshark #dig #ffuf
    #icinga #github #cve-2022-24716 #cve-2022-24715 #file-read
    #arbitrary-write #icinga-module #firejail #cve-2022-31214 #sssd
    #hashcat #chisel #evil-winrm #manageengine #adselfservice
    #cve-2022-47966 #metasploit #saml #saml-decoder

    ![](/img/cerberus-cover.png)

    Cerberus is unique in that it's one of the few boxes on HTB (or any
    CTF) that has Windows hosting a Linux VM. To start, I can only
    access an IcingaWeb2 instance running in the VM. I'll exploit two
    CVEs in Icinga, first with file read to get credentials, and then a
    file write to write a fake module and get execution. Inside the VM,
    I'll exploit Firejail to get root. I'll also get creds for a user on
    the host from SSSD, and then tunnel through the VM to get WinRM
    access to the host. To get SYSTEM on the host, I'll exploit a SAML
    vulnerability in ManageEngine's ADSelfService Plus.

-   Jul 22, 2023

    ### [HTB: Derailed](/htb-derailed.md)

    #ctf #hackthebox #htb-derailed #nmap #ruby #rails #debian #ffuf
    #idor #xss #wasm #webassembly #javascript #bof #wasm-bof
    #pattern-create #command-injection #cors #chatgpt #python #file-read
    #open-injection #open-injection-ruby #openmediavault #sqlite #git
    #hashcat #chisel #deb #deb-package #youtube #htb-investigation
    #htb-pikaboo #htb-onetwoseven

    ![](/img/derailed-cover.png)

    Derailed starts with a Ruby on Rails web notes application. I'm able
    to create notes, and to flag notes for review by an admin. The
    general user input is relatively locked down as far as cross site
    scripting, but I'll find a buffer overflow in the webassembly that
    puts the username on the page and use that to get a XSS payload
    overwriting the unfiltered date string. From there, I'll use the
    administrator's browser session to read an admin page with a file
    read vulnerability where I can get the page source, and abuse an
    open injection in Ruby (just like in Perl) to get execution. I'll
    pivot uses using creds from the database. To get root, I'll exploit
    openmediavault's RPC, showing three different ways - adding an SSH
    key for root, creating a cron, and installing a Debian package. In
    Beyond Root, I'll debug the webassembly in Chromium dev tools.

-   Jul 15, 2023

    ### [HTB: Socket](/htb-socket.md)

    #ctf #hackthebox #htb-socket #nmap #ffuf #qrcode #python #ubuntu
    #flask #websocket #python-websockets #pyinstaller #burp #burp-proxy
    #burp-repeater #burp-repeater-websocket #websocket-sqli
    #username-anarchy #crackmapexec #pyinstaller-spec #pyinstxtractor
    #pycdc #htb-forgot #htb-absolute

    ![](/img/socket-cover.png)

    Socket has a web application for a company that makes a QRcode
    encoding / decoding software. I'll download both the Linux and
    Windows application, and through dynamic analysis, see web socket
    connections to the box. I'll find a SQLite injection over the
    websocket and leak a password and username that can be used for SSH.
    That user is able to run the PyInstaller build process as root, and
    I'll abuse that to read files, and get a shell. In Beyond Root, I'll
    look at pulling the Python source code from the application, even
    though I didn't need that to solve the box.

-   Jul 8, 2023

    ### [HTB: Inject](/htb-inject.md)

    #ctf #htb-inject #hackthebox #nmap #ubuntu #file-read
    #directory-traversal #tomcat #feroxbuster #burp-repeater #burp
    #spring-cloud-function-spel-injection #java #java-sprint #maven
    #snyk #spring-cloud-function-web #cve-2022-22963 #command-injection
    #brace-expansion #ansible #pspy #ansible-playbook

    ![](/img/inject-cover.png)

    Inject has a website with a file read vulnerability that allows me
    to read the source code for the site. The source leaks that it's
    using SpringBoot, and have a vulnerable library in use that allows
    me to get remote code execution. I'll show how to identify this
    vulnerability both manually and using Snyk. The root step is about
    abusing a cron that's running the Ansible automation framework.

-   Jul 1, 2023

    ### [HTB: Pollution](/htb-pollution.md)

    #htb-pollution #ctf #hackthebox #debian #nmap #redis #redis-cli
    #feroxbuster #ffuf #subdomain #mybb #burp #burp-history-export #xxe
    #htpasswd #hashcat #source-code #php #lfi #php-filter-injection
    #php-fpm #fastcgi #express #nodejs #snyk #prototype-pollution
    #htb-updown #htb-encoding

    ![](/img/pollution-cover.png)

    Pollution starts off with a website where I can find a token in a
    forum post that has a Burp history export attached. With that token,
    I can escalate my account to admin, and get access to an endpoint
    vulnerable to XML external entity (XXE) injection. With that, I'll
    read files, including the source code for the site to get access to
    redis, where I'll modify my state to get access to the developers
    site. That site has a PHP local file include (LFI) that I can
    exploit with filter injection to get code execution. This filter
    injection technique has become popular, but was relatively unknown
    at the time of Pollution's release. I'll pivot to the next user by
    exploiting PHP's FastCGI Process Manager (PHP-FPM), where I'll get
    access to the source code for a NodeJS / Express API in development.
    That API has a prototpye pollution vulnerability, which I can
    exploit to get execution and a shell as root. In beyond root, I take
    a quick look at the max length of a URL encountered during the XXE
    exploit.

-   Jun 24, 2023

    ### [HTB: Stocker](/htb-stocker.md)

    #hackthebox #ctf #htb-stocker #nmap #ubuntu #ffuf #subdomain
    #feroxbuster #burp #burp-repeater #chatgpt #express #nodejs #nosql
    #nosql-auth-bypass #nosql-injection #xss #serverside-xss #pdf
    #file-read

    ![](/img/stocker-cover.png)

    Stocker starts out with a NoSQL injection allowing me to bypass
    login on the dev website. From there, I'll exploit purchase order
    generation via a serverside cross site scripting in the PDF
    generation that allows me to read files from the host. I'll get the
    application source and use a password it contains to get a shell on
    the box. The user can run some NodeJS scripts as root, but the sudo
    rule is misconfiguration that allows me to run arbirtray JavaScript,
    and get a shell as root.

-   Jun 17, 2023

    ### [HTB: Escape](/htb-escape.md)

    #ctf #htb-escape #hackthebox #nmap #crackmapexec #windows #smbclient
    #mssql #mssqlclient #xp-cmdshell #responder #net-ntlmv2 #hashcat
    #winrm #evil-winrm #certify #adcs #rubeus #certipy #esc1
    #silver-ticket #pass-the-hash #xp-dirtree #htb-querier #htb-hackback
    #htb-proper #openssl

    ![](/img/escape-cover.png)

    Escape is a very Windows-centeric box focusing on MSSQL Server and
    Active Directory Certificate Services (ADCS). I'll start by finding
    some MSSQL creds on an open file share. With those, I'll use
    xp_dirtree to get a Net-NTLMv2 challenge/response and crack that to
    get the sql_svc password. That user has access to logs that contain
    the next user's creds. To get administrator, I'll attack active
    directory certificate services, showing both certify and certipy. In
    Beyond Root, I'll show an alternative vector using a silver ticket
    attack from the first user to get file read as administrator through
    MSSQL.

-   Jun 10, 2023

    ### [HTB: Soccer](/htb-soccer.md)

    #hackthebox #ctf #htb-soccer #nmap #ffuf #subdomain #ferobuster
    #express #ubuntu #tiny-file-manager #default-creds #upload #webshell
    #php #websocket #burp #sqli #websocket-sqli #boolean-based-sqli
    #sqlmap #doas #dstat

    ![](/img/soccer-cover.png)

    Soccer starts with a website that is managed over Tiny File Manager.
    On finding the default credentials, I'll use that to upload a
    webshell and get a shell on the box. With this foothold, I'll
    identify a second virtual host with a new site. That site uses
    websockets to do a validation task. I'll exploit an SQL injection
    over the websocket to leak a password and get a shell over SSH. The
    user is able to run dstat as root using doas, which I'll exploit by
    crafting a malicious plugin.

-   Jun 7, 2023

    ### [HTB: TwoMillion](/htb-twomillion.md)

    #ctf #htb-twomillion #hackthebox #nmap #ffuf #feroxbuster #php
    #ubuntu #javascript #burp #burp-repeater #api #command-injection
    #cve-2023-0386 #htb-invite-challenge #cyberchef #youtube

    ![](/img/twomillion-cover.png)

    TwoMillion is a special release from HackTheBox to celebrate
    2,000,000 HackTheBox members. It released directly to retired, so no
    points and no bloods, just for run. It features a website that looks
    like the original HackTheBox platform, including the original invite
    code challenge that needed to be solved in order to register. Once
    registered, I'll enumerate the API to find an endpoint that allows
    me to become an administrator, and then find a command injection in
    another admin endpoint. I'll use database creds to pivot to the next
    user, and a kernel exploit to get to root. In Beyond Root, I'll look
    at another easter egg challenge with a thank you message, and a
    YouTube video exploring the webserver and it's vulnerabilities.

-   Jun 3, 2023

    ### [HTB: Bagel](/htb-bagel.md)

    #ctf #htb-bagel #hackthebox #nmap #python #flask #source-code
    #file-read #dotnet #websocket #ffuf #source-code
    #reverse-engineering #proc #wscat #dnspy #json #json-deserialization
    #dotnet-deserialization #json.net

    ![](/img/bagel-cover.png)

    Bagel is centered around two web apps. The first is a Flask server.
    I'll exploit a file read vulnerability to locate and retrieve the
    source. In that source, I see how it connects to the other .NET
    server over web sockets. I'll abuse the first file read to get the
    DLL for that server. On reversing that DLL, I'll find a JSON
    derserialization issue, and exploit it to get file read and the
    user's SSH key. I'll pivot to the next user using creds from the
    DLL. To get root, I'll exploit a sudo rule that let's the user run
    dotnet as root.

-   May 27, 2023

    ### [HTB: Absolute](/htb-absolute.md)

    #htb-absolute #hackthebox #ctf #windows #iis #crackmapexec
    #ldapsearch #dnsenum #feroxbuster #exiftool #username-anarchy
    #kerbrute #as-rep-roast #hashcat #kerberos #kinit #klist #bloodhound
    #bloudhound-python #rpc #dynamic-reversing #wireshark
    #shadow-credentials #certipy #krbrelay #visual-studio #runascs
    #krbrelayup #rubeus #dcsync #htb-outdated

    ![](/img/absolute-cover.png)

    Absolute is a much easier box to solve today than it was when it
    first released in September 2022. At that time, many of the tools
    necessary to solve the box didn't support Kerberos authentication,
    forcing the place to figure out ways to make things work. Still,
    even today, it's a maze of Windows enumeration and exploitation that
    starts with some full names in the metadata of images. I'll figure
    out the username format for the domain, and AS-REP-Roast to get
    creds. LDAP enumeration leads to the next set of creds. Access to a
    share provides a Nim binary, where some dynamic analysis provides
    yet another set of creds. This user is able to modify a group and
    from there modify a user to add a shadow credential and finally get
    a shell on the box. To get administrator access, I'll abuse relaying
    Kerberos, showing both KrbRelay to add a user to the administrators
    group, and KrbRelayUp to get the machine account hash and do a DC
    sync attack.

-   May 20, 2023

    ### [HTB: Precious](/htb-precious.md)

    #ctf #hackthebox #htb-precious #nmap #subdomain #ffuf #ruby #phusion
    #passenger #nginx #exiftool #pdfkit #feroxbuster #cve-2022-25765
    #command-injection #bundler #yaml-deserialization #youtube

    ![](/img/precious-cover.png)

    Precious is on the easier side of boxes found on HackTheBox. It
    starts with a simple web page that takes a URL and generates a PDF.
    I'll use the metadata from the resulting PDF to identify the
    technology in use, and find a command injection exploit to get a
    foothold on the box. Then I'll find creds in a Ruby Bundler
    configuration file to get to user. To get to root, I'll exploit a
    yaml deserialization vulnerability in a script meant to manage
    dependencies. In Beyond Root, I'll explore the Ruby web application,
    how it's hosted, and fix the bug that doesn't allow me to fetch a
    PDF of the page itself.

-   May 13, 2023

    ### [HTB: Interface](/htb-interface.md)

    #htb-interface #hackthebox #ctf #nmap #ubuntu #next-js #feroxbuster
    #subdomain #api #ffuf #dompdf #php #cve-2022-28368 #webshell #upload
    #pspy #arithmetic-expression-injection
    #quoted-expressinion-injection #exiftool #symbolic-link #htb-rope
    #htb-wall

    ![](/img/interface-cover.png)

    Interface starts with a site and an API that, after some fuzzing /
    enumeration, can be found to offer an endpoint to upload HTML and
    get back a PDF, converted by DomPDF. I'll exploit a vulnerability in
    DomPDF to get a font file into a predictable location, and poison
    that binary file with a PHP webshell. To escalate, I'll abuse a
    cleanup script with Arithmetic Expression Injection, which abuses
    the `[[ "$VAR" -eq "something" ]]` syntax in Bash scripts. In Beyond
    Root, I'll look at an unintended abuse of another cleanup script and
    how symbolic links could (before the box was patched) be used to
    overwrite and change the ownership of arbitrary files.

-   May 6, 2023

    ### [HTB: Flight](/htb-flight.md)

    #htb-flight #hackthebox #ctf #nmap #subdomain #crackmapexec #windows
    #php #apache #feroxbuster #file-read #directory-traversal #responder
    #net-ntlmv2 #password-spray #lookupsid #rpc #ntlm-theft #runascs
    #iis #webshell #aspx #rubeus #machine-account #dcsync #secretsdump
    #psexec

    ![](/img/flight-cover.png)

    Flight is a Windows-centered box that puts a unique twist by showing
    both a Apache and PHP website as well as an internal IIS / ASPX
    website. I'll get the PHP site to connect back to my server on SMB,
    leaking a Net NTLMv2, and crack that to get a plaintext password.
    I'll get a list of domain users over RPC, and password spray that
    password to find another user using the same password. That user has
    write access to a share, where I'll drop files designed to provoke
    another auth back to my server to catch another Net NTLMv2. That
    user has access to the new IIS site, and can write an ASPX webshell
    to get a shell as the IIS account. As a service account, it will
    authenticate over the network as the machine account. I'll abuse
    that to get the administrator's hash and from there a shell.

-   Apr 29, 2023

    ### [HTB: MetaTwo](/htb-metatwo.md)

    #htb-metatwo #ctf #hackthebox #nmap #wfuzz #php #wordpress
    #bookingpress #cve-2022-0739 #sqli #sqlmap #john #xxe
    #cve-2021-29447 #credentials #passpie #pgp #gpg

    ![](/img/metatwo-cover.png)

    MetaTwo starts with a simple WordPress blog using the BookingPress
    plugin to manage booking events. I'll find an unauthenticated SQL
    injection in that plugin and use it to get access to the WP admin
    panel as an account that can manage media uploads. I'll exploit an
    XML external entity (XXE) injection to read files from the host,
    reading the WP configuration, and getting the creds for the FTP
    server. On the FTP server I'll find a script that is sending emails,
    and use the creds from that to get a shell on the host. The user has
    a Passpie instance that stores the root password. I'll crack the PGP
    key protecting the password and get a shell as root.

-   Apr 22, 2023

    ### [HTB: Investigation](/htb-investigation.md)

    #ctf #hackthebox #htb-investigation #nmap #php #exiftool
    #feroxbuster #cve-2022-23935 #command-injection #youtube #perl
    #open-injection #open-injection-perl #event-logs #msgconvert #mutt
    #mbox #evtx-dump #jq #ghidra #reverse-engineering #race-condition
    #htb-pikaboo #htb-meta

    ![](/img/investigation-cover.png)

    Investigation starts with a website that accepts user uploaded
    images and runs Exiftool on them. This version has a command
    injection. I'll dig into that vulnerability, and then exploit it to
    get a foothold. Then I find a set of Windows event logs, and analyze
    them to extract a password. Finally, I find a piece of malware that
    runs as root and understand it to get execution.

-   Apr 15, 2023

    ### [HTB: Encoding](/htb-encoding.md)

    #hackthebox #htb-encoding #ctf #nmap #php #file-read #lfi
    #feroxbuster #wfuzz #subdomain #ssrf #filter #php-filter-injection
    #youtube #source-code #git #git-manual #gitdumper #python #flask
    #proxy #uri-structure #burp #burp-repeater #git-hooks #systemd
    #service #chatgpt #parse_url #htb-updown

    ![](/img/encoding-cover.png)

    Encoding centered around a web application where I'll first identify
    a file read vulnerability, and leverage that to exfil a git repo
    from a site that I can't directly access. With that repo, I'll
    identify a new web URL that has a local file include vulnerability,
    and leverage a server-side request forgery to hit that and get
    execution using php filter injection. To get to the next user I'll
    install a malicious git hook. That user is able to create and start
    services, which I'll abuse to get root. In Beyond root, I'll look at
    an SSRF that worked for IppSec but not me, and show how we
    troubleshot it to find some unexpected behavior from the PHP
    `parse_url` function.

-   Apr 8, 2023

    ### [HTB: BroScience](/htb-broscience.md)

    #hackthebox #ctf #htb-broscience #nmap #php #feroxbuster #file-read
    #directory-traversal #filter #wfuzz #dotdotpwn #psql #postgresql
    #php-deserialization #deserialization #hashcat #command-injection
    #openssl

    ![](/img/broscience-cover.png)

    Hacking BroScience involves using a directory traversal / file read
    vulnerability (minus points to anyone who calls it an LFI) to get
    the PHP source for a website. First I'll use that code to forge an
    activation token allowing me to register my account. Then, the
    source gives the information necessary to exploit a deserialization
    vulnerability by building a malicious PHP serialized object,
    encoding it, and sending it as my cookie. This provides a webshell
    and a shell on the box. I'll find some hashes in the database that
    can be cracked, leading to the next user. The wrinkle here is to
    include the site-wide salt. For root, there's a command injection in
    a script that's checking for certificate expiration. I'll craft a
    malicious certificate that performs the injection to get execution
    as root.

-   Apr 1, 2023

    ### [HTB: Sekhmet](/htb-sekhmet.md)

    #hackthebox #htb-sekhmet #ctf #nmap #ffuf #subdomain #nodejs
    #express #feroxbuster #deserialization #json-deserialization
    #modsecurity #waf #filter #bypass #sssd #kerberos #zipcrypto
    #bkcrack #known-plaintext #crypto #hashcat #kinit #klist #ksu
    #tunnel #smbclient #proxychains #command-injection #watch #tmux
    #ldapsearch #ldap #password-spray #kerbrute #winrm #evil-winrm
    #dpapi #mimikatz #pypykatz #edge-saved-passwords #applocker
    #applocker-bypass #sharp-chromium #sharp-collection #htb-hathor
    #htb-anubis #htb-celestial #htb-nodeblog #htb-ransom #htb-access

    ![](/img/sekhmet-cover.png)

    Sekhmet has Windows and Linux exploitation, and a lot of Kerberos.
    I'll start exploiting a ExpressJS website vulnable to a JSON
    deserialization attack. To get execution, I'll have to bypass a
    ModSecurity web application firewall. This lands me in a Linux VM.
    In the VM, I'll find a backup archive and break the encryption using
    a known plaintext attack on ZipCrypto to get another user's domain
    hash. On cracking that, I'm able to get root on the VM. As the
    domain user, I'll access a share, and figure that there's a text
    file being updated based on the mobile attribute for four users in
    the AD environment. There's a command injection in the script that's
    updating, and I'll use that to get a hash for the user running the
    script. After password spraying that password to find another user,
    I'll get access to the host and find DPAPI protected creds in the
    user's Edge instance. On cracking those, I get domain admin
    credentials.

-   Mar 25, 2023

    ### [HTB: Vessel](/htb-vessel.md)

    #ctf #htb-vessel #hackthebox #nmap #ffuf #nodejs #express
    #feroxbuster #git #gitdumper #express-escape-functions
    #escape-functions #mysqljs #mysqljs-escape-functions #CVE-2022-24637
    #source-code #github #mass-assignment #log-poisoning #webshell #php
    #python #pyinstaller #pyinstxtractor #uncompyle6 #python-pyside2
    #python-qt #pdfcrack #cve-2022-0811 #virus-total #pinns #crio
    #kernel-parameters #crashdump #youtube #htb-updown

    ![](/img/vessel-cover.png)

    Vessel is a really clever box with some nice design. Several of the
    bugs are publicly disclosed, but at the time of release didn't have
    public exploit, so they required digging into the tech to figure out
    how to abuse them. I'll start by pulling a git repo from the
    website, and find an unsafe call to MySQL from Express. This bug is
    surprising, as the code looks good, and I'll dig into it more in
    Beyond Root. After abusing the type confusion to get SQL injection
    and a hash, I'll log in and find a link to a new subdomain hosting
    an instance of Open Web Analytics. I'll abuse an information
    discloser vulnerability to get admin access to OWA, and then a mass
    assignment vuln to move a log into a web-accessible directory and
    poison that log to get execution and a shell. I'll reverse a
    PyInstaller-generated exe to recover a password to pivot to the next
    user. From there, I'll abuse a SetUID binary that's part of CRI-O to
    change kernel parameters and get a shell as root.

-   Mar 18, 2023

    ### [HTB: Extension](/htb-extension.md)

    #hackthebox #htb-extension #ctf #nmap #subdomain #password-reset
    #laravel #feroxbuster #roundcube #gitea #burp #burp-repeater
    #laravel-csrf #wfuzz #api #hashcat #idor #firefox-extension #xss
    #filter #firefox-dev-tools #gitea-api #password-reuse
    #hash-extension #hash-extender #command-injection #deepce #docker
    #docker-escape #docker-sock #htb-altered #htb-backend
    #htb-backendtwo #htb-ransom #htb-intense #htb-feline

    ![](/img/extension-cover.png)

    Extension has multiple really creative attack vectors with some
    unique features. I'll start by leaking usernames and hashes, getting
    access to the site and to the email box for a few users. Abusing an
    IDOR vulnerability I'll identify the user that I need to get access
    as next. I'll enumerate the password reset functionality, and notice
    that only the last few characters of the token sent each time are
    changing. I'm not able to brute force a single token, but I can
    submit hundreds of resets set the odds such that I can guess a valid
    on in only a few guesses. With this access, I get creds for a Gitea
    instance, where I'll find a custom Firefox extension. I'll abuse
    that extension, bypassing the cross site scripting filters to hit
    the Gitea API and pull down a backup file from another user. That
    backup gives SSH access to the host, and some password reuse pivots
    to the next user. With this access, I'll identify a hash extension
    vulnerability in the web application, and abuse that to access a
    command injection and get RCE in the website container. The Docker
    socket inside the container is writable, allowing for a simple
    container breakout.

-   Mar 11, 2023

    ### [HTB: Mentor](/htb-mentor.md)

    #htb-mentor #hackthebox #ctf #nmap #youtube #snmp #fastapi #flask
    #feroxbuster #snmp-brute #onesixtyone #snmpwalk #snmpbulkwalk
    #command-injection #postgresql #chisel #psql #crackstation
    #password-reuse #htb-forgot #htb-sneaky

    ![](/img/mentor-cover.png)

    Mentor focuses on abusing a FastAPI API and SNMP enumeration. I'll
    brute force a second community string that gives more access than
    the default "public" string. With that, I'll get access to the
    running process command lines, and recover a password. With that
    password, I can get a valid auth token to the API, and find a backup
    endpoint that has a command injection vulnerability, which I'll
    exploit to get a shell. From inside the web container, I'll find
    creds for the database and dump the users table. On cracking the
    hash for one user, I can get SSH access to the host. For root, I'll
    find a password in the SNMP configuration.

-   Mar 4, 2023

    ### [HTB: Forgot](/htb-forgot.md)

    #hackthebox #htb-forgot #ctf #nmap #flask #burp #burp-proxy #varnish
    #cache #cache-abuse #web-cache-deception #feroxbuster #ffuf
    #host-header-injection #htb-response #tensorflow #cve-2022-29216
    #command-injection

    ![](/img/forgot-cover.png)

    Forgot starts with a host-header injection that allows me to reset a
    users password and have the link sent to them be to my webserver.
    From there, I'll abuse some wildcard routes and a Varnish cache to
    get a cached version of the admin page, which leaks SSH creds. To
    get to root, I'll abuse an unsafe eval in TensorFlow in a script
    designed to check for XSS.

-   Feb 25, 2023

    ### [HTB: Awkward](/htb-awkward.md)

    #hackthebox #ctf #htb-awkward #nmap #webpack #vuejs #wfuzz
    #auth-bypass #jwt #jwt-io #burp #burp-repeater #hashcat #ssrf
    #express #api #express-api #awk #awk-injection #file-read
    #hashcat-jwt #python-jwt #youtube #python-requests #xpad #pspy #mail
    #gtfobins #pm2 #command-injection

    ![](/img/awkward-cover.png)

    Awkward involves abusing a NodeJS API over and over again. I'll
    start by bypassing the auth check, and using that to find an API
    where I can dump user hashes. I'll find another API where I can get
    it to do a SSRF, and read internal documentation about the API. In
    that documentation, I'll spot an awk injection that leads to a file
    disclosure vulnerability. With that, I'll locate a backup archive
    and get a password from a config file that allows for SSH access. To
    pivot to root, I'll abuse the website again with symlinks to have it
    write to a file that I can't modify, which triggers an email being
    sent. I'll write a command injection payload to get execution as
    root. In Beyond Root, I'll show two unintended ways that involved
    getting a shell as www-data. One was patched two days after release,
    so I'll show how I make the machine vulnerable again. The other is a
    sed parameter injection.

-   Feb 18, 2023

    ### [HTB: RainyDay](/htb-rainyday.md)

    #hackthebox #ctf #htb-rainyday #nmap #ffuf #subdomain #docker
    #container #feroxbuster #idor #john #chisel #foxyproxy #socks
    #proxychains #api #flask #flask-cookie #python #python-requests
    #youtube #flask-unsign #jail #python-use-after-free #unicode #emoji
    #john-rules #htb-scanned

    ![](/img/rainyday-cover.png)

    RainyDay is a different kind of machine from HackTheBox. It's got a
    lot of enumerating and fuzzing to find next steps and a fair amount
    of programming required to solve. I'll start by exploiting an IDOR
    vulnerability to leak hashes, cracking one and getting access to a
    website that manages containers. From inside a container, I can
    reach a dev instance and an API that effectively let's me apply a
    given regex to a file on the filesystem, which I'll turn into a file
    read exploit with some Python scripting. From there I can leak the
    flask secret key and get into another user's account, where I'll
    find a misconfiguration that allows me to escape the container's
    jail and read the user's private SSH key. From the host, I'll first
    exploit Python itself to get execution as the next user. Then I'll
    abuse unicode characters to slip more characters than allowed into a
    hashing program, and use that to brute force a secret salt, allowing
    me to crash the root hash. In Beyond Root, I'll look at a mistake
    that allowed for skipping a large part of this box.

-   Feb 11, 2023

    ### [HTB: Photobomb](/htb-photobomb.md)

    #htb-photobomb #ctf #hackthebox #bash #bash-test #nmap #feroxbuster
    #image-magick #command-injection #injection #burp #burp-repeater
    #path-hijack #bash-builtins #sudo-setenv

    ![](/img/photobomb-cover.png)

    Photobomb was on the easy end of HackTheBox weekly machines. I'll
    find credentials in a JavaScript file, and use those to get access
    to an image manipulation panel. There's a command injection
    vulnerability in the panel, which I'll use to get execution and a
    shell. For privesc, the user can run a script as root, and there are
    two ways to get execution from this. The first is a find command
    that is called without the full path. The second is abusing the
    disabled Bash builtin \[.

-   Feb 4, 2023

    ### [HTB: Response](/htb-response.md)

    #hackthebox #ctf #htb-response #nmap #linux #ffuf #subdomain
    #feroxbuster #burp #burp-repeater #burp-proxy #hmac #oracle
    #foxyproxy #python #youtube #proxy #ssrf #socket-io #ldap #docker
    #ldif #ldapadd #ldappasswd #chatgpt #wireshark #forensics
    #cross-protocol-request-forgery #cprf #xp-ssrf #javascript #htb-luke
    #ftp #directory-traversal #python-https #certificate #openssl #dns
    #smtp #python-smptd #virus-total #meterpreter #crypto #mettle
    #bulk-extractor #openssh #partial-ssh-key #rsa #rsactftool
    #htb-proper #htb-crossfittwo

    ![](/img/response-cover.png)

    Response truly lived up to the insane rating, and was quite
    masterfully crafted. To start, I'll construct a HTTP proxy that can
    abuse an SSRF vulnerability and a HMAC digest oracle to proxy
    traffic into the inner network and a chat application. With access
    as guest, I'll find bob is eager to talk to the admin. I'll redirect
    the LDAP auth to my host, where my LDAP server will grant access as
    admin, and I can talk to bob. bob speaks of an FTP server and gives
    creds, but I can't access it. I'll write a JavaScript payload that
    will above a cross protocol request forgery via a link sent to bob
    to read credentials off the FTP server. Next I'll add my host as a
    computer to get scanned by a scanning program, and exploit a
    directory traversal in the state name of my TLS certificate to read
    the next user's SSH key. Finally, I'll find a PCAP and a core dump
    from a meterpreter process. I'll write a decoder for the traffic,
    and, after pulling the AES key from the core dump memory, decrypt
    the traffic and pull a copy of a zip file that was exfiled from
    root's home directory. Inside that zip is a screenshot which
    includes just the bottom of the user's private key, as well as the
    authorized_keys file with their public key. I'll manually parse the
    two files to get all I need to reconstruct the full private key and
    get a shell as root.

-   Jan 28, 2023

    ### [HTB: Ambassador](/htb-ambassador.md)

    #htb-ambassador #hackthebox #ctf #nmap #feroxbuster #grafana
    #searchsploit #file-read #directory-traversal #consul #msfconsole
    #tunnel

    ![](/img/ambassador-cover.png)

    Ambassador starts off with a Grafana instance. I'll exploit a
    directory traversal / file read vulnerability to read the config and
    get the password for the admin. From the Grafana admin panel, I'll
    get creds to the MySQL instance. Logging into that leaks credentials
    for a developer and I can get a shell with SSH. This developer has
    access to a git repo that leaks a token used for Consul in an old
    commit. I'll use that to interact with Consul and get execution as
    root. I'll show doing it both manually as well as using Metasploit.

-   Jan 21, 2023

    ### [HTB: UpDown](/htb-updown.md)

    #htb-updown #hackthebox #ctf #nmap #ssrf #feroxbuster #wfuzz
    #subdomain #git #gitdumper #source-code #php #phar #upload
    #php-disable-functions #php-proc_open #python2-input #python
    #easy-install #htb-crimestopper #php-filter-injection #youtube
    #htb-crimestoppers #dfunc-bypasser

    ![](/img/updown-cover.png)

    UpDown presents a website designed to check the status of other
    webpages. The obvious attack path is an server-side request forgery,
    but nothing interesting comes from it. There is a dev subdomain, and
    I'll find the git repo associated with it. Using that, I'll figure
    out how to bypass the Apache filtering, and find a code execution
    vulnerability out of an LFI using the PHP Archive (or PHAR) format.
    With a shell, I'll exploit a legacy Python script using input, and
    then get root by abusing easy_install.

-   Jan 14, 2023

    ### [HTB: Shoppy](/htb-shoppy.md)

    #hackthebox #ctf #htb-shoppy #nmap #feroxbuster #nosql-injection
    #mattermost #nosql-auth-bypass #burp #burp-repeater #nodejs #mongodb
    #crackstation #reverse-engineering #sudo #ghidra #docker
    #docker-group #youtube #htb-mango #htb-nodeblog #htb-goodgames

    ![](/img/shoppy-cover.png)

    Shoppy was one of the easier HackTheBox weekly machines to exploit,
    though identifying the exploits for the initial foothold could be a
    bit tricky. I'll start by finding a website and use a NoSQL
    injection to bypass the admin login page, and another to dump users
    and hashes. With a cracked hash, I'll log into a Mattermost server
    where I'll find creds to the box that work for SSH. From there, I'll
    need the lighest of reverse enginnering to get a static password
    from a binary, which gets me to the next user. This user is in the
    docker group, so I'll load an image mounting the host file system,
    and get full disk access. I'll show two ways to get a shell from
    that. In Beyond Root, a video walkthrough of the vulnerable
    web-server code, showing how the injections worked, and fixing them.

-   Jan 7, 2023

    ### [HTB: Health](/htb-health.md)

    #ctf #htb-health #hackthebox #nmap #feroxbuster #laravel #redirect
    #hook #gogs #ssrf #python #flask #sqli #sqli-union #sqlite
    #sqli-sqlite #hashcat #sha256 #chatgpt #htb-ransom

    ![](/img/health-cover.png)

    Health originally released as easy, but was bumped up to Medium
    three days later. That's because there's a tricky SQL injection that
    you have to exploit via a redirect, which eliminates things like
    sqlmap. After using the SSRF into redirect to exploit Gogs and leak
    the user table, I'll crack the hash and get SSH access to the box.
    For root, I'll exploit a cron that runs through the website by
    generating tasks directly in the database, bypassing the filtering
    on the website.

-   Jan 7, 2023

    ### [2022 SANS Holiday Hack Challenge, featuring KringleCon V: Golden Rings](/holidayhack2022/)

    #ctf #sans-holiday-hack

    ![](/img/hh22-cover.png)

    The 2022 SANS Holiday Hack Challenge is a battle to recover the five
    golden rings stolen from Santa by Grinchum. This all takes place at
    the North Pole where Santa is hosting the 5th annual KringleCon,
    including
    [talks](https://www.sans.org/mlp/holiday-hack-challenge#kringlecon)
    from 11 leaders in the information security community. In addition
    to the talks, there are six objectives to solve, each consisting of
    multiple terminals and/or challenges. In solving all of these, I'll
    recover the five rings, and in the process clear the magic that's
    created Grinchum, turning him back into Smilegol. As usual, the
    challenges were interesting and set up in such a way that it was
    very beginner friendly, with lots of hints and talks to ensure that
    you learned something while solving.

-   Jan 3, 2023

    ### [Hackvent 2022 - Hard](/hackvent2022/hard)

    #ctf #hackvent #physical #radio #universal-radio-hacker #nrz #nrz-s
    #python #python-pil #python-pyzbar #pulse-view #sigrok #serial #uart
    #7z #john #hashcat #john-mask #hashcat-mask #aes #aes-ecb #heap
    #pwntools #unicod

    ![](/img/hv22-hard-cover.png)

    Days fifteen through twentyone were the hard challenges. There were
    some really great coding challenges. I loved day sixteen, where I'll
    have to check *tons* of QRcodes to find the flag. And day twenty,
    where I'll abuse a unicode bug to brute force padding on an AES
    encryption. There were couple signals analysis challenges, including
    a radio wave and serial line decode. There was also a neat trick
    abusing how zip archives handle long passwords, and a nice
    relateively beginner-friendly heap exploitation.

-   Jan 3, 2023

    ### [Hackvent 2022 - Medium](/hackvent2022/medium)

    #ctf #hackvent #social-media #osint #ghidra #virus-total #text4shell
    #cve-2022-42889 #ssti #tcpdump #sqli #postgresql #burp
    #burp-repeater #idor #aws #imds #aws-secretsmanager #gtfobin
    #prototype-pollution #xss #reflective-xss #youtube

    ![](/img/hv22-med-cover.png)

    The medium 2022 Hackvent challenges covered days eight through
    fourteen, and included one more hidden challenge. They get a bit
    more into exploitation, with SQL injection, AWS / cloud, prototype
    pollution, some OSINT, and a really interesting reflective XSS
    attack.

-   Jan 3, 2023

    ### [Hackvent 2022 - Easy](/hackvent2022/easy)

    #ctf #hackvent #qrcode #python #python-pil #zbarimg
    #python-null-bytes #javascript #pcap #gcode #wireshark #blockchain
    #solidity #youtube #metamask #remix #python-web3 #micro-qr

    ![](/img/hv22-easy-cover.png)

    Hackvent is one of the three holiday CTFs I try to play every
    December. This year I made it through 20 of the first 21 days before
    life got too busy. The first seven challenges (eight if you count
    the hidden challenge) were rated easy, and included some interesting
    programming challenges, some blockchain, and lots of QR codes.

-   Dec 17, 2022

    ### [HTB: Support](/htb-support.md)

    #hackthebox #ctf #htb-support #nmap #ldapsearch #crackmapexec
    #smbclient #dotnet #wireshark #reverse-engineering #dnspy
    #bloodhound #ldapdomaindump #evil-winrm #powerview #powermad #rubeus
    #sharp-collection #ms-ds-machineaccountquota

    ![](/img/support-cover.png)

    Support is a box used by an IT staff, and one authored by me! I'll
    start by getting a custom .NET tool from an open SMB share. With
    some light .NET reversing, through dynamic analysis, I can get the
    credentials for an account from the binary. With those, I'll
    enumerate LDAP and find a password in an info field on a shared
    account. That account has full privileges over the DC machine
    object, and I'll abuse that to dump the administrator hash and get
    full access to the box.

-   Dec 10, 2022

    ### [HTB: Outdated](/htb-outdated.md)

    #ctf #hackthebox #htb-outdated #nmap #windows #domain-controller
    #crackmapexec #smbclient #cve-2022-30190 #folina #swaks #phishing
    #hyper-v #bloodhound #addkeycredentiallink #shadow-credential
    #whisker #pywhisker #visual-studio #rubeus #sharp-collection
    #evil-winrm #wsus #sharpwsus #hive-nightmare #secretsdump
    #pkinittools

    ![](/img/outdated-cover.png)

    Outdated has three steps that are all really interesting. First,
    I'll exploit Folina by sending a link to an email address collected
    via recon over SMB. Then I'll exploit shadow credentials to move
    laterally to the next user. Finally, I'll exploit the Windows Server
    Update Services (WSUS) by pushing a malicious update to the DC and
    getting a shell as system. In Beyond Root, I'll look at a couple
    steps involving Hive Nightmare that I was able to bypass.

-   Dec 3, 2022

    ### [HTB: CarpeDiem](/htb-carpediem.md)

    #hackthebox #htb-carpediem #ctf #nmap #feroxbuster #wfuzz #vhosts
    #php #trudesk .md-file #upload #burp #burp-repeater #webshell
    #docker #container #pivot #chisel #mongo #mongoexport #bcrypt
    #python #api #source-code #voip #zoiper #voicemail #backdrop-cms
    #wireshark #tcpdump #tls-decryption #weak-tls #backdrop-plugin
    #docker-escape #cgroups #cve-2022-0492 #htb-ready

    ![](/img/carpediem-cover.png)

    CarpeDiem is a hard linux box that involves pivoting through a small
    network of Docker containers. I'll start by getting admin access to
    a website, and using an upload feature to get a webshell and a
    foothold in that container. From there, I'll enumerate the network
    and find an instance of trudesk, from which I'll read a ticket about
    a new employee who will get their creds via their voicemail. I'll
    follow the instructions in the ticket to get access to the
    voicemail, and their SSH password. I'll pivot back into a Backdrop
    CMS instance by getting creds and uploading a malicious plugin. From
    there, I'll get root in that container, and then abuse CVE-2022-0492
    to get root on the host.

-   Nov 26, 2022

    ### [HTB: RedPanda](/htb-redpanda.md)

    #ctf #htb-redpanda #hackthebox #nmap #springboot #ssti #feroxbuster
    #wfuzz #filter #thymeleaf #burp #burp-repeater #pspy #java #xxe
    #groups #directory-traversal

    ![](/img/redpanda-cover.png)

    RedPanda starts with a SSTI vulnerability in a Java web application.
    I'll exploit that to get execution and a shell. To get to root, I'll
    abuse another Java application that's running as root to assign
    credit to various authors. To abuse this, I'll generate a complex
    attack chain that starts by injecting a log that points to a
    malicious JPG image I generate. That JPG has metadata that exploits
    a directory traversal to point to unintended XML, where I can do an
    XML external entity attack to read files as root. With that
    abililty, I'll read root's private SSH key. In Beyond Root, I'll
    look at why my reverse shell as the first user and an SSH session as
    that user has access to different groups.

-   Nov 21, 2022

    ### [HTB: Squashed](/htb-squashed.md)

    #htb-squashed #hackthebox #ctf #nmap #feroxbuster #nfs #showmount
    #x11 #xauthority #webshell #screenshare #keepass

    ![](/img/squashed-cover.png)

    Squashed abuses a couple of NFS shares in a nice introduction to
    NFS. First I'll get access to a web directory, and, after adjusting
    my local userid to match that one required by the system, upload a
    webshell and get execution. Then I'll get an X11 magic cookie from a
    different NFS share and use it to get a screenshot of the current
    user's desktop, showing the root password in a password manager.

-   Nov 19, 2022

    ### [HTB: Hathor](/htb-hathor.md)

    #htb-hathor #ctf #hackthebox #nmap #crackmapexec #aspx #mojoportal
    #default-creds #upload #webshell #burp #burp-repeater #defender
    #applocker #firewall #windows-firewall #youtube #insomnia-webshell
    #get-badpasswords #crackstation #kerberos #klist #kinit #wireshark
    #msfvenom #dll #visual-studio #shortcut #recycle-bin #certificate
    #pfx #windows-process-monitor #openssl #pkcs12 #crackpkcs12
    #authenticode #sign #dcsync #ktutil #gettgt #evil-winrm #wmiexec
    #htb-anubis #htb-hackback #htb-scrambled

    ![](/img/hathor-cover.png)

    Hathor is an insane box that lives up to the difficulty. I'll start
    with some default creds logging into a mojoPortal website. From
    there, I'll figure out how to upload a webshell, and copy it to get
    the right extension. All my efforts to get a shell are blocked, and
    I'll do a deep dive analysis on the firewall and AppLocker settings.
    I'll eventually get a shell by overwriting a Dll over SMB, and when
    that Dll is loaded, I get execution. Still, the running binary is
    blocked outbound at the firewall. I'll have to use that execution to
    overwrite an approved Exe, and then get a shell calling that. To get
    the next user, I'll find a code signing certificate in the recycle
    bin, and use it to modify a Get-bADpasswords script that I can
    trigger to run as the next user. From that last user, I'll perform a
    DCSync attack to get the admin's hash. NTLM is disabled, so I'll
    show a couple ways to use that hash to get a Kerberos ticket and
    execution on the box.

-   Nov 12, 2022

    ### [HTB: Shared](/htb-shared.md)

    #hackthebox #ctf #htb-shared #nmap #wfuzz #sqli #sqli-union #sqlmap
    #burp #burp-repeater #crackstation #pspy #cve-2022-21699 #ipython
    #redis #wireshark #strace #ghidra #reverse-engineering
    #cve-2022-0543

    ![](/img/shared-cover.png)

    Shared starts out with a SQL injection via a cookie value. From
    there, I'll find creds and get access over SSH. The first pivot
    abused a code execution vulnerability in iPython. From there, I'll
    reverse (both dynamically and statically) a binary to get Redis
    creds, and exploit Redis to get execution.

-   Nov 11, 2022

    ### [Flare-On 2022: The challenge that shall not be named](/flare-on-2022/challenge_that_shall_not_be_named)

    #flare-on #ctf #flare-on-the-challenge-that-shall-not-be-named
    #reverse-engineering #memory-dump #pyinstaller #pyarmor
    #pyinstxtractor #uncompyle6 #pyarmor-unpacker #hook #python

    ![](/img/flare2022-notnamed-cover.png)

    The challenge that shall not be named is a Windows executable
    generated with PyArmor, a tool that aims to create unreversible
    binarys from Python. The binary makes an HTTP request with an
    encrypted flag. I'll first solve it by holding open that web request
    and dumping the process memory to find the flag in plaintext. I'll
    also show how to hook the crypt Python library to read the flag as
    it's being encrypted.

-   Nov 11, 2022

    ### [Flare-On 2022: Nur geträumt](/flare-on-2022/nur_getraumt)

    #flare-on #ctf #flare-on-nur-getraumt #mac #mini-vmac #emulation
    #super-resedit

    ![](/img/flare2022-nurgetraumt-cover.png)

    Nur geträumt is mostly a challenge about getting an old Mac disk
    image running in an emulator, and then poking around to get enough
    clues to solve a trivia problem. There's no real reversing involved,
    but rather reading what is available from reading resources with
    Super ResEdit, a tool for reversing these old Mac application.

-   Nov 11, 2022

    ### [Flare-On 2022: encryptor](/flare-on-2022/encryptor)

    #flare-on #ctf #flare-on-encryptor #reverse-engineering #crypto
    #ransomware #youtube #ghidra #rsa #chacha20 #cyberchef #x64dbg
    #python

    ![](/img/flare2022-encryptor-cover.png)

    The given binary for encryptor is a fake ransomware sample. I'll
    figure out which files it tries to encrypt, and then understand how
    it generates a random key for ChaCha20, then encrypts that key using
    RSA and attaches it. The mistake it makes is using the private key
    to encrypt, which means I can use the public key to decrypt, and get
    the ChaCha key, and then use that to decrypt a given file.

-   Nov 11, 2022

    ### [Flare-On 2022: backdoor](/flare-on-2022/backdoor)

    #flare-on #ctf #flare-on-backdoor #reverse-engineering #dotnet
    #dnspy #patch #dns-c2 #ilspy #metadatatoken #dynamic-method #python
    #saitama #malware-bazaar

    ![](/img/flare2022-backdoor-cover.png)

    backdoor is the hardest challenge in the 2022 Flare-On challenge,
    and one of the harder ones I've done. The sample is a .NET binary,
    but most the functions are heavily obfuscated. I'll deobfuscate
    through two different processes, patching assembly back into the
    binary to get something that DNSpy can reverse. Eventually I'll find
    a real malware sample, the Saitama backdoor, that executes command
    and control over DNS. Once I understand the DNS protocol, I'll write
    a DNS server to send commands in the required order to trigger the
    flag.

-   Nov 11, 2022

    ### [Flare-On 2022: anode](/flare-on-2022/anode)

    #flare-on #ctf #flare-on-anode #reverse-engineering #nexe
    #javascript #nodejs #nexe-unpacker #ghidra #random-numbers #patch
    #python

    ![](/img/flare2022-anode-cover.png)

    anode is a JavaScript application packed into an EXE with NEXE. The
    challenge would be straight forward, but the instance of Node that's
    packed in the executable with the JavaScript is dorked such that
    BigInts don't evaluate as booleans correctly and the random numbers
    are seeded the same way each time. I'll patch the JavaScript in the
    executable (carefully to maintain the length) to print out all 1024
    steps that it takes changing the input into an encoded value, and
    write a Python script to reverse that and recover the flag.

-   Nov 11, 2022

    ### [Flare-On 2022: à la mode](/flare-on-2022/alamode)

    #flare-on #ctf #flare-on-a-la-mode #reverse-engineering #youtube
    #dotnet #dll #dnspy #polyglot #ghidra #ida #x32dbg #rc4 #cyberchef
    #peb #tib

    ![](/img/flare2022-alamode-cover.png)

    à la mode is a polyglot file, part .NET binary, part standard
    binary. The .NET part of the file shows a named pipe client that
    gets the flag over a connection. The standard binary loads functions
    dynamically by getting kernelbase.dll's address from the process
    environment block, and getting offsets by deobfuscated string
    function names. Then it uses those functions to stand up a named
    pipe server. I'll get the flag dynamically, and then go to show how
    it is using RC4, and decrypt it.

-   Nov 11, 2022

    ### [Flare-On 2022: T8](/flare-on-2022/t8)

    #flare-on #ctf #flare-on-t8 #reverse-engineering #wireshark #ghidra
    #x32dbg #capa #rc4 #crypto #cyberchef

    ![](/img/flare2022-t8-cover.png)

    For T8, I'll have to first bypass a really long sleep by
    manipulating the date time on my VM. Then I'll look at a GET
    request, and compare it to what's in a given PCAP. The response
    doesn't match the PCAP. The first step is to understand the payload
    sent, and then to fake a server and send a response to understand
    how to it is decrypted, and then apply that to the PCAP data.

-   Nov 11, 2022

    ### [Flare-On 2022: darn_mice](/flare-on-2022/darn_mice)

    #flare-on #ctf #flare-on-darn-mice #reverse-engineering #ghidra
    #x32dbg #python

    ![](/img/flare2022-darnmice-cover.png)

    darn_mice involves reversing a Windows binary that doesn't do
    anything when run without arguments. I'll have to find the correct
    argument to pass it to get it to spit out the flag.

-   Nov 11, 2022

    ### [Flare-On 2022: Magic 8 Ball](/flare-on-2022/magic_8_ball)

    #flare-on #ctf #flare-on-magic-8-ball #reverse-engineering #sdl
    #simple-directmedia #ghidra #x32dbg

    ![](/img/flare2022-magic8ball-cover.png)

    Magic 8 Ball presents a 32 bit Windows executable that will return a
    flag shaken the right number of times and in the right directions.

-   Nov 11, 2022

    ### [Flare-On 2022: Pixel Poker](/flare-on-2022/pixel_poker)

    #flare-on #ctf #flare-on-pixel-poker #reverse-engineering #direct-x
    #ghidra #x32dbg

    ![](/img/flare2022-pixelpoker-cover.png)

    In Pixel Poker, I'll reverse engineer a Windows Direct-X 11
    application using both Ghidra and x32dbg to find the correct pixel
    to click on. On clicking, it returns a meme and the flag.

-   Nov 11, 2022

    ### [Flare-On 2022: Flaredle](/flare-on-2022/flaredle)

    #flare-on #ctf #flare-on-flaredle #reverse-engineering #javascript

    ![](/img/flare2022-flaredle-cover.png)

    Flaredle is a take off on the popular word game, Wordle. In Wordle,
    you guess letters in a five letter word. In Flaredle, it's a 21
    character work. I'll look at the JavaScript to find the winning
    word, and use it to get the flag.

-   Nov 5, 2022

    ### [HTB: Moderators](/htb-moderators.md)

    #htb-moderators #hackthebox #ctf #nmap #feroxbuster #wfuzz #fuzz
    #crackstation #filter #burp #burp-repeater #upload #webshell
    #php-disable-functions #wordpress #wordpress-brandfolder
    #wordpress-passwords-manager #wordpress-plugin #source-code #crypto
    #virtualbox #virtualbox-encryption #pyvboxdie-cracker #hashcat #luks
    #chisel

    ![](/img/moderators-cover.png)

    Moderators was a long box with a bunch of web enumerations, some
    source code analysis, and cracking multiple passwords for a VM. I'll
    start by enumerating a website to eventually find a file upload
    page, where I'll bypass filters to get a webshell. With a shell,
    I'll access an internal WordPress site exploiting the Brandfolder
    plugin to pivot to the next user. From there, with access to the
    WordPress config, I'll get the MySQL password which gives access to
    secrets stored via another WordPress plugin. I'll have to look at
    the source for that plugin to figure out how to decrypt the
    information and get another user's SSH key. Finally, I'll find a
    VirtualBox VM, and break through both VirtualBox encryption and LUKS
    to find a password that gets root access.

-   Oct 29, 2022

    ### [HTB: Trick](/htb-trick.md)

    #htb-trick #ctf #hackthebox #nmap #smtp #smtp-user-enum
    #zone-transfer #vhosts #wfuzz #feroxbuster
    #employee-management-system #sqli #sqli-bypass #cve-2022-28468
    #boolean-based-sqli #sqlmap #file-read #lfi #directory-traversal
    #mail-poisoning #log-poisoning #burp #burp-repeater #fail2ban
    #htb-admirertoo

    ![](/img/trick-cover.png)

    Trick starts with some enumeration to find a virtual host. There's
    an SQL injection that allows bypassing the authentication, and
    reading files from the system. That file read leads to another
    subdomain, which has a file include. I'll show how to use that LFI
    to get execution via mail poisoning, log poisoning, and just reading
    an SSH key. To escalate to root, I'll abuse fail2ban.

-   Oct 22, 2022

    ### [HTB: Faculty](/htb-faculty.md)

    #htb-faculty #ctf #hackthebox #nmap #php #feroxbuster #sqli
    #sqli-bypass #auth-bypass #sqlmap #mpdf #cyberchef #burp
    #burp-repeater #file-read #password-reuse #credentials #meta-git
    #command-injection #gdb #ptrace #capabilities #python #msfvenom
    #shellcode

    ![](/img/faculty-cover.png)

    Faculty starts with a very buggy school management web application.
    I'll abuse SQL injection to bypass authentication, and then a mPDF
    vulenrability to read files from disk. I'll find a password for the
    database connection in the web files that is also used for a user
    account on the box. Next I'll abuse meta-git to get a shell as the
    next user. The final user has access to the GNU debugger with ptrace
    capabilities. This allows me to connect to any process on the box
    and inject shellcode, getting execution in the context of that
    process. I'll abuse a process running as root to get root access.

-   Oct 15, 2022

    ### [HTB: Perspective](/htb-perspective.md)

    #hackthebox #ctf #htb-perspective #windows #iis #aspx #dotnet
    #feroxbuster #web.config #.md #upload #burp #burp-proxy
    #burp-repeater #burp-intruder #filter #formatauthenticationticket
    #ssrf #pdf .md-scriptless-injection #meta #crypto #deserialization
    #viewstate #viewstateuserkey #machinekey #ysoserial.net #nishang
    #command-injection #padding-oracle #padbuster #youtube #potato
    #seimpersonate #juicypotatong #htb-overflow #htb-lazy #htb-smasher

    ![](/img/perspective-cover.png)

    Perspective is all about exploiting a ASP.NET application in many
    different ways. I'll start by uploading a SHTML file that allows me
    to read the configuration file for the application. With that, I'll
    leak one of the keys used by the application, and the fact that
    there are more protections in place. That key is enough for me to
    forge a cookie as admin and get access to additional places on the
    site. There's a server-side request forgery vulnerability in that
    part of the site, and I'll use it to access a crypto service running
    on localhost. I'll decrypt another application key, showing both how
    to do it with math and via a POST request via the SSRF. With that, I
    can sign a serialized object and get execution. With a shell, I'll
    find a staging version of the application with additional logging
    and some protections that break my previous attack. I'll use a
    padding oracle attack to encrypt cookies, and exploit a command
    injection via the cookie and the password reset process to get a
    shell as administrator. In Beyond Root, I'll look at an unintended
    way to get admin on the website, and get JuicyPotatoNG working,
    despite most ports being blocked.

-   Oct 8, 2022

    ### [HTB: OpenSource](/htb-opensource.md)

    #ctf #hackthebox #htb-opensource #nmap #upload #source-code #git
    #git-hooks #flask #directory-traversal #file-read #flask-debug
    #flask-debug-pin #youtube #chisel #gitea #pspy #htb-bitlab #werkzeug
    #werkzeug-debug

    ![](/img/opensource-cover.png)

    OpenSource starts with a web application that has a downloadable
    source zip. That zip has a Git repo in it, and that leaks the
    production code as well as account creds. The website has a
    directory traversal vulnerability that allows me to read and write
    files. I'll show two ways to get a shell. The first is abusing the
    file read to get the information to calculate the Flask debug pin.
    The later is overwriting one of the Flask source files to get
    execution. From there, I'll access a private Gitea instance and find
    an SSH key to get a shell on the host. The host has a cron running
    Git commands as root, so I'll use git hooks to abuse this and get a
    shell as root.

-   Oct 1, 2022

    ### [HTB: Scrambled](/htb-scrambled.md)

    #htb-scrambled #ctf #hackthebox #kerberos #deserialization #windows
    #silver-ticket #reverse-engineering #mssql #oscp-like

    ![](/img/scrambled-cover.png)

    Scrambled presented a purely Windows-based path. There are some
    hints on a webpage, and from there the exploitation is all Windows.
    NTLM authentication is disabled for the box, so a lot of the tools
    I'm used to using won't work, or at least work differently. I'll
    find user creds with hints from the page, and get some more hints
    from a file share. I'll kerberoast and get a challenge/response for
    a service account, and use that to generate a silver ticket, getting
    access to the MSSQL instance. From there, I'll get some more creds,
    and use those to get access to a share with some custom dot net
    executables. I'll reverse those to find a deserialization
    vulnerability, and exploit that to get a shell as SYSTEM. Because
    the tooling for this box is so different I'll show it from both
    Linux and Windows attack systems. In Beyond Root, two other ways to
    abuse the MSSQL access, via file read and JuicyPotatoNG.

-   Sep 28, 2022

    ### [HTB: Noter - Alternative Root (First Blood)](/htb-noter-alternative-root-first-blood.md)

    #ctf #hackthebox #htb-noter #tunnel #mysql #mysql-privileges
    #mysql-file-write #ssh #vsftpd #vsftpd-local-enable

    ![](/img/noter-unintended-cover.png)

    When jkr got first blood on Noter, he did it using all the same
    intended pieces for the box, but in a very clever way that allowed
    getting a root shell as the first shell on the box. I had intended
    to include that in my original Noter writeup, but completely forgot,
    so I'm adding it here.

-   Sep 24, 2022

    ### [HTB: Seventeen](/htb-seventeen.md)

    #ctf #htb-seventeen #hackthebox #nmap #feroxbuster #wfuzz #vhosts
    #exam-management-system #searchsploit #sqli #boolean-based-sqli
    #sqlmap #crackstation #roundcube #cve-2020-12640 #upload #burp
    #burp-proxy #docker #credentials #password-reuse #javascript #nodejs
    #npm #verdaccio #home-env #malicious-node-module #htb-blunder
    #oscp-like

    ![](/img/seventeen-cover.png)

    Seventeen presented a bunch of virtual hosts, each of which added
    some piece to eventually land execution. The exam site has a
    boolean-based SQL injection, which provides access to the database,
    which leaks another virtual host and it's DB. The oldmanagement
    system provides file upload, and leaks the hostname of a Roundcube
    webmail instance. I'll upload a webshell and exploit CVE-2020-12640
    in Roundcube to include it and get execution. There's two pivots of
    password reuse, before getting root by installing a malicious Node
    module from a rogue NPM server. In Beyond Root, I'll look at why
    root uses the .npmrc file from kavi's home directory and unintended
    bypassing the htaccess file for webshell execution.

-   Sep 17, 2022

    ### [HTB: StreamIO](/htb-streamio.md)

    #hackthebox #htb-streamio #ctf #nmap #windows #domain-controller
    #php #wfuzz #vhosts #crackmapexec #feroxbuster #sqli #sqli-union
    #waf #hashcat #hydra #lfi #rfi #burp #burp-repeater #mssql #sqlcmd
    #evil-winrm #firefox #firepwd #bloodhound #bloodhound-python #laps
    #htb-hancliffe #oscp-like

    ![](/img/streamio-cover.png)

    StreamIO is a Windows host running PHP but with MSSQL as the
    database. It starts with an SQL injection, giving admin access to a
    website. Then there's a weird file include in a hidden debug
    parameter, which eventually gets a remote file include giving
    execution and a foothold. With that I'll gain access to a high
    privileged access to the db, and find another password in a backup
    table. From that user, I'll fetch saved Firefox credentials, and use
    those to read a LAPS password and get an administrator shell.

-   Sep 10, 2022

    ### [HTB: Scanned](/htb-scanned.md)

    #ctf #hackthebox #htb-scanned #nmap #django #source-code #chroot
    #jail #sandbox-escape #makefile #ptrace #fork #dumbable #c #python
    #youtube #hashcat #shared-object

    ![](/img/scanned-cover.png)

    The entire Scanned challenge is focused on a single web application,
    and yet it's one of the hardest boxes HackTheBox has published. The
    box starts with a website that is kind of like VirusTotal, where
    users can upload executables (Linux only) and they run, and get back
    a list of system calls and return values. The source for the site
    and the sandbox is also downloadable. In the source, I'll see how
    the sandbox sets up chroot jails to isolate the malware. I'll take
    advantage of two mistakes in the coding to write a binary that
    escapes the jail and reads the database for the application,
    including the Django admin password. That password also works for
    SSH. With a foothold on the box, I'll abuse the sandbox again, this
    time writing a program that sleeps, and then calls a SetUID binary
    from outside the jail. During the sleep, I'll load a malicious
    library into the jail that hijacks execution, and because the binary
    is SetUID, I get execution as root.

-   Sep 3, 2022

    ### [HTB: Noter](/htb-noter.md)

    #ctf #hackthebox #htb-noter #nmap #ftp #python #flask #flask-cookie
    #flask-unsign #feroxbuster #wfuzz #source-code #md-to-pdf
    #command-injection #mysql #raptor #shared-object

    ![](/img/noter-cover.png)

    Noter starts by registering an account on the website and looking at
    the Flask cookie. It's crackable, but I don't have another user's
    name or anything else to fake of value. I'll show a couple different
    ways to find a username, by generating tons of valid cookies and
    testing them, and by using the login error messages to find a valid
    username. With access as a higher priv user on the website, I get
    creds to the FTP server, where I find the default password scheme,
    and use that to pivot to the FTP admin. As admin, I get the site
    source, and find a RCE, both the intended way exploiting a markdown
    to PDF JavaScript library, as well as an unintended command
    injection. To get root, I'll find MySQL running as root and use the
    Raptor exploit to get command execution through MySQL.

-   Aug 27, 2022

    ### [HTB: Talkative](/htb-talkative.md)

    #hackthebox #ctf #htb-talkative #nmap #wfuzz #jamovi #bolt-cms
    #feroxbuster #rocket-chat #r-lang #docker #webhook #twig #ssti
    #mongo #deepce #shocker #docker-shocker #cap-dac-read-search
    #htb-paper #htb-anubis #htb-registry #oscp-like

    ![](/img/talkative-cover.png)

    Talkative is about hacking a communications platform. I'll start by
    abusing the built-in R scripter in jamovi to get execution and shell
    in a docker container. There I'll find creds for the Bolt CMS
    instance, and use those to log into the admin panel and edit a
    template to get code execution in the next container. From that
    container, I can SSH into the main host. From the host, I'll find a
    different network of containers, and find MongoDB running in one.
    I'll connect to that and use it to get access as admin for a Rocket
    Chat instance. I'll abuse the Rocket Chat webhook functionality to
    get a shell in yet another Docker container. This container has a
    dangerous capabilities, `CAP_DAC_READ_SEARCH`, which I'll abuse to
    both read and write files on the host.

-   Aug 20, 2022

    ### [HTB: Timelapse](/htb-timelapse.md)

    #ctf #htb-timelapse #hackthebox #nmap #windows #active-directory
    #crackmapexec #smbclient #laps #zip2john #john #pfx2john #evil-winrm
    #winrm-keys #powershell-history #htb-pivotapi #oscp-like

    ![](/img/timelapse-cover.png)

    Timelapse is a really nice introduction level active directory box.
    It starts by finding a set of keys used for authentication to the
    Windows host on an SMB share. I'll crack the zip and the keys
    within, and use Evil-WinRM differently than I have shown before to
    authenticate to Timelapse using the keys. As the initial user, I'll
    find creds in the PowerShell history file for the next user. That
    user can read from LAPS, the technology that helps to keep local
    administrator passwords safe and unique. With that read access, I'll
    get the administrator password and use Evil-WinRM to get a shell.

-   Aug 13, 2022

    ### [HTB: Retired](/htb-retired.md)

    #ctf #hackthebox #htb-retired #nmap #feroxbuster #upload
    #directory-traversal #file-read #filter #bof #wfuzz #ghidra
    #reverse-engineering #proc #maps #gdb #pattern #mprotect #rop
    #jmp-rsp #msfvenom #shellcode #python #symlink #make #capabilities
    #cap-dac-override #binfmt-misc #sched_debug #htb-previse
    #htb-fingerprint #execute-after-redirect

    ![](/img/retired-cover.png)

    Retired starts out with a file read plus a directory traversal
    vulnerability. (There's also an EAR vulnerability that I originally
    missed, but added in later). With that, I'll get a copy of a binary
    that gets fed a file via an upload on the website. There's a buffer
    overflow, which I can exploit via an uploaded file. I'll use ROP to
    make the stack executable, and then run a reverse shell shellcode
    from it. With a shell, I'll throw a symlink into a backup directory
    and get an SSH key from the user. To get root, I'll abuse
    binfmt_misc. In Beyond Root, some loose ends that were annoying me.

-   Aug 6, 2022

    ### [HTB: Overgraph](/htb-overgraph.md)

    #htb-overgraph #ctf #hackthebox #nmap #wfuzz #vhosts #feroxbuster
    #graphql #angularjs #otp #nosql-injection #graphql-playground
    #graphql-voyager #local-storage #csti #xss #reflective-xss #csrf
    #ffmpeg #ssrf #file-read #exploit #patchelf #ghidra #checksec
    #python #gdb #youtube #pwntools

    ![](/img/overgraph-cover.png)

    The initial web exploitation in Overgraph was really hard. I'll have
    to find and chain together a reflective cross site scripting (XSS),
    a client side template injection (CSTI), and a cross site request
    forgery (CSRF) to leak an admin's token. With that token, I can
    upload videos, and I'll exploit FFmpeg to get local file read (one
    line at a time!), and read the user's SSH key. For root, there's a
    binary to exploit, but it's actually rather beginner if you skip the
    heap exploit and just use the arbitrary file write.

-   Jul 30, 2022

    ### [HTB: Late](/htb-late.md)

    #htb-late #ctf #hackthebox #nmap #ocr #flask #kolourpaint #tesseract
    #burp-repeater #ssti #jinja2 #payloadsallthethings #linpeas #pspy
    #bash #chattr #lsattr #extended-attributes #youtube

    ![](/img/late-cover.png)

    Late really had two steps. The first is to find a online image OCR
    website that is vulnerable to server-side template injection (SSTI)
    via the OCRed text in the image. This is relatively simple to find,
    but getting the fonts correct to exploit the vulnerability is a bit
    tricky. Still, some trial and error pays off, and results in a
    shell. From there, I'll identify a script that's running whenever
    someone logs in over SSH. The current user has append access to the
    file, and therefore I can add a malicious line to the script and
    connect over SSH to get execution as root. In Beyond Root, a YouTube
    video showing basic analysis of the webserver, from NGINX to
    Gunicorn to Python Flask.

-   Jul 23, 2022

    ### [HTB: Catch](/htb-catch.md)

    #ctf #hackthebox #htb-catch #nmap #apk #android #feroxbuster #gitea
    #swagger #lets-chat #cachet #jadx #mobsf #api #cve-2021-39172 #burp
    #burp-repeater #wireshark #redis #php-deserialization
    #deserialization #phpggc #laravel #cve-2021-39174 #cve-2021-39165
    #sqli #ssti #sqlmap #docker #bash #command-injection #apktool
    #htb-routerspace #flare-on-flarebear

    ![](/img/catch-cover.png)

    Catch requires finding an API token in an Android application, and
    using that to leak credentials from a chat server. Those credentials
    provide access to multiple CVEs in a Cachet instance, providing
    several different paths to a shell. The intended and most
    interesting is to inject into a configuration file, setting my host
    as the redis server, and storing a malicious serialized PHP object
    in that server to get execution. To escalate to root, I'll abuse a
    command injection vulnerability in a Bash script that is checking
    APK files by giving an application a malicious name field.

-   Jul 16, 2022

    ### [HTB: Acute](/htb-acute.md)

    #hackthebox #ctf #htb-acute #nmap #feroxbuster
    #powershell-web-access #exiftool #meterpreter #metasploit #msfvenom
    #defender #defender-bypass-directory #screenshare #credentials
    #powershell-runas #powershell-configuration #oscp-like

    ![](/img/acute-cover.png)

    Acute is a really nice Windows machine because there's nothing super
    complex about the attack paths. Rather, it's just about manuverting
    from user to user using shared creds and privilieges available to
    make the next step. It's a pure Windows box. There's two hosts to
    pivot between, limited PowerShell configurations, and lots of
    enumeration.

-   Jul 9, 2022

    ### [HTB: RouterSpace](/htb-routerspace.md)

    #hackthebox #htb-routerspace #ctf #nmap #ubuntu #android #apk
    #feroxbuster #apktool #reverse-engineering #android-react-native
    #react-native #genymotion #burp #android-burp #command-injection
    #linpeas #pwnkit #cve-2021-4034 #polkit #cve-2021-3560
    #cve-2021-22555 #baron-samedit #cve2021-3156 #htb-paper

    ![](/img/routerspace-cover.png)

    RouterSpace was all about dynamic analysis of an Android
    application. Unfortunately, it was a bit tricky to get setup and
    working. I'll use a system-wide proxy on the virtualized Android
    device to route traffic through Burp, identifying the API endpoint
    and finding a command injection. For root, I'll exploit the Baron
    Samedit vulnerability in sudo that came our in early 2021.

-   Jul 2, 2022

    ### [HTB: Undetected](/htb-undetected.md)

    #hackthebox #htb-undetected #ctf #nmap #feroxbuster #php #wfuzz
    #vhosts #composer #phpunit #cve-2017-9841 #webshell
    #reverse-engineering #ghidra #awk #backdoor #hashcat #apache-mod
    #sshd #oscp-plus

    ![](/img/undetected-cover.png)

    Undetected follows the path of an attacker against a partially
    disabled website. I'll exploit a misconfigured PHP package to get
    execution on the host. From there, I'll find a kernel exploit left
    behind by the previous attacker, and while it no longer works, the
    payload shows how it modified the passwd and shadow files to add
    backdoored users with static passwords, and those users are still
    present. Further enumeration finds a malicious Apache module
    responsible for downloading and installing a backdoored sshd binary.
    Reversing that provides a password I can use to get a root shell.

-   Jun 25, 2022

    ### [HTB: Phoenix](/htb-phoenix.md)

    #hackthebox #htb-phoenix #ctf #htb-pressed #htb-static #nmap
    #wordpress #wpscan #wp-pie-register #wp-asgaros-forum #sqli
    #injection #time-based-sqli #sqlmap #hashcat #2fa #wp-miniorange
    #totp #youtube #source-code #crypto #cyberchef #oathtool
    #wp-download-from-files #webshell #upload #pam #sch #unsch #pspy
    #proc #wildcard

    ![](/img/phoenix-cover.png)

    Phoenix starts off with a WordPress site using a plugin with a blind
    SQL injection. This injection is quite slow, and I think leads to
    the poor reception for this box overall. Still, very slow blind SQL
    injection shows the value in learning to pull out only the bits you
    need from the DB. I'll get usernames and password hashes, but that
    leaves me at a two factors prompt. I'll reverse enginner that plugin
    to figure out what I need from the DB, and get the seed to generate
    the token. From there, I'll abuse another plugin to upload a
    webshell and get a shell on the box. The first pivot involves
    password reuse and understanding the pam 2FA setup isn't enabled on
    one interface. The next pivot is wildcard injection in a complied
    shell script. I'll dump the script out (several ways), and then use
    the injection to get a shell as root.

-   Jun 18, 2022

    ### [HTB: Paper](/htb-paper.md)

    #hackthebox #ctf #htb-paper #nmap #feroxbuster #wfuzz #vhosts
    #wordpress #wpscan #rocket-chat #cve-2019-17671 #directory-traversal
    #password-reuse #credentials #crackmapexec #linpeas #cve-2021-3156
    #cve-2021-4034 #pwnkit #cve-2021-3650 #oscp-like

    ![](/img/paper-cover.png)

    Paper is a fun easy-rated box themed off characters from the TV show
    "The Office". There's a WordPress vulnerability that allows reading
    draft posts. In a draft post, I'll find the URL to register accounts
    on a Rocket Chat instance. Inside the chat, there's a bot that can
    read files. I'll exploit a directory traversal to read outside the
    current directory, and find a password that can be used to access
    the system. To escalate from there, I'll exploit a 2021 CVE in
    PolKit. In Beyond Root, I'll look at a later CVE in Polkit, Pwnkit,
    and show why Paper wasn't vulnerable, make it vulnerable, and
    exploit it.

-   Jun 11, 2022

    ### [HTB: Meta](/htb-meta.md)

    #hackthebox #ctf #htb-meta #nmap #wfuzz #vhosts #wfuzz #feroxbuster
    #exiftool #composer #cve-2021-22204 #command-injection #pspy
    #mogrify #cve-2020-29599 #polyglot #hackvent #image-magick
    #image-magick-scripting-language #neofetch #gtfobins #source-code
    #oscp-like

    ![](/img/meta-cover.png)

    Meta was all about image processing. It starts with an image
    metadata service where I'll exploit a CVE in exfiltool to get code
    execution. From there, I'll exploit a cron running an ImageMagick
    script against uploaded files using an SVC/ImageMagick Scripting
    Language polyglot to get shell as the user. For root, I'll abuse
    neofetch and environment variables.

-   Jun 4, 2022

    ### [HTB: Timing](/htb-timing.md)

    #hackthebox #ctf #htb-timing #nmap #php #feroxbuster #wfuzz #lfi
    #directory-traversal #source-code #side-channel #timing #python
    #bash #youtube #mass-assignment #burp #burp-repeater #webshell
    #firewall #git #password-reuse #credentials #axel #sudo-home
    #htb-backendtwo

    ![](/img/timing-cover.png)

    Timing starts out with a local file include and a directory
    traversal that allows me to access the source for the website. I'll
    identify and abuse a timing attack to identify usernames on a login
    form. After logging in, there's a mass assignment vulnerability that
    allows me to upgrade my user to admin. As admin, I'll use the LFI
    plus upload to get execution. To root, I'll abuse a download program
    to overwrite root's authorized_keys file and get SSH access. In
    Beyond Root, I'll look at an alternative root, and dig more into
    mass assignment vulnerabilities.

-   May 31, 2022

    ### [SetUID Rabbit Hole](/setuid-rabbithole.md)

    #ctf #htb-jail #suid #linux #execve #c #nfs #setuid #seteuid
    #setresuid

    ![](/img/setuid-rabbit-cover.png)

    In looking through writeups for Jail after finishing mine, I came
    across an interesting rabbit hole, which led me down the path of a
    good deal of research, where I learned interesting detail related to
    a few things I've been using for years. I'll dive into Linux user
    IDs and SetUID / SUID, execve vs system, and sh vs bash, and test
    out what I learn on Jail.

-   May 28, 2022

    ### [HTB: AdmirerToo](/htb-admirertoo.md)

    #htb-admirertoo #hackthebox #ctf #nmap #feroxbuster #vhosts #wfuzz
    #adminer #cve-2021-21311 #ssrf #adminer-oneclick-login #opentsdb
    #python #flask #cve-2020-35476 #credentials #opencats #fail2ban
    #cve-2021-25294 #upload #cve-2021-32749 #whois #hydra #wireshark
    #ncat #htb-forge

    ![](/img/admirertoo-cover.png)

    AdmirerToo is all about chaining exploits together. I'll use a SSRF
    vulnerability in Adminer to discover a local instance of OpenTSDB,
    and use the SSRF to exploit a command injection to get a shell. Then
    I'll exploit a command injection in Fail2Ban that requires I can
    control the result of a whois query about my IP. I'll abuse a file
    write vulnerability in OpenCats to upload a malicious whois.conf,
    and then exploit fail2ban getting a shell. In Beyond Root, I'll look
    at the final exploit and why nc didn't work for me at first, but
    ncat did.

-   May 23, 2022

    ### [HTB: Jail](/htb-jail.md)

    #hackthebox #htb-jail #ctf #nmap #centos #nfs #feroxbuster #bof
    #source-code #gdb #peda #pwntools #shellcode #socket-reuse
    #nfs-nosquash #rvim #gtfobins #rar #quipquip #crypto #hashcat
    #hashcat-rules #atbash #rsa #rsactftool #facl #getfacl
    #htb-laboratory #htb-tartarsauce

    ![](/img/jail-cover.png)

    Jail is an old HTB machine that is still really nice to play today.
    There's a bunch of interesting fundamentals to work through. It
    starts with a buffer overflow in a jail application that can be
    exploited to get execution. It's a very beginner BOF, with stack
    execution enabled, access to the source, and a way to leak the input
    buffer address. From there, I'll abuse an NFS share without user
    squashing to escalate to the next user. Then there's an rvim escape
    to get the next user. And finally a crypto challenge to get root.
    Jail sent me a bit down the rabbit hole on NFS, so some interesting
    exploration in Beyond Root, including an alternative way to make the
    jump from frank to adm.

-   May 21, 2022

    ### [HTB: Pandora](/htb-pandora.md)

    #ctf #hackthebox #htb-pandora #nmap #feroxbuster #vhosts #snmp
    #snmpwalk #snmpbulkwalk #mibs #python #python-dataclass #pandora-fms
    #cve-2021-32099 #sqli #injection #sqli-union #sqlmap #auth-bypass
    #cve-2020-13851 #command-injection #upload #webshell #path-hijack
    #mpm-itk #apache #youtube #htb-sneaky #htb-openkeys #oscp-like

    ![](/img/pandora-cover.png)

    Pandora starts off with some SNMP enumeration to find a username and
    password that can be used to get a shell. This provides access to a
    Pandora FMS system on localhost, which has multiple vulnerabilities.
    I'll exploit a SQL injection to read the database and get session
    cookies. I can exploit that same page to get admin and upload a
    webshell, or exploit another command injection CVE to get execution.
    To get root, there's a simple path hijack in a SUID binary, but I
    will have to switch to SSH access, as there's a sandbox in an Apache
    module preventing my running SUID as root while a descendant process
    of Apache. I'll explore that in depth in Beyond Root.

-   May 18, 2022

    ### [HTB: Mirai](/htb-mirai.md)

    #hackthebox #htb-mirai #ctf #nmap #raspberrypi #feroxbuster #plex
    #pihole #default-creds #deleted-file #extundelete #testdisk
    #photorec

    ![](/img/mirai-cover.png)

    Mirai was a RaspberryPi device running PiHole that happens to still
    have the RaspberryPi default usename and password. That user can
    even sudo to root, but there is a bit of a hitch at the end. I'll
    have to recover the deleted root flag from a usb drive.

-   May 16, 2022

    ### [HTB: Brainfuck](/htb-brainfuck.md)

    #htb-brainfuck #hackthebox #ctf #nmap #vhosts #wordpress #ubuntu
    #wpscan #wp-support-plus #crypto #auth-bypass #smtp #email #vigenere
    #john #rsa #lxc #lxd #sudo #htb-spectra #htb-tabby

    ![](/img/brainfuck-cover.png)

    Brainfuck was one of the first boxes released on HackTheBox. It's a
    much more unrealistic and CTF style box than would appear on HTB
    today, but there are still elements of it that can be a good
    learning opportunity. There's WordPress exploitation and a bunch of
    crypto, including RSA and Vigenere.

-   May 14, 2022

    ### [HTB: Fingerprint](/htb-fingerprint.md)

    #ctf #hackthebox #htb-fingerprint #nmap #ubuntu #ubuntu-1804 #python
    #werkzeug #feroxbuster #execute-after-redirect #burp #burp-repeater
    #burp-proxy #glassfish #java #browser-fingerprint #source-code
    #directory-traversal #flask #proc #hql #hql-injection
    #boolean-injection #youtube #xss #jwt #jwt-io #deserialization
    #java-deserialization #maven #jd-gui #java-byte-code #tunnel #crypto
    #aes #aes-ecb #padding-attack #htb-previse

    ![](/img/fingerprint-cover.png)

    For each step in Fingerprint, I'll have to find multiple
    vulnerabilities and make them work together to accomplish some goal.
    To get a shell, I'll abuse a execute after return (EAR)
    vulnerability, a directory traversal, HQL injection, cross site
    scripting, to collect the pieces necessary for the remote exploit.
    I'll generate a custom Java serialized payload and abuse a shared
    JWT signing secret to get execution and a shell. To get to the next
    user I'll need to brute force an SSH key character by character
    using a SUID program, and find the decryption password in a Java
    Jar. To get root, I'll need to abuse a new version of one of the
    initial webservers, conducting a padding attack on the AES cookie to
    force a malicious admin cookie, and then use the directory traversal
    to read the root SSH key.

-   May 11, 2022

    ### [HTB: Fulcrum](/htb-fulcrum.md)

    #ctf #hackthebox #htb-fulcrum #nmap #ubuntu #windows #feroxbuster
    #api #xxe #burp #burp-repeater #python #ssrf #rfi #qemu #tunnel
    #powershell #powershell-credential #chisel #evil-winrm #web.config
    #ldap #powerview #credentials #htb-reel #htb-omni

    ![](/img/fulcrum-cover.png)

    Fulcrum is a 2017 release that got a rebuild in 2022. It's a Linux
    server with four websites, including one that returns Windows .NET
    error messages. I'll exploit an API endpoint via XXE, and use that
    as an SSRF to get execution through a remote file include. From
    there I'll pivot to the Windows webserver with some credentials,
    enumeration LDAP, pivot to the file server, which can read shares on
    the DC. In those shares, I'll find a login script with creds
    associated with one of the domain admins, and use that to read the
    flag from the DC, as well as to get a shell. This box has a lot of
    tunneling, representing a small mixed-OS network on one box.

-   May 7, 2022

    ### [HTB: Unicode](/htb-unicode.md)

    #ctf #htb-unicode #hackthebox #nmap #flask #python #jwt-io
    #feroxbuster #jwt-rsa #open-redirect #filter #waf #unicode
    #unicode-normalization #directory-traversal #credentials #share
    #pyinstaller #pyinstxtractor #uncompyle6 #parameter-injection
    #htb-backdoor

    ![](/img/unicode-cover.png)

    Unicode's name reflects the need to bypass web filtering of input by
    abusing unicode characters, and how they are normalized to abuse a
    directory traversal bug. There's also some neat JWT abuse, targeting
    the RSA signed versions and using an open redirect to trick the
    server into trusting a public key I host. To escalate, there's some
    parameter injection in a PyInstaller-built ELF file.

-   May 5, 2022

    ### [HTB: Return](/htb-return.md)

    #ctf #hackthebox #htb-return #nmap #windows #crackmapexec #printer
    #feroxbuster #ldap #wireshark #evil-winrm #server-operators #service
    #service-hijack #windows-service #htb-fuse #htb-blackfield

    ![](/img/return-cover.png)

    Return was a straight forward box released for the HackTheBox
    printer track. This time I'll abuse a printer web admin panel to get
    LDAP credentials, which can also be used for WinRM. The account is
    in the Server Operators group, which allows it to modify, start, and
    stop services. I'll abuse this to get a shell as SYSTEM.

-   May 3, 2022

    ### [HTB: Antique](/htb-antique.md)

    #htb-antique #hackthebox #ctf #printer #nmap #jetdirect #telnet
    #python #snmp #snmpwalk #tunnel #chisel #cups #cve-2012-5519
    #hashcat #shadow #cve-2015-1158 #pwnkit #shared-object
    #cve-2021-4034

    ![](/img/antique-cover.png)

    Antique released non-competitively as part of HackTheBox's Printer
    track. It's a box simulating an old HP printer. I'll start by
    leaking a password over SNMP, and then use that over telnet to
    connect to the printer, where there's an exec command to run
    commands on the system. To escalate, I'll abuse an old instance of
    CUPS print manager software to get file read as root, and get the
    root flag. In Beyond Root, I'll look at two more CVEs, another CUPS
    one that didn't work because no actual printers were attached, and
    PwnKit, which does work.

-   May 2, 2022

    ### [HTB: BackendTwo](/htb-backendtwo.md)

    #htb-backendtwo #ctf #uhc #hackthebox #nmap #uvicorn #python #api
    #json #jq #wfuzz #feroxbuster #swagger #fastapi #jwt #pyjwt #jwt-io
    #simple-modify-headers #credentials #pam-wordle #mass-assignment
    #cyberchef #htb-backend #htb-altered #htb-backdoor

    ![](/img/backendtwo-cover.png)

    BackendTwo is this month's UHC box. It builds on the first Backend
    UHC box, but with some updated vulnerabilities, as well as a couple
    small repeats from steps that never got played in UHC competition.
    It starts with an API that I'll fuzz to figure out how to register.
    Then I'll abuse a mass assignment vulnerability to give my user
    admin privs. From there, I can use a file read endpoint read /proc
    to find the page source, and eventually the signing secret for the
    JWT. With that, I can forge a new token allowing access to the file
    write api, where I'll quietly insert a backdoor into an endpoint
    that returns a shell (and show how to just smash the door in as
    well). To escalate, it's password reuse and cheating at pam-wordle.

-   Apr 30, 2022

    ### [HTB: Search](/htb-search.md)

    #htb-search #hackthebox #ctf #nmap #domain-controller
    #active-directory #vhosts #credentials #feroxbuster #smbmap
    #smbclient #password-spray #ldapsearch #ldapdomaindump #jq
    #bloodhound-python #bloodhound #kerberoast #hashcat #crackmapexec
    #msoffice #office #excel #certificate #pfx2john #firefox-certificate
    #certificate #client-certificate #powershell-web-access #gmsa
    #youtube #oscp-plus

    ![](/img/search-cover.png)

    Search was a classic Active Directory Windows box. It starts by
    finding credentials in an image on the website, which I'll use to
    dump the LDAP for the domain, and find a Kerberoastable user.
    There's more using pivoting, each time finding another clue, with
    spraying for password reuse, credentials in an Excel workbook, and
    access to a PowerShell web access protected by client certificates.
    With that initial shell, its a a few hops identified through
    Bloodhound, including recoving a GMSA password, to get to domain
    admin.

-   Apr 28, 2022

    ### [HTB: Rabbit](/htb-rabbit.md)

    #ctf #htb-rabbit #hackthebox #nmap #iis #apache #wamp #feroxbuster
    #owa #exchange #joomla #complain-management-system #searchsploit
    #sqli #burp #burp-repeater #sqlmap #crackstation #phishing
    #openoffice #macro #certutil #powershellv2 #webshell #schtasks
    #attrib #htb-sizzle #htb-fighter

    ![](/img/rabbit-cover.png)

    Rabbit was all about enumeration and rabbit holes. I'll work to
    quickly eliminate vectors and try to focus in on ones that seem
    promising. I'll find an instance of Complain Management System, and
    exploit multiple SQL injections to get a dump of hashes and
    usernames. I'll use them to log into an Outlook Web Access portal,
    and use that access to send phishing documents with macros to get a
    shell. From there, I'll find one of the webservers running as SYSTEM
    and write a webshell to get a shell. In Beyond Root, a look at a
    comically silly bug in the Complain Management System's forgot
    password feature, as well as at the scheduled tasks on the box
    handling the automation.

-   Apr 25, 2022

    ### [HTB: Fighter](/htb-fighter.md)

    #htb-fighter #hackthebox #ctf #nmap #iis #vhosts #wfuzz #feroxbuster
    #sqli #burp #burp-repeater #xp-cmdshell #nishang #windows-firewall
    #applocker #driverquery #capcom-sys #ghidra #python #msbuild
    #applocker-bypass #msfvenom #msfconsole #metasploit #juicypotato
    #htb-fuse

    ![](/img/fighter-cover.png)

    Fighter is a solid old Windows box that requires avoiding AppLocker
    rules to exploit an SQL injection, hijack a bat script, and exploit
    the imfamous Capcom driver. I'll show the intended path, as well as
    some AppLocker bypasses, how to modify the Metasploit Capcom exploit
    to work, and JuicyPotato (which was born from this box).

-   Apr 24, 2022

    ### [Parallelizing in Bash and Python](/parallelizing-in-bash-and-python.md)

    #htb-backdoor #ctf #hackthebox #python #bash #bash-async #async
    #python-async #youtube #programming #bruteforce

    ![](/img/backdoor-scripts-cover.png)

    To solve the Backdoor box from HackTheBox, I used a Bash script to
    loop over 2000 pids using a directory traversal / local file read
    vulnerability and pull their command lines. I wanted to play with
    parallelizing that attack, both in Bash and Python. I'll share the
    results in this post / YouTube video.

-   Apr 23, 2022

    ### [HTB: Backdoor](/htb-backdoor.md)

    #htb-backdoor #ctf #hackthebox #nmap #wordpress #wpscan #feroxbuster
    #exploit-db #directory-traversal #ebooks-download #proc #bash
    #msfvenom #gdb #gdbserver #gdb-remote #metasploit #screen
    #htb-pressed #oscp-plus

    ![](/img/backdoor-cover.png)

    Backdoor starts by finding a WordPress plugin with a directory
    traversal bug that allows me to read files from the filesystem. I'll
    use that to read within the /proc directory and identify a
    previously unknown listening port as gdbserver, which I'll then
    exploit to get a shell. To get to root, I'll join a screen session
    running as root in multiuser mode.

-   Apr 20, 2022

    ### [HTB: Ariekei](/htb-ariekei.md)

    #ctf #hackthebox #htb-ariekei #nmap #vhosts #wfuzz #youtube #waf
    #feroxbuster #cgi #shellshock #cve-2014-6271 #image-tragick
    #image-magick #cve-2016-3714 #docker #pivot #password-reuse #tunnel
    #ssh2john #hashcat #htb-shocker

    ![](/img/ariekei-cover.png)

    Ariekei is an insane-rated machine released on HackTheBox in 2017,
    focused around two very well known vulnerabilities, Shellshock and
    Image Tragic. I'll find Shellshock very quickly, but not be able to
    exploit it due to a web application firewall. I'll turn to another
    virtual host where there's an image upload, and exploit Image Tragic
    to get a shell in a Docker container. I'll use what I can enumerate
    about the network of docker containers and their secrets to to pivot
    to a new container that can talk directly to the website that's
    vulnerable to Shellshock without the WAF, and exploit it to get
    access there. After escalating, I'll find an SSH key that provides
    access to the host, and abuse the docker group to escalate to root.

-   Apr 16, 2022

    ### [HTB: Toby](/htb-toby.md)

    #hackthebox #ctf #htb-toby #nmap #vhosts #wfuzz #wordpress #backdoor
    #wpscan #gogs #git #source-code #feroxbuster #cyberchef #crypto
    #php-deobfuscation #wireshark #python #youtube #docker #pivot
    #hashcat #chisel #pam #ghidra #htb-kryptos

    ![](/img/toby-cover.png)

    Toby was a really unique challenge that involved tracing a previous
    attackers steps and poking a backdoors without full information
    about how they work. I'll start by getting access to PHP source that
    shows where a webshell is loaded, but not the full execution. I'll
    have to play with it to get it to give execution, figuring out how
    it communicates. From there I'll pivot into a MySQL container and
    get hashes to get into the Gogs instance. Source code analysis plus
    some clever password generation allows me to pivot onto the main
    host, where I'll have to use trouble tickets to find a PAM backdoor
    and brute force the password.

-   Apr 14, 2022

    ### [HTB: Jeeves](/htb-jeeves.md)

    #htb-jeeves #hackthebox #ctf #nmap #windows #feroxbuster #gobuster
    #jetty #jenkins #keepass #kpcli #hastcat #passthehash #crackstation
    #psexec-py #alternative-data-streams #htb-object

    ![](/img/jeeves-cover.png)

    Jeeves was first released in 2017, and I first solved it in 2018.
    Four years later, it's been an interesting one to revisit. Some of
    the concepts seem not that new and exciting, but it's worth
    remembering that Jeeves was the first to do them. I'll start with a
    webserver and find a Jenkins instance with no auth. I can abuse
    Jenkins to get execution and remote shell. From there, I'll find a
    KeePass database, and pull out a hash that I can pass to get
    execution as Administrator. root.txt is actually hidden in an
    alternative data stream.

-   Apr 12, 2022

    ### [HTB: Backend](/htb-backend.md)

    #htb-backend #ctf #hackthebox #nmap #api #json #uvicorn #feroxbuster
    #wfuzz #swagger #fastapi #python #jwt #pyjwt #jwt-io
    #simple-modify-headers #burp #credentials #uhc

    ![](/img/backend-cover.png)

    Backend was all about enumerating and abusing an API, first to get
    access to the Swagger docs, then to get admin access, and then debug
    access. From there it allows execution of commands, which provides a
    shell on the box. To escalate to root, I'll find a root password in
    the application logs where the user must have put in their password
    to the name field.

-   Apr 11, 2022

    ### [HTB: Tally](/htb-tally.md)

    #hackthebox #ctf #htb-tally #nmap #windows #sharepoint #mssql
    #keepass #hashcat #kpcli #crackmapexec #smbclient #mssqlclient
    #xp-cmdshell #firefox #user-agent #searchsploit #cve-2016-1960
    #shellcode #python #scheduled-task #rottenpotato #sweetpotato
    #cve-2017-0213 #visual-studio #windows-sessions #msfvenom
    #metasploit #migrate

    ![](/img/tally-cover.png)

    Tally is a difficult Windows Machine from Egre55, who likes to make
    boxes with multiple paths for each step. The box starts with a lot
    of enumeration, starting with a SharePoint instance that leaks creds
    for FTP. With FTP access, there are two paths to root. First there's
    a KeePass db with creds for SMB, which has a binary with creds for
    MSSQL, and I can use MSSQL access to run commands and get a shell.
    Alternatively, I can spot a Firefox installer and a note saying that
    certain HTML pages on the FTP server will be visited regularly, and
    craft a malicious page to exploit that browser. To escalate, there's
    a scheduled task running a writable PowerShell script as
    administrator. There's also SeImpersonate privilege in a shell
    gained via MSSQL, which can be leveraged to get root as well.
    Finally, I'll show a local Windows exploit that was common at the
    time of the box release, CVE-2017-0213.

-   Apr 9, 2022

    ### [HTB: Overflow](/htb-overflow.md)

    #hackthebox #htb-overflow #ctf #nmap #ubuntu #cookies
    #padding-oracle #python #feroxbuster #padbuster #vhosts #sqli
    #sqlmap #hashcat #cmsmadesimple #cve-2021-22204 #exiftool
    #password-reuse #facl #getfacl #hosts #time-of-check-time-of-use
    #ghidra #bof #crypto #gdb #youtube #htb-lazy

    ![](/img/overflow-cover.png)

    Overflow starts with a padding oracle attack on a cookie for a
    website. I'll get to do some need cookie analysis before employing
    padbuster to decrypt the cookie and forge a new admin one. As admin,
    I get access to a logs panel with an SQL injection, where I can dump
    the db and crack the password to log into the CMS as well as a new
    virtual host with job adds. I'll submit a malicious image that
    exploits a CVE in exiftool to get a shell. I'll pivot to the next
    user with a credential from the web source. The next user is
    regularly running a script that pulls from another domain. With
    access to the hosts file, I'll direct that domain to my machine and
    get execution. Finally, to get root, I'll exploit a buffer overflow
    and a time of check / time of use vulnerability to get arbitrary
    read as root, and leverage that to get a shell.

-   Apr 7, 2022

    ### [HTB: Minion](/htb-minion.md)

    #htb-minion #hackthebox #ctf #nmap #windows #asp #aspx #iis
    #feroxbuster #webshell #wfuzz #ssrf #icmp-exfil #youtube #python
    #powershell #python-cmd #powershell-runas #alternative-data-streams
    #crackstation #ghidra #htb-nest

    ![](/img/minion-cover.png)

    Minion is four and a half years old, but it's still really
    difficult. The steps themselves are not that hard, but the
    difficulty comes with the firewall that only allows ICMP out. So
    while I find a blind command execution relatively quickly, I'll have
    to write my own shell using Python and PowerShell to exfil data over
    pings. The rest of the steps are also not hard on their own, just
    difficult to work through my ICMP shell. I'll hijack a writable
    PowerShell script that runs on a schedule, and then find a password
    from the Administrator user in an alternative data stream on a
    backup file to get admin access.

-   Apr 4, 2022

    ### [HTB: Inception](/htb-inception.md)

    #ctf #hackthebox #htb-inception #nmap #dompdf #feroxbuster #squid
    #proxychains #wfuzz #container #lxd #php-filter #webdav #davtest
    #wireshark #webshell #forward-shell #wordpress #ping-sweep #tftp
    #apt #apt-pre-invoke #youtube #htb-joker #htb-granny

    ![](/img/inception-cover.png)

    Inception was one of the first boxes on HTB that used containers.
    I'll start by exploiting a dompdf WordPress plugin to get access to
    files on the filesystem, which I'll use to identify a WedDAV
    directory and credentials. I'll abuse WebDAV to upload a webshell,
    and get a foothold in a container. Unfortunately, outbound traffic
    is blocked, so I can't get a reverse shell. I'll write a forward
    shell in Python to get a solid shell. After some password reuse and
    sudo, I'll have root in the container. Looking at the host, from the
    container I can access FTP and TFTP. Using the two I'll identify a
    cron running apt update, and write a pre-invoke script to get a
    shell.

-   Apr 2, 2022

    ### [HTB: Shibboleth](/htb-shibboleth.md)

    #ctf #htb-shibboleth #hackthebox #nmap #vhosts #wfuzz #feroxbuster
    #zabbix #ipmi #msfconsole #msfvenom #shared-object #rakp #ipmipwner
    #hashcat #password-reuse #credentials #mysql #cve-2021-27928
    #youtube #htb-zipper #oscp-like

    ![](/img/shibboleth-cover.png)

    Shibboleth starts with a static website and not much else. I'll have
    to identify the clue to look into BMC automation and find IPMI
    listening on UDP. I'll leak a hash from IPMI, and crack it to get
    creds to a Zabbix instance. Within Zabbix, I'll have the agent run a
    command, providing a foothold. Some credential reuse pivots to the
    next user. To get root, I'll exploit a CVE in MariaDB / MySQL. In
    Beyond Root, a video reversing the shared object file I used in that
    root exploit, as well as generating my own in C.

-   Mar 30, 2022

    ### [HTB: Altered](/htb-altered.md)

    #ctf #hackthebox #htb-altered #uhc #nmap #laravel #php
    #type-juggling #password-reset #wfuzz #bruteforce #feroxbuster
    #rate-limit #sqli #sqli-file #sqli-union #burp #burp-repeater
    #webshell #dirtypipe #cve-2022-0847 #pam-wordle #passwd #ghidra
    #reverse-engineering #htb-ransom

    ![](/img/altered-cover.png)

    Altered was another Ultimate Hacking Championship (UHC) box that's
    now up on HTB. This one has another Laravel website. This time I'll
    abuse the password reset capability, bypassing the rate limiting
    using HTTP headers to brute force the pin. Once in, I'll find a
    endpoint that's vulnerable to SQL injection, but only after abusing
    type-juggling to bypass an integrity check. Using that SQL
    injection, I'll write a webshell and get a foothold. To get to root,
    I'll abuse Dirty Pipe, with a twist. Most of the scripts to exploit
    Dirty Pipe modify the passwd file, but this box has pam-wordle
    installed, so you much play a silly game of tech-based Wordle to
    auth. I'll show both how to solve this, and how to use a different
    technique that overwrites a SUID executable. In Beyond Root, I'll
    reverse how that latter exploit works.

-   Mar 26, 2022

    ### [HTB: Secret](/htb-secret.md)

    #hackthebox #htb-secret #ctf #nmap #jwt #pyjwt #express #feroxbuster
    #api #source-code #git #command-injection #pr-set-dumpable #suid
    #crash-dump #var-crash #appport-unpack #core-dump

    ![](/img/secret-cover.png)

    To get a foothold on Secret, I'll start with source code analysis in
    a Git repository to identify how authentication works and find the
    JWT signing secret. With that secret, I'll get access to the admin
    functions, one of which is vulnerable to command injection, and use
    this to get a shell. To get to root, I'll abuse a SUID file in two
    different ways. The first is to get read access to files using the
    open file descriptors. The alternative path is to crash the program
    and read the content from the crashdump.

-   Mar 19, 2022

    ### [HTB: Stacked](/htb-stacked.md)

    #hackthebox #ctf #htb-stacked #nmap #localstack #feroxbuster #wfuzz
    #vhosts #docker #docker-compose #xss #burp #burp-repeater
    #xss-referer #aws #awslocal #aws-lambda #cve-2021-32090
    #command-injection #pspy #container #htb-crossfit #htb-bankrobber
    #htb-bucket #htb-epsilon #oscp-plus

    ![](/img/stacked-cover.png)

    Stacked was really hard. The foothold involved identifying XSS in a
    referer header that landed in an mail application that I could not
    see. I'll use the XSS to enumerate that mailbox and find a subdomain
    used for an instance of localstack. From there, I'll find I can
    create Lambda functions, and there's a command injection
    vulnerability in the dashboard if it displays a malformed function
    name. I'll use the XSS to load that page in an IFrame and trigger
    the vulnerability, providing a foothold in the localstack container.
    To escalate in that container, I'll use Pspy to monitor what happens
    when localstack runs a lambda function, and find that it is also
    vulnerable to command injection as root. From root in the container,
    I can get full access to the host filesystem and a shell. In Beyond
    Root, I'll take a look at the mail application and the automations
    triggering the XSS vulnerabilities.

-   Mar 15, 2022

    ### [HTB: Ransom](/htb-ransom.md)

    #ctf #hackthebox #htb-ransom #uhc #nmap #type-juggling #ubuntu #php
    #laravel #feroxbuster #burp #burp-repeater #zipcrypto
    #known-plaintext #crypto #bkcrack

    ![](/img/ransom-cover.png)

    Ransom was a UHC qualifier box, targeting the easy to medium range.
    It has three basic steps. First, I'll bypass a login screen by
    playing with the request and type juggling. Then I'll access files
    in an encrypted zip archive using a known plaintext attack and
    bkcrypt. Finally, I'll find credentials in HTML source that work to
    get root on the box. In Beyond Root, I'll look at the structure of a
    Laravel application, examine how the api requests were handled and
    how I managed to get JSON data into a GET request, and finally look
    at the type juggling, why it worked, and how to fix it.

-   Mar 12, 2022

    ### [HTB: Devzat](/htb-devzat.md)

    #hackthebox #ctf #htb-devzat #nmap #ubuntu #vhosts #wfuzz #devzat
    #feroxbuster #go #git #source-code #file-read #directory-traversal
    #command-injection #influxdb #cve-2019-20933 #jwt #pyjwt #jwt-io
    #htb-cereal #htb-dyplesher #htb-travel #htb-epsilon

    ![](/img/devzat-cover.png)

    Devzat is centered around a chat over SSH tool called Devzat. To
    start, I can connect, but there is at least one username I can't
    access. I'll find a pet-themed site on a virtual host, and find it
    has an exposed git repository. Looking at the code shows file read /
    directory traversal and command injection vulnerabilities. I'll use
    the command injection to get a shell. From localhost, I can access
    the chat for the first user, where there's history showing another
    user telling them about an influxdb instance. I'll find an auth
    bypass exploit to read the db, and get the next user's password.
    This user has access to the source for a new version of Devzat.
    Analysis of this version shows a new command, complete with a file
    read vulnerability that I'll use to read root's private key and get
    a shell over SSH.

-   Mar 10, 2022

    ### [HTB: Epsilon](/htb-epsilon.md)

    #hackthebox #ctf #htb-epsilon #nmap #feroxbuster #git #gitdumper
    #source-code #flask #python #aws #awscli #aws-lambda #htb-gobox
    #htb-bolt #htb-bucket #jwt #ssti #burp #burp-repeater #pspy
    #timing-attack #cron

    ![](/img/epsilon-cover.png)

    Epsilon originally released in the 2021 HTB University CTF, but
    later released on HTB for others to play. In this box, I'll start by
    finding an exposed git repo on the webserver, and use that to find
    source code for the site, including the AWS keys. Those keys get
    access to lambda functions which contain a secret that is reused as
    the secret for the signing of JWT tokens on the site. With that
    secret, I'll get access to the site and abuse a server-side template
    injection to get execution and an initial shell. To escalate to
    root, there's a backup script that is creating tar archives of the
    webserver which I can abuse to get a copy of root's home directory,
    including the flag and an SSH key for shell access.

-   Mar 5, 2022

    ### [HTB: Hancliffe](/htb-hancliffe.md)

    #htb-hancliffe #hackthebox #ctf #nmap #hashpass #nuxeo #uri-parsing
    #feroxbuster #ssti #java #windows #unified-remote #tunnel #chisel
    #msfvenom #firefox #firepwd #winpeas #evil-winrm #youtube #htb-seal
    #htb-logforge #reverse-engineering #ghidra #x32dbg #rot-47 #atbash
    #cyberchef #pattern-create #bof #jmp-esp #metasm #nasm #socket-reuse
    #shellcode #pwntools #wmic #dep #breaking-parser-logic

    ![](/img/hancliffe-cover.png)

    Hancliffe starts with a uri parsing vulnerability that provides
    access to an internal instance of Nuxeo, which is vulnerable to a
    Java server-side template injection that leads to RCE. With a
    foothold, I can tunnel to access an instance of Universal Remote,
    which allows RCE as the next user. That user has a stored password
    in Firefox for H@\$hPa\$\$, which gives the password for the next
    user. Finally, this user has access to a development application
    that is vulnerable to an interesting and tricky buffer overflow,
    where I'll have to jump around on the stack and use socket reuse to
    get execution as administrator.

-   Feb 28, 2022

    ### [HTB: Object](/htb-object.md)

    #hackthebox #htb-object #ctf #uni-ctf #nmap #iis #windows
    #feroxbuster #wfuzz #jenkins #cicd #firewall #windows-firewall
    #jenkins-credential-decryptor #pwn-jenkins #evil-winrm #crackmapexec
    #bloodhound #sharphound #active-directory #github
    #forcechangepassword #genericwrite #writeowner #logon-script
    #powerview #scheduled-task #powershell #htb-jeeves #oscp-like

    ![](/img/object-cover.png)

    Object was tricky for a CTF box, from the HackTheBox University CTF
    in 2021. I'll start with access to a Jenkins server where I can
    create a pipeline (or job), but I don't have permissions to manually
    tell it to build. I'll show two ways to get it to build anyway,
    providing execution. I'll enumerate the firewall to see that no TCP
    traffic can reach outbound, and eventually find credentials and get
    a connection over WinRM. From there, it's three hops of Active
    Directory abuse, all made clear by BloodHound. First a password
    change, then abusing logon scripts, and finally some group
    privileges. In Beyond Root, I'll enumerate the automation that ran
    the logon scripts as one of the users.

-   Feb 26, 2022

    ### [HTB: Driver](/htb-driver.md)

    #ctf #hackthebox #htb-driver #nmap #windows #feroxbuster #net-ntlmv2
    #scf #responder #hashcat #crackmapexec #evil-winrm #cve-2019-19363
    #winpeas #powershell #history #powershell-history #printer
    #metasploit #exploit-suggestor #windows-sessions #printnightmare
    #cve-2021-1675 #invoke-nightmare #htb-sizzle

    ![](/img/driver-cover.png)

    Drive released as part of the HackTheBox printer exploitation track.
    To get access, there's a printer web page that allows users to
    upload to a file share. I'll upload an scf file, which triggers
    anyone looking at the share in Explorer to try network
    authentication to my server, where I'll capture and crack the
    password for the user. That password works to connect to WinRM,
    providing a foothold to Driver. To escalate, I can exploit either a
    Ricoh printer driver or PrintNightmare, and I'll show both.

-   Feb 23, 2022

    ### [HTB: GoodGames](/htb-goodgames.md)

    #htb-goodgames #hackthebox #ctf #uni-ctf #vhosts #sqli #sqli-bypass
    #sqli-union #feroxbuster #burp #burp-repeater #ssti #docker #escape
    #docker-mount #htb-bolt

    ![](/img/goodgames-cover.png)

    GoodGames has some basic web vulnerabilities. First there's a SQL
    injection that allows for both a login bypass and union injection to
    dump data. The admin's page shows a new virtualhost, which, after
    authing with creds from the database, has a server-side template
    injection vulnerability in the name in the profile, which allows for
    coded execution and a shell in a docker container. From that
    container, I'll find the same password reused by a user on the host,
    and SSH to get access. On the host, I'll abuse the home directory
    that's mounted into the container and the way Linux does file
    permissions and ownership to get a shell as root on the host.

-   Feb 19, 2022

    ### [HTB: Bolt](/htb-bolt.md)

    #ctf #hackthebox #htb-bolt #youtube #nmap #vhosts #wfuzz #ffuf
    #docker #docker-tar #feroxbuster #roundcube #webmail #passbolt #dive
    #sqlite #hashcat #source-code #ssti #payloadsallthethings
    #password-reuse #password-reset #credentials #chrome #john #python

    ![](/img/bolt-cover.png)

    Bolt was all about exploiting various websites with different bits
    of information collected along the way. To start, I'll download a
    Docker image from the website, and pull various secrets from the
    older layers of the image, including a SQLite database and the
    source to the demo website. With that, I'm able to get into the demo
    website and exploit a server-side template injection vulnerability
    to get a foothold on the box. After some password reuse to get to
    the next user, I'll go into the user's Chrome profile to pull out
    the PGP key associated with their Passbolt password manager account,
    and use it along with database access to reset the users password
    and get access to their passwords, including the root password. In
    Beyond Root, a deep dive into the SSTI payloads used on this box.

-   Feb 14, 2022

    ### [HTB: SteamCloud](/htb-steamcloud.md)

    #hackthebox #htb-steamcloud #ctf #uni-ctf #nmap #kubernetes
    #minikube #htb-unobtainium #kubectl #kubeletctl #container

    ![](/img/steamcloud-cover.png)

    SteamCloud just presents a bunch of Kubernetes-related ports.
    Without a way to authenticate, I can't do anything with the
    Kubernetes API. But I also have access to the Kubelet running on one
    of the nodes (which is the same host), and that gives access to the
    pods running on that node. I'll get into one and get out the keys
    necessary to auth to the Kubernetes API. From there, I can spawn a
    new pod, mounting the host file system into it, and get full access
    to the host. I'll eventually manage to turn that access into a shell
    as well.

-   Feb 12, 2022

    ### [HTB: EarlyAccess](/htb-earlyaccess.md)

    #ctf #htb-earlyaccess #hackthebox #nmap #wfuzz #vhosts #php #laravel
    #xss #xss-cookies #python #injection #sqli #second-order
    #second-order-sqli #htb-nightmare #command-injection #api
    #php-filter #source-code #burp #burp-repeater #docker #container
    #password-reuse #wget #escape #arp #directory-traversal

    ![](/img/earlyaccess-cover.png)

    When it comes to telling a story, EarlyAccess might be my favorite
    box on HackTheBox. It's the box of a game company, with fantastic
    marketing on their front page for a game that turns out to be snake.
    I'll need multiple exploits including XSS and second order SQLI to
    get admin on the signup site, abuse that to move the the game site,
    and from there to the dev site. From the dev site I'll find a
    command injection to get a shell in the website's docker container.
    I'll abuse an API to leak another password to get onto the host.
    From there its back into another docker container, where I'll crash
    the container to get execution and shell as root, getting access to
    the shadow file and a password for the host. Finally, I'll abuse
    capabilities on arp to get read as root, the flag, and the root SSH
    key. In Beyond root, looking at a couple unintended paths.

-   Feb 9, 2022

    ### [HTB: Flustered](/htb-flustered.md)

    #htb-flustered #hackthebox #ctf #uni-ctf #nmap #feroxbuster #wfuzz
    #vhosts #squid #glusterfs #mysql #foxyproxy #ssti #flask #docker
    #container #azure-storage #azure-storage-explorer #youtube

    ![](/img/flustered-cover.png)

    Fluster starts out with a coming soon webpage and a squid proxy.
    When both turn out as dead ends, I'll identify GlusterFS, with a
    volume I can mount without auth. This volume has the MySQL data
    stores, and from it I'll find Squid credentials. With access to the
    proxy, I'll find the application source code, and exploit a
    server-side template injection vulnerability to get execution. With
    a foothold, I'll find the keys necessary to get access to a second
    Gluster volume, which gives access as user. To root, I'll connect to
    a Docker container hosting an emulated Azure Storage, and using a
    key from the host, pull the root SSH key. In Beyond root, an
    exploration into Squid and NGINX configs, and a look at full
    recreating the database based on the files from the remote volume.

-   Feb 7, 2022

    ### [FunWare \[CactusCon 2022 CTF\]](/funware-cactuscon-2022-ctf.md)

    #ctf #cactuscon #ctf-funware #forensics #malware
    #reverse-engineering #ftk-imager #access-data-file #ransomeware
    #pyinstaller #pyinstxtractor #flare-on-wopr #uncompyle6 #python
    #firefox #firepwd #sqlite

    ![](/img/cactuscon-ctf-2022-cover.png)

    Over the weekend, a few of us from Neutrino Cannon competed in the
    CactusCon 2022 CTF by ThreatSims. PolarBearer and I worked on a
    challenge called Funware, which was a interesting forensics
    challenge that starts with a disk image of a system that'd been
    ransomwared, and leads to understanding the malware, decrypting the
    files, and finding where it was downloaded from. It was a fun
    forensics challenge. Thanks to
    [\@pwnEIP](https://twitter.com/pwnEIP) and
    [\@Cone_Virus](https://twitter.com/Cone_Virus) for the challenge and
    for getting me the questions after it was over so I could write this
    up.

-   Feb 5, 2022

    ### [HTB: Horizontall](/htb-horizontall.md)

    #ctf #hackthebox #htb-horizontall #nmap #feroxbuster #source-code
    #vhosts #strapi #cve-2019-18818 #cve-2019-19609 #command-injection
    #burp #burp-repeater #laravel #phpggc #deserialization #oscp-like

    ![](/img/horizontall-cover.png)

    Horizonatll was built around vulnerabilities in two web frameworks.
    First there's discovering an instance of strapi, where I'll abuse a
    CVE to reset the administrator's password, and then use an
    authenticated command injection vulnerability to get a shell. With a
    foldhold on the box, I'll examine a dev instance of Laravel running
    only on localhost, and manage to crash it and leak the secrets. From
    there, I can do a deserialization attack to get execution as root.
    In Beyond Root, I'll dig a bit deeper on the strapi CVEs and how
    they were patched.

-   Feb 3, 2022

    ### [HTB: Pressed](/htb-pressed.md)

    #ctf #htb-pressed #hackthebox #nmap #wordpress #uhc #burp #wpscan
    #totp #2fa #xml-rpc #python #python-wordpress-xmlrpc #cyberchef
    #webshell #pwnkit #cve-2021-4034 #pkexec #iptables #youtube
    #htb-scavenger #htb-stratosphere #wp-miniorgange

    ![](/img/pressed-cover.png)

    Pressed presents a unique attack vector on WordPress, where you have
    access to admin creds right from the start, but can't log in because
    of 2FA. This means it's time to abuse XML-RPC, the thing that wpscan
    shows as a vulnerability on every WordPress instance, is rarely
    useful. I'll leak the source for the single post on the site, and
    see that's it's using PHPEverywhere to run PHP from within the post.
    I'll edit the post to include a webshell. The firewall is blocking
    outbound traffic, so I can't get a reverse shell. The box is
    vulnerable to PwnKit, so I'll have to modify the exploit to work
    over the webshell. After leaking the root flag, I'll go beyond with
    a Video where I take down the firewall and get a root shell.

-   Jan 29, 2022

    ### [HTB: Anubis](/htb-anubis.md)

    #hackthebox #ctf #htb-anubis #nmap #iis #crackmapexec #vhosts #wfuzz
    #feroxbuster #ssti #xss #certificate #adcs #htb-sizzle #youtube
    #openssl #certificate-authority #client-certificate #tunnel #chisel
    #proxychains #foxyproxy #wireshark #responder #hashcat #net-ntlmv2
    #smbclient #jamovi #cve-2021-28079 #electron #javascript #certutil
    #certreq #certify #certificate-template #kerberos #klist #kinit
    #evil-winrm #posh-adcs #rubeus #sharp-collection #powerview
    #psexec-py #faketime #htb-sizzle

    ![](/img/anubis-cover.png)

    Anubis starts simply enough, with a ASP injection leading to code
    execution in a Windows Docker container. In the container I'll find
    a certificate request, which leaks the hostname of an internal web
    server. That server is handling software installs, and by giving it
    my IP, I'll capture and crack the NetNTLMv2 hash associated with the
    account doing the installs. That account provides SMB access, where
    I find Jamovi files, one of which has been accessed recently. I'll
    exploit these files to get execution and a foothold on the host. To
    escalate, I'll find a certificate template that the current user has
    full control over. I'll use that control to add smart card
    authentication as a purpose for the template, and create one for
    administrator. I'll show how to do this the more manual way, getting
    the certificate and then authenticating with Kerveros from my Linux
    VM. Then I'll go back and do it again using PoshADCS and Rubeus all
    on Anubis.

-   Jan 22, 2022

    ### [HTB: Forge](/htb-forge.md)

    #ctf #htb-forge #hackthebox #nmap #wfuzz #ssrf #feroxbuster #vhosts
    #filter #redirection #flask #python #pdb #youtube #oscp-like

    ![](/img/forge-cover.png)

    The website on Forge has an server-side request forgery (SSRF)
    vulnerability that I can use to access the admin site, available
    only from localhost. But to do that, I have to bypass a deny list of
    terms in the given URL. I'll have the server contact me, and return
    a redirect to the site I actually want to have it visit. From the
    admin site, I can see that it too has an SSRF, and it can manage FTP
    as well. I'll update my redirect to have it fetch files from the
    local FTP server, including the user flag and the user's SSH private
    key. The user is able to run a Python script as root, and because of
    how this script uses PDB (the Python debugger), I can exploit the
    crash to get a shell as root. In Beyond Root, I'll look at bypassing
    the filter, and explore the webserver configuration to figure out
    how the webserver talks FTP.

-   Jan 15, 2022

    ### [HTB: Developer](/htb-developer.md)

    #ctf #htb-developer #hackthebox #youtube #nmap #feroxbuster #django
    #python #crypto #dnspy #ps2exe #xls #office #msoffice #excel
    #hashcat #reverse-engineering #gdb #ghidra #cyberchef
    #reverse-tab-nabbing #flask #deserialization #sentry #postgresql

    ![](/img/developer-cover.png)

    Developer is a CTF platform modeled off of HackTheBox! When I sign
    up for an account, there are eight real challenges to play across
    four different categories. On solving one, I can submit a write-up
    link, which the admin will click. This link is vulnerable to
    reverse-tab-nabbing, a neat exploit where the writeup opens in a new
    window, but it can get the original window to redirect to a site of
    my choosing. I'll make it look like it logged out, and capture
    credentials from the admin, giving me access to the Django admin
    panel and the Sentry application. I'll crash that application to see
    Django is running in debug mode, and get the secret necessary to
    perform a deserialization attack, providing execution and a foothold
    on the box. I'll dump the Django hashes from the Postgresql DB for
    Senty and crack them to get the creds for the next user. For root,
    there's a sudo executable that I can reverse to get the password
    which leads to SSH access as root.

-   Jan 10, 2022

    ### [HTB: NodeBlog](/htb-nodeblog.md)

    #ctf #htb-nodeblog #hackthebox #uhc #youtube #python #nmap
    #feroxbuster #nodejs #nosql-injection #payloadsallthethings #xxe
    #node-serialize #deserialization #json-deserialization #mongo
    #mongodump #bsondump

    ![](/img/nodeblog-cover.png)

    This UHC qualifier box was a neat take on some common NodeJS
    vulnerabilities. First there's a NoSQL authentication bypass. Then
    I'll use XXE in some post upload ability to leak files, including
    the site source. With that, I'll spot a deserialization
    vulnerability which I can abuse to get RCE. I'll get the user's
    password from Mongo via the shell or through the NoSQL injection,
    and use that to escalate to root. In Beyond Root, a look at
    characters that broke the deserialization payload, and scripting the
    NoSQL injection.

-   Jan 8, 2022

    ### [HTB: Previse](/htb-previse.md)

    #htb-previse #ctf #hackthebox #nmap #execute-after-redirect #burp
    #burp-repeater #source-code #php #injection #command-injection
    #path-hijack #hashcat #sudo #sqli #sqli-insert #youtube #oscp-like

    ![](/img/previse-cover.png)

    To get a foothold on Previse, first I'll exploit an execute after
    redirect vulnerability in the webpage that allows me access to
    restricted sites despite not being logged in. From those sites, I'll
    create a user for myself and log in normally. Then I get the source
    to the site, and I'll find a command injection vulnerability (both
    using the source and just by enumerating the site) to get a foothold
    on the box. To escalate, I'll go into the database and dump the user
    hashes, one of which cracks to the password for a user on the box.
    For root, there's a bash script with a path hijack vulnerability
    that can run with sudo, allowing for execution. In Beyond Root I'll
    look at the standard sudo config and what was changed for Previse,
    and then look at an unintended SQL injection in an insert statement.

-   Jan 8, 2022

    ### [2021 SANS Holiday Hack Challenge, featuring KringleCon 4: Calling Birds](/holidayhack2021/)

    #ctf #sans-holiday-hack

    ![](/img/hh21-cover.png)

    The 2021 SANS Holiday Hack Challenge was the battle of two competing
    conferences. Santa is hosting the 4th annual KringleCon at the North
    Pole, and Jack Front has set up a competing conference next door,
    FrostFest. This years challenge conference included [14 talks from
    leaders in information
    security](https://www.youtube.com/watch?v=lRbd2C6NHOg&list=PLjLd1hNA7YVx99qJF3OoPF-qunjqw-SoU),
    including a late entry from the elf, Professor Qwerty Petabyte,
    covering Log4j. In addition to the talks, there were 15 terminals /
    in-game puzzles and 13 objectives to solve. In solving all of these,
    the Jack Frost's plot was foiled. As usual, the challenges were
    interesting and set up in such a way that it was very beginner
    friendly, with lots of hints and talks to ensure that you learned
    something while solving.

-   Jan 1, 2022

    ### [Hackvent 2021](/hackvent2021)

    #ctf #hackvent #python #git #gitdumper #obfuscation #brainfuck
    #polyglot #jsfuck #de4js #python-pil #reverse-engineering #pcap
    #wireshark #nmap #content-length #ignore-content-length
    #cistercian-numerals #code-golf #type-juggling #ghidra #clara-io
    #stl #youtube #kotlin #race-condition #p-384 #eliptic-curve #signing
    #crypto

    ![](/img/hv21-cover.png)

    This year I was only able to complete 14 of the 24 days of
    challenges, but it was still a good time. I learned something about
    how web clients handle content lengths, how to obfuscate JavaScript
    for a golf competition, and exploited some neat crypto to sign
    commands for a server.

-   Dec 29, 2021

    ### [HTB: LogForge](/htb-logforge.md)

    #ctf #hackthebox #htb-logforge #nmap #uhc #jsp #jsessionid #tomcat
    #feroxbuster #apache-tomcat-parse #burp #burp-repeater #msfvenom
    #war #log4shell #log4j #jndi #ysoserial #jndi-exploit-kit
    #ysoserial-modified #jd-gui #reverse-engineering #jar #wireshark
    #ldap #uri-parsing #htb-seal #htb-pikaboo #breaking-parser-logic

    ![](/img/logforge-cover.png)

    LogForge was a UHC box that HTB created entirely focused on Log4j /
    Log4Shell. To start, there's an Orange Tsai attack against how
    Apache is hosting Tomcat, allowing the bypass of restrictions to get
    access to the manager page. From there, I'll exploit Log4j to get a
    shell as the tomcat user. With a foothold on the machine, there's an
    FTP server running as root listening only on localhost. This FTP
    server is Java based, and reversing it shows it's using Log4j to log
    usernames. I'll exploit this to leak the environment variables used
    to store the username and password needed to access the FTP server,
    and use that to get access to the root flag. The password also works
    to get a root shell. In Beyond Root I'll look at using netcat to
    read the LDAP requests and do some binary RE of LDAP on the wire.

-   Dec 18, 2021

    ### [HTB: Static](/htb-static.md)

    #ctf #htb-static #hackthebox #nmap #feroxbuster #vpn #openvpn #totp
    #fixgz #oathtool #ntp #ntpdate #route #xdebug #dbgpClient
    #htb-olympus #htb-jewel #tunnel #socks #filter #cve-2019-11043
    #webshell #format-string #htb-rope #gdb #aslr #socat #pspy
    #path-hijack #easy-rsa

    ![](/img/static-cover.png)

    Static was a really great hard box. I'll start by finding a
    corrupted gzipped SQL backup, which I can use to leak the seed for a
    TOTP 2FA, allowing me access to an internal page. There I'll get a
    VPN config, which I'll use to connect to the network and get access
    to additional hosts. There's a web host that has xdebug running on
    it's PHP page, allowing for code execution. From there, I'll pivot
    to a PKI host that I can only reach from web. I'll exploit a PHP-FPM
    bug to get a shell on there. On this box, there's a binary with
    setuid capabilities and a format string exploit, which I'll use to
    leak addresses and then overwrite the path to a binary called to
    have it run my reverse shell. In Beyond Root, I'll look at an
    unintended Path Hijack in an actual open-source program, easy-rsa.

-   Dec 11, 2021

    ### [HTB: Writer](/htb-writer.md)

    #hackthebox #ctf #htb-writer #nmap #feroxbuster #sqli #injection
    #auth-bypass #ffuf #sqlmap #burp #burp-repeater #apache #flask
    #django #command-injection #hashcat #postfix #swaks #apt #oscp-like

    ![](/img/writer-cover.png)

    Writer was really hard for a medium box. There's an SQL injection
    that provides both authentication bypass and file read on the
    system. The foothold involved either chaining togethers file uploads
    and file downloads to get a command injection, or using an SSRF to
    trigger a development site that is editable using creds found in the
    site files to access SMB. With a shell, the first pivot is using
    creds from the Django DB after cracking the hash. Then I'll inject
    into a Postfix mail filter and trigger it be sending an email.
    Finally, there's an editable apt config file that allows command
    injection as root. In beyond root, I'll show the intended path using
    the SSRF to trigger the modified dev site.

-   Dec 4, 2021

    ### [HTB: Pikaboo](/htb-pikaboo.md)

    #ctf #htb-pikaboo #hackthebox #nmap #debian #feroxbuster
    #off-by-slash #lfi #log-poisoning #perl-diamond-injection #perl
    #open-injection #open-injection-perl #ldap #ldapsearch #htb-seal
    #oscp-plus #breaking-parser-logic

    ![](/img/pikaboo-cover.png)

    Pikaboo required a lot of enumeration and putting together different
    pieces to get through each step. I'll only ever get a shell as
    www-data and root, but for each step there's several pieces to pull
    together and combine to some effect. I'll start by abusing an
    off-by-slash vulnerability in the interaction between NGINX and
    Apache to get access to a staging server. In there, I'll use an LFI
    to include FTP logs, which I can poison with PHP to get execution.
    As www-data, I'll find a cron running a Perl script as root, which
    is vulnerable to command injection via the diamond operator. I'll
    find creds for another user in LDAP and get access to FTP, where I
    can drop a file that will be read and give execution to get a shell
    as root.

-   Nov 27, 2021

    ### [HTB: Intelligence](/htb-intelligence.md)

    #ctf #htb-intelligence #hackthebox #nmap #windows #crackmapexec
    #smbmap #smbclient #smb #dns #dnsenum #ldapsearch #exiftool
    #feroxbuster #kerbrute #python #password-spray #bloodhound
    #bloodhound-python #dnstool #responder #hashcat #readgmsapassword
    #gmsa #gmsadumper #silver-ticket #wmiexec #oscp-like

    ![](/img/intelligence-cover.png)

    Intelligence was a great box for Windows and Active Directory
    enumeration and exploitation. I'll start with a lot of enumeration
    against a domain controller. Eventually I'll brute force a naming
    pattern to pull down PDFs from the website, finding the default
    password for new user accounts. Spraying that across all the users I
    enumerated returns one that works. From there, I'll find a
    PowerShell script that runs every five minutes on Intelligence that
    is making a web request to each DNS in the AD environment that
    starts with web. I'll add myself as a server, and use responder to
    capture a hash when it next runs. On cracking that hash, I'll have a
    new user, and bloodhound shows that account has control over a
    service accounts GMSA password. That service account has delegation
    on the domain. I'll exploit those relationships to get administrator
    on the box.

-   Nov 22, 2021

    ### [HTB: Union](/htb-union.md)

    #ctf #htb-union #hackthebox #uhc #nmap #sqli #filter #waf
    #feroxbuster #burp #burp-repeater #sqli-file #credentials #injection
    #command-injection #sudo #iptables

    ![](/img/union-cover.png)

    The November Ultimate Hacking Championship qualifier box is Union.
    There's a tricky-to-find union SQL injection that will allow for
    file reads, which leaks the users on the box as well as the password
    for the database. Those combine to get SSH access. Once on the box,
    I'll notice that www-data is modifying the firewall, which is a
    privileged action, using sudo. Analysis of the page source shows it
    is command injectable via the X-Forwarded-For header, which provides
    a shell as www-data. This account has full sudo rights, providing
    root access.

-   Nov 20, 2021

    ### [HTB: BountyHunter](/htb-bountyhunter.md)

    #ctf #htb-bountyhunter #hackthebox #nmap #xxe #feroxbuster #decoder
    #python #credentials #password-reuse #python-eval #command-injection

    ![](/img/bountyhunter-cover.png)

    BountyHunter has a really nice simple XXE vulnerability in a webpage
    that provides access to files on the host. With that, I can get the
    users on the system, as well as a password in a PHP script, and use
    that to get SSH access to the host. To privesc, there's a ticket
    validation script that runs as root that is vulnerable to Python
    eval injection.

-   Nov 18, 2021

    ### [RunCode Live 2021 Solutions](/runcode-live-2021-solutions.md)

    #ctf #runcode #youtube

    ![](/img/runcode.png)

    I've been posting solutions on YouTube for the RunCode Live 2021
    competition held 11-13 November 2021. This a a programming CTF, so
    I'll show how I approach various problems using mostly Python. Check
    them out, and subscribe on YouTube to get notified as I add more
    videos.

-   Nov 13, 2021

    ### [HTB: Seal](/htb-seal.md)

    #hackthebox #ctf #htb-seal #nmap #wfuzz #vhosts #nginx #tomcat
    #feroxbuster #git-bucket #off-by-slash #git #mutual-authentication
    #uri-parsing #war #msfvenom #ansible #htb-tabby #oscp-like
    #breaking-parser-logic

    ![](/img/seal-cover.png)

    In Seal, I'll get access to the NGINX and Tomcat configs, and find
    both Tomcat passwords and a misconfiguration that allows me to
    bypass the certificate-based authentication by abusing differences
    in how NGINX and Tomcat parse urls. The rest of the box is about
    Ansible, the automation platform. I'll abuse a backup playbook being
    run on a cron to get the next user. And I'll write my own playbook
    and abuse sudo to get root.

-   Nov 8, 2021

    ### [HTB: Three More PivotAPI Unintendeds](/htb-pivotapi-more.md)

    #ctf #hackthebox #htb-pivotapi #windows #mssql-shell #seimpersonate
    #efspotato #sebackupvolume #ntfscontrolfile #dcsync #secretsdump
    #rubeus #sharp-collection #kerberos #ticketconverter #ntpdate
    #crackmapexec #wmiexec

    ![](/img/pivotapi-more-cover.png)

    There were three other techniques that were used as shortcuts on
    PivotAPI that I thought were worth sharing but that I didn't have
    time to get into my original post. xct tipped me off to exploiting
    Sempersonate using EfsPotato (even after the print spooler was
    disabled), as well as abusing SeManageVolume to get full read/write
    as admin. TheCyberGeek and IppSec both showed how to abuse
    delegation to do a DCSync attack.

-   Nov 6, 2021

    ### [HTB: PivotAPI](/htb-pivotapi.md)

    #ctf #hackthebox #htb-pivotapi #nmap #windows #active-directory
    #exiftool #as-rep-roast #getuserspns #hashcat #mssql #mssqlclient
    #bloodhound #smbmap #smbclient #mbox #mutt #msgconvert
    #reverse-engineering #procmon #vbs #api-monitor #crackmapexec
    #mssql-shell #mssqlproxy #evil-winrm #keepass #genericall
    #powersploit #powerview #tunnel #dotnet #dnspy #forcechangepassword
    #laps #winpeas #powershell-run-as #cyberchef #seimpersonate
    #printspoofer #htb-safe #oscp-plus

    ![](/img/pivotapi-cover.png)

    PivotAPI had so many steps. It starts and ends with Active Directory
    attacks, first finding a username in a PDF metadata and using that
    to AS-REP Roast. This user has access to some binaries related to
    managing a database. I'll reverse them mostly with dynamic analysis
    to find the password through several layers of obfuscation,
    eventually gaining access to the MSSQL service. From there, I'll use
    mssqlproxy to tunnel WinRM through the DB, where I find a KeePass
    DB. Those creds give SSH access, where I'll then pivot through some
    vulnerable privileges to get access to a developers share. In there,
    another binary that I can use to fetch additional creds. Finally,
    after another pivot through misconfigured privileges, I'll get
    access to the LAPS password for the administrator. In Beyond Root,
    I'll show some unintended paths.

-   Nov 3, 2021

    ### [Flare-On 2021: PetTheKitty](/flare-on-2021/petthekitty)

    #flare-on #ctf #flare-on-petthekitty #reverse-engineering #youtube
    #wireshark #delta-patch #dll #ghidra #python #scapy

    ![](/img/flare2021-petthekitty-cover.png)

    PetTheKitty started with a PCAP with two streams. The first was used
    to download and run a DLL malware, and the second was the C2
    communications of that malware. The malware and the initial
    downloader user Windows Delta patches to exchange information. I'll
    reverse the binary to understand the algorithm and decode the
    reverse shell session to find the flag.

-   Nov 2, 2021

    ### [HTB: Nunchucks](/htb-nunchucks.md)

    #hackthebox #ctf #htb-nunchucks #uhc #nmap #wfuzz #vhosts
    #feroxbuster #ssti #express #express-nunchucks #capabilities
    #gtfobins #apparmor

    ![](/img/nunchucks-cover.png)

    October's UHC qualifying box, Nunchucks, starts with a template
    injection vulnerability in an Express JavaScript application. There
    are a lot of templating engines that Express can use, but this one
    is using Nunchucks. After getting a shell, there's what looks like a
    simple GTFObins privesc, as the Perl binary has the setuid
    capability. However, AppArmor is blocking the simple exploitation,
    and will need to be bypassed to get a root shell.

-   Nov 1, 2021

    ### [Flare-On 2021: known](/flare-on-2021/known)

    #flare-on #ctf #flare-on-known #reverse-engineering #youtube #crypto
    #ghidra #python

    ![](/img/flare2021-known-cover.png)

    known presented a ransomware file decrypter, as well as a handful of
    encrypted files. If I can figure out the key to give the decrypter,
    it will decrypt the files, one of which contains the flag. I'll use
    Ghidra to determine the algorithm, then recreate it in Python, and
    brute force all possible keys to find the right one.

-   Oct 30, 2021

    ### [HTB: Explore](/htb-explore.md)

    #ctf #hackthebox #htb-explore #nmap #android #adb #es-file-explorer
    #cve-2019-6447 #credentials #tunnel

    ![](/img/explore-cover.png)

    Explore is the first Android box on HTB. There's a relatively simple
    file read vulnerability in ES File Explorer that allows me to read
    images off the phone, including one with a password in it. With that
    password I'll SSH into the phone, and access the Android debug (adb)
    service, where I can easily get a shell as root.

-   Oct 29, 2021

    ### [Flare-On 2021: myaquaticlife](/flare-on-2021/myaquaticlife)

    #flare-on #ctf #flare-on-myaquaticlife #reverse-engineering #upx
    #multimedia-builder #mmunbuilder #x64dbg #ghidra #python #bruteforce

    ![](/img/flare2021-myaquaticlife-cover.png)

    myaquaticlife was a Windows exe built on a really old multimedia
    framework, Multimedia Builder. I'll use a project on Github to
    decompile it back to the framework file, and look at it in the
    original software. There's a DLL used as a plugin that tracks the
    order of clicks on fish, and I can figure out the order to click and
    get the flag.

-   Oct 28, 2021

    ### [Flare-On 2021: beelogin](/flare-on-2021/beelogin)

    #flare-on #ctf #flare-on-beelogin #reverse-engineering #javascript
    #jsfuck #de4js #python #bruteforce #deobfuscation

    ![](/img/flare2021-beelogin-cover.png)

    beelogin starts with a simple HTML page with five input fields.
    Diving into the source, there's almost sixty thousand lines of
    JavaScript. The vast majority of that ends up being junk that isn't
    run. I'll trim it down to around 30 lines. Then there's some math to
    track where each of 64 bytes in the key impact which bytes of the
    result. Once I have that, I can check for bytes that produce valid
    JavaScript, and find the key. The result is some obfuscated
    JavaScript that comes out to be doing the same thing again, on the
    second half of the key. Once I have both halves, I can get the flag
    or put the key in and get the page to give it to me.

-   Oct 27, 2021

    ### [Flare-On 2021: flarelinuxvm](/flare-on-2021/flarelinuxvm)

    #flare-on #ctf #flare-on-flarelinuxvm #reverse-engineering #vm
    #cyberchef #encoding #crypto #ghidra #ransomware #youtube

    ![](/img/flare2021-flarelinuxvm-cover.png)

    Flare Linux VM starts with a VM and some ransomware encrypted files.
    I'll have to triage, find the malware, and reverse it to understand
    that it's using a static key stream to encrypted the files. With
    that stream, I can decrypt and get the files, which provide a series
    of CTF puzzles to get a password which I can give to the binary and
    get the final flag.

-   Oct 26, 2021

    ### [HTB: Spooktrol](/htb-spooktrol.md)

    #htb-spooktrol #ctf #hackthebox #nmap #api #fastapi #python
    #feroxbuster #reverse-engineering #wireshark #ghidra #burp
    #burp-proxy #upload #sqlite #uhc

    ![](/img/spooktrol-cover.png)

    spooktrol is another UHC championship box created by IppSec. It's
    all about attacking a malware C2 server, which have a long history
    of including silly bugs in them. In this one, I'll hijack the
    tasking message and have it upload a file, which, using a directory
    traversal bug, allows me to write to root's authorized keys file on
    the container. Then, I'll exploit the C2's database to write a task
    to another agent and get a shell on that box. In Beyond Root, I'll
    look at an unintended directory traversal vulnerability in the
    implant download.

-   Oct 25, 2021

    ### [Flare-On 2021: spel](/flare-on-2021/spel)

    #flare-on #ctf #flare-on-spel #reverse-engineering #ghidra #unpack
    #shellcode #dll #x64dbg #anti-debug

    ![](/img/flare2021-spel-cover.png)

    spel was a Russian nesting doll of binaries. It starts with a giant
    function that has thousands move instructions setting a single byte
    at a time into a buffer and then calling it. That buffer is
    shellcode that loads and calls a DLL. That DLL loads and calls a
    function from a second DLL. In that DLL, there are a series of
    checks that cause the program to exit (different file name, network
    connection), before the flag bytes are eventually decoded from a PNG
    resource in the original binary, and then scrambled into an order
    only observable in debug.

-   Oct 24, 2021

    ### [Flare-On 2021: antioch](/flare-on-2021/antioch)

    #flare-on #ctf #flare-on-antioch #reverse-engineering #docker
    #docker-tar #python #ghidra #hackvent

    ![](/img/flare2021-antioch-cover.png)

    antioch was a challenge based on the old movie, Monty Python and the
    Holy Grail. I'm given a Tar archive, which is a Docker image, the
    output of a command like `docker save`. It has a lot of layer data,
    but most the layers are not referenced in the manifest. The image
    does have a single ELF executable in it. Though reversing this
    binary, I'll see how it expects input matching the various authors
    from the metadata in the unused layers, and how each author has an
    id associated with it. I'll use the order of those IDs to
    reconstruct the Docker image to include the files in the right
    order, and then the new image will give the flag.

-   Oct 23, 2021

    ### [HTB: Spider](/htb-spider.md)

    #hackthebox #htb-spider #ctf #nmap #flask #python #flask-cookie
    #payloadsallthethings #ssti #jinja2 #injection #sqli #sqlmap
    #sqlmap-eval #ssti-blind #waf #filter #tunnel #xxe

    ![](/img/spider-cover.png)

    Spider was all about classic attacks in unusual places. There's a
    limited SSTI in a username that allows me to leak a Flask secret.
    I'll use that to generate Flask cookies with SQL injection payloads
    inside to leak a user id, and gain admin access on the site. From
    there, another SSTI, but this time blind, to get RCE and a shell.
    For root, there's a XXE in a cookie that allows me to leak the final
    flag as well as the root ssh key.

-   Oct 22, 2021

    ### [Flare-On 2021: wizardcult](/flare-on-2021/wizardcult)

    #flare-on #ctf #flare-on-wizardcult #reverse-engineering #go #python
    #youtube #crypto #ghidra #irc #inspircd #c2

    ![](/img/flare2021-wizardcult-cover.png)

    The last challenge in Flare-On 8 was probably not harder than the
    ninth one, but it might have been the one I had the most fun
    attacking. In a mad rush to finish on time, I didn't take great
    notes, so instead, I went back and solved it start to finish on
    YouTube.

-   Oct 22, 2021

    ### [Flare-On 2021: credchecker](/flare-on-2021/credchecker)

    #flare-on #ctf #flare-on-credchecker #reverse-engineering .md
    #javascript #python #youtube

    ![](/img/flare2021-credchecker-cover.png)

    Flare-On 8 got off to an easy start with an HTML page and a login
    form. The page has JavaScript to accept and check the password, and
    I'll show two ways to get the flag - pulling the password and then
    logging in, and decrypting the flag buffer.

-   Oct 16, 2021

    ### [HTB: Dynstr](/htb-dynstr.md)

    #hackthebox #ctf #htb-dynstr #nmap #dynamic-dns #no-ip #feroxbuster
    #dnsenum #command-injection #injection #cyberchef #scriptreplay #dns
    #nsupdate #authorized-keys #wildcard #php #bash #passwd #oscp-plus

    ![](/img/dynstr-cover.png)

    Dynstr was a super neat concept based around a dynamic DNS provider.
    To start, I'll find command injection in the DNS / IP update API.
    Then I'll find a private key in a script replay of a debugging
    session and strace logs. I'll also need to tinker with the DNS
    resolutions to allow myself to connect over SSH, as the
    authorized_keys file has restrictions in it. For root, there's a
    simple wildcard injection into a script I can run as root, and I'll
    show two ways to exploit that. In Beyond Root, a break down of the
    DNS API, and a look at an unintended flag leak and a dive into Bash
    variables and number comparisons.

-   Oct 9, 2021

    ### [HTB: Monitors](/htb-monitors.md)

    #ctf #htb-monitors #hackthebox #nmap #vhosts #wordpress #wpscan
    #wp-with-spritz #sqli #injection #exploitdb #password-reuse #lfi
    #apache-config #cacti #cve-2020-14295 #python #systemd #crontab
    #docker #feroxbuster #solr #cve-2020-9496 #ysoserial #docker-escape
    #kernel-module #oscp-plus

    ![](/img/monitors-cover.png)

    Monitors starts off with a WordPress blog that is vulnerable to a
    local file include vulnerability that allows me to read files from
    system. In doing so, I'll discover another virtual host serving a
    vulnerable version of Cacti, which I'll exploit via SQL injection
    that leads to code execution. From there, I'll identify a new
    service in development running Apache Solr in a Docker container,
    and exploit that to get into the container. The container is running
    privilieged, which I'll abuse by installing a malicious kernel
    module to get access as root on the host.

-   Oct 2, 2021

    ### [HTB: Cap](/htb-cap.md)

    #htb-cap #hackthebox #ctf #nmap #pcap #idor #feroxbuster #wireshark
    #credentials #capabilities #linpeas

    ![](/img/cap-cover.png)

    Cap provided a chance to exploit two simple yet interesting
    capabilities. First, there's a website with an insecure direct
    object reference (IDOR) vulnerability, where the site will collect a
    PCAP for me, but I can also access other user's PCAPs, to include
    one from the user of the box with their FTP credentials, which also
    provides SSH access as that user. With a shell, I'll find that in
    order for the site to collect pcaps, it needs some privileges, which
    are provided via Linux capabilities, including one that I'll abuse
    to get a shell as root.

-   Sep 27, 2021

    ### [HTB: Jarmis](/htb-jarmis.md)

    #ctf #hackthebox #htb-jarmis #ja3 #ja3s #jarm #tls #nmap #vhosts
    #ncat #feroxbuster #fastapi #ssrf #wfuzz #jq #metasploit
    #msf-custom-module #iptables #omigod #cve-2021-38647 #python #flask
    #gopher #code-review #htb-laser #htb-travel #uhc

    ![](/img/jarmis-cover.png)

    My favorite part about Jarmis was that it is centered around this
    really neat technology used to fingerprint and identify TLS servers.
    There's an application that will scan a given server and report back
    the Jarm signature, and if that signature matches something
    potentially malicious in the database, it will do a GET request to
    that server to collect additional metadata. I'll abuse that service
    to get a list of open ports on localhost and find 5985/5986, which
    are typically WinRM. Given that Jarmis is a Linux host, it's odd,
    and it turns out that this is the same port that OMI listens to, and
    the host is vulnerable to OMIGod. To exploit this, I'll find a POC
    and convert it into a Gopher redirect by redirecting the GET
    request. I'll need to create a malicious server as well, and I'll
    show two ways, using IPTables and a custom Metasploit module. In
    Beyond Root, I'll look at the webserver config, and find the error
    in the public Jarm code that allowed me to use Jarm as a port
    scanner.

-   Sep 25, 2021

    ### [HTB: Pit](/htb-pit.md)

    #ctf #htb-pit #hackthebox #centos #nmap #udp #snmp #feroxbuster
    #snmpwalk #seeddms #cve-2019-12744 #exploitdb #webshell #upload
    #selinux #cockpit #htb-sneaky #getfacl #facl #oscp-like

    ![](/img/pit-cover.png)

    Pit used SNMP in two different ways. First, I'll enumerate it to
    leak the location of a webserver running SeedDMS, where I'll abuse a
    webshell upload vulnerability to get RCE on the host. I'm not able
    to get a reverse shell because of SeLinux, but I can enumerate
    enough to find a password for michelle, and use that to get access
    to a Cockpit instance which offers a terminal. From there, I'll find
    that I can write scripts that will be run by SNMP, and I'll use that
    to get execution and a shell as root. In Beyond Root, a look at
    SeLinux and how it blocked things I tried to do on Pit.

-   Sep 18, 2021

    ### [HTB: Sink](/htb-sink.md)

    #htb-sink #hackthebox #ctf #nmap #gitea #haproxy #gunicorn
    #request-smuggling #localstack #aws #aws-secretsmanager #aws-kms
    #iptables #htb-bucket #htb-gobox #git

    ![](/img/sink-cover.png)

    Sink was an amazing box touching on two major exploitation concepts.
    First is the request smuggling attack, where I send a malformed
    packet that tricks the front-end server and back-end server
    interactions such that the next user's request is handled as a
    continuation of my request. After that, I'll find a AWS instance
    (localstack) and exploit various services in that, including secrets
    manager and the key management. In Beyond Root, I'll look at the way
    this box was configured to allow for multiple users to do request
    smuggling at the same time.

-   Sep 14, 2021

    ### [HTB: Validation](/htb-validation.md)

    #ctf #htb-validation #hackthebox #uhc #nmap #cookies #feroxbuster
    #burp #burp-repeater #sqli #injection #second-order-sqli #python
    #python-cmd #sqli-file #webshell #password-reuse #credentials

    ![](/img/validation-cover.png)

    Validation is another box HTB made for the UHC competition. It is a
    qualifier box, meant to be easy and help select the top ten to
    compete later this month. Once it was done on UHC, HTB makes it
    available. In this box, I'll exploit a second-order SQL injection,
    write a script to automate the enumeration, and identify the SQL
    user has FILE permissions. I'll use that to write a webshell, and
    get execution. For root, it's simple password reuse from the
    database. In Beyond Root, I'll look at how this box started and
    ended in a container.

-   Sep 11, 2021

    ### [HTB: Schooled](/htb-schooled.md)

    #ctf #htb-schooled #hackthebox #nmap #moodle #feroxbuster #wfuzz
    #vhosts #cve-2020-25627 #cve-2020-14321 #moodle-plugin #webshell
    #password-reuse #credentials #hashcat #pkg #freebsd #package
    #htb-teacher

    ![](/img/schooled-cover.png)

    Schooled starts with a string of exploits to gain more and more
    privilege in a Moodle instance, eventually leading to a malicious
    plugin upload that provides a webshell. I'll pull some hashes from
    the DB and crack them to get to the next user. This user can run the
    FreeBSD package manager, pkg, as root, and can also write to the
    hosts file. I'll trick it into connecting to my VM, and give it a
    malicious package that provide root. In Beyond Root, I'll look at
    the Moodle plugin a bit more in depth.

-   Sep 4, 2021

    ### [HTB: Unobtainium](/htb-unobtainium.md)

    #hackthebox #ctf #htb-unobtainium #nmap #kubernetes #deb #package
    #electron #nodejs #lfi #prototype-pollution #command-injection
    #injection #asar #sans-holiday-hack #htb-onetwoseven #source-code
    #kubectl

    ![](/img/unobtainium-cover.png)

    Unobtainium was the first box on HackTheBox to play with Kubernetes,
    a technology for deploying and managing containers. It also has a
    Electron application to reverse, which allows for multiple exploits
    against the server, first local file include, then prototype
    pollution, and finally command injection. With a shell, I'll find a
    way to gain admin access over Kubernetes and get root with a
    malicious container.

-   Aug 30, 2021

    ### [HTB: Gobox](/htb-gobox.md)

    #hackthebox #htb-gobox #ctf #uhc #nmap #ubuntu #go #ssti
    #feroxbuster #youtube #python #python-cmd #aws #awscli #docker #s3
    #webshell #upload #nginx-module #backdoor #nginxexecute

    ![](/img/gobox-cover.png)

    HackTheBox made Gobox to be used in the Hacking Esports UHC
    competition on Aug 29, 2021. Once the competition is over, HTB put
    it out for all of us to play. This is neat box, created by IppSec,
    where I'll exploit a server-side template injection vulnerability in
    a Golang webserver to leak creds to the site, and then the full
    source. I'll use the source with the SSTI to get execution, but no
    shell. I'll write a script to make enumeration easy, and then
    identify the host is in AWS, and is managing a bucket the hosts
    another site. I'll upload a PHP webshell to get a shell on the main
    host. Finally, I'll find a backdoor NGINX module which is enabled,
    reverse it to get execution, and get a shell as root.

-   Aug 28, 2021

    ### [HTB: Knife](/htb-knife.md)

    #ctf #hackthebox #htb-knife #nmap #php-backdoor #feroxbuster
    #php-8.1.0-dev #sudo #knife #gtfobins #vim #oscp-like

    ![](/img/knife-cover.png)

    Knife is one of the easier boxes on HTB, but it's also one that has
    gotten significantly easier since it's release. I'll start with a
    webserver that isn't hosting much of a site, but is leaking that
    it's running a dev version of PHP. This version happens to be the
    version that had a backdoor inserted into it when the PHP
    development servers were hacked in March 2021. At the time of
    release, just searching for this version string didn't immediately
    lead to the backdoor, but within two days of release it did. For
    root, the user can run knife as root. At the time of release, there
    was no GTFObins page for knife, so the challenge required reading
    the docs to find a way to run arbitrary code. That page now exists.

-   Aug 27, 2021

    ### [Pivoting off Phishing Domain](/pivoting-off-phishing-domain.md)

    #forensics #threat-intel #phishing #riskiq #maltego #youtube

    ![](/img/image-20210827040428323.png)

    John Hammond YouTube channel is full of neat stuff, from CTF
    solutions to real malware analysis. Recently, he did an analysis of
    an email with an HTML attachment which presented as a fake Microsoft
    login page. When a victim enters creds, the page would send them to
    www.hurleyauctions\[.\]us, and redirect the user to an actual
    Microsoft Outlook site. John looked at bit at the registration
    information on the domain, but I wanted to dive a bit deeper,
    specifically using RiskIQ and Maltego.

-   Aug 21, 2021

    ### [HTB: Proper](/htb-proper.md)

    #ctf #htb-proper #hackthebox #nmap #windows #iis #gobuster #ajax
    #sqlmap #sqli #keyed-hash #sqli-orderby #sqlmap-eval #hashcat #lfi
    #rfi #time-of-check-time-of-use #inotifywait #go #ida #ghidra
    #arbitrary-write #reverse-engineering #file-read #wertrigger
    #pipe-monitor #powershell #named-pipe #cve-2021-1732 #htb-hackback
    #htb-scriptkiddie

    ![](/img/proper-cover.png)

    Proper was a fascinating Windows box with three fascinating stages.
    First, there's a SQL injection, but the url parameters are hashed
    with a key, so I need to leak that key, and then make sure to update
    the hash for each request. I get to play with the eval option for
    SQLmap, as well as show some manual scripting to do it. Next,
    there's a time of check / time of use vulnerability in a file
    include that allows me to do a remote file include over SMB,
    swapping out the contents between the first and second read to get
    code execution. For root, there's a Go binary that does cleanup of
    files in the users Downloads folder that I can abuse to get
    arbitrary write as SYSTEM. I'll abuse this with the windows error
    reporting system to get execution. In Beyond Root, I'll look at a
    couple more ways to get root using this binary.

-   Aug 14, 2021

    ### [HTB: CrossFitTwo](/htb-crossfittwo.md)

    #hackthebox #ctf #htb-crossfittwo #nmap #openbsd #feroxbuster #burp
    #websocket #sqli #injection #vhosts #unbound #python #python-cmd
    #flask #sqlmap #relayd #api #wfuzz #cors #phishing #socket-io
    #javascript #nodejs #node-modules #yubikey #changelist #ykgenerate
    #htb-crossfit

    ![](/img/crossfittwo-cover.png)

    Much like CrossFit, CrossFitTwo was just a monster of a box. The
    centerpiece is a crazy cross-site scripting attack through a
    password reset interface using DNS to redirect the admin to a site I
    control to then have them register an account for me. I'll then
    hijack some socket.io messages to get access to chats where I'll
    capture a password to get a shell. On the box, I'll abuse NodeJS's
    module load order, then extract the root ssh key from a changelist
    backup and the yubikey seed needed to get SSH as root.

-   Aug 7, 2021

    ### [HTB: Love](/htb-love.md)

    #hackthebox #ctf #htb-love #nmap #vhosts #voting-system
    #searchsploit #feroxbuster #ssrf #burp #webshell #upload #winpeas
    #alwaysinstallelevated #msi #htb-ethereal #msfvenom #oscp-like

    ![](/img/love-cover.png)

    Love was a solid easy-difficulty Windows box, with three stages.
    First, I'll use a simple SSRF to get access to a webpage that is
    only allowed to be viewed from localhost that leaks credentials for
    a Voting System instance. Then, I'll exploit an upload vulnerability
    in Voting System to get RCE, showing both using the searchsploit
    script and manual exploitation. Finally, I'll abuse the
    AlwaysInstallElevated setting to get a system shell.

-   Jul 31, 2021

    ### [HTB: TheNotebook](/htb-thenotebook.md)

    #ctf #htb-thenotebook #hackthebox #nmap #feroxbuster #jwt #jwt-io
    #upload #webshell #cve-2019-5736 #runc #docker #go

    ![](/img/thenotebook-cover.png)

    TheNotebook starts off with a website where I'll abuse a JWT
    misconfiguration to convince the server to validate my token using a
    key hosted on my server. From there, I'll get access to a site where
    I can upload a PHP webshell and get execution. After finding an SSH
    key in a backup, I'll exploit a vulnerability in runc, the
    executable that underlies Docker to get execution as the root user
    in the host.

-   Jul 24, 2021

    ### [HTB: Armageddon](/htb-armageddon.md)

    #hackthebox #htb-armageddon #ctf #nmap #ubuntu #drupal
    #drupalgeddon2 #searchsploit #webshell #upload #hashcat #mysql #sudo
    #snap #snapcraft #burp #oscp-like

    ![](/img/armageddon-cover.png)

    Argageddon was a box targeted at beginners. The foothold exploit,
    Drupalgeddon2 has many public exploit scripts that can be used to
    upload a webshell and run commands. I'll get access to the database
    and get the admin's hash, crack it, and find that password is reused
    on the host as well. To get root, I'll abuse the admin's ability to
    install snap packages as root.

-   Jul 17, 2021

    ### [HTB: Breadcrumbs](/htb-breadcrumbs.md)

    #ctf #htb-breadcrumbs #hackthebox #nmap #gobuster #burp #python
    #cookies #jwt #upload #webshell #defender #password-reuse #tunnel
    #stickynotes #sqlite #ghidra #chisel #sqli #injection #cyberchef
    #aes #crypto #htb-buff #oscp-plus

    ![](/img/breadcrumbs-cover.png)

    Breadcrumbs starts with a fair amount of web enumeration and working
    to get little bits of additional access. First I'll leak the page
    source with a directory traversal vulnerability, and use that to get
    the algorithms necessary to forge both a session cookie and a JWT
    token. With both of those cookies, I gain administrator access to
    the site, and can upload a webshell after bypassing some filtering
    and Windows Defender. I'll find the next user's data in the website
    files. I'll find another password in Sticky Notes data, and use that
    to get access to a new password manager under development. To get to
    administrator, I'll exploit a SQL injection in the password manager
    to get the encrypted password and the key material to decrypt it,
    providing the admin password.

-   Jul 10, 2021

    ### [HTB: Atom](/htb-atom.md)

    #ctf #htb-atom #hackthebox #nmap #xampp #redis #reverse-engineering
    #portable-kanban #smbmap #smbclient #crackmapexec #feroxbuster #asar
    #nodejs #electron #wireshark #msfvenom #cyberchef #printnightmare
    #invoke-nightmare #cve-2021-34527 #htb-sharp #oscp-plus

    ![](/img/atom-cover.png)

    Atom was a box that involved insecure permissions on an update
    server, which allowed me to write a malicious payload to that server
    and get execution when an Electron App tried to update from my host.
    I'll reverse the electron app to understand the tech, and exploit it
    to get a shell. For root, I'll have to exploit a Portable-Kanban
    instance which is using Redis to find a password. In Beyond Root, a
    quick visit back to PrintNightmare.

-   Jul 8, 2021

    ### [Playing with PrintNightmare](/playing-with-printnightmare.md)

    #hackthebox #htb-heist #cve-2021-1675 #cve-2021-34527
    #printnightmare #evil-winrm #invoke-nightmare #sharpprintnightmare
    #dll #samba #visual-studio #htb-hackback

    ![](/img/printnightmare-cover.png)

    CVE-2021-34527, or PrintNightmare, is a vulnerability in the Windows
    Print Spooler that allows for a low priv user to escalate to
    administrator on a local box or on a remote server. This is
    especially bad because it is not uncommon for Domain Controllers to
    have an exposed print spooler, and thus, this exploit can take an
    attacker from low-priv user to domain admin. There are a few proof
    of concept exploits out there, and I wanted to give them a spin an
    old HackTheBox machine. I'll also look at disabling the Print
    Spooler and how it breaks the exploits, and discuss the July 6
    patch.

-   Jul 3, 2021

    ### [HTB: Ophiuchi](/htb-ophiuchi.md)

    #htb-ophiuchi #hackthebox #ctf #nmap #ubuntu #yaml #tomcat #java
    #jar #deserialization #gobuster #marshalsec #yaml-payload #wasm
    #wasm-fiddle #webassembly #htb-ropetwo #oscp-like

    ![](/img/ophiuchi-cover.png)

    Ophiuchi presented two interesting attacks. First there was a Java
    YAML deserialization attack that involved generating a JAR payload
    to inject via a serialized payload. Then there was a somewhat
    contrived challenge that forced me to generate web assembly (or
    WASM) code to get execution of a Bash script.

-   Jun 26, 2021

    ### [HTB: Spectra](/htb-spectra.md)

    #hackthebox #ctf #htb-spectra #nmap #chromeos #nano #wordpress
    #wpscan #wordpress-plugin #credentials #password-reuse
    #autologon-credentials #initctl #sudo

    ![](/img/spectra-cover.png)

    Spectra was the first ChromeOS box on HackTheBox. I'll start looking
    at a web server and find a password as well as a WordPress site. The
    password gets me into the admin panel, where I can edit a plugin or
    write a new plugin to get execution. From there I'll find auto-login
    credentials and use them to get a shell as the next user. That user
    can control the init daemon with sudo, which I'll abuse to get root.

-   Jun 19, 2021

    ### [HTB: Tentacle](/htb-tentacle.md)

    #hackthebox #htb-tentacle #ctf #nmap #dig #dns #dnsenum #vhosts
    #kerbrute #kerberos #ntpdate #squid #as-rep-roast #john #proxychains
    #nmap-over-proxy #wpad #opensmtpd #exploitdb #cve-2020-7247 #msmtprc
    #credentials #password-reuse #kinit #keytab #klist #htb-unbalanced
    #htb-joker #getfacl #facl

    ![](/img/tentacle-cover.png)

    Tentacle was a box of two halves. The start is all about a squid
    proxy, and bouncing through two one them (one of them twice) to
    access an internal network, where I'll find a wpad config file that
    alerts me to another internal network. In that second network, I'll
    exploit an OpenSMTPd server and get a foothold. The second half was
    about abusing Kerberos in a Linux environment. I'll use creds to get
    SSH authenticated by Kerberos, then abuse a backup script that give
    that principle access as another user. That user can access the
    KeyTab file, which allows them to administer the domain, and
    provides root access. In Beyond Root, a dive too deep into the
    rabbit hole of understanding the KeyTab file.

-   Jun 16, 2021

    ### [HTB: Enterprise](/htb-enterprise.md)

    #htb-enterprise #hackthebox #ctf #nmap #docker #ubuntu #debian
    #wordpress #joomla #wpscan #feroxbuster #wordpress-plugin #sqli
    #sqlmap #error-based-sqli #password-reuse #webshell #xinetd #bof
    #ret2libc #ltrace #ghidra #pattern #checksec #gdb #peda #pwntools
    #python #htb-frolic

    ![](/img/enterprise-cover.png)

    To own Enterprise, I'll have to work through different containers to
    eventually reach the host system. The WordPress instance has a
    plugin with available source and a SQL injection vulnerability. I'll
    use that to leak creds from a draft post, and get access to the
    WordPress instance. I can use that to get RCE on that container, but
    there isn't much else there. I can also use those passwords to
    access the admin panel of the Joomla container, where I can then get
    RCE and a shell. I'll find a directory mounted into that container
    that allows me to write a webshell on the host, and get RCE and a
    shell there. To privesc, I'll exploit a service with a simple buffer
    overflow using return to libc. In Beyond Root, I'll dig more into
    the Double Query Error-based SQLI.

-   Jun 12, 2021

    ### [HTB: Tenet](/htb-tenet.md)

    #ctf #hackthebox #htb-tenet #nmap #gobuster #vhosts #wordpress
    #wpscan #php #deserialization #php-deserialization #webshell
    #password-reuse #credentials #race-condition #bash

    ![](/img/tenet-cover.png)

    Tenet provided a very straight-forward deserialization attack to get
    a foothold and a race-condition attack to get root. Both are the
    kinds of attacks seem more commonly on hard- and insane-rated boxes,
    but at a medium difficult here.

-   Jun 8, 2021

    ### [HTB: Node](/htb-node.md)

    #htb-node #hackthebox #ctf #nmap #express #nodejs #feroxbuster
    #crackstation #john #source-code #password-reuse #bof #ret2libc
    #mongo #ltrace #ghidra #pattern-create #checksec #aslr
    #aslr-bruteforce #exploit #command-injection #filter #wildcard

    ![](/img/node-cover.png)

    Node is about enumerating a Express NodeJS application to find an
    API endpoint that shares too much data., including user password
    hashes. To root the box, there's a simple return to libc buffer
    overflow exploit. I had some fun finding three other ways to get the
    root flag, as well as one that didn't work out.

-   Jun 5, 2021

    ### [HTB: ScriptKiddie](/htb-scriptkiddie.md)

    #ctf #htb-scriptkiddie #hackthebox #nmap #searchsploit #msfvenom
    #cve-2020-7384 #msfconsole #command-injection #injection #incron
    #irb #oscp-like

    ![](/img/scriptkiddie-cover.png)

    ScriptKiddie was the third box I wrote that has gone live on the
    HackTheBox platform. From the time I first heard about the command
    injection vulnerability in msfvenom, I wanted to make a box themed
    around a novice hacker and try to incorporate it. To own this box,
    I'll find the website which has a few tools for a hacker might use,
    including an option to have msfvenon create a payload. I'll upload a
    malicious template and get code execution on the box. From there,
    I'll exploit a cron with another command injection to reach the next
    user. Finally, to root, I'll abuse the sudo rights of that user to
    run msfconsole as root, and use the built in shell commands to get a
    root shell. In Beyond Root, a look at some of the automations I put
    in place for the box.

-   May 31, 2021

    ### [Cereal Unintended Root](/htb-cereal-unintended.md)

    #ctf #hackthebox #htb-cereal #dotnet #iis #timing-attack

    ![](/img/cereal-unintended-cover.png)

    There's a really neat unintended path to root on Cereal discovered
    by HackTheBox user FF5. The important detail to notice is that a
    shell as sonny running via a webshell has additional groups related
    to IIS that don't show up in an SSH shell. I can use these groups to
    exploit the IIS service and how it manages the website running as
    root with a timing attack that will allow me to slip my own code
    into the site and execute it. I'll find the directory where IIS
    stages files and compiles them, the Shadow Copy Folders. I'll delete
    everything in there, and trigger IIS to rebuilt. It will copy the
    source into the directory and compile it, but there's a chance for
    me to modify the source between the copy and the compile.

-   May 29, 2021

    ### [HTB: Cereal](/htb-cereal.md)

    #ctf #hackthebox #htb-cereal #nmap #iis #windows #vhosts #wfuzz
    #feroxbuster #react #dotnet #csharp #git #gitdumper #source-code
    #jwt #python #javascript #visual-studio #ssrf #xss #deserialization
    #json-deserialization #npm #npm-audit #react-marked-markdown
    #webshell #aspx #roguepotato #potato #sweetpotato #printspoofer
    #graphql #graphql-voyager #graphql-playground #jq #ssrf
    #genericpotato #htb-hackback #htb-travel #htb-dyplesher

    ![](/img/cereal-cover.png)

    Cereal was all about takign attacks I've done before, and breaking
    the ways I've previously done them so that I had to dig deeper and
    really understand them. I'll find the source for a website on an
    exposed Git repo. The site is built in C#/.NET on the backend, and
    React JavaScript on the client side. I'll first have to find the
    code that generates authentication tokens and use that to forge a
    token that gets me past the login. There I have access to a form
    that can submit cereal flavor requests. I'll chain together a
    cross-site scripting vulnerability and a deserialization
    vulnerability to upload a webshell. That was made more tricky
    because the serverside code had logic in place to break payloads
    generated by YSoSerial. With execution, I'll find the first user
    password and get SSH access. That user has SeImpersonate. But with
    no print spooler service on the box, and no outbound TCP port 135,
    neither RoguePotato, SweetPotato, or PrintSpoofer could abuse it to
    get a SYSTEM shell. I'll enumerate a site running on localhost and
    its GraphQL backend to find a serverside request forgery
    vulnerability, which I'll abuse with GenericPotato to get a shell as
    System.

-   May 25, 2021

    ### [HTB: Shocker](/htb-shocker.md)

    #htb-shocker #hackthebox #ctf #nmap #feroxbuster #cgi #shellshock
    #bashbug #burp #cve-2014-6271 #gtfobin

    ![](/img/shocker-cover.png)

    The name Shocker gives away pretty quickly what I'll need to do on
    this box. There were a couple things to look out for along the way.
    First, I'll need to be careful when directory brute forcing, as the
    server is misconfigured in that the cgi-bin directory doesn't show
    up without a trailing slash. This means that tools like gobuster and
    feroxbuster miss it in their default state. I'll show both manually
    exploiting ShellShock and using the nmap script to identify it is
    vulnerable. Root is a simple GTFObin in perl. In Beyond Root, I'll
    look at the Apache config and go down a rabbit hole looking at what
    commands cause execution to stop in ShellShock and try to show how I
    experimented to come up with a theory that seems to explain what's
    happening.

-   May 22, 2021

    ### [HTB: Delivery](/htb-delivery.md)

    #ctf #hackthebox #htb-delivery #nmap #vhosts #osticket #mattermost
    #password-reuse #mysql #hashcat #hashcat-rules #oscp-like

    ![](/img/delivery-cover.png)

    Delivery is a easy-rated box that I found very beginner friendly. It
    didn't require anything technically complex, but rather a bit of
    creative thinking. The box presents a helpdesk and an instance of
    Mattermost. By creating a ticket at the helpdesk, I get an email
    that I can use to update the ticket. I'll use that email to register
    a Mattermost account, where I find internal conversations that
    include creds for SSH. With access to the box, I'll check out the
    database and dump the root password hash. Using hashcat rules
    mentioned in the Mattermost chat, I'll crack that password, which is
    the root password on the box.

-   May 19, 2021

    ### [HTB: Kotarak](/htb-kotarak.md)

    #htb-kotarak #ctf #hackthebox #nmap #tomcat #feroxbuster #ssrf
    #msfvenom #war #container #lxc #ntds #secretsdump #wget
    #cve-2016-4971 #authbind #disk #lvm #htb-nineveh #htb-jerry
    #htb-tabby

    ![](/img/kotarak-cover.png)

    Kotarak was an old box that I had a really fun time replaying for a
    writeup. It starts with an SSRF that allows me to find additional
    webservers on ports only listening on localhost. I'll use that to
    leak a Tomcat config with username and password, and upload a
    malicious war to get a shell. From there, I can access files from an
    old Windows pentest to include an ntds.dit file and a system hive.
    That's enough to dump a bunch of hashes, one of which cracks and
    provides creds I can use to get the next user. The root flag is
    actually in a container that is using Wget to request a file every
    two minutes. It's an old vulnerable version, and a really neat
    exploit that involves sending a redirect to an FTP server and using
    that to write a malicious config file in the root home directory in
    the container. I'll also show an alternative root abusing the user's
    disk group to exfil the entire root filesystem and grab the flag on
    my local system.

-   May 17, 2021

    ### [Digging into cgroups Escape](/digging-into-cgroups.md)

    #ctf #hackthebox #htb-ready #docker #container #cgroups #escape
    #overlayfs #release-agent

    ![](/img/ready-cgroups-cover.png)

    The method I used in Ready to get code execution on the host system
    from a docker container running as privileged was a series of bash
    commands that didn't make any sense on first glance. I wanted to
    dive into them and see what was happening under the hood.

-   May 15, 2021

    ### [HTB: Ready](/htb-ready.md)

    #ctf #htb-ready #hackthebox #nmap #ubuntu #gitlab #cve-2018-19571
    #ssrf #cve-2018-19585 #crlf-injection #burp #redis #docker
    #container #escape #docker-privileged #cgroups #oscp-like

    ![](/img/ready-cover.png)

    Ready was another opportunity to abuse CVEs in GitLab to get a
    foothold in a GitLab container. Within that container, I'll find
    some creds that will escalate to root. I'll also notice that the
    container is run with the privileged flag, which gives it a lot of
    power with respect to the host system. I'll show two ways to abuse
    this, using cgroups and just accessing the host filesystem.

-   May 11, 2021

    ### [HTB: Blue](/htb-blue.md)

    #htb-blue #hackthebox #ctf #nmap #nmap-scripts #smbmap #smbclient
    #metasploit #ms17-010 #eternalblue #meterpreter #impacket
    #virtualenv

    ![](/img/blue-cover.png)

    Blue was the first box I owned on HTB, on 8 November 2017. And it
    really is one of the easiest boxes on the platform. The root first
    blood went in two minutes. You just point the exploit for MS17-010
    (aka ETERNALBLUE) at the machine and get a shell as System. I'll
    show how to find the machine is vulnerable to MS17-010 using Nmap,
    and how to exploit it with both Metasploit and using Python scripts.

-   May 8, 2021

    ### [HTB: Attended](/htb-attended.md)

    #hackthebox #htb-attended #ctf #nmap #smtp #stmp-user-enum #swaks
    #phishing #vim #cve-2019-12735 #vim-modelines #firewall #scripting
    #python #ssh-config #ssh-keys #ping-sweep #nc-port-scan #openbsd
    #reverse-engineering #ida #gdb #debug #ssh-keygen #bof #rop
    #pattern-create #ropper #command-injection #htb-flujab #htb-ypuffy
    #htb-travel

    ![](/img/attended-cover.png)

    Attended was really hard. At the time of writing three days before
    it retires, just over 100 people have rooted it, making it the least
    rooted box on HackTheBox. It starts with a phishing exercise where
    hints betray that the user will open a text file in Vim, opening
    them to the Vim modelines exploit to get command execution. But
    there's a firewall blocking any outbound traffic that isn't ICMP or
    a valid HTTP GET request, so I'll write some scripts to build
    command and control through that. Then I find a place I can drop an
    SSH config file that will be run by the second user, which I'll
    abuse to get SSH access. For root, there's a buffer overflow in a
    command processing SSH auth on the gateway. I'll craft a malicious
    SSH key to overflow that binary and get a reverse shell. In Beyond
    Root, I'll look at an unintended command injection in the SSH config
    running script.

-   May 4, 2021

    ### [Networking VMs for HTB](/networking-vms-for-htb.md)

    #ctf #hackthebox #configuration #virtual-machine #parrot-os

    ![](/img/vms-cover.png)

    When doing HTB or other CTFs, I typically run from a Linux VM
    (formerly Kali, lately Parrot), but I also need to use a Windows VM
    from time to time as well. Some of those times, I'll need to
    interact with the HTB machines over the VPN from the Windows host,
    and it's always a bit of a pain to turn off the VPN in the Linux VM,
    and then turn it on from Windows. This post shows how I configured
    my VMs so that Windows traffic can route through the Linux VM to
    HTB.

-   May 3, 2021

    ### [More Bucket Beyond Root](/more-bucket-beyond-root.md)

    #ctf #htb-bucket #hackthebox #s3 #aws #awscli #apache #docker
    #localstack #cron #automation

    ![](/img/bucket-more-cover.png)

    \@teh_zeron reach out on twitter to ask why there's no images
    directory in the webroot on Bucket. I showed how my PHP webshell
    will show up there, and the index page seems to always be there.
    I'll look closely at how Bucket was set up, how different requests
    are handled, and the automation that is syncing between the host and
    the container.

-   May 1, 2021

    ### [HTB: Sharp](/htb-sharp.md)

    #hackthebox #htb-sharp #ctf #nmap #portable-kanban
    #reverse-engineering #dnspy #crypto #crackmapexec #dotnet-remoting
    #ysoserial.net #deserialization #exploitremotingservice #wcf
    #visual-studio #csharp #htb-json

    ![](/img/sharp-cover.png)

    Sharp was all about C# and .NET. It started with a PortableKanban
    config. At the time of release, there was no public scripts
    decrypting the database, so it involved reverse engineering a real
    .NET binary. From there, I'll reverse and exploit a .NET remoting
    service with a serialized payload to get shell as user. To escalate
    to system, I'll reverse a Windows Communication Foundation
    (WCF)-based service to find an endpoint that runs PowerShell code.
    I'll create a client to return a reverse shell. I'm also going to
    solve this one from a Windows VM (mostly).

-   Apr 27, 2021

    ### [HTB: Toolbox](/htb-toolbox.md)

    #hackthebox #htb-toolbox #ctf #nmap #windows #wfuzz #docker-toolbox
    #sqli #injection #postgresql #sqlmap #default-creds #docker
    #container

    ![](/img/toolbox-cover.png)

    Toolbox is a machine that released directly into retired as a part
    of the Containers and Pivoting Track on HackTheBox. It's a Windows
    instance running an older tech stack, Docker Toolbox. Before Windows
    could support containers, this used VirtualBox to run a lightweight
    custom Linux OS optimized for running Docker. I'll get a foodhold
    using SQL injection which converts into RCE with sqlmap. Then I'll
    use default credentials to pivot into the VM, where I find an SSH
    key that gives administrator access to the host system.

-   Apr 24, 2021

    ### [HTB: Bucket](/htb-bucket.md)

    #ctf #htb-bucket #hackthebox #s3 #aws #awscli #nmap #vhosts #wfuzz
    #upload #webshell #php #credentials #password-reuse #dynamodb
    #tunnel #localstack #pd4ml #pdfdetach #getfacl #facl

    ![](/img/bucket-cover.png)

    Bucket is a pentest against an Amazon AWS stack. There's an S3
    bucket that is being used to host a website and is configured to
    allow unauthenticated read / write. I'll upload a webshell to get a
    foothold on the box. From there, I'll access the DynamoDB instance
    to find some passwords, one of which is re-used for the user on the
    box. There's another webserver on localhost with a in-development
    service that creates a PDF based on entries in the database. I'll
    exploit that to get file read on the system as root, and turn that
    into a root shell. In Beyond Root, I'll look at some of the
    configuration that allowed the box to simulate AWS inside HTB.

-   Apr 17, 2021

    ### [HTB: Laboratory](/htb-laboratory.md)

    #hackthebox #htb-laboratory #ctf #gitlab #nmap #vhosts #gobuster
    #searchsploit #cve-2020-10977 #deserialization #hackerone #docker
    #ruby #irb #suid #path-hijack

    ![](/img/laboratory-cover.png)

    As the name hints at, Laboratory is largely about exploiting a
    GitLab instance. I'll exploit a CVE to get arbitrary read and then
    code execution in the GitLab container. From there, I'll use that
    access to get access to the admin's private repo, which happens to
    have an SSH key. To escalate to root, I'll exploit a SUID binary
    that is calling `system("chmod ...")` in an unsafe way, dropping my
    own binary and modifying the PATH so that mine gets run as root.

-   Apr 10, 2021

    ### [HTB: APT](/htb-apt.md)

    #hackthebox #htb-apt #ctf #nmap #ipv6 #rpc #ioxidresolver
    #active-directory #domain-controller #crackmapexec #hashcat
    #secretsdump #ntds #kerbrute #wail2ban #pykerbrute #mimikatz
    #passthehash #powershell #remote-registry #powerview #reg-py
    #evil-winrm #history #lmcompatibilitylevel #net-ntlmv1 #winpeas
    #seatbelt #amsi #defender #responder #roguepotato #ntlmrelayx
    #visual-studio #crack-sh #powershell-history #oscp-plus

    ![](/img/apt-cover.png)

    APT was a clinic in finding little things to exploit in a Windows
    host. I'll start with access to only RPC and HTTP, and the website
    has nothing interesting. I'll use RPC to identify an IPv6 address,
    which when scanned, shows typical Windows DC ports. Over SMB, I'll
    pull a zip containing files related to an Active Directory
    environment. After cracking the password, I'll use these files to
    dump 2000 users / hashes. Kerbrute will identify one user that is
    common between the backup and the AD on APT. The hash for that user
    doesn't work, and brute forcing using NTLM hashes gets me blocked
    using SMB, so I'll modify pyKerbrute to test all the hashes from the
    backup with the user, finding one that works. With that hash, I can
    access the registry and find additional creds that provide WinRM
    access. With a shell, I'll notice that the system still allows
    Net-NTLMv1, which is an insecure format. I'll show two ways to get
    the Net-NTLMv1 challenge response, first an unintended path using
    Defender and Responder, and then the intended path using RoguePotato
    and a custom RPC server created by modifying NTLMRelayX.

-   Apr 3, 2021

    ### [HTB: Time](/htb-time.md)

    #ctf #htb-time #hackthebox #nmap #cve-2019-12384 #java
    #deserialization #json-deserialization #sql #linpeas #systemd
    #short-lived-shells #oscp-like

    ![](/img/time-cover.png)

    Time is a straight forward box with two steps and low enumeration.
    The first step involves looking at the error code coming off a web
    application and some Googling to find an associated CVE. From there,
    I'll build a serialized JSON payload using the template in some of
    the CVE writeups, and get code execution and a shell. There's a
    Systemd timer running every few seconds, and the script being run is
    world writable. To get root, I'll just add some commands to that
    script and let it run. In Beyond Root, I look at the webserver and
    if I could write a file in the webroot, and also at handling the
    initial short-lived shell I got from the Systemd timer.

-   Mar 27, 2021

    ### [HTB: Luanne](/htb-luanne.md)

    #htb-luanne #ctf #hackthebox #nmap #netbsd
    #supervisor-process-manager #default-creds #http-basic-auth #burp
    #feroxbuster #api #lua #command-injection #htpasswd #hashcat #doas
    #pgp #netpgp #source-code #oscp-like

    ![](/img/luanne-cover.png)

    Luanne was the first NetBSD box I've done on HTB. I'll gain access
    to an instance of Supervisor Process Manager, and use that to leak a
    process list, which shows where to look on the port 80 webserver.
    I'll find an API that I know is backed by a Lua script, and exploit
    a command injection vulnerability to get execution and a shell. I'll
    get credentials for a webserver listening on localhost and find an
    SSH key hosted there to get to the second user. That user can doas
    (like sudo on BSD) arbitrary commands as root, the password is
    needed. It's in an encrypted backup file which can be decrypted
    using PGP on the host. In Beyond Root, I'll look at the Lua script,
    figure out how it works, where the injection vulnerability is, and
    compare that to the patched dev version to see how it was fixed.

-   Mar 20, 2021

    ### [HTB: CrossFit](/htb-crossfit.md)

    #htb-crossfit #hackthebox #ctf #nmap #ftp-tls #openssl #wfuzz
    #vhosts #gobuster #xss #javascript #xmlhttprequest #cors #csrf
    #laravel #lftp #webshell #ansible #credentials #hashcat
    #php-shellcommand #vsftpd #pam #hidepid #pspy #reverse-engineering
    #ghidra #arbitrary-write

    ![](/img/crossfit-cover.png)

    CrossFit is all about chaining attacks together to get the target to
    do my bidding. It starts with a cross-site scripting (XSS) attack
    against a website. The site detects the attack, and forwards my user
    agent to the admins to investigation. An XSS payload in the
    user-agent will trigger, giving some access there. I'll abuse
    cross-origin resource sharing (CORS) to identify another subdomain,
    and then use the XSS to do a cross-site request forgery, having the
    admins create an account for me on that subdomain, which provides
    FTP access, where I can upload a webshell, and use the XSS once
    again to trigger it for a reverse shell. I'll dig a hash out of
    ansible configs and crack it to get the next user. To escalate
    again, I'll exploit a command injection vulnerability in a PHP
    plugin, php-shellcommand, by writing to the database. To get root,
    I'll reverse engineer a binary that runs on a cron and figure out
    how to trick it to write a SSH key into root's authorized_keys file.

-   Mar 17, 2021

    ### [HTB: Optimum](/htb-optimum.md)

    #hackthebox #htb-optimum #ctf #nmap #windows #httpfileserver #hfs
    #searchsploit #cve-2014-6287 #nishang #winpeas #watson #sherlock
    #process-architechure #ms16-032 #cve-2016-0099 #htb-bounty

    ![](/img/optimum-cover.png)

    Optimum was sixth box on HTB, a Windows host with two CVEs to
    exploit. The first is a remote code execution vulnerability in the
    HttpFileServer software. I'll use that to get a shell. For privesc,
    I'll look at unpatched kernel vulnerabilities. Today to enumerate
    these I'd use Watson (which is also built into winPEAS), but getting
    the new version to work on this old box is actually challenging, so
    I'll use Sherlock (a predecessor to Watson) to identify these
    vulnerabilities. I got hung up for a bit not realizing my shell was
    running in a 32-bit process, causing my kernel exploits to fail.
    I'll show some analysis of that as well.

-   Mar 15, 2021

    ### [Reel2: Root Shell](/reel2-root-shell.md)

    #hackthebox #ctf #htb-reel2 #htb-reel #nmap #wallstant #apache
    #xampp #mysql #webshell #chisel

    ![](/img/reel2-more-cover.png)

    Both YB1 and JKR suggested a neat method for getting a shell on
    Reel2 that involves abusing the Apache Web server running as SYSTEM
    to write a webshell. It's a neat path that involves identifying
    where the config files are and getting access to the database using
    the arbitrary read intended to get the root flag.

-   Mar 13, 2021

    ### [HTB: Reel2](/htb-reel2.md)

    #hackthebox #htb-reel2 #ctf #windows #nmap #gobuster #owa #wallstant
    #javascript #sprayingtoolkit #phishing #responder #hashcat
    #ps-remoting #jea #jea-escape #stickynotes #htb-reel

    ![](/img/reel2-cover.png)

    Much like it's predascor, Reel, Reel2 was focused on realistic
    attacks against a Windows environment. This time I'll collect names
    from a social media site and use them to password spray using the
    SprayingToolkit. Once I find a working password, I'll send a link
    from that account and get an NTLM hash using responder. From there I
    need to break out of a JEA limited PowerShell, find creds to another
    account, and trick a custom command from that account into reading
    root.txt.

-   Mar 11, 2021

    ### [HTB: Sense](/htb-sense.md)

    #htb-sense #hackthebox #ctf #oscp-like #pfsense #nmap #gobuster
    #dirbuster #searchsploit #metasploit #command-injection #feroxbuster
    #cve-2016-10709 #burp

    ![](/img/sense-cover.png)

    Sense is a box my notes show I solved almost exactly three years
    ago. It's a short box, using directory brute forcing to find a text
    file with user credentials, and using those to gain access to a PF
    Sense Firewall. From there I'll exploit a code injection using
    Metasploit to get code execution and a shell as root. In Beyond
    Root, I'll look at a couple things that I would do differently
    today. First, I'll show out Feroxbuster to do the recurrsive
    directory brute force, and then I'll dig into the exploit and how it
    works and how it might be done without Metasploit.

-   Mar 6, 2021

    ### [HTB: Passage](/htb-passage.md)

    #htb-passage #ctf #hackthebox #nmap #cutenews #webshell #upload
    #searchsploit #github #source-code #base64 #penglab #hashcat #vim
    #usbcreator #arbitrary-write #file-read #cyberchef #oscp-like
    #passwd

    ![](/img/passage-cover.png)

    In Passage, I'll find and exploit CuteNews with a webshell upload.
    I'll have to analyze the CuteNews source to figure out how it stores
    user data in files to find the hash for the next user, which I'll
    crack. That user shares an SSH key with the next user on the box. To
    root, I'll exploit a bug in USBCreator that allows me to run sudo
    without knowing the user's password. In Beyond Root, I'll dive into
    the basics of base64 and how to search for strings in large amounts
    of base64 data.

-   Mar 2, 2021

    ### [HTB: Sneaky](/htb-sneaky.md)

    #hackthebox #htb-sneaky #ctf #nmap #udp #snmp #mibs #gobuster #sqli
    #injection #auth-bypass #onesixtyone #snmpwalk #ipv6 #suid #bof #pwn
    #reverse-engineering #ghidra #gdb #shellcode

    ![](/img/sneaky-cover.png)

    Sneaky presented a website that after some basic SQL injection,
    leaked an SSH key. But SSH wasn't listening. At least not on IPv4.
    I'll show three ways to find the IPv6 address of Sneaky, and then
    SSH using that address to get user. For root, there's a simple
    buffer overflow with no protections. I'll show a basic attack,
    writing shellcode onto the stack and then returning into it.

-   Feb 27, 2021

    ### [HTB: Academy](/htb-academy.md)

    #hackthebox #ctf #htb-academy #nmap #ubuntu #php #laravel #vhosts
    #gobuster #cve-2018-15133 #deserialization #metasploit
    #password-reuse #credentials #adm #logs #aureport #composer
    #gtfobins

    ![](/img/academy-cover.png)

    HackTheBox releases a new training product, Academy, in the most
    HackTheBox way possible - By putting out a vulnerable version of it
    to hack on. There's a website with a vulnerable registration page
    that allows me to register as admin and get access to a status
    dashboard. There I find a new virtual host, which is crashing,
    revealing a Laravel crash with data including the APP_KEY. I can use
    that to create a serialized payload to submit as an HTTP header or
    cookie to get execution. From there, I'll reuse database creds to
    get to the next user, and then find more creds in auth logs, and
    finally get root with sudo composer.

-   Feb 23, 2021

    ### [HTB: Beep](/htb-beep.md)

    #ctf #htb-beep #hackthebox #nmap #elastix #pbx #dirsearch
    #searchsploit #lfi #webmin #smtp #svwar #sslscan #shellshock
    #webshell #upload #credentials #password-reuse #oscp-like
    #htb-unattended

    ![](/img/beep-cover.png)

    Even when it was released there were many ways to own Beep. I'll
    show five, all of which were possible when this box was released
    in 2017. Looking a the timestamps on my notes, I completed Beep in
    August 2018, so this writeup will be a mix of those plus new
    explorations. The box is centered around PBX software. I'll exploit
    an LFI, RCE, two different privescs, webmin, credential reuse,
    ShellShock, and webshell upload over SMTP.

-   Feb 20, 2021

    ### [HTB: Feline](/htb-feline.md)

    #hackthebox #htb-feline #ctf #nmap #ubuntu #upload #tomcat
    #deserialization #java #cve-2020-9484 #ysoserial #docker #saltstack
    #cve-2020-11651 #chisel #docker-sock #container #socat #htb-fatty
    #htb-arkham

    ![](/img/feline-cover.png)

    Feline was another Tomcat box, this time exploiting a neat CVE that
    allowed me to upload a malcious serialized payload and then trigger
    it by giving a cookie that points the session to that file. The rest
    of the box focuses on Salt Stack, an IT automation platform. My
    foothold shell is on the main host, but Salt is running in a
    container. I'll exploit another CVE to get a shell in the Salt
    container, and then exploit that containers access to the docker
    socket to get root on the host. In Beyond Root, I'll show an
    alternative way of interacting with the docker socket by uploading
    the docker binary, and I'll look at the permissions on that socket
    and how it's shared into the container.

-   Feb 16, 2021

    ### [HTB: Charon](/htb-charon.md)

    #htb-charon #ctf #hackthebox #nmap #gobuster #sqli #injection
    #command-injection #filter #bash #waf #crackstation #upload
    #webshell #burp #burp-repeater #crypto #rsa #rsactftool #history
    #suid #ltrace #ghidra

    ![](/img/charon-cover.png)

    Another 2017 box, but this one was a lot of fun. There's an SQL
    injection the designed to break sqlmap (I didn't bother to go into
    sqlmap, but once I finished saw from others). Then there's a file
    upload, some crypto, and a command injection. I went into good
    detail on the manual SQLI and the RSA crypto. In Beyond Root, I'll
    look at a second SQLI that didn't prove usefu, and at the filters I
    had to bypass on the useful SQLI.

-   Feb 13, 2021

    ### [HTB: Jewel](/htb-jewel.md)

    #ctf #htb-jewel #hackthebox #nmap #gitweb #git #ruby #rails #gemfile
    #cve-2020-8164 #cve-2020-8165 #irb #deserialization
    #google-authenticator #totp #postgresql #penglab #hashcat #oathtool
    #gem

    ![](/img/jewel-cover.png)

    Jewel was all about Ruby, with a splash of Google Authenticator 2FA
    in the middle. I'll start with an instance of GitWeb providing the
    source for a website. That source allows me to identify a Ruby on
    Rails deserialization exploit that provides code execution. To
    escalate, I'll find the user's password in the database, and the
    seed for the Google Authenticator to calculate the time-based one
    time password, both of which are needed to run sudo. From there, I
    can use GTFObins to get execution from the gem program.

-   Feb 9, 2021

    ### [HTB: Apocalyst](/htb-apocalyst.md)

    #hackthebox #htb-apocalyst #ctf #nmap #wordpress #wpscan #gobuster
    #wfuzz #steghide #passwd

    ![](/img/apocalyst-cover.png)

    Apocalyst wasn't my favorite box. It is all about building a
    wordlist to find a specific image file on the site, and then
    extracting another list from that image using StegHide. That list
    contains the WordPress user's password, giving access to the admin
    panel and thus execution. To root, I'll find a writable passwd file
    and add in a root user.

-   Feb 6, 2021

    ### [HTB: Doctor](/htb-doctor.md)

    #hackthebox #ctf #htb-doctor #nmap #splunk #vhosts #flask
    #payloadsallthethings #ssti #command-injection #injection #adm
    #linpeas #splunk-whisperer2 #oscp-like #htb-secnotes

    ![](/img/doctor-cover.png)

    Doctor was about attacking a message board-like website. I'll find
    two vulnerabilities in the site, Server-Side Template injection and
    command injection. Either way, the shell I get back has access to
    read logs, where I'll find a password sent to a password reset url,
    which works for both the next user and to log into the Splunk Atom
    Feed. I'll exploit that with SplunkWhisperer2 to get RCE and a root
    shell. In Beyond Root, I'll look at a strange artifact I found on
    the box where, and examine the source for both web exploit.

-   Feb 2, 2021

    ### [HTB: Europa](/htb-europa.md)

    #htb-europa #ctf #hackthebox #vhosts #wfuzz #sqli #injection #sqlmap
    #preg_replace #cron

    ![](/img/europa-cover.png)

    Europa was a relatively easy box by today's HTB standards, but it
    offers a good chance to play with the most basic of SQL injections,
    the auth bypass. I'll also use sqlmap to dump the database. The
    foothold involves exploiting the PHP preg_replace function, which is
    something you'll only see on older hosts at this point. To get root,
    I'll find a cron job that calls another script that I can write.

-   Jan 30, 2021

    ### [HTB: Worker](/htb-worker.md)

    #htb-worker #hackthebox #ctf #svn #credentials #password-reuse
    #vhosts #wfuzz #azure #azure-devops #burp #devops #pipeline #git
    #webshell #upload #aspx #evil-winrm #azure-pipelines #potato
    #roguepotato #juicypotato #chisel #socat #tunnel #oscp-like #cicd
    #htb-sizzle #htb-json

    ![](/img/worker-cover.png)

    Worker is all about exploiting an Azure DevOps environment. I'll
    find creds in an old SVN repository and use them to get into the
    Azure DevOps control panel where several websites are managed. I'll
    upload a webshell into one of the sites and rebuild it, gaining
    execution and a shell. With the shell I'll find creds for another
    user, and use that to get back into Azure DevOps, this time as
    someone with permission to create pipelines, which I'll use to get a
    shell as System. In Beyond Root, I'll show RoguePotato, as this was
    one of the first vulnerable boxes to release after that came out.

-   Jan 23, 2021

    ### [HTB: Compromised](/htb-compromised.md)

    #hackthebox #ctf #htb-compromised #ubuntu #litecart #searchsploit
    #gobuster #mysql #credentials #php #mysql-udf #upload #webshell
    #php-disable-functions #phpinfo #strace #pam-backdoor
    #ldpreload-backdoor #ghidra #ghidra-version-tracking
    #reverse-engineering #ldpreload #htb-stratosphere

    ![](/img/compromised-cover.png)

    Compromised involves a box that's already been hacked, and so the
    challenge is to follow the hacker and both exploit public
    vulnerabilities as well as make use of backdoors left behind by the
    hacker. I'll find a website backup file that shows how the login
    page was backdoored to record admin credentials to a web accessible
    file. With those creds, I'll exploit a vulnerable LiteCart instance,
    though the public exploit doesn't work. I'll troubleshot that to
    find that the PHP functions typically used for execution are
    disabled. I'll show two ways to work around that to get access to
    the database and execution as the mysql user, who's shell has been
    enabled by the hacker. As the mysql user, I'll find a strace log,
    likely a makeshift keylogger used by the hacker with creds to pivot
    to the next user. To get root, I'll take advantage of either of two
    backdoors left on the box by the attacker, a PAM backdoor and a
    LDPRELOAD backdoor. In Beyond Root, I'll show how to run commands as
    root using the PAM backdoor from the webshell as www-data.

-   Jan 16, 2021

    ### [HTB: RopeTwo](/htb-ropetwo.md)

    #ctf #htb-ropetwo #hackthebox #pwn #python #c #javascript #v8 #d8
    #gef #pwngdb #reverse-engineering #ghidra #gdb #xss #heap #pwntools
    #realloc #fake-chunk #tcache #unsorted-bin #main-arena #fsop
    #free-hook #heapinfo #kernel-pwn #kernel-debug #rop #kernel-rop
    #kaslr #ropgadget #stack-pivot #prepare-kernel-cred #commit-creds
    #apport #htb-traceback #apt #http-proxy #cve-2020-8831 #wasm
    #wasm-fiddle #webassembly #htb-playertwo

    ![](/img/ropetwo-cover.png)

    RopeTwo, much like Rope, was just a lot of binary exploitation. It
    starts with a really neat attack on Google's v8 JavaScript engine,
    with a couple of newly added vulnerable functions to allow out of
    bounds read and write. I'll use that with an XSS vulnerability in
    the website to get code execution and a shell. To privesc to user,
    I'll use a heap exploit in a SUID binary. The binary was very
    limiting on the way I could interact with the heap, which lead to my
    having to re-write my exploit from scratch several times. From user,
    I'll escalate again by attacking a kernel module that created a
    vulnerable device. I'll leak the kernel memory to get past KASLR,
    and use some common kernel exploit techniques to execute a ROP chain
    and return a root shell. In Beyond Root, I'll look at the unintended
    method used to get first blood on this box.

-   Jan 12, 2021

    ### [Holiday Hack 2020: \'Zat You, Santa Claus? featuring KringleCon 3: French Hens](/holidayhack2020/)

    #ctf #sans-holiday-hack

    ![](/img/hh20-cover.png)

    The 2020 SANS Holiday Hack Challenge was less of a challenge to
    figure out who did it, and more picking apart how Jack Frost managed
    to hack Santa's processes. This all takes place at the third annual
    Kringle Con, where the worlds leading security practitioners show up
    for talks and challenges. Hosted at back at a
    currently-being-renovated North Pole, this years conference included
    [13 talks from leaders in information
    security](https://www.youtube.com/playlist?list=PLjLd1hNA7YVwqXqaBJfbXqkFb7LKw3r31),
    as well as 12 terminals / in-game puzzles and 11 objectives to
    solve. In solving all of these, the Jack Frost's plot was foiled. As
    usual, the challenges were interesting and set up in such a way that
    it was very beginner friendly, with lots of hints and talks to
    ensure that you learned something while solving.

-   Jan 9, 2021

    ### [HTB: Omni](/htb-omni.md)

    #ctf #htb-omni #hackthebox #windows-iot-core #sirep #sireprat
    #powershell-credential #secretsdump #penglab #hashcat #chisel
    #credentials #windows-device-portal #oscp-like

    ![](/img/omni-cover.png)

    Omni looks like a normal Windows host at first, but it's actually
    Windows IOT Core, the flavor of Windows that will run on a Raspberry
    Pi. I'll abuse Sirep protocol to get code execution as SYSTEM. From
    there, I'll get access as both the app user and as administrator to
    decrypt the flags in each of their home directories. I'll show
    multiple ways to get the user's credentials.

-   Jan 1, 2021

    ### [Hackvent 2020 - leet(ish)](/hackvent2020/leet)

    #ctf #hackvent #polyglot #binwalk #jsnice #python #chef #docker
    #docker-tar #steghide #tomcat #cve-2020-9484 #ysoserial
    #deserialization #elf #reverse-engineering #ghidra #lru-cache #ios
    #itunes #itunes-backup2hashcat #fonepaw #rsa #rsactftool #wireshark
    #pcap

    ![](/img/hackvent2020-leet-cover.png)

    The leet challenges started on day 20, but then followed an
    additional three hard challenges before the second and final leet
    one. These were all really good challenges. My favorite was a binary
    and a PCAP of an attacker exploiting the binary, where I needed to
    reverse the crypto operations in the binary and the exploit to
    recover the data that was stolen. I really liked one that was
    another polyglot file where an image turned into an HTML page that
    dropped a Python script which pull out a docker image containing
    images that contained a flag. There was also more web exploitation
    of a Tomcat deserialization CVE, a really interesting ELF reversing
    challenge, and pulling data from an iOS backup.

-   Jan 1, 2021

    ### [Hackvent 2020 - Hard](/hackvent2020/hard)

    #ctf #hackvent #xls #excel #forensic #cbc #crypto #gimp #polyglot
    #mbr #ghidra #ida #bochs #python #flask #command-injection
    #injection #rubiks #stl #rubik-cube #ja3 #go #ja3transport #jwt
    #ecryptfs #hashcat #ecryptfs2john #pyyaml #yaml-deserialization
    #binwalk

    ![](/img/hackvent2020-hard-cover.png)

    The first seven hard challenges included my favorite challenge of
    the year, Santa's Special GIFt, where the given file is both a GIF
    image and a master boot record. Handing it as such allowed me to
    reverse the code and emulate it to get two flags. There's another
    challenge that looks at the failures of CBC on encrypting an raw
    bitmap image, three web exploitation challenges exploiting command
    injection, JA3 impresonation, and Python YAML deserialization, and
    another Rubik's cube to solve.

-   Jan 1, 2021

    ### [Hackvent 2020 - Medium](/hackvent2020/medium)

    #ctf #hackvent #rubiks #py222 #python-pil #scrambles #python #dnspy
    #perl #obfuscation #ssti #jinja2 #flask #werkzeug-debug #colb
    #networkx #graphs #cliques #mobilefish #rsa #crypto #wiener #mpz

    ![](/img/hackvent2020-medium-cover.png)

    Medium continues with another seven challenges over seven days.
    There's a really good crypto challenge involving recovering RSA
    parameters recovered from a PCAP file and submitted to a Wiener
    attack, web hacking through an server-side template injection,
    dotNet reversing, a Rubik's cube challenge, and what is becoming the
    annual obfuscated Perl game.

-   Jan 1, 2021

    ### [Hackvent 2020 - Easy](/hackvent2020/easy)

    #ctf #hackvent #encoding #gimp #python #stegsolve #steganography
    #cyberchef #crypto #known-plaintext #bkcrack #binwalk #steghide

    ![](/img/hackvent2020-easy-cover.png)

    Hackvent started out early with a -1 day released on 29 November.
    There were seven easy challenges, including -1, one hidden, and five
    daily challenges. These challenges were heavy in crypto, image
    editing / steg, and encoding. My favorite in the group was Chinese
    Animals, where I spent way more figuring out what was going on after
    solving than actually solving.

-   Dec 26, 2020

    ### [Advent of Code 2020: Day 25](/adventofcode2020/25)

    #ctf #advent-of-code #python #modular-arithmetic

    ![](/img/aoc2020-25-cover.png)

    Day 25 is an encryption problem using modular arithmetic. I've given
    two public keys, both of which are of the form 7^d^ mod 20201227
    where d is unknown. The challenge is to find each d.

-   Dec 24, 2020

    ### [Advent of Code 2020: Day 24](/adventofcode2020/24)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-24-cover.png)

    The twist on day 24 is that it takes place on a grid of hexagons, so
    each tile has six neighbors, and a normal x,y or r,c coordinate
    system will be very difficult to use. I'll use an x, y, z coordinate
    system to flip tiles based on some input and then watch it evolve
    based on it's neighbors.

-   Dec 23, 2020

    ### [Advent of Code 2020: Day 23](/adventofcode2020/23)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-23-cover.png)

    Today is another game. This time I'm given a list of numbers and
    asked to mix it according to some given rules a certain number of
    times. Today is also the first time this year where I wrote part
    one, and then completely started over given part two.

-   Dec 22, 2020

    ### [Advent of Code 2020: Day 22](/adventofcode2020/22)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-22-cover.png)

    I'm asked to play out a game between two players that in part one
    looks like the classic card game of war, and in part two goes off in
    a different direction of "recursive combat". Both parts came
    together pretty quickly, though part two had a few places where
    small mistakes made identifying mistakes difficult.

-   Dec 22, 2020

    ### [Advent of Code 2020: Day 21](/adventofcode2020/21)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-21-cover.png)

    Day 21 was welcome relief after day 20. In this one, I'll parse a
    list of foods, each with an ingredients list and a listing of some
    (not necessarily all) of the allergies. I'll use that list to pair
    up allergens to ingredients.

-   Dec 22, 2020

    ### [Advent of Code 2020: Day 20](/adventofcode2020/20)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-20-cover.png)

    Day 20 was almost the end of my 2020 Advent of Code. I managed to
    solve part one in 15 minutes, but then part two got me for days. I
    finally solved it, but I can't promise pretty code.

-   Dec 19, 2020

    ### [Advent of Code 2020: Day 19](/adventofcode2020/19)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-19-cover.png)

    Another day with a section of convoluted validation rules and a
    series of items to be validated. Today's rules apply to a string,
    and I'll actually use a recursive algorithm to generate a single
    regex string that can then be applied to each input to check
    validity. It gets slightly more difficult in the second part, where
    loops are introduced into the rules. In order to work around this,
    I'll guess at a depth at which I can start to ignore further loops.

-   Dec 19, 2020

    ### [HTB: Laser](/htb-laser.md)

    #ctf #hackthebox #htb-laser #nmap #ubuntu #jetdirect #pret #printer
    #crypto #python #proto3 #grpc #solr #cve-2019-17558 #gopher #pspy
    #sshpass #socat #tunnel #htb-playertwo #htb-travel

    ![](/img/laser-cover.png)

    Laser starts without the typical attack paths, offering only SSH and
    two unusual ports. One of those is a printer, which gives the
    opportunity to leak data including a print job and the memory with
    the encryption key for that job. The PDF gives details of how the
    second port works, using protocol buffers over gRPC. I'll use this
    spec to write my own client, and use that to build a port scanner
    and scan the box for other open ports on localhost. When I find
    Apache Solr, I'll use create another exploit to go through the gRPC
    service and send a POST request using Gopher to exploit Solr and get
    code execution and a shell. To escalate to root, I'll collect SSH
    credentials for the root user in a container, and then use socat to
    redirect a cron SCP and SSH job back at the host box and exploit
    that to get code execution and root.

-   Dec 18, 2020

    ### [Advent of Code 2020: Day 18](/adventofcode2020/18)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-18-cover.png)

    Day 18 is reimplementing a simple math system with addition,
    multiplication, and parentheses, where the order of operations
    changes. I'll write a single calc function that takes in the string
    to evaluate as well as the order of operations to apply.

-   Dec 17, 2020

    ### [Advent of Code 2020: Day 17](/adventofcode2020/17)

    #ctf #advent-of-code #python #conway #game-of-life

    ![](/img/aoc2020-17-cover.png)

    Day 17 was a modified version of Conway's Game of Life, played
    across three and four dimensions, where a cells state in the next
    time step is determined by the its current state and the state of
    its neighbors.

-   Dec 16, 2020

    ### [Advent of Code 2020: Day 16](/adventofcode2020/16)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-16-cover.png)

    Day 16 was an interesting one to think about, as the algorithm for
    solving it wasn't obvious. It wasn't the case like some of the
    previous ones where there was an intuitive way to think about it but
    it would take too long. It was more a case of wrapping your head
    around the problem and how to organize the data so that you could
    match keys to values using validity rules and a bunch of examples. I
    made a guess that the data might clean up nicely in a certain way,
    and when it did, it made the second part much easier.

-   Dec 15, 2020

    ### [Advent of Code 2020: Day 15](/adventofcode2020/15)

    #ctf #advent-of-code #python #defaultdict

    ![](/img/aoc2020-15-cover.png)

    Day 15 is a game the elves play, where you have to remember the
    numbers said in a list, and append the next number based on when it
    was previously said. I'll solve by storing the numbers not in a list
    and searching it each time, but rather in a dictionary of lists,
    where the key is the number and the value is a list of indexes. It
    still runs a bit slow in part two, but it works.

-   Dec 14, 2020

    ### [Advent of Code 2020: Day 14](/adventofcode2020/14)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-14-cover.png)

    Part one of day 14 looked to be some basic binary masking and
    manipulation. But in part two, it got trickier, as now I need to
    handle Xs in the mask as both 0 and 1, meaning that there would be
    2^num\ X^ results. I used a recursive function to generate the list
    of indexes there.

-   Dec 13, 2020

    ### [Advent of Code 2020: Day 13](/adventofcode2020/13)

    #ctf #advent-of-code #python #chinese-remainder-theorem

    ![](/img/aoc2020-13-cover.png)

    Day 13 is looking at a series of buses that are running on their own
    time cycles, and trying to find times where the buses arrive in
    certain patterns. It brings in a somewhat obscure number theory
    concept called the Chinese Remainder Theorem, which has to do with
    solving a series of modular linear equations that all equal the same
    value.

-   Dec 12, 2020

    ### [HTB: OpenKeyS](/htb-openkeys.md)

    #ctf #htb-openkeys #hackthebox #nmap #vim #bsd #openbsd #gobuster
    #php #auth-userokay #cve-2019-19521 #cve-2019-19520 #cve-2019-19522
    #shared-object #skey #cve-2020-7247 #htb-onetwoseven

    ![](/img/openkeys-cover.png)

    OpenKeyS was all about a series of OpenBSD vulnerabilities published
    by Qualys in December 2019. I'll enumerate a web page to find a vim
    swap file that provides some hints about how the login form is doing
    auth. I'll use that to construct an attack that allows me to bypass
    the authentication and login as Jennifer, retrieving Jennifer's SSH
    key. To root, I'll exploit two more vulnerabilities, first to get
    access to the auth group using a shared library attack on xlock, and
    then abusing S/Key authentication. In Beyond Root, I'll look at
    another OpenBSD vulnerability that was made public just after the
    box was released, and play with PHP and the \$\_REQUEST variable.

-   Dec 12, 2020

    ### [Advent of Code 2020: Day 12](/adventofcode2020/12)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-12-cover.png)

    Day 12 is about moving a ship across a coordinate plane using
    directions and a way point that moves and rotates around the ship.
    There's a bit of geometry, and I made a really dumb mistake that
    took me a long time to figure out.

-   Dec 11, 2020

    ### [Advent of Code 2020: Day 11](/adventofcode2020/11)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-11-cover.png)

    Day 11 is grid-based challenge, where I'm giving a grid floor, empty
    seat, and occupied seat, and asked to step through time using rules
    that define how a seat will be occupied at time t+1 given the state
    of it and it's neighbors at time t. My code gets really ugly today,
    but it solves.

-   Dec 10, 2020

    ### [Advent of Code 2020: Day 10](/adventofcode2020/10)

    #ctf #advent-of-code #python #lru-cache

    ![](/img/aoc2020-10-cover.png)

    Day 10 is about looking at a list of numbers. In the first part I'll
    just need to make a histogram of the differences between the numbers
    when sorted. For part two, it's the first challenge this year where
    I'll need to come up with an efficient algorithm to handle it. I'm
    asked to come up with the number of valid combinations according to
    some constraints. I'll use recursion to solve it, and it only works
    in reasonable time with caching on that recursion.

-   Dec 9, 2020

    ### [Advent of Code 2020: Day 9](/adventofcode2020/9)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-9-cover.png)

    Day 9 is two challenges about looking across lists of ints to find
    pairs or slices with a given sum.

-   Dec 8, 2020

    ### [Advent of Code 2020: Day 8](/adventofcode2020/8)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-8-cover.png)

    Today I'm asked to build a small three instruction computer, and
    parse a series of instructions (puzzle input). I'm told that the
    instructions form an infinite loop, which is easy to identify in
    this simple computer any time an instruction is executed a second
    time. I'll look at finding where that infinite loop is entered, as
    well as finding the one instruction that can be patched to fix the
    code. I'll create a class for the computer with the thinking that I
    might be coming back to use it again and build on it later.

-   Dec 7, 2020

    ### [Advent of Code 2020: Day 7](/adventofcode2020/7)

    #ctf #advent-of-code #python #lru-cache #defaultdict

    ![](/img/aoc2020-7-cover.png)

    Day 7 gives me a list of bags, and what bags must go into those
    bags. The two parts are based on looking for what can hold what and
    how many. I'll use defaultdicts to manage the rules, and two
    recurrsive functions (including one that benefits from lru_cache) to
    solve the parts.

-   Dec 6, 2020

    ### [Advent of Code 2020: Day 6](/adventofcode2020/6)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-6-cover.png)

    Day 6 was another text parsing challenge, breaking the input into
    groups and then counting across the users within each group. Both
    parts were similar, with the first counting if any user said yes to
    a given question, and the latter if every user said yes to a given
    question. Python makes this a breeze either way.

-   Dec 5, 2020

    ### [HTB: Unbalanced](/htb-unbalanced.md)

    #htb-unbalanced #hackthebox #ctf #nmap #squid #http-proxy #foxyproxy
    #rsync #encfs #john #gobuster #squidclient #xpath-injection #python
    #pihole #webshell #upload #credentials #password-reuse #htb-joker
    #htb-zetta

    ![](/img/unbalanced-cover.png)

    Unbalanced starts with a Squid proxy and RSync. I'll use RSync to
    pull back the files that underpin an Encrypted Filesystem (EncFS)
    instance, and crack the password to gain access to the backup config
    files. In those files I'll find the Squid config, which includes the
    internal site names, as well as the creds to manage the Squid.
    Looking at the proxy stats, I can find two internal IPs, and guess
    the existence of a third, which is currently out of order for
    security fixes. In the site on the third IP, I'll find XPath
    injection allowing me to leak a bunch of usernames and passwords,
    one of which provides SSH access to the host. I'll exploit into a
    Pi-Hole container using an exploit to upload a webshell, and find a
    script which contains the root creds for the host. In Beyond Root,
    I'll look at why the searchsploit version of the PiHole exploit
    didn't work.

-   Dec 5, 2020

    ### [Advent of Code 2020: Day 5](/adventofcode2020/5)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-5-cover.png)

    Day 5 is wrapped in a story about plane ticket seat finding, but
    really it boils down to a simple binary to integer conversion, and
    then finding the difference of two sets and cleaning up what's left
    based on some simple rules.

-   Dec 4, 2020

    ### [Advent of Code 2020: Day 4](/adventofcode2020/4)

    #ctf #advent-of-code #python #regex

    ![](/img/aoc2020-4-cover.png)

    Day 4 presented another text parsing challenge. In the first part, I
    just needed to validate if each section contained a specific seven
    strings, which is easy enough to solve in Python. For part two, I
    need to now look at the text following each of these strings, and
    apply some validation rules. At first I thought I'd throw out my
    part 1 work and start processing all the data into a Python dict.
    But then I realized I could just write a regex for each validation,
    and use the same pattern.

-   Dec 3, 2020

    ### [Advent of Code 2020: Day 3](/adventofcode2020/3)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-3-cover.png)

    Advent of code always dives into visual mapping in a way that makes
    you conceptualize 2D (or 3D) space and move through it. I've got a
    map that represents a slope with clear spaces and trees, and that
    repeats moving to the right. As this is an early challenge, it's
    still relatively simple to handle the map with just an array of
    strings, which I'll do to count the trees I encounter on different
    trajectories moving across the map.

-   Dec 2, 2020

    ### [Advent of Code 2020: Day 2](/adventofcode2020/2)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-2-cover.png)

    Day 2 was about processing lines that contained two numbers, a
    character, and a string which is referred to as a password. Both
    parts are about using the numbers and the character to determine if
    the password is "valid". How the numbers and character become a rule
    is different in parts 1 and 2.

-   Dec 1, 2020

    ### [Advent of Code 2020: Day 1](/adventofcode2020/1)

    #ctf #advent-of-code #python

    ![](/img/aoc2020-1-cover.png)

    Advent of Code is a CTF put on by Google every December, providing
    coding challenges, and it's a favorite of mine to practice. There
    are 25 days to collect 50 stars. For Day 1, the puzzle was basically
    reading a list of numbers, and looking through them for a pair and a
    set of three that summed to 2020. For each part, I'll multiple the
    identified numbers together to get the solution.

-   Nov 28, 2020

    ### [HTB: SneakyMailer](/htb-sneakymailer.md)

    #htb-sneakymailer #ctf #hackthebox #nmap #wfuzz #vhosts #gobuster
    #phishing #swaks #htb-xen #imap #smtp #evolution #webshell #php
    #pypi #hashcat #htpasswd #setup-py #htb-chaos #htb-canape #sudo #pip
    #service #oscp-like

    ![](/img/sneakymailer-cover.png)

    SneakyMailer starts with web enumeration to find a list of email
    addresses, which I can use along with SMTP access to send phishing
    emails. One of the users will click on the link, and return a POST
    request with their login creds. That provides access to the IMAP
    inbox for that user, where I'll find creds for FTP. The FTP access
    is in the web directory, and while there's nothing interesting
    there, I can write a webshell and get execution, and a shell. To
    privesc, I'll submit a malicious Python package to the local PyPi
    server, which provides execution and a shell as that user. For root,
    I'll abuse a sudo rule to run pip, installing the same package
    again. In Beyond Root, I'll look at the automation on the box
    running as services.

-   Nov 21, 2020

    ### [HTB: Buff](/htb-buff.md)

    #ctf #hackthebox #htb-buff #nmap #windows #gobuster
    #gym-management-system #searchsploit #cloudme #chisel #msfvenom
    #webshell #defender #oscp-like

    ![](/img/buff-cover.png)

    Buff is a really good OSCP-style box, where I'll have to identify a
    web software running on the site, and exploit it using a public
    exploit to get execution through a webshell. To privesc, I'll find
    another service I can exploit using a public exploit. I'll update
    with my own shellcode to make a reverse shell, and set up a tunnel
    so that I can connect to the service that listens only on localhost.
    From there, the exploit script returns an administrator shell. In
    Beyond Root, I'll step through the first script and perform the
    exploit manually, and look at how Defender was blocking some of my
    attempts.

-   Nov 14, 2020

    ### [HTB: Intense](/htb-intense.md)

    #htb-intense #ctf #hackthebox #nmap #snmp #snmpwalk #sqli #injection
    #sqlite #python #burp #bruteforce #penglab #cookies #hash-extension
    #hash-extender #directory-traversal #snmp-shell #tunnel #bof
    #logic-error #htb-rope #gdb #peda

    ![](/img/intense-cover.png)

    Intense presented some cool challenges. I'll start by finding a SQL
    injection vulnerability into an sqlite database. I'm able to leak
    the admin hash, but not crack it. Using the source code for the
    site, I'll see that if I can use a hash extension attack, I can use
    the hash trick the site into providing admin access. From there,
    I'll use a directory traversal bug in a log reading API to find SNMP
    read/write creds, which I'll use to get a shell with snmp-shell. I
    can use that to find a custom binary listening on localhost, as well
    as it's source code. I'll use the snmp account to create an SSH
    tunnel, and exploit a logic bug in the code to overflow the buffer,
    bypass protections, and get a shell as root. In Beyond Root, I'll
    look at why I didn't have success with the system libc call in my
    ROP, figure out why, and fix it.

-   Nov 7, 2020

    ### [HTB: Tabby](/htb-tabby.md)

    #htb-tabby #hackthebox #ctf #lfi #php #gobuster #tomcat
    #host-manager #tomcat-manager #war #msfvenom #password-reuse
    #credentials #zip2john #john #hashcat #penglab #lxc #lxd
    #reverse-engineering #htb-jerry #htb-teacher #htb-popcorn
    #htb-lightweight #htb-sunday #oscp-like #htb-mischief #htb-obscurity

    ![](/img/tabby-cover.png)

    Tabby was a well designed easy level box that required finding a
    local file include (LFI) in a website to leak the credentials for
    the Tomcat server on that same host. The user who's creds I gain
    access to only has access to the command line manager API, not the
    GUI, but I can use that to upload a WAR file, get execution, and a
    shell. I'll crack the password on a backup zip archive and then use
    that same password to change to the next user. That user is a member
    of the lxd group, which allows them to start containers. I've shown
    this root before, but this time I'll include a really neat trick
    from m0noc that saves several steps. In Beyond Root, I'll pull apart
    the WAR file and show what's actually in it.

-   Nov 2, 2020

    ### [Flare-On 2020: break](/flare-on-2020/break)

    #flare-on #ctf #flare-on-break #reverse-engineering #ghidra #ptrace
    #hook #ldpreload #pre-main #gdb #crypto #feistel-cipher #unpack
    #modinv #python #htb-mischief #htb-obscurity #htb-teacher
    #htb-popcorn #htb-lightweight #htb-sunday

    ![](/img/flare2020-break-cover.png)

    break was an amazing challenge. Just looking at main, it looks like
    a simple comparison against a static flag. But there's an init
    function that runs first, forking a child process that then attaches
    a debugger to the parent, hooking all of it's system calls and
    crashes. The child itself forks a second child, which attaches to
    the first child, handling several intentional crash points in the
    first child's code. The effectively prevents my debugging the parent
    for first child, as only one debugger can attach at a time. I'll use
    two different approaches - hooking library calls and patching the
    second child's functionality directly into the first child, allowing
    me to debug the first child. Using these techniques, I'll wind
    through three parts of the flag, each successively more difficult to
    break out.

-   Nov 1, 2020

    ### [Flare-On 2020: crackinstaller](/flare-on-2020/crackinstaller)

    #flare-on #ctf #flare-on-crackinstaller #reverse-engineering
    #capcom-sys #driver #kernel-debug

    ![](/img/flare2020-crackinstaller-cover.png)

    crackinstaller.exe was a complicated binary that installed the
    Capcom.sys driver, and then exploited it to load another driver into
    memory. It also dropped and installed another DLL, a credential
    helper. I used kernel debugging to see how the second driver is
    loaded, and eventually find a password, which I can feed into the
    credential helper to get the flag. I spent over two of the six weeks
    working crackinstaller.exe, and unfortunately, I stopped taking
    meaningful notes very early in that process, so this won't be much
    of a writeup, but rather a high level overview.

-   Nov 1, 2020

    ### [Flare-On 2020: Aardvark](/flare-on-2020/aardvark)

    #flare-on #ctf #flare-on-aardvark #reverse-engineering #wsl #ghidra
    #resource-hacker #process-hacker #gdb #peda #pwndbg

    ![](/img/flare2020-aardvark-cover.png)

    Aardvark was a game of tik-tac-toe where the computer always goes
    first, and can't lose. Instead of having the decision logic of the
    computer in the program, it drops an ELF binary to act as the
    computer, and communicates with it over a unix socket, all of which
    is possible on Windows with the Windows Subsystem for Linux (WSL).
    Once I understand how the computer is playing, I'll modify the
    computers logic so that I can win, and get the flag. I'll play with
    different ways to patch the binary, starting manually with gdb, and
    moving to patching the ELF resource a couple different ways.

-   Oct 31, 2020

    ### [HTB: Fuse](/htb-fuse.md)

    #ctf #htb-fuse #hackthebox #windows #ldap #ldapsearch #rpc #smb
    #winrm #evil-winrm #crackmapexec #smbmap #rpcclient #papercut
    #gobuster #cewl #hydra #smbpasswd #rpcclient #capcom-sys #driver
    #visual-studio #eoploaddriver #msfvenom #scheduled-task #ghidra
    #oscp-like

    ![](/img/fuse-cover.png)

    Fuse was all about pulling information out of a printer admin page.
    I'll collect usernames and use cewl to make a wordlist, which
    happens to find the password for a couple accounts. I'll need to
    change the password on the account to use it, and then I can get RPC
    access, where I'll find more creds in the comments. I can use those
    creds for WinRM access, where I'll find myself with privileges to
    load a driver. I'll use the popular Capcom.sys driver to load a
    payload that returns a shell as system. In Beyond Root, I'll look at
    the scheduled tasks that are managing the users passwords and trying
    to uninstall drivers put in place by HTB players.

-   Oct 30, 2020

    ### [Flare-On 2020: RE Crowd](/flare-on-2020/recrowd)

    #flare-on #ctf #flare-on-re-crowd #reverse-engineering #pcap
    #wireshark #tshark #cve-2017-7269 #shellcode #scdbg #crypto #python
    #x64dbg #cff-explorer #cyberchef #procmon

    ![](/img/flare2020-recrowd-cover.png)

    RE Crowd was a different kind of reversing challenge. I'm given a
    PCAP that includes someone trying to exploit an IIS webserver using
    CVE-2017-7269. This exploit uses alphanumeric shellcode to run on
    success. I'll pull the shellcode and analyze it, seeing that it's a
    Metasploit loader that connects to a host and then the host sends
    back an encrypted blob. The host then sends another encrypted blob
    back to the attcker. I'll use what I can learn about the attacker's
    commands to decrypt that exfil and find the flag.

-   Oct 29, 2020

    ### [Flare-On 2020: CodeIt](/flare-on-2020/codeit)

    #flare-on #ctf #flare-on-codeit #reverse-engineering #autoit
    #exe2aut #upx #myauttoexe #script-obfuscation #crypto

    ![](/img/flare2020-codeit-cover.png)

    The sixth Flare-On7 challenge was tricky in a way that's hard to put
    on the page. It really was just a AutoIt script wrapped in a Windows
    exe. I'll use a tool to revert it back to a large, obfuscated
    script, and then get to work deobfuscating it. Eventually I'll see
    that it is looking for a specific hostname, and on switching my
    hostname to match, I get a QRcode that contains the flag.

-   Oct 28, 2020

    ### [Flare-On 2020: TKApp](/flare-on-2020/tkapp)

    #flare-on #ctf #flare-on-tkapp #reverse-engineering #tizen #tpk
    #dnspy #dotnet #emulation #python

    ![](/img/flare2020-tkapp-cover.png)

    TKApp was a Tizen mobile application that was made to run on a smart
    watch. Inside the archive, there's a .NET dll that drives the
    application, so I can break it open with dnSpy. Four variables are
    initialized through different user actions or different aspects of
    the files on the watch, and then used to generate a key to decrypt a
    buffer. I'll show both static analysis to pull the keys and then
    decrypt in Python, as well as how to emulate a watch and then go
    through the steps to get it to display the flag in the gallery.

-   Oct 27, 2020

    ### [Flare-On 2020: report.xls](/flare-on-2020/report)

    #flare-on #ctf #flare-on-report #reverse-engineering #xls #vba
    #olevba #evil-clippy #pcode #vba-stomp #python #pcodedmp #pcode2code
    #script-obfuscation

    ![](/img/flare2020-report-cover.png)

    report.xls was my kind of challenge. It's an Excel book with an
    macro with some relatively standard obfuscation and sandbox evasion.
    In analyzing the VBA, I see more and more hints that something odd
    is going on. Eventually I'll extract an mp3 file with several more
    hints that the VBA has been stomped, replacing the p-code with
    something different from the VBA. When I dump the p-code and analyze
    it, I'll find an image with the flag.

-   Oct 26, 2020

    ### [Flare-On 2020: wednesday](/flare-on-2020/wednesday)

    #flare-on #ctf #flare-on-wednesday #reverse-engineering #ghidra
    #nimlang #x64dbg #patching

    ![](/img/flare2020-wednesday-cover.png)

    wednesday was a game that involved getting my dude to the end
    jumping over and going under blocks. The game was written in Nim
    lang, and had a lot of complex functions to manage the game. It was
    a long way to go, so I patched it to just let me run through blocks
    and not worry about under vs over.

-   Oct 26, 2020

    ### [Flare-On 2020: garbage](/flare-on-2020/garbage)

    #flare-on #ctf #flare-on-garbage #upx #pe #cff-explorer #ghidra
    #reverse-engineering #resource-hacker

    ![](/img/flare2020-garbage-cover.png)

    garbage was all about understanding the structure of an exe file,
    and how to repair it when the last few hundred bytes were truncated.
    I'll troubleshoot the binary and eventually get it working to the
    point that I can unpack it, do static analysis, and get the flag.
    I'll also show how to fix the binary so that it will just run and
    print the flag in a message box.

-   Oct 26, 2020

    ### [Flare-On 2020: Fidler](/flare-on-2020/fidler)

    #flare-on #ctf #flare-on-fidler #python #pygame #reverse-engineering

    ![](/img/flare2020-fidler-cover.png)

    Flare-On 7 got off to an easy start with a Windows executable that
    was generated with PyGame, and included the Python source. That made
    this challenge more of a Python source code analysis exercise than a
    reversing challenge. I'll find the password and the win conditions
    in the source, and win both by decrypting the flag and by modifying
    the source.

-   Oct 24, 2020

    ### [HTB: Dyplesher](/htb-dyplesher.md)

    #hackthebox #ctf #htb-dyplesher #nmap #memcached #gobuster #gogs
    #git #gitdumper #memcached-binary #memcached-auth #memcached-cli
    #memcat #credentials #git-bundle #sqlite #hashcat #bukkit #minecraft
    #spigot #intellij #java #jar #webshell #packet-capture #wireshark
    #cuberite #rabbitmq #amqp-publish #lua #htb-canape #htb-waldo
    #htb-dab

    ![](/img/dyplesher-cover.png)

    Dyplesher pushed server modern technologies that are not common in
    CTFs I've done. Initial access requires finding a virtual host with
    a .git directory that allows me to find the credentials used for the
    memcache port. After learning about the binary memcache protocol
    that supports authentication, I'm able to connect and dump usernames
    and password from the cache, which provide access to a Gogs
    instance. In Gogs, I'll find four git bundles (repo backups), one of
    which contains custom code with an SQLite db containing password
    hashes. One cracks, providing access to the web dashboard. In this
    dashboard, I'm able to upload and run Bukkit plugins. I'll write a
    malicious one that successfully writes both a webshell and an SSH
    key, both of which provide access to the box as the same first user.
    This user has access to a dumpcap binary, which I'll use to capture
    traffic finding Rabbit message queue traffic that contains the
    usernames and password for the next user. This user has instructions
    to send a url over the messaging queue, which will cause the box to
    download and run a cuberite plugin. I'll figure out how to publish
    my host into the queue, and write a malicious Lua script that will
    provide root access. In Beyond Root, I'll look more deeply at the
    binary memcache protocol.

-   Oct 17, 2020

    ### [HTB: Blunder](/htb-blunder.md)

    #htb-blunder #hackthebox #ctf #nmap #ubuntu #bludit #cms
    #searchsploit #github #cewl #bruteforce #python #upload #filter
    #credentials #crackstation #cve-2019-14287 #sudo #oscp-like
    #htaccess

    ![](/img/blunder-cover.png)

    Blunder starts with a blog that I'll find is hosted on the BludIt
    CMS. Some version enumeration and looking at releases on GitHub
    shows that this version is vulnerable to a bypass of the bruteforce
    protections, as well as an upload and execute filter bypass on the
    PHP site. I'll write my own scripts for each of these, and use them
    to get a shell. From there, I'll find creds for the next user, where
    I'll find the first flag. Now I can also access sudo, where I'll see
    I can run sudo to get a bash shell as any non-root user. I'll
    exploit CVE-2019-14287 to run that as root, and get a root shell.

-   Oct 10, 2020

    ### [HTB: Cache](/htb-cache.md)

    #ctf #htb-cache #hackthebox #nmap #ubuntu #gobuster #vhosts
    #javascript #credentials #password-reuse #wfuzz #openemr
    #searchsploit #auth-bypass #sqli #injection #sqlmap #hashcat
    #memcached #docker #htb-dab #htb-olympus

    ![](/img/cache-cover.png)

    Cache rates medium based on number of steps, none of which are
    particularly challenging. There's a fair amount of enumeration of a
    website, first, to find a silly login page that has hardcoded
    credentials that I'll store for later, and then to find a new VHost
    that hosts a vulnerable OpenEMR system. I'll exploit that system
    three ways, first to bypass authentication, which provides access to
    a page vulnerable to SQL-injection, which I'll use to dump the
    hashes. After cracking the hash, I'll exploit the third
    vulnerability with a script from ExploitDB which provides
    authenticated code execution. That RCE provides a shell. I'll
    escalate to the next user reusing the creds from the hardcoded
    website. I'll find creds for the next user in memcached. This user
    is in the docker group, which I'll exploit to get root access.

-   Oct 3, 2020

    ### [HTB: Blackfield](/htb-blackfield.md)

    #htb-blackfield #ctf #hackthebox #nmap #dns #ldap #ldapsearch
    #crackmapexec #smbmap #smbclient #as-rep-roast #hashcat #bloodhound
    #bloodhound-python #rpc-password-reset #pypykatz #evil-winrm
    #sebackupprivilege #copy-filesepackupprivilege #efs #diskshadow
    #ntds #vss #secretsdump #smbserver #icacls #cipher #windows-sessions
    #metasploit #meterpreter #oscp-plus #htb-forest #htb-multimaster
    #htb-re

    ![](/img/blackfield-cover.png)

    Blackfield was a beautiful Windows Activity directory box where I'll
    get to exploit AS-REP-roasting, discover privileges with bloodhound
    from my remote host using BloodHound.py, and then reset another
    user's password over RPC. With access to another share, I'll find a
    bunch of process memory dumps, one of which is lsass.exe, which I'll
    use to dump hashes with pypykatz. Finally with a hash that gets a
    WinRM shell, I'll abuse backup privileges to read the ntds.dit file
    that contains all the hashes for the domain (as well as a copy of
    the SYSTEM reg hive). I'll use those to dump the hashes, and get
    access as the administrator. In Beyond Root, I'll look at the EFS
    that prevented my reading root.txt using backup privs, as well as go
    down a rabbit hole into Windows sessions and why the cipher command
    was returning weird results.

-   Sep 26, 2020

    ### [HTB: Admirer](/htb-admirer.md)

    #htb-admirer #hackthebox #ctf #nmap #debian #gobuster #robots-text
    #source-code #adminer #mysql #credentials #sudo #pythonpath
    #path-hijack #python-library-hijack #oscp-like #htb-nineveh
    #htb-kryptos

    ![](/img/admirer-cover.png)

    Admirer provided a twist on abusing a web database interface, in
    that I don't have creds to connect to any databases on Admirer, but
    I'll instead connect to a database on myhost and use queries to get
    local file access to Admirer. Before getting there, I'll do some web
    enumeration to find credentials for FTP which has some outdated
    source code that leads me to the Adminer web interface. From there,
    I can read the current source, and get a password which works for
    SSH access. To privesc, I'll abuse sudo configured to allow me to
    pass in a PYTHONPATH, allowing a Python library hijack.

-   Sep 19, 2020

    ### [HTB: Multimaster](/htb-multimaster.md)

    #htb-multimaster #ctf #hackthebox #nmap #wfuzz #waf #filter #unicode
    #sqlmap #tamper #hashcat #crackmapexec #cyberchef #python #sqli
    #injection #windows #mssql #rid #evil-winrm #cef-debugging
    #reverse-engineering #bloodhound #amsi #powersploit #as-rep-roast
    #server-operators #service #service-hijack #sebackupprivilege
    #serestoreprivilege #robocopy #cve-2020-1472 #zerologon #htb-forest

    ![](/img/multimaster-cover.png)

    Multimaster was a lot of steps, some of which were quite difficult.
    I'll start by identifying a SQL injection in a website. I'll have to
    figure out the WAF and find a way past that, dumping credentials but
    also writing a script to use MSSQL to enumerate the domain users. To
    pivot to the second user, I'll exploit an instance of Visual Studio
    Code that's left an open CEF debugging socket open. That user has
    access to a DLL in the web directory, in which I'll find more
    credentials to pivot to another user. This user has GenericWrite
    privileges on another user, so I'll abuse that to get a shell. This
    final user is in the Server Operators group, allowing me to modify
    services to get a shell as SYSTEM. I'll show two alternative roots,
    abusing the last user's SeBackupPrivilege and SeRestorePrivilege
    with robotcopy to read the flag, and using ZeroLogon to go right to
    administrator in one step.

-   Sep 17, 2020

    ### [ZeroLogon - Owning HTB machines with CVE-2020-1472](/zerologon-owning-htb-machines-with-cve-2020-1472.md)

    #cve-2020-1472 #exploit #domain-controller #htb-monteverde
    #zerologon #impacket #python #virtualenv #secretsdump

    ![](/img/zero-cover.png)

    CVE-2020-1472 was patched in August 2020 by Microsoft, but it didn't
    really make a splash until the last week when proof of concept
    exploits started hitting GutHub. It truly is a short path to domain
    admin. I'll look at the exploit and own some machines from HTB with
    it.

-   Sep 12, 2020

    ### [HTB: Travel](/htb-travel.md)

    #hackthebox #ctf #htb-travel #nmap #ubuntu #vhosts #wfuzz #gobuster
    #wordpress #awesome-rss #simplepie #git #gittools #gitdumper
    #source-code #memcached #ssrf #filter #deserialization #php #gopher
    #gopherus #payloadsallthethings #webshell #container #docker
    #database #credentials #password-reuse #hashcat #viminfo #ldap
    #authorizedkeyscommand #ldif #ldapadd #getent #htb-ypuffy

    ![](/img/travel-cover.png)

    Travel was just a great box because it provided a complex and
    challenging puzzle with new pieces that were fun to explore. I'll
    start off digging through various vhosts until I eventually find an
    exposed .git folder on one. That provides me the source for another,
    which includes a custom RSS feed that's cached using memcache. I'll
    evaluate that code to find a deserialization vulnerability on the
    read from memcache. I'll create an exploit using a server-side
    request forgery attack to poison the memcache with a serialized PHP
    payload that will write a webshell, and then trigger it, gaining
    execution and eventually a shell inside a container. I'll find a
    hash in the database which I can crack to get a password for the
    user on the main host. This user is also the LDAP administrator, and
    SSH is configured to check LDAP for logins. I'll pick an arbitrary
    user and add an SSH private key, password, and the sudo group to
    their LDAP such that then when I log in as that user, I can just
    sudo to root. In Beyond Root I'll explore a weird behavior I
    observed in the RSS feed.

-   Sep 10, 2020

    ### [HTB: Haircut](/htb-haircut.md)

    #ctf #htb-haircut #hackthebox #nmap #php #upload #command-injection
    #parameter-injection #webshell #gobuster #curl #filter #screen
    #oscp-like

    ![](/img/haircut-cover.png)

    Haircut started with some web enumeration where I'll find a PHP site
    invoking curl. I'll use parameter injection to write a webshell to
    the server and get execution. I'll also enumerate the filters and
    find a way to get command execution in the page itself. To jump to
    root, I'll identify a vulnerable version of screen that is set SUID
    (which is normal). I'll walk through this exploit. In Beyond Root,
    I'll take a quick look at the filtering put in place in the PHP
    page.

-   Sep 8, 2020

    ### [RoguePotato on Remote](/roguepotato-on-remote.md)

    #htb-remote #hackthebox #ctf #windows #seimpersonate #roguepotato
    #lonelypotato #juicypotato #ippsec #socat #htb-re

    ![](/img/roguepotato-remote-cover.png)

    JuicyPotato was a go-to exploit whenever I found myself with a
    Windows shell with SeImpersonatePrivilege, which typically was
    whenever there was some kind of webserver exploit. But Microsoft
    changed things in Server 2019 to brake JuicyPotato, so I was really
    excited when splinter_code and decoder came up with RoguePotato, a
    follow-on exploit that works around the protections put into place
    in Server 2019. When I originally solved Remote back in March,
    RoguePotato had not yet been released. I didn't have time last week
    to add it to my Remote write-up, so I planned to do a follow up post
    to show it. While in the middle of this post, I also watched
    IppSec's video where he tries to use RoguePotato on Remote in a way
    that worked but shouldn't have, raising a real mystery. I'll dig
    into that and show what happened as well.

-   Sep 5, 2020

    ### [HTB: Remote](/htb-remote.md)

    #htb-remote #hackthebox #ctf #nmap #nfs #umbraco #hashcat #nishang
    #teamviewer #credentials #evilwinrm #oscp-like

    ![](/img/remote-cover.png)

    To own Remote, I'll need to find a hash in a config file over NFS,
    crack the hash, and use it to exploit a Umbraco CMS system. From
    there, I'll find TeamView Server running, and find where it stores
    credentials in the registry. After extracting the bytes, I'll write
    a script to decrypt them providing the administrator user's
    credentials, and a shell over WinRM or PSExec.

-   Sep 3, 2020

    ### [HTB: Mantis](/htb-mantis.md)

    #htb-mantis #ctf #hackthebox #nmap #smbmap #smbclient #rcpclient
    #kerbrute #orchard-cms #gobuster #mssql #mssqlclient #dbeaver
    #crackmapexec #ms14-068 #kerberos #kinit #golden-ticket #goldenpac

    ![](/img/mantis-cover.png)

    Mantis was one of those Windows targets where it's just a ton of
    enumeration until you get a System shell. The only exploit on the
    box was something I remember reading about years ago, where a low
    level user was allowed to make a privileged Kerberos ticket. To get
    there, I'll have to avoid a few rabbit holes and eventually find
    creds for the SQL Server instance hidden on a webpage. The database
    has domain credentials for a user. I'll use those to perform the
    attack, which will return SYSTEM access.

-   Aug 29, 2020

    ### [HTB: Quick](/htb-quick.md)

    #htb-quick #hackthebox #ctf #nmap #ubuntu #gobuster #vhosts #wfuzz
    #quic #http3 #curl #edgeside-include-injection #esi #injection
    #race-condition #cracking #python #credentials #su #oscp-plus

    ![](/img/quick-cover.png)

    Quick was a chance to play with two technologies that I was familiar
    with, but I had never put hands on with either. First it was finding
    a website hosted over Quic / HTTP version 3. I'll build curl so that
    I can access that, and find creds to get into a ticketing system. In
    that system, I will exploit an edge side include injection to get
    execution, and with a bit more work, a shell. Next I'll exploit a
    new website available on localhost and take advantage of a race
    condition that allows me to read and write arbitrary files as the
    next user. Finally, to get root I'll find creds in a cached config
    file. In Beyond Root, I'll use a root shell to trouble-shoot my
    difficulties getting a shell and determine where things were
    breaking.

-   Aug 27, 2020

    ### [HTB: Calamity](/htb-calamity.md)

    #htb-calamity #ctf #hackthebox #nmap #gobuster #webshell #scripting
    #filter #phpbash #steganography #audacity #lxd #bof #gdb #peda
    #checksec #nx #mprotect #python #exploit #pattern-create #ret2libc
    #youtube #htb-obscurity #htb-frolic #htb-mischief

    ![](/img/calamity-cover.png)

    Calamity was released as Insane, but looking at the user ratings, it
    looked more like an easy/medium box. The user path to through the
    box was relatively easy. Some basic enumeration gives access to a
    page that will run arbitrary PHP, which provides execution and a
    shell. There's an audio steg challenge to get the user password and
    a user shell. People likely rated the box because there was an
    unintended root using lxd. I've done that before, and won't show it
    here. The intended path was a contrived but interesting pwn
    challenge that involved three stages of input, the first two
    exploiting a very short buffer overflow to get access to a longer
    buffer overflow and eventually a root shell. In Beyond Root, I'll
    look at some more features of the source code for the final binary
    to figure out what some assembly did, and why a simple return to
    libc attack didn't work.

-   Aug 22, 2020

    ### [HTB: Magic](/htb-magic.md)

    #hackthebox #ctf #htb-magic #nmap #sqli #injection #upload #filter
    #gobuster #webshell #php #mysqldump #su #suid #path-hijack #apache
    #oscp-like #htb-networked

    ![](/img/magic-cover.png)

    Magic has two common steps, a SQLI to bypass login, and a webshell
    upload with a double extension to bypass filtering. From there I can
    get a shell, and find creds in the database to switch to user. To
    get root, there's a binary that calls popen without a full path,
    which makes it vulnerable to a path hijack attack. In Beyond Root,
    I'll look at the Apache config that led to execution of a .php.png
    file, the PHP code that filtered uploads, and the source for the
    suid binary.

-   Aug 15, 2020

    ### [HTB: Traceback](/htb-traceback.md)

    #htb-traceback #ctf #hackthebox #nmap #webshell #vim #gobuster
    #smevk #lua #luvit #ssh #motd #linpeas #linenum

    ![](/img/traceback-cover.png)

    Traceback starts with finding a webshell that's already one the
    server with some enumeration and a bit of open source research. From
    there, I'll pivot to the next user with sudo that allows me to run
    Luvit, a Lua interpreter. To get root, I'll notice that I can write
    to the message of the day directory. These scripts are run by root
    whenever a user logs in. I actually found this by seeing the cron
    that cleans up scripts dropped in this directory, but I'll also show
    how to find it with some basic enumeration as well. In Beyond Root,
    I'll take a quick look at the cron that's cleaning up every thiry
    seconds.

-   Aug 13, 2020

    ### [HTB: Joker](/htb-joker.md)

    #hackthebox #htb-joker #ctf #nmap #udp #tftp #squid #http-proxy
    #foxyproxy #hashcat #penglab #gobuster #python #werkzeug #iptables
    #socat #sudo #sudoedit #sudoedit-follow #ssh #tar #cron #wildcard
    #symbolic-link #checkpoint #htb-tartarsauce #htb-shrek #flask-debug

    ![](/img/joker-cover.png)

    Rooting Joker had three steps. The first was using TFTP to get the
    Squid Proxy config and creds that allowed access to a webserver
    listening on localhost that provided a Python console. To turn that
    into a shell, I'll have to enumerate the firewall and find that I
    can use UDP. I'll show two ways to abuse a sudo rule to make the
    second step. I can take advantage of the sudoedit_follow flag, or
    just abuse the wildcards in the rule. The final pivot to root
    exploits a cron running creating tar archives, and I'll show three
    different ways to abuse it.

-   Aug 10, 2020

    ### [Tunneling with Chisel and SSF](/tunneling-with-chisel-and-ssf-update.md)

    #hackthebox #tunnel #chisel #ssf #htb-reddish

    ![](/img/pipes-cover.png)

    \[Update 2020-08-10\] Chisel now has a built in SOCKS proxy! I also
    added a cheat sheet since I reference this post too often.
    \[Original\] Having just [written up HTB
    Reddish](/htb-reddish.md), pivoting without SSH was at
    the top of my mind, and I've since learned of two programs that
    enable pivots, Chisel and Secure Socket Funneling (SSF). I learned
    about Chisel from Ippsec, and you can see [his using it to solve
    Reddish in his
    video](https://www.youtube.com/watch?v=Yp4oxoQIBAM&t=1469s). I
    wanted to play with it, and figured I'd document what I learned
    here. I learned about SSF from another HTB user,
    [jkr](https://www.hackthebox.eu/home/users/profile/77141), who not
    only introduced me to SSF, but pulled together the examples in this
    post.

-   Aug 8, 2020

    ### [HTB: Fatty](/htb-fatty.md)

    #hackthebox #htb-fatty #ctf #java #nmap #ftp #update-alternatives
    #jar #wireshark #procyon #javac #directory-traversal #filter
    #reverse-engineering #tar #scp #cron #sqli #injection
    #deserialization #ysoserial #pspy #htb-arkham

    ![](/img/fatty-cover.png)

    Fatty forced me way out of my comfort zone. The majority of the box
    was reversing and modifying a Java thick client. First I had to
    modify the client to get the client to connect. Then I'll take
    advantage of a directory traversal vulnerability to get a copy of
    the server binary, which I can reverse as well. In that binary,
    first I'll find a SQL injection that allows me to log in as an admin
    user, which gives me access to additional functionality. One of the
    new functions uses serialized objects, which I can exploit using a
    deserialization attack to get a shell in the container running the
    server. Escalation to root attacks a recurring process that is using
    SCP to copy an archive of log files off the container to the host.
    By guessing that the log files are extracted from the archive, I'm
    able to create a malicious archive that allows me over the course of
    two SCPs to overwrite the root authorized_keys file and then SSH
    into Fatty as root.

-   Aug 8, 2020

    ### [Jar Files: Analysis and Modifications](/jar-files-analysis-and-modifications.md)

    #java #reverse-engineering #decompile #jar #recompile #procyon
    #javac

    ![](/img/jar-cover.png)

    I recently ran into a challenge where I was given a Java Jar file
    that I needed to analyze and patch to exploit. I didn't find many
    good tutorials on how to do this, so I wanted to get my notes down.
    For now it's just a cheat sheet table of commands. *Updated 8 Aug
    2020*: Now that Fatty from HackTheBox has retired, I've updated this
    post to reflect some examples.

-   Aug 4, 2020

    ### [HTB Pwnbox Review](/htb-pwnbox-review.md)

    #ctf #hackthebox #pwnbox #parrot #vm #ssh #scp #tmux #api

    ![](/img/pwnbox-cover.png)

    I was recently talking with some of the folks over at HackTheBox,
    and they asked my thoughts about Pwnbox. My answer was that I'd
    never really used it, but that I would give it a look and provide
    feedback. The system is actually quite feature packed. It is only
    available to VIP members, but if you are VIP, it's worth spending a
    few minutes setting up the customizations. That way, if you should
    find yourself in need of an attack VM, you have it, and you might
    even just switch there.

-   Aug 1, 2020

    ### [HTB: Oouch](/htb-oouch.md)

    #htb-oouch #hackthebox #ctf #oauth #nmap #ftp #vsftpd #vhosts #csrf
    #gobuster #api #ssh #container #docker #dbus #iptables
    #command-injection #injection #uwsgi #waf #cron #htb-lame
    #htb-secnotes

    ![](/img/oouch-cover.png)

    The first half of Oouch built all around OAuth, a technology that is
    commonplace on the internet today, and yet I didn't understand well
    coming into the challenge. This box forced me to gain an
    understanding, and writing this post cemented that even further. To
    get user, I'll exploit an insecure implementation of OAuth via a
    CSRF twice. The first time to get access to qtc's account on the
    consumer application, and then to get access to qtc's data on the
    authorization server, which includes a private SSH key. With a
    shell, I'll drop into the consumer application container and look at
    how the site was blocking XSS attacks, which includes some messaging
    over DBus leading to iptables blocks. I'll pivot to the www-data
    user via a uWSGI exploit and then use command injection to get
    execution as root. In Beyond Root, I'll look at the command
    injection in the root DBus server code.

-   Jul 29, 2020

    ### [HTB: Lazy](/htb-lazy.md)

    #hackthebox #htb-lazy #ctf #nmap #ubuntu #php #gobuster #cookies
    #python #crypto #burp #burp-repeater #padding-oracle #padbuster
    #firefox #bit-flip #ssh #suid #path-hijack #hashcat #penglab #gdb
    #ltrace #cyberchef #des #peda #debug

    ![](/img/lazy-cover.png)

    Lazy was a really solid old HackTheBox machine. It's a medium
    difficulty box that requires identifying a unique and interesting
    cookie value and messing with it to get access to the admin account.
    I'll show both a padding oracle attack and a bit-flipping attack
    that each allow me to change the encrypted data to grant admin
    access. That access provides an SSH key and a shell. To privesc,
    there's a SetUID binary that is vulnerable to a path hijack attack.
    In Beyond Root, I'll poke at the PHP source for the site, identify a
    third way to get logged in as admin, and do a bit of debugging on
    the SetUID binary.

-   Jul 25, 2020

    ### [HTB: Cascade](/htb-cascade.md)

    #hackthebox #htb-cascade #ctf #nmap #rpc #ldap #ldapsearch #smb
    #tightvnc #vncpwd #evil-winrm #crackmapexec #sqlite #dnspy #debug
    #ad-recycle #oscp-plus

    ![](/img/cascade-cover.png)

    Cascade was an interesting Windows all about recovering credentials
    from Windows enumeration. I'll find credentials for an account in
    LDAP results, and use that to gain SMB access, where I find a
    TightVNC config with a different users password. From there, I get a
    shell and access to a SQLite database and a program that reads and
    decrypts a password from it. That password allows access to an
    account that is a member of the AD Recycle group, which I can use to
    find a deleted temporary admin account with a password, which still
    works for the main administrator account, providing a shell.

-   Jul 22, 2020

    ### [HTB: Shrek](/htb-shrek.md)

    #ctf #hackthebox #htb-shrek #nmap #php #gobuster #audacity
    #steganography #crypto #ssh #ecc #seccure #python #chown #wildcard
    #ghidra #pspy #passwd #extended-attributes #xattr #lsattr #cron
    #suid

    ![](/img/shrek-cover.png)

    Shrek is another 2018 HackTheBox machine that is more a string of
    challenges as opposed to a box. I'll find an uploads page in the
    website that doesn't work, but then also find a bunch of malware (or
    malware-ish) files in the uploads directory. One of them contains a
    comment about a secret directory, which I'll check to find an MP3
    file. Credentials for the FTP server are hidden in a chunk of the
    file at the end. On the FTP server, there's an encrypted SSH key,
    and a bunch of files full of base64-encoded data. Two have a
    passphrase and an encrypted blob, which I'll decrypt to get the SSH
    key password, and use to get a shell. To privesc, I'll find a
    process running chmod with a wildcard, and exploit that to change
    the ownership of the passwd file to my user, so I can edit it and
    get a root shell. In Beyond Root, I'll examine the text file in the
    directory and why it doesn't get it changed ownership, look at the
    automation and find a curious part I wasn't expecting, and show an
    alternative root based on that automation (which may be the intended
    path).

-   Jul 18, 2020

    ### [HTB: Sauna](/htb-sauna.md)

    #ctf #hackthebox #htb-sauna #nmap #windows #ldapsearch #ldap
    #kerberos #seclists #as-rep-roast #getnpusers #hashcat #evil-winrm
    #smbserver #winpeas #autologon-credentials #bloodhound #sharphound
    #neo4j #dcsync #secretsdump #mimikatz #wmiexec #psexec #oscp-plus

    ![](/img/sauna-cover.png)

    Sauna was a neat chance to play with Windows Active Directory
    concepts packaged into an easy difficulty box. I'll start by using a
    Kerberoast brute force on usernames to identify a handful of users,
    and then find that one of them has the flag set to allow me to grab
    their hash without authenticating to the domain. I'll AS-REP Roast
    to get the hash, crack it, and get a shell. I'll find the next users
    credentials in the AutoLogon registry key. BloodHound will show that
    user has privileges the allow it to perform a DC Sync attack, which
    provides all the domain hashes, including the administrators, which
    I'll use to get a shell.

-   Jul 14, 2020

    ### [HTB: Tenten](/htb-tenten.md)

    #hackthebox #htb-tenten #ctf #nmap #wordpress #wpscan #gobuster
    #wp-job-manager #cve-2015-6668 #python #steganography #steghide #ssh
    #john #sudo #mysql

    ![](/img/tenten-cover.png)

    Tenten had a lot of the much more CTF-like aspects that were more
    prevalent in the original HTB machine, like a uploaded hacker image
    file from which I will extract an SSH private key from it using
    steganography. I learned a really interesting lesson about wpscan
    and how to feed it an API key, and got to play with a busted
    WordPress plugin. In Beyond Root I'll poke a bit at the WordPress
    database and see what was leaking via the plugin exploit.

-   Jul 11, 2020

    ### [HTB: Book](/htb-book.md)

    #hackthebox #ctf #htb-book #nmap #ubuntu #gobuster #sql-truncation
    #sql #xss #lfi #pspy #logrotate #logrotten #crontab #oscp-plus

    ![](/img/book-cover.png)

    Getting a foothold on Book involved identifying and exploiting a few
    vulnerabilities in a website for a library. First there's a SQL
    truncation attack against the login form to gain access as the admin
    account. Then I'll use a cross-site scripting (XSS) attack against a
    PDF export to get file read from the local system. This is
    interesting because typically I think of XSS as something that I
    present to another user, but in this case, it's the PDF generate
    software. I'll use this to find a private SSH key and get a shell on
    the system. To get root, I'll exploit a regular logrotate cron using
    the logrotten exploit, which is a timing against against how
    logrotate worked. In Beyond Root, I'll look at the various crons on
    the box and how they made it work and cleaned up.

-   Jul 7, 2020

    ### [HTB: Bank](/htb-bank.md)

    #htb-bank #hackthebox #ctf #nmap #vhosts #dns #dig #zone-transfer
    #wfuzz #gobuster #burp #regex #burp-repeater #filter #suid #php
    #passwd

    ![](/img/bank-cover.png)

    Bank was an pretty straight forward box, though two of the major
    steps had unintended alternative methods. I'll enumerate DNS to find
    a hostname, and use that to access a bank website. I can either find
    creds in a directory of data, or bypass creds all together by
    looking at the data in the HTTP 302 redirects. From there, I'll
    upload a PHP webshell, bypassing filters, and get a shell. To get
    root, I can find a backdoor SUID copy of dash left by the
    administrator, or exploit write privileges in /etc/passwd. In Beyond
    Root, I'll look at the coding mistake in the 302 redirects, and show
    how I determined the SUID binary was dash.

-   Jul 4, 2020

    ### [HTB: ForwardSlash](/htb-forwardslash.md)

    #htb-forwardslash #ctf #hackthebox #ubuntu #nmap #php #vhosts #wfuzz
    #gobuster #burp #burp-repeater #rfi #lfi #xxe #credentials #ssh
    #sudo #suid #python #luks #crypto

    ![](/img/forwardslash-cover.png)

    ForwardSlash starts with enumeration of a hacked website to identify
    and exploit at least one of two LFI vulnerabilities (directly using
    filters to base64 encode or using XXE) to leak PHP source which
    includes a password which can be used to get a shell. From there,
    I'll exploit a severely non-functional "backup" program to get file
    read as the other user. With this, I'll find a backup of the
    website, and find different credentials in one of the pages, which I
    can use for a shell as the second user. To root, I'll break a
    homespun encryption algorithm to load an encrypted disk image which
    contains root's private SSH key. In Beyond Root, I'll dig into the
    website source to understand a couple surprising things I found
    while enumerating.

-   Jun 30, 2020

    ### [HTB: Blocky](/htb-blocky.md)

    #hackthebox #ctf #htb-blocky #nmap #wordpress #java #jar #decompile
    #jd-gui #phpmyadmin #wpscan #ssh #sudo #oswe-like #oscp-like

    ![](/img/blocky-cover.png)

    Blocky really was an easy box, but did require some discipline when
    enumerating. It would be easy to miss the /plugins path that hosts
    two Java Jar files. From one of those files, I'll find creds, which
    as reused by a user on the box, allowing me to get SSH access. To
    escalate to root, the user is allowed to run any command with sudo
    and password, which I'll use to sudo su returning a session as root.

-   Jun 27, 2020

    ### [HTB: PlayerTwo](/htb-playertwo.md)

    #ctf #htb-playertwo #hackthebox #nmap #vhosts #gobuster #wfuzz
    #twirp #proto3 #api #totp #signing #binwalk #hexedit #pspy #php
    #linux #chisel #mqtt #paho #python #ssh #exploit #htb-rope #heap
    #tcache #ldd #patchelf #ghidra #checksec #gdb #pwntools
    #type-juggling #pwngdb #htb-ellingson #htb-player

    ![](/img/playertwo-cover.png)

    PlayerTwo was just a monster of a box. Enumeration across three
    virtual hosts reveals a Twirp API where I can leak some credentials.
    Another API can be enumerated to find backup codes for for the 2FA
    for the login. With creds and backup codes, I can log into the site,
    which has a firmware upload section. The example firmware is signed,
    but only the first roughly eight thousand bytes. I'll find a way to
    modify the arguments to a call to system to get execution and a
    shell. With a shell, I see a MQTT message queue on localhost, and
    connecting to it, I'll find a private SSH key being sent, which I
    can use to get a shell as the next user. Finally, to get to root,
    I'll do a heap exploit against a root SUID binary to get a shell. In
    a Beyond Root section that could be its own blog post, I'll dig into
    a few unintended ways to skips parts of the intended path, and dig
    deeper on others.

-   Jun 23, 2020

    ### [HTB: Popcorn](/htb-popcorn.md)

    #htb-popcorn #hackthebox #ctf #nmap #ubuntu #karmic #gobuster
    #torrent-hoster #filter #webshell #php #upload #cve-2010-0832
    #arbitrary-write #passwd #dirtycow #ssh #oswe-like #oscp-like
    #htb-nineveh

    ![](/img/popcorn-cover.png)

    Popcorn was a medium box that, while not on TJ Null's list, felt
    very OSCP-like to me. Some enumeration will lead to a torrent
    hosting system, where I can upload, and, bypassing filters, get a
    PHP webshell to run. From there, I will exploit CVE-2010-0832, a
    vulnerability in the linux authentication system (PAM) where I can
    get it to make my current user the owner of any file on the system.
    There's a slick exploit script, but I'll show manually exploiting it
    as well. I'll quickly also show DirtyCow since it does work here.

-   Jun 20, 2020

    ### [HTB: ServMon](/htb-servmon.md)

    #htb-servmon #hackthebox #ctf #nmap #windows #ftp #nvms-1000
    #gobuster #wfuzz #searchsploit #directory-traversal #lfi #ssh
    #crackmapexec #tunnel #exploit-db #nsclient++ #oscp-like

    ![](/img/servmon-cover.png)

    ServMon was an easy Windows box that required two exploits. There's
    a hint in the anonymous FTP as to the location of a list of
    passwords. I can use a directory traversal bug in a NVMS 1000 web
    instance that will allow me to leak those passwords, and use one of
    them over SSH to get a shell. Then I can get the local config for
    the NSClient++ web instance running on TCP 8443, and use those
    credentials plus another exploit to get a SYSTEM shell.

-   Jun 17, 2020

    ### [HTB Endgame: XEN](/endgame-xen.md)

    #endgame #ctf #hackthebox #htb-xen #nmap #iis #citrix #xenapp #smtp
    #smtp-user-enum #phishing #swaks #escape #alwaysinstallelevated
    #powerup #uac-bypass #msfvenom #metasploit #tunnel #kerberoast
    #getuserspns #hashcat #powerview #crackmapexec #password-spray #ppk
    #puttygen #proxychains #ssh #kwprocessor #keyboard-walks #netscaler
    #tcpdump #packet-capture #scp #ssh #wireshark #ldap #bloodhound
    #sharphound #xfreerdp #winrm #evil-winrm #sebackupprivilege #ntds
    #diskshadow #secretsdump #wmiexec #copy-filesebackupprivilege
    #active-directory

    ![](/img/endgame-xen-cover.png)

    Endgame XEN is all about owning a small network behind a Citrix
    virtual desktop environment. I'll phish creds for the Citrix
    instance from users in the sales department, and then use them to
    get a foothold. I'll break out of the restrictions in that
    environment, and then get administrator access. From there I'll
    pivot into the domain, finding a Kerberoastable user and breaking
    the hash to get access to an SMB share with an encrypted SSH key.
    I'll break that, and get access to the NetScaler device, where I'll
    capture network traffic to find service creds in LDAP traffic. I'll
    spray those creds against the domain to find they also work for a
    backup service, which I'll use to access the DC, and to exfil the
    Active Directory database, where I can find the domain administrator
    hash.

-   Jun 13, 2020

    ### [HTB: Monteverde](/htb-monteverde.md)

    #htb-monteverde #hackthebox #ctf #nmap #windows #active-directory
    #smb #smbclient #smbmap #rpc #rpcclient #crackmapexec
    #password-spray #credentials #azure-active-directory #evil-winrm
    #azure-connect #powershell #sqlcmd #mssql #oscp-plus

    ![](/img/monteverde-cover.jpg)

    For the third week in a row, a Windows box on the easier side of the
    spectrum with no web server retires. Monteverde was focused on Azure
    Active Directory. First I'll look at RPC to get a list of users, and
    then check to see if any used their username as their password. With
    creds for SABatchJobs, I'll gain access to SMB to find an XML config
    file with a password for one of the users on the box who happens to
    have WinRM permissions. From there, I can abuse the Azure active
    directory database to leak the administrator password. In Beyond
    Root, I'll look deeper into two versions of the PowerShell script I
    used to leak the creds, and how they work or don't work.

-   Jun 8, 2020

    ### [HTB Endgame: P.O.O.](/endgame-poo.md)

    #endgame #ctf #hackthebox #htb-poo #nmap #iis #windows #gobuster
    #ds-store #iis-shortname #wfuzz #mssql #mssqlclient
    #mssql-linked-servers #xp-cmdshell #mssql-triggers
    #sp_execute_external_script #web.config #ipv6 #winrm #sharphound
    #bloodhound #kerberoast #invoke-kerberoast #hashcat #powerview
    #juicypotato #active-directory

    ![](/img/endgame-poo-cover.png)

    Endgame Professional Offensive Operations (P.O.O.) was the first
    Endgame lab released by HTB. Endgame labs require at least Guru
    status to attempt (though now that P.O.O. is retired, it is
    available to all VIP). The lab contains two Windows hosts, and I'm
    given a single IP that represents the public facing part of the
    network. To collect all five flags, I'll take advantage of DS_STORE
    files and Windows short filenames to get creds for the MSSQL
    instance, abuse trust within MSSQL to escalate my access to allow
    for code execution. Basic xp_cmdshell runs as a user without much
    access, but Python within MSSQL runs as a more privileged user,
    allowing me access to a config file with the administrator
    credentials. I'll observe that WinRM is not blocked on IPv6, and get
    a shell. To pivot to the DC, I'll run SharpHound and see that a
    kerberoastable user has Generic All on the Domain Admins group, get
    the hash, break it, and add that user to DA.

-   Jun 6, 2020

    ### [HTB: Nest](/htb-nest.md)

    #htb-nest #ctf #hackthebox #nmap #smb #smbmap #smbclient #crypto #vb
    #visual-studio #dnspy #dotnetfiddle #crackmapexec
    #alternative-data-streams #psexec #oscp-plus #htb-hackback
    #htb-dropzone #htb-bighead

    ![](/img/nest-cover.png)

    Next was unique in that it was all about continually increasing SMB
    access, with a little bit of easy .NET RE thrown in. I probably
    would rate the box medium instead of easy, because of the RE, but
    that's nitpicking. I'll start with unauthenticated access to a
    share, and find a password for tempuser. With that access, I'll find
    an encrypted password for C.Smith. I'll also use a Notepad++ config
    to find a new directory I can access (inside one I can't), which
    reveals a Visual Basic Visual Studio project that includes the code
    to decrypt the password. With access as C.Smith, I can find the
    debug password for a custom application listening on 4386, and use
    that to leak another encrypted password. This time I'll debug the
    binary to read the decrpyted administrator password from memory, and
    use it to get a shell as SYSTEM with PSExec. When this box was first
    released, there was an error where the first user creds could
    successfully PSExec. I wrote a post on that back in January, but
    I've linked that post to this one on the left. In Beyond Root, I'll
    take a quick look at why netcat can't connect to the custom service
    on 4386, but telnet can.

-   Jun 1, 2020

    ### [Debugging CME, PSexec on HTB: Resolute](/resolute-more-beyond-root.md)

    #crackmapexec #smb #hackthebox #ctf #htb-resolute #windows
    #scmanager #sddl #dacl #psexec #github #source-code #metasploit
    #wireshark smb #cyberchef #scdbg #htb-nest

    ![](/img/resolute-br-cover.png)

    When I ran CrackMapExec with ryan's creds against Resolute, it
    returned Pwn3d!, which is weird, as none of the standard PSExec
    exploits I attempted worked. Beyond that, ryan wasn't an
    administrator, and didn't have any writable shares. I'll explore the
    CME code to see why it returned Pwn3d!, look at the requirements for
    a standard PSExec, and then debug the Metasploit exploit that does
    go directly to SYSTEM with ryan's creds.

-   May 30, 2020

    ### [HTB: Resolute](/htb-resolute.md)

    #htb-resolute #ctf #hackthebox #nmap #smb #smbmap #smbclient
    #rpcclient #rpc #password-spray #crackmapexec #evil-winrm
    #pstranscript #net-use #dnscmd #msfvenom #smbserver #lolbas #winrm
    #htb-forest #htb-hackback

    ![](/img/resolute-cover.png)

    It's always interesting when the initial nmap scan shows no web
    ports as was the case in Resolute. The attack starts with
    enumeration of user accounts using Windows RPC, including a list of
    users and a default password in a comment. That password works for
    one of the users over WinRM. From there I find the next users creds
    in a PowerShell transcript file. That user is in the DnsAdmins
    group, which allows for an attack against dnscmd to get SYSTEM. In
    beyond root, I'll identify the tool the box creator used to connect
    to the box and generate the PowerShell transcript.

-   May 28, 2020

    ### [HTB: Grandpa](/htb-grandpa.md)

    #hackthebox #ctf #htb-grandpa #windows-2003 #iis #nmap #gobuster
    #webdav #davtest #searchsploit #msfvenom #cve-2017-7269
    #explodingcan #metasploit #icacls #systeminfo
    #windows-exploit-suggester #seimpersonate #churrasco #oscp-like
    #htb-granny

    ![](/img/grandpa-cover.png)

    Grandpa was one of the really early HTB machines. It's the kind of
    box that wouldn't show up in HTB today, and frankly, isn't as fun as
    modern targets. Still, it's a great proxy for the kind of things
    that you'll see in OSCP, and does teach some valuable lessons,
    especially if you try to work without Metasploit. With Metasploit,
    this box can probably be solved in a few minutes. Typically, the
    value in avoiding Metasploit comes from being able to really
    understand the exploits and what's going on. In this case, it's more
    about the struggle of moving files, finding binarys, etc.

-   May 23, 2020

    ### [HTB: Rope](/htb-rope.md)

    #hackthebox #ctf #htb-rope #directory-traversal #format-string
    #pwntools #bruteforce #pwn #python #ida #aslr #pie #sudo #library
    #tunnel #canary #rop

    ![](/img/rope-cover.png)

    Rope was all about binary exploitation. For initial access, I'll use
    a directory traversal bug in the custom webserver to get a copy of
    that webserver as well as it's memory space. From there, I can use a
    format string vulnerability to get a shell. To get to the next user,
    I'll take advantage of an unsafe library load in a program that the
    current user can run with sudo. Finally, for root, I'll exploit a
    locally running piece of software that requires brute forcing the
    canary, RBP, and return addresses to allows for an overflow and
    defeat PIE, and then doing a ROP libc leak to get past ASLR, all to
    send another ROP which provides a shell.

-   May 19, 2020

    ### [HTB: Arctic](/htb-arctic.md)

    #htb-arctic #ctf #hackthebox #nmap #coldfusion #javascript
    #searchsploit #jsp #upload #metasploit #directory-traversal
    #crackstation #windows-exploit-suggester #ms10-095 #oscp-like

    ![](/img/arctic-cover.png)

    Arctic would have been much more interesting if not for the
    30-second lag on each HTTP request. Still, there's enough of an
    interface for me to find a ColdFusion webserver. There are two
    different paths to getting a shell, either an unauthenticated file
    upload, or leaking the login hash, cracking or using it to log in,
    and then uploading a shell jsp. From there, I'll use MS10-059 to get
    a root shell.

-   May 16, 2020

    ### [HTB: Patents](/htb-patents.md)

    #ctf #htb-patents #hackthebox #nmap #upload #libreoffice #office
    #xxe #gobuster #docx #custom-folder #sans-holiday-hack #dtd
    #log-poisoning #directory-traversal #lfi #webshell #docker #pspy
    #password-reuse #git #reverse-engineering #bof #exploit #python
    #pwntools #ghidra #pwn #onegadget #rop #libc #libc-database #df
    #mount #cyberchef #php #payloadsallthethings

    ![](/img/patents-cover.png)

    Patents was a really tough box, that probably should have been rated
    insane. I'll find two listening services, a webserver and a custom
    service. I'll exploit XXE in Libre Office that's being used to
    convert docx files to PDFs to leak a configuration file, which
    uncovers another section of the site. In that section, there is a
    directory traversal vulnerability that allows me to use log
    poisoning to get execution and a shell in the web docker container.
    To get root in that container, I'll find a password in the process
    list. As root, I get access to an application that's communicating
    with the custom service on the host machine. I'll also find a Git
    repo with the server binary, which I can reverse and find an exploit
    in, resulting in a shell as root on the host machine. In Beyond
    Root, I'll look at chaining PHP filters to exfil larger data over
    XXE.

-   May 12, 2020

    ### [ngrok FTW](/ngrok-ftw.md)

    #ctf #ngrok #tunnel

    ![](/img/ngrok-cover.png)

    When I did the COVID-19 CTF, I needed a way to exploit one of the
    targets and have it callback to me. I spent a lot of time trying to
    get socket reuse shellcode to work, and if I had just tried a
    reverse shell payload, I would have gotten there a lot sooner. But
    getting the connection back to me seemed hard. I'd heard of ngrok
    for years as some kind of tunneling service. I'd seen malware use
    it. But I never really looked into how it worked or how I could use
    it, and it turns out to be super handy and really dead simple. This
    is barely worth a blog post, and it won't help with HackTheBox, but
    it's just one of those things that when you have a need for it, it's
    so easy and useful.

-   May 9, 2020

    ### [HTB: Obscurity](/htb-obscurity.md)

    #htb-obscurity #ctf #hackthebox #nmap #python #gobuster #dirsearch
    #wfuzz #python-injection #command-injection #code-analysis #crypto
    #credentials #race-condition #injection #lxd #lxc #arbitrary-write
    #python-path #htb-mischief

    ![](/img/obscurity-cover.jpg)

    Obscuirt was a medium box that centered on finding bugs in Python
    implementations of things - a webserver, an encryption scheme, and
    an SSH client. I'll start by locating the source for the custom
    Python webserver, and injecting into it to get code execution and a
    shell. I'll pivot to the next user abusing a poor custom cipher to
    decrypt a password. To get root, I'll show four different ways. Two
    involve an SSH-like script that I can abuse both via a race
    condition to leak the system hashes and via injection to run a
    command as root instead of the authed user. The other two were
    patches after the box was released, but I'll show them, exploiting
    the Python path, and exploiting the lxd group.

-   May 4, 2020

    ### [COVID-19 CTF: CovidScammers](/covid-19-ctf-covidscammers.md)

    #ctf #wireshark #reverse-engineering #ltrace #crypto #python
    #pwntools #fuzz #bof #pattern-create #shellcode #dup2

    ![](/img/covid19ctf-cover.png)

    Last Friday I competed with the Neutrino Cannon CTF team in the
    COVID-19 CTF created by Threat Simulations and RunCode as a part of
    DERPCON 2020. I focused much of my efforts on a section named
    CovidScammers. It was a really interesting challenge that
    encompassed forensics, reverseing, programming, fuzzing, and
    exploitation. I managed to get a shell on the C2 server just as I
    had to sign off for the day, so I didn't complete the next steps
    that unlocked after that. Still, I really enjoyed the challenge and
    wanted to show the steps up to that point.

-   May 2, 2020

    ### [HTB: OpenAdmin](/htb-openadmin.md)

    #htb-openadmin #hackthebox #ctf #nmap #gobuster #opennetadmin
    #searchsploit #password-reuse #webshell #ssh #john #sudo #gtfobins
    #oscp-like

    ![](/img/openadmin-cover.png)

    OpenAdmin provided a straight forward easy box. There's some
    enumeration to find an instance of OpenNetAdmin, which has a remote
    coded execution exploit that I'll use to get a shell as www-data.
    The database credentials are reused by one of the users. Next I'll
    pivot to the second user via an internal website which I can either
    get code execution on or bypass the login to get an SSH key.
    Finally, for root, there's a sudo on nano that allows me to get a
    root shell using GTFObins.

-   Apr 30, 2020

    ### [HTB: SolidState](/htb-solidstate.md)

    #hackthebox #ctf #htb-solidstate #nmap #james #pop3 #smtp
    #bash-completion #ssh #rbash #credentials #directory-traversal #cron
    #pspy #oscp-like

    ![](/img/solidstate-cover.png)

    The biggest trick with SolidState was not focusing on the website
    but rather moving to a vulnerable James mail client. In fact, if I
    take advantage of a restrictred shell escape, I don't even need to
    exploit James, but rather just use the admin interface with default
    creds to gain access to the various mailboxes, find SSH creds,
    escape rbash, and continue from there. But I will also show how to
    exploit James using a directory traversal vulnerability to write a
    bash completion script and then trigger that with a SSH login. For
    root, there's a cron running an writable python script, which I can
    add a reverse shell to. In Beyond Root, I'll look at payloads for
    the James exploit, both exploring what didn't work, and improving
    the OPSEC.

-   Apr 25, 2020

    ### [HTB: Control](/htb-control.md)

    #ctf #hackthebox #htb-control #nmap #mysql #http-header #wfuzz #sqli
    #injection #mysql-file-write #hashcat #powershell-run-as #winpeas
    #registry-win #service #windows-service #powershell #oscp-plus
    #htb-nest

    ![](/img/control-cover.png)

    Control was a bit painful for someone not comfortable looking deep
    at Windows objects and permissions. It starts off simply enough,
    with a website where I'll have to forge an HTTP header to get into
    the admin section, and then identify an SQL injection to write a
    webshell and dump user hashes. I can use the webshell to get a
    shell, and then one of the cracked hashes to pivot to a different
    user. From there, I'll find that users can write the registry keys
    associated with Services. I'll construct some PowerShell to find
    potential services that I can restart, and then modify them to run
    NetCat to return a shell.

-   Apr 22, 2020

    ### [HTB: Nineveh](/htb-nineveh.md)

    #htb-nineveh #hackthebox #ctf #nmap #vhosts #gobuster #phpinfo
    #bruteforce #phpliteadmin #sql #sqlite #searchsploit #hydra
    #directory-traversal #lfi #webshell #strings #binwalk #tar #ssh
    #port-knocking #knockd #chkrootkit #pspy #oscp-like

    ![](/img/nineveh-cover.png)

    There were several parts about Nineveh that don't fit with what I
    expect in a modern HTB machine - steg, brute forcing passwords, and
    port knocking. Still, there were some really neat attacks. I'll show
    two ways to get a shell, by writing a webshell via phpLiteAdmin, and
    by abusing PHPinfo. From there I'll use my shell to read the knockd
    config and port knock to open SSH and gain access using the key pair
    I obtained from the steg image. To get root, I'll exploit chkroot,
    which is running on a cron.

-   Apr 18, 2020

    ### [HTB: Mango](/htb-mango.md)

    #hackthebox #htb-mango #ctf #nmap #certificate #vhosts #wfuzz #nosql
    #mongo #injection #nosql-injection #python #ssh #password-reuse #jjs
    #gtfobins #sudoers #oscp-plus #oswe-like

    ![](/img/mango-cover.png)

    Mango's focus was exploiting a NoSQL document database to bypass an
    authorization page and to leak database information. Once I had the
    users and passwords from the database, password reuse allowed me to
    SSH as one of the users, and then su to the other. From there, I'll
    take advantage of a SUID binary associated with Java, jjs. I'll show
    both file read and get a shell by writing a public SSH key into
    root's authorized keys file.

-   Apr 14, 2020

    ### [HTB: Cronos](/htb-cronos.md)

    #htb-cronos #ctf #hackthebox #nmap #dns #nslookup #zone-transfer
    #dig #gobuster #vhosts #vhosts #laravel #searchsploit #sqli
    #injection #command-injection #burp #linpeas #cron #php #mysql
    #cve-2018-15133 #metasploit #oscp-like

    ![](/img/cronos-cover.png)

    Cronos didn't provide anything too challenging, but did present a
    good intro to many useful concepts. I'll enumerate DNS to get the
    admin subdomain, and then bypass a login form using SQL injection to
    find another form where I could use command injections to get code
    execution and a shell. For privesc, I'll take advantage of a root
    cron job which executes a file I have write privileges on, allowing
    me to modify it to get a reverse shell. In Beyond Root, I'll look at
    the website and check in on how I was able to do both the SQLi and
    the command injection, as well as fail to exploit the machine with a
    Laravel PHP framework deserialization bug, and determine why.

-   Apr 11, 2020

    ### [HTB: Traverxec](/htb-traverxec.md)

    #htb-traverxec #hackthebox #ctf #nmap #nostromo #searchsploit
    #metasploit #htpasswd #hashcat #ssh #john #gtfobins #journalctrl
    #oscp-like

    ![](/img/traverxec-cover.png)

    Traverxec was a relatively easy box that involved enumerating and
    exploiting a less popular webserver, Nostromo. I'll take advantage
    of a RCE vulnerability to get a shell on the host. I could only find
    a Metasploit script, but it was a simple HTTP request I could
    recreate with curl. Then I'll pivot into the users private files
    based on his use of a web home directory on the server. To get root,
    I'll exploit sudo used with journalctrl.

-   Apr 9, 2020

    ### [HTB: Sniper Beyond Root](/htb-sniper-beyondroot.md)

    #hackthebox #ctf #htb-sniper #cron #scheduled-task #persistence
    #powershell #startup #magic #htb-secnotes #htb-re

    ![](/img/sniper-br-cover.png)

    In Sniper, the administrator user is running CHM files that are
    dropped into c:\\docs, and this is the path from the chris user to
    administrator. I was asked on Twitter how the CHM was executed, so I
    went back to take a look.

-   Apr 8, 2020

    ### [HTB: More Lame](/htb-lame-more.md)

    #hackthebox #htb-lame #ctf #nmap #distcc #searchsploit
    #cve-2004-2687 #cve-2008-0166 #ssh #rsa #suid #gtfobins #wireshark
    #python #oscp-like #htb-irked

    ![](/img/lame-more-cover.png)

    After I put out a Lame write-up yesterday, it was pointed out that I
    skipped an access path entirely - distcc. Yet another vulnerable
    service on this box, which, unlike the Samba exploit, provides a
    shell as a user, providing the opportunity to look for PrivEsc
    paths. This box is so old, I'm sure there are a ton of kernel
    exploits available. I'll skip those for now focusing on ~~two~~
    three paths to root - finding a weak public SSH key, using SUID
    nmap, and backdoored UnrealIRCd.

-   Apr 7, 2020

    ### [HTB: Lame](/htb-lame.md)

    #hackthebox #htb-lame #ctf #nmap #ftp #vsftpd #samba #searchsploit
    #exploit #metasploit #oscp-like #htb-lacasadepapel

    ![](/img/lame-cover.png)

    Lame was the first box released on HTB (as far as I can tell), which
    was before I started playing. It's a super easy box, easily knocked
    over with a Metasploit script directly to a root shell. Still, it
    has some very OSCP-like aspects to it, so I'll show it with and
    without Metasploit, and analyze the exploits. It does throw one
    head-fake with a VSFTPd server that is a vulnerable version, but
    with the box configured to not allow remote exploitation. I'll dig
    into VSFTPd in Beyond Root.

-   Apr 4, 2020

    ### [HTB: Registry](/htb-registry.md)

    #htb-registry #hackthebox #ctf #nmap #wfuzz #vhosts #gobuster #zcat
    #docker #bolt-cms #searchsploit #api #docker-fetch #ssh #credentials
    #sqlite #hashcat #webshell #firewall #tunnel #restic #cron

    ![](/img/registry-cover.png)

    Registry provided the chance to play with a private Docker registry
    that wasn't protected by anything other than a weak set of
    credentials. I'll move past that to get the container and the SSH
    key and password inside. From there, I'll exploit an instance of
    Bolt CMS to pivot to the www-data user. As www-data, I can access
    the Restic backup agent as root, and exploit that to get both the
    root flag and a root ssh key.

-   Mar 28, 2020

    ### [HTB: Sniper](/htb-sniper.md)

    #hackthebox #ctf #htb-sniper #nmap #commando #gobuster #lfi #rfi
    #wireshark #samba #log-poisoning #powershell #webshell
    #powershell-run-as #chm #nishang #oscp-plus

    ![](/img/sniper-cover.png)

    Sniper involved utilizing a relatively obvious file include
    vulnerability in a web page to get code execution and then a shell.
    The first privesc was a common credential reuse issue. The second
    involved poisoning a `.chm` file to get code execution as the
    administrator.

-   Mar 24, 2020

    ### [update-alternatives](/update-alternatives.md)

    #linux #update-alternatives #nc #java #namei #bash

    ![](/img/Linux.png)

    Debian Linux (and its derivatives like Ubuntu and Kali) has a system
    called alternatives that's designed to manage having different
    version of some software, or aliasing different commands to
    different versions within the system. Most of the time, this is
    managed by the package management system. When you run apt install
    x, it may do some of this behind the scenes for you. But there are
    times when it is really useful to know how to interact with this
    yourself. For example, I'm currently working on a challenge that
    requires using an older version of Java to interact with a file.
    I'll use update-altneratives to install the new Java version, and
    then to change what version java, javac, jar, etc utilize.

-   Mar 21, 2020

    ### [HTB: Forest](/htb-forest.md)

    #hackthebox #ctf #htb-forest #nmap #active-directory #dig #dns #rpc
    #rpcclient #as-rep-roast #hashcat #winrm #evil-winrm #sharphound
    #smbserver #bloodhound #dcsync #aclpwn #wireshark #scheduled-task
    #oscp-like #htb-active #htb-reel #htb-sizzle

    ![](/img/forest-cover.png)

    One of the neat things about HTB is that it exposes Windows concepts
    unlike any CTF I'd come across before it. Forest is a great example
    of that. It is a domain controller that allows me to enumerate users
    over RPC, attack Kerberos with AS-REP Roasting, and use Win-RM to
    get a shell. Then I can take advantage of the permissions and
    accesses of that user to get DCSycn capabilities, allowing me to
    dump hashes for the administrator user and get a shell as the admin.
    In Beyond Root, I'll look at what DCSync looks like on the wire, and
    look at the automated task cleaning up permissions.

-   Mar 14, 2020

    ### [HTB: Postman](/htb-postman.md)

    #hackthebox #htb-postman #ctf #nmap #webmin #redis #ssh #john
    #credentials #cve-2019-12840 #metasploit #oscp-like

    ![](/img/postman-cover.png)

    Postman was a good mix of easy challenges providing a chance to play
    with Redis and exploit Webmin. I'll gain initial access by using
    Redis to write an SSH public key into an authorized_keys file. Then
    I'll pivot to Matt by cracking his encrypted SSH key and using the
    password. That same password provides access to the Webmin instance,
    which is running as root, and can be exploited to get a shell. In
    Beyond Root, I'll look at a Metasploit Redis exploit and why it
    failed on this box.

-   Mar 7, 2020

    ### [HTB: Bankrobber](/htb-bankrobber.md)

    #ctf #htb-bankrobber #hackthebox #nmap #mysql #smb #gobuster
    #cookies #xss #csrf #sqli #injection #bof #ida #chisel #python
    #pattern-create #phantom-js #reverse-engineering #oscp-like
    #htb-giddy #htb-querier

    ![](/img/bankrobber-cover.png)

    BankRobber was neat because it required exploiting the same exploit
    twice. I'll find a XSS vulnerability that I can use to leak the
    admin user's cookie, giving me access to the admin section of the
    site. From there, I'll use a SQL injection to leak the source for
    one of the PHP pages which shows it can provide code execution, but
    only accepts requests from localhost. I'll use the same XSS
    vulnerability to get the admin to send that request from Bankrobber,
    returning a shell. To privesc to SYSTEM, I'll find a binary running
    as SYSTEM and listening only on localhost. I'm not able to grab a
    copy of the binary as my current user, but I can create a tunnel and
    poke at it directly. First I'll brute force a 4-digit pin, and then
    I'll discover a simple buffer overflow that allows me to overwrite a
    string that is the path to an executable that's later run. I can
    overwrite that myself to get a shell. In Beyond Root, I'll look at
    how the XSS was automated and at the executable now that I have
    access.

-   Feb 29, 2020

    ### [HTB: Scavenger](/htb-scavenger.md)

    #ctf #hackthebox #htb-scavenger #nmap #whois #sqli #injection
    #zone-transfer #exim #cve-2019-10149 #vhosts #wfuzz #dirsearch
    #wpscan #mantisbt #webshell #ir #python #python-cmd #mkfifo-shell
    #forward-shell #hydra #rootkit #ida #iptables #reverse-engineering
    #htb-stratosphere

    ![](/img/scavenger-cover.png)

    Scavenger required a ton of enumeration, and I was able to solve it
    without ever getting a typical shell. The box is all about
    enumerating the different sites on the box (and using an SQL
    injection in whois to get them all), and finding one is hacked and a
    webshell is left behind. The firewall rules make getting a reverse
    shell impossible, but I'll use the RCE to enumerate the box (and
    build a stateful Python shell in the process, though it's not
    necessary). Enumerating will turn up several usernames and
    passwords, which I'll use for FTP access to get more creds, the user
    flag, and a copy of a rootkit that's running on the box. A
    combination of finding the rootkit described on a webpage via
    Googling and reversing to see how it's changed gives me the ability
    to trigger any session to root. In Beyond Root, I'll look more
    in-depth at the SQLi in the whois server, examine the iptables rules
    that made getting a reverse shell impossible, and show how to use
    CVE-2019-10149 against the EXIM mail server to get execution as root
    as well.

-   Feb 22, 2020

    ### [HTB: Zetta](/htb-zetta.md)

    #ctf #htb-zetta #hackthebox #nmap #ftp-bounce #rfc-2428 #ipv6 #rsync
    #credentials #ssh #tudu #syslog #git #postgresql #sqli

    ![](/img/zetta-cover.png)

    Zetta starts off different from the start, using FTP Bounce attacks
    to identify the IPv6 address of the box, and then finding RSync
    listening on IPv6 only. I'll use limited RSync access to get the
    size of a user's password, and then brute force it to get access to
    the roy home directory, where I can write my key to the authorized
    keys file to get SSH access. I'll escalate to the postgres user with
    an SQL injection into Syslog, where the box author cleverly uses Git
    to show the config but not the most recent password. Finally, I'll
    recover the password for root using some logic and the postgres
    user's password. In Beyond Root, I'll look at the authentication for
    the FTP server that allowed any 32 character user with the username
    as the password, dig into the RSync config, and look at the bits of
    the Syslog config that were hidden from me.

-   Feb 15, 2020

    ### [HTB: Json](/htb-json.md)

    #hackthebox #htb-json #ctf #commando #nmap #deserialization #dotnet
    #javascript #deobfuscation #jsnice #gobuster #oauth #ysoserial.net
    #filezilla #chisel #ftp #dnspy #python #des #crypto #juicypotato
    #potato #oswe-like #htb-arkham

    ![](/img/json-cover.png)

    Json involved exploiting a .NET deserialization vulnerability to get
    initial access, and then going one of three ways to get root.txt.
    I'll show each of the three ways I'm aware of to escalate:
    Connecting to the FileZilla Admin interface and changing the users
    password; reversing a custom application to understand how to
    decrypt a username and password, which can then be used over the
    same FTP interface; and JuicyPotato to get a SYSTEM shell. Since
    this is a Windows host, I'll work it almost entirely from my Windows
    Commando VM.

-   Feb 1, 2020

    ### [HTB: RE](/htb-re.md)

    #hackthebox #ctf #htb-re #nmap #vhosts #jekyll #smbclient #smbmap
    #libreoffice #office #ods #macro #invoke-obfuscation #nishang
    #zipslip #winrar #cron #webshell #ghidra #xxe #responder #hashcat
    #evil-winrm #winrm #chisel #tunnel #usosvc #accesschk #service
    #service-hijack #diaghub #esf #mimikatz #hashes-org #htb-ai
    #htb-hackback #htb-helpline

    ![](/img/re-cover.png)

    RE was a box I was really excited about, and I was crushed when the
    final privesc didn't work on initial deployment. Still, it got
    patched, and two unintended paths came about as well, and everything
    turned out ok. I'll approach this write-up how I expected people to
    solve it, and call out the alternative paths (and what mistakes on
    my part allowed them) as well. I'll upload a malicious ods file to a
    malware sandbox where it is run as long as it is obfuscated. From
    there, I'll abuse WinRar slip vulnerability to write a webshell. Now
    as IIS user, I can access a new folder where Ghidra project files
    can be dropped to exploit an XXE in Ghidra. There's two unintended
    paths from IIS to SYSTEM using the UsoSvc and Zipslip and Diaghub,
    where then I have to get coby's creds to read root.txt. I'll show
    all of these, and look at some of the automation scripts (including
    what didn't work on initial deployment) in Beyond Root.

-   Jan 26, 2020

    ### [Digging into PSExec with HTB Nest](/digging-into-psexec-with-htb-nest.md)

    #hackthebox #ctf #htb-nest #psexec #smb #windows #scmanager #sddl
    #dacl #sacl #ace #icacls

    ![](/img/nest-unintended-cover.png)

    "You have to have administrator to PSExec." That's what I'd always
    heard. Nest released on HTB yesterday, and on release, it had an
    unintended path where a low-priv user was able to PSExec, providing
    a shell as SYSTEM. This has now been patched, but I thought it was
    interesting to see what was configured that allowed this non-admin
    user to get a shell with PSExec. Given this is a live box, I won't
    go into any of the details that still matter, saving that for a
    write-up in 20ish weeks or so.

-   Jan 25, 2020

    ### [HTB: AI](/htb-ai.md)

    #hackthebox #ctf #htb-ai #nmap #gobuster #text2speech #flite #sqli
    #tomcat #jdwp #jdb #jwdp-shellifier

    ![](/img/ai-cover.png)

    AI was a really clever box themed after smart speakers like Echo and
    Google Home. I'll find a web interface that accepts sound files, and
    use that to find SQL injection that I have to pass using words. Of
    course I'll script the creation of the audio files, and use that to
    dump credentials from the database that I can use to access the
    server. For privesc, I'll find an open Java Debug port on Tomcat
    running as root, and use that to get a shell.

-   Jan 18, 2020

    ### [HTB: Player](/htb-player.md)

    #hackthebox #ctf #htb-player #nmap #vhosts #ssh #searchsploit #wfuzz
    #burp #jwt #codiad #bfac #ffmpeg #lshell #webshell #deserialization
    #php #lfi #escape

    ![](/img/player-cover.png)

    Player involved a lot of recon, and pulling together pieces to go
    down multiple different paths to user and root. I'll start
    identifying and enumerating four different virtual hosts. Eventually
    I'll find a backup file with PHP source on one, and use it to get
    access to a private area. From there, I can use a flaw in FFMPEG to
    leak videos that contain the text contents of various files on
    Player. I can use that information to get credentials where I can
    SSH, but only with a *very* limited shell. However, I can use an SSH
    exploit to get code execution that provides limited and partial file
    read, which leads to more credentials. Those credentials are good
    for a Codiad instance running on another of the virtual hosts, which
    allows me to get a shell as www-data. There's a PHP script running
    as a cron as root that I can exploit either by overwriting a file
    include, or by writing serialized PHP data. In Beyond Root, I'll
    look at two more altnerative paths, one jumping right to shell
    against Codiad, and the other bypassing lshell.

-   Jan 14, 2020

    ### [Holiday Hack 2019: KringleCon2](/holidayhack2019/)

    #ctf #sans-holiday-hack

    ![](/img/hh19-cover.png)

    The 2019 SANS Holiday Hack Challenge presented a twisted take on how
    a villain, the Tooth Fairy, tried to take down Santa and ruin
    Christmas. It all takes place at the second annual Kringle Con,
    where the worlds leading security practitioners show up to hear
    talks and solve puzzles. Hosted at Elf-U, this years conference
    included [14 talks from leaders in information
    security](https://www.youtube.com/playlist?list=PLjLd1hNA7YVzyhhqBQaW-tF45xnS6oHAP),
    as well as 11 terminals / in-game puzzles and 13 objectives to
    figure out. In solving all of these, the Tooth Fairy's plot was
    foiled, and Santa was able to deliver presents on Christmas. As
    usual, the challenges were interesting and set up in such a way that
    it was very beginner friendly, with lots of hints and talks to
    ensure that you learned something while solving. While last year
    really started the trend of defensive themed challenges, 2019 had a
    ton of interesting defensive challenges, with hands on with machine
    learning as well as tools like Splunk and Graylog.

-   Jan 11, 2020

    ### [HTB: Bitlab](/htb-bitlab.md)

    #hackthebox #ctf #htb-bitlab #nmap #bookmark #javascript
    #obfuscation #webshell #git #gitlab #docker #ping-sweep #chisel
    #tunnel #psql #credentials #ssh #reverse-engineering #ida #x64dbg
    #git-hooks #reverse-engineering #oscp-plus

    ![](/img/bitlab-cover.png)

    Bitlab was a box centered around automation of things, even if the
    series challenges were each rather unrealistic. It starts with a
    Gitlab instance where the help link has been changed to give access
    to javascript encoded credentials. Once logged in, I have access to
    the codebase for the custom profile pages use in this instance, and
    there's automation in place such that when I merge a change into
    master, it goes live right away. So I can add a webshell and get
    access to the box. In the database, I'll find the next users
    credentials for SSH access. For Root, I'll reverse engineer a
    Windows executable which is executing Putty with credentials, and
    use those creds to get root. In Beyond Root, I'll look at an
    unintended path from www-data to root using git hooks, and explore a
    call to `GetUserNameW` that is destined to fail.

-   Jan 4, 2020

    ### [HTB: Craft](/htb-craft.md)

    #hackthebox #ctf #htb-craft #nmap #gogs #api #wfuzz #flask #python
    #python-eval #git #ssh #vault-project #jwt #john #jwtcat

    ![](/img/craft-cover.png)

    Craft was a really well designed medium box, with lots of
    interesting things to poke at, none of which were too difficult.
    I'll find credentials for the API in the Gogs instance, as well as
    the API source, which allows me to identify a vulnerability in the
    API that gives code execution. Then I'll use the shell on the API
    container to find creds that allow me access to private repos back
    on Gogs, which include an SSH key. With SSH access to the host, I'll
    target the vault project software to get SSH access as root. In
    Beyond Root, I'll look at the JWT, and my failed attempts to crack
    the secret.

-   Jan 1, 2020

    ### [Hackvent 2019 - leet](/hackvent2019/leet)

    #ctf #hackvent #arduino #hex-file #avr-simulator #binascii #python
    #burp #php #john #ghidra #arm #ioctl #reverse-engineering

    ![](/img/hackvent2019-leet-cover.png)

    There were only three leet challenges, but they were not trivial,
    and IOT focused. First, I'll reverse a Arduino binary from hexcode.
    Then, there's a web hacking challenge that quickly morphs into a
    crypto challenge, which I can solve by reimplementing the leaked
    PRNG from Ida Pro to generate a valid password. Finally, there's a
    firmware for a Broadcom wireless chip that I'll need to find the
    hooked ioctl function and pull the flag from it.

-   Jan 1, 2020

    ### [Hackvent 2019 - Hard](/hackvent2019/hard)

    #ctf #hackvent #websocket #mqtt #cve-2017-7650 #x32dbg #patching
    #unicode #php #sql #mach-o #deb #ghidra #salsa20 #crypto #emojicode
    #ps4 #ecc #reverse-engineering

    ![](/img/hackvent2019-hard-cover.png)

    The hard levels of Hackvent conitnued with more web hacking, reverse
    engineering, crypto, and an esoteric programming language. In the
    reversing challenges, there was not only an iPhone debian package,
    but also a PS4 update file.

-   Jan 1, 2020

    ### [Hackvent 2019 - Medium](/hackvent2019/medium)

    #ctf #hackvent #crypto #sql #credit-cards #rule-30 #gimp #strace
    #ltrace #jwt #python #vb #x32dbg #ghidra #jsf #perl #obfuscation
    #deparse #reverse-engineering

    ![](/img/hackvent2019-medium-cover.png)

    The medium levels brought the first reverse enginnering challenges,
    the first web hacking challenges, some image manipulation, and of
    course, some obfuscated Perl.

-   Dec 31, 2019

    ### [Hackvent 2019 - Easy](/hackvent2019/easy)

    #ctf #hackvent #forensics #stereolithography #stl #clara-io
    #aztec-code #hodor #ahk #autohotkey #steganography #python
    #python-pil #bacon #crypto #stegsnow #base58

    ![](/img/hackvent2019-easy-cover.png)

    Hackvent is a fun CTF, offering challenges that start off quite easy
    and build to much harder over the course of 24 days, with bonus
    points for submitting the flag within the first 24 hours for each
    challenge. This was the first year I made it past day 12, and I was
    excited to finish all the challenges with all time bonuses! I'll
    break the solutions into four parts. The first is the easy
    challenges, days 1-7, which provided some basic image forensics,
    some interesting file types, an esoteric programming language, and
    two hidden flags.

-   Dec 14, 2019

    ### [Advent of Code 2019: Day 14](/adventofcode2019/14)

    #ctf #advent-of-code #python #defaultdict

    ![](/img/aoc2019-14-cover.png)

    Day 14 is all about stacking requirements and then working them to
    understand the inputs required to get the output desired. I'll need
    to organize my list of reactions in such a way that I can work back
    from the desired end output to how much ore is required to get
    there.

-   Dec 14, 2019

    ### [HTB: Smasher2](/htb-smasher2.md)

    #htb-smasher2 #hackthebox #ctf #exploit #auth-bypass #logic-error
    #python #reference-counting #kernal-driver #mmap
    #reverse-engineering

    ![](/img/smasher2-cover.png)

    Like the first Smasher, Smasher2 was focused on exploitation.
    However this one didn't have a buffer overflow or what I typically
    think of as binary exploitation. It starts with finding a
    vulnerability in a compiled Python module (written in C) to get
    access to an API key. Then I'll have to bypass a WAF to use that API
    to get execution and then a shell onSmasher2. For PrivEsc, I'll need
    to exploit a kernel driver to get a root shell.

-   Dec 13, 2019

    ### [Advent of Code 2019: Day 13](/adventofcode2019/13)

    #ctf #advent-of-code #python #intcode-computer #defaultdict

    ![](/img/aoc2019-13-cover.png)

    Continuing with the computer, now I'm using it to power an arcade
    game. I'll use the given intcodes to run the game, and I'm
    responsible for moving the joystick via input to the game. This
    challenge was awesome. I made a video of the game running in my
    terminal, which wasn't necessary, but turned out pretty good.

-   Dec 12, 2019

    ### [Advent of Code 2019: Day 12](/adventofcode2019/12)

    #ctf #advent-of-code #python

    ![](/img/aoc2019-12-cover.png)

    Day 12 asks me to look at moons and calculate their positions based
    on a simplified gravity between them. In the first part, I'll run
    the system for 1000 steps and return a calculation ("energy") based
    on each moons position and velocity at that point. In the second
    part, I'll have to find when the positions repeat, which I can do by
    recognizing that the three axes are independent of each other, and
    that I can find the cycle time for each axis, and then find the
    least common multiple of them to get when all three are in order.

-   Dec 11, 2019

    ### [Advent of Code 2019: Day 11](/adventofcode2019/11)

    #ctf #advent-of-code #python #intcode-computer #defaultdict

    ![](/img/aoc2019-11-cover.png)

    Continuing with the computer, now I'm using it to power a robot. My
    robot will walk around, reading the current color, submitting that
    to the program, and getting back the color to paint the current
    square and instructions for where to move next.

-   Dec 10, 2019

    ### [Advent of Code 2019: Day 10](/adventofcode2019/10)

    #ctf #advent-of-code #python

    ![](/img/aoc2019-10-cover.png)

    This challenge gives me a map of asteroids. I'll need to play with
    different ways to find which ones are directly in the path of
    others, first to see which asteroids can see the most others, and
    then to destroy them one by one with a laser.

-   Dec 9, 2019

    ### [Advent of Code 2019: Day 9](/adventofcode2019/9)

    #ctf #advent-of-code #python #intcode-computer #defaultdict

    ![](/img/aoc2019-9-cover.png)

    More computer work in day 9, this time adding what is kind of a
    stack pointer and an opcode to adjust that pointer. Now I can add a
    relative address mode, getting positions relative to the stack
    pointer.

-   Dec 8, 2019

    ### [Advent of Code 2019: Day 8](/adventofcode2019/8)

    #ctf #advent-of-code #python

    ![](/img/aoc2019-8-cover.png)

    After spending hours on day 7, I finished day 8 in about 15 minutes.
    It was simply reading in a series of numbers which represented
    pixels in various layers in an email. In part one I'll break the
    pixels into layers, and evaluate each one. In part two, I'll
    actually create the image.

-   Dec 8, 2019

    ### [Advent of Code 2019: Day 7](/adventofcode2019/7)

    #ctf #advent-of-code #python #intcode-computer

    ![](/img/aoc2019-7-cover.png)

    The computer is back again, and this time, I'm chaining it and using
    it as an amplifier. In the each part, I'll find the way to get
    maximum thrust from five amplifiers given that each can take one of
    five given phases. In part two, there's a loop of amplification.

-   Dec 7, 2019

    ### [HTB: Wall](/htb-wall.md)

    #hackthebox #ctf #htb-wall #nmap #gobuster #hydra #centreon
    #cve-2019-13024 #waf #filter #python #uncompyle6 #screen
    #modsecurity #htaccess #htb-flujab

    ![](/img/wall-cover.png)

    Wall presented a series of challenges wrapped around two public
    exploits. The first exploit was a CVE in Centreon software. But to
    find it, I had to take advantage of a misconfigured webserver that
    only requests authenticatoin on GET requests, allowing POST requests
    to proceed, which leads to the path to the Centreon install. Next,
    I'll use the public exploit, but it fails because there's a WAF
    blocking requests with certain keywords. I'll probe to identify the
    blocks words, which includes the space character, and use the Linux
    environment variable \${IFS} instead of space to get command
    injection. Once I have that, I can get a shell on the box. There's a
    compiled Python file in the users home directory, which I can
    decompile to find the password for the second user. From either of
    these users, I can exploit SUID screen to get a root shell. In
    Beyond Root, I'll look at the webserver configuration, the WAF,
    improve the exploit script, and look at some trolls the author left
    around.

-   Dec 6, 2019

    ### [Advent of Code 2019: Day 6](/adventofcode2019/6)

    #ctf #advent-of-code #python #recursion #defaultdict

    ![](/img/aoc2019-6-cover.png)

    This was a fun challenge, because it seemed really hard at first,
    but once I figured out how to think about it, it was quite simple.
    I'm given a set of pairings, each of which contains two objects, the
    second orbits around the first. I'll play with counting the number
    of orbits going on, as well as working a path through the orbits.
    This was the first time I brought out recurrisive programming this
    year, and it really fit well.

-   Dec 5, 2019

    ### [Advent of Code 2019: Day 5](/adventofcode2019/5)

    #ctf #advent-of-code #python #intcode-computer

    ![](/img/aoc2019-5-cover.png)

    Today I'm tasked with building on the simple computer I built in
    [day 2](/adventofcode2019/2). I'll add new instructions for input /
    output and comparisons / branching. I'll also get parameter modes,
    so in addition to reading values from other positions, I can now
    handle constants (known in computer architecture as immediates).

-   Dec 3, 2019

    ### [Advent of Code 2019: Day 4](/adventofcode2019/4)

    #ctf #advent-of-code #python

    ![](/img/aoc2019-4-cover.png)

    I solved day 4 much faster than day 3, probably because it moved
    away from spatial reasoning and just into input validation. I'm
    given a range of 6-digit numbers, and asked to pick ones that meet
    certain criteria.

-   Dec 3, 2019

    ### [Advent of Code 2019: Day 3](/adventofcode2019/3)

    #ctf #advent-of-code #python

    ![](/img/aoc2019-3-cover.png)

    I always start to struggle when AOC moves into spatial challenges,
    and this is where the code starts to get a bit ugly. In this
    challenge, I have to think about two wires moving across a
    coordinate plane, and look for positions where they intersect. Then
    I'll score each intersection, first by Manhattan distance to the
    origin, and then by total number of steps from the origin along both
    wires, and return the minimum.

-   Dec 2, 2019

    ### [Advent of Code 2019: Day 2](/adventofcode2019/2)

    #ctf #advent-of-code #python #intcode-computer

    ![](/img/aoc2019-2-cover.png)

    This puzzle is to implement a little computer with three op codes,
    add, multiply, and finish. In the first part, I'm given two starting
    register values, 12 and 2. In the second part, I need to brute force
    those values to find a given target output.

-   Dec 1, 2019

    ### [Advent of Code 2019: Day 1](/adventofcode2019/1)

    #ctf #advent-of-code #python

    ![](/img/aoc2019-1-cover.png)

    This puzzle was basically reading a list of numbers, performing some
    basic arithmetic, and summing the results. For part two, there's a
    twist in that I'll need to do that same math on the results, and add
    then as long as they are greater than 0.

-   Nov 30, 2019

    ### [HTB: Heist](/htb-heist.md)

    #ctf #hackthebox #htb-heist #nmap #cisco #john #cisco-type-7
    #smbclient #smbmap #crackmapexec #rpcclient #ipc #lookupsid
    #evil-winrm #powershell #docker #firefox #procdump #out-minidump
    #mimikittenz #credentials

    ![](/img/heist-cover.png)

    Heist brought new concepts I hadn't seen on HTB before, yet keep to
    the easy difficulty. I'll start by find a Cisco config on the
    website, which has some usernames and password hashes. After
    recovering the passwords, I'll find that one works to get RPC
    access, which I'll use to find more usernames. One of those
    usernames with one of the original passwords works to get a WinRM
    session on the Heist. From there, I'll notice that Firefox is
    running, and dump the process memory to find the password for the
    original website, which is also the administrator password for the
    box.

-   Nov 26, 2019

    ### [LD_PRELOAD Rootkit on Chainsaw](/htb-chainsaw-rootkit.md)

    #htb-chainsaw #ctf #hackthebox #rootkit #ldpreload #ida #nm #strace
    #reverse-engineering #ghidra

    ![](/img/chainsaw-rootkit-cover.png)

    There was something a bit weird going on with Chainsaw from
    HackTheBox. It turns out there's a LD_PRELOAD rootkit running to
    hide the NodeJS processes that serve the smart contracts. Why? I
    have no idea. But since it's a really neat concept, I wanted to pull
    it apart. Big thanks to jkr for helping me get started in this
    rabbit hole (the good kind), and to h0mbre for his recent blog post
    about these rootkits.

-   Nov 23, 2019

    ### [HTB: Chainsaw](/htb-chainsaw.md)

    #htb-chainsaw #ctf #hackthebox #nmap #ftp #solididy #python #web3
    #remix #command-injection #injection #ipfs #ssh #email #john
    #path-hijack #suid #bmap #df #debugfs #ida #ghidra #pyinstaller
    #reverse-engineering

    ![](/img/chainsaw-cover.png)

    Chainsaw was centered around blockchain and smart contracts, with a
    bit of InterPlanetary File System thrown in. I'll get the details of
    a Solididy smart contract over an open FTP server, and find command
    injection in it to get a shell. I'll find an SSH key for the bobby
    user in IPFS files. bobby has access to a SUID binary that I can
    interact with two ways to get a root shell. But even as root, the
    flag is hidden, so I'll have to dig into the slack space around
    root.txt to find the flag. In Beyond root, I'll look at the
    ChainsawClub binaries to see how they apply the same Web3 techniques
    I used to get into the box in the first place.

-   Nov 16, 2019

    ### [HTB: Networked](/htb-networked.md)

    #ctf #htb-networked #hackthebox #nmap #apache #dirsearch #php
    #upload #webshell #filter #command-injection #sudo #ifcfg #oscp-like

    ![](/img/networked-cover.png)

    Networked involved abusing an Apache misconfiguration that allowed
    me to upload an image containing a webshell with a double extension.
    With that, I got a shell as www-data, and then did two privescs. The
    first abused command injection into a script that was running to
    clean up the uploads directory. Then I used access to an ifcfg
    script to get command execution as root. In Beyond Root, I'll look a
    bit more at that Apache configuration.

-   Nov 9, 2019

    ### [HTB: Jarvis](/htb-jarvis.md)

    #ctf #htb-jarvis #hackthebox #nmap #waf #gobuster #sqli #injection
    #sqlmap #phpmyadmin #cve-2018-12613 #python #systemctl #service
    #gtfobins #command-injection #oscp-like

    ![](/img/jarvis-cover.png)

    Jarvis provide three steps that were all relatively basic. First,
    there's an SQL injection with a WAF that breaks `sqlmap`, at least
    in it's default configuration. Then there's a command injection into
    a Python script. And finally there's creating a malicious service.
    In Beyond root, I'll look at the WAF and the cleanup script.

-   Nov 2, 2019

    ### [HTB: Haystack](/htb-haystack.md)

    #hackthebox #ctf #htb-haystack #gobuster #steganography
    #elasticsearch #ssh #kibana #cve-2018-17246 #javascript #lfi
    #logstash #herokuapp

    ![](/img/haystack-cover.png)

    Haystack wasn't a realistic pentesting box, but it did provide
    insight into tools that are common on the blue side of things with
    Elastic Stack. I'll find a hint in an image on a webpage, an use
    that to find credentials in an elastic search instance. Those creds
    allow SSH access to Haystack, and access to a local Kibana instance.
    I'll use a CVE against Kibana to get execution as kibana. From
    there, I have access to the LogStash config, which is misconfigured
    to allow a execution via a properly configured log as root.

-   Oct 26, 2019

    ### [HTB: Safe](/htb-safe.md)

    #htb-safe #ctf #hackthebox #rop #pwntools #bof #python #exploit
    #keepass #kpcli #john #htb-redcross #htb-ellingson

    ![](/img/safe-cover.png)

    Safe was two steps - a relatively simple ROP, followed by cracking a
    Keepass password database. Personally I don't believe binary
    exploitation belongs in a 20-point box, but it is what it is. I'll
    show three different ROP strategies to get a shell.

-   Oct 19, 2019

    ### [HTB: Ellingson](/htb-ellingson.md)

    #htb-ellingson #hackthebox #ctf #nmap #werkzeug #python #flask
    #debugger #ssh #bash #hashcat #credentials #bof #rop #pwntools #aslr
    #gdb #peda #ret2libc #checksec #pattern-create #onegadget #cron
    #htb-october #htb-redcross #flask-debug

    ![](/img/ellingson-cover.png)

    Ellingson was a really solid hard box. I'll start with ssh and http
    open, and find that they've left the Python debugger running on the
    webpage, giving me the opporutunity to execute commands. I'll use
    that access to write my ssh key to the authorized_keys file, and get
    a shell as hal. I'll find that hal has access to the shadow.bak
    file, and from there, I can break margo's password. Once sshed in as
    margo, I will find a suid binary that I can overflow to get a root
    shell. In Beyond Root, I'll explore two cronjobs. The first breaks
    the privesc from hal to margo, resetting the permissions on the
    shadow.bak file to a safe configuration. The second looks like a
    hint that was disabled, or maybe forgotten.

-   Oct 12, 2019

    ### [HTB: Writeup](/htb-writeup.md)

    #htb-writeup #ctf #hackthebox #nmap #robots-txt #cmsms #sqli
    #credentials #injection #pspy #run-parts #perl

    ![](/img/writeup-cover.png)

    Writeup was a great easy box. Neither of the steps were hard, but
    both were interesting. To get an initial shell, I'll exploit a blind
    SQLI vulnerability in CMS Made Simple to get credentials, which I
    can use to log in with SSH. From there, I'll abuse access to the
    staff group to write code to a path that's running when someone
    SSHes into the box, and SSH in to trigger it. In Beyond Root, I'll
    look at other ways to try to hijack the root process.

-   Oct 10, 2019

    ### [Flare-On 2019: wopr](/flare-on-2019/wopr.md)

    #flare-on #ctf #flare-on-wopr #python #pyinstaller
    #python-exe-unpacker #uncompyle6 #pdb #exe #z3 #reverse-engineering

    ![](/img/flare2019-7-cover.png)

    wopr was like an onion - the layers kept peeling back revealing more
    layers. I'm given an exe which was created by PyInstaller, which
    I'll unpack to get to the Python code. That code has a layer of
    unpacking based on a binary implementation of tabs and spaces in the
    doc strings. Once I get to the next layer, I need to calculate the
    hash of the text segment for the currently running binary, and use
    that as a key to some equations. Using a solver to solve the system,
    I can find the input necessary to return the flag.

-   Oct 9, 2019

    ### [Flare-On 2019: bmphide](/flare-on-2019/bmphide.md)

    #flare-on #ctf #flare-on-bmphide #dnspy #dotnet #anti-debug
    #steganography #reverse-engineering

    ![](/img/flare2019-6-cover.png)

    bmphide was my favorite challenge this year (that I got to). It was
    challenging, yet doable and interesting. I'm given a bitmap image
    and a Windows .NET executable. That executable is used to hide
    information in the low bits of the image. I'll have to reverse the
    exe to understand how to extract the data. I'll also have to work
    around some anti-debug.

-   Oct 6, 2019

    ### [Flare-On 2019: demo](/flare-on-2019/demo.md)

    #flare-on #ctf #flare-on-demo #x64dbg #reverse-engineering

    ![](/img/flare2019-5-cover.png)

    demo really threw me, to the point that I almost skipped writing it
    up. The file given is a demoscene, which is a kind of competition to
    get the best visual performce out of an executable limited in size.
    To achieve this, packers are used to compress the binary. In the exe
    for this challenge, a 3D Flare logo comes up and spins, but the flag
    is missing. I'll have to unpack the binary and start messing with
    random DirectX functions until I find two ways to make the flag show
    up.

-   Oct 5, 2019

    ### [HTB: Ghoul](/htb-ghoul.md)

    #hackthebox #htb-ghoul #ctf #nmap #gobuster #hydra #zipslip #tomcat
    #docker #ssh #pivot #cewl #john #gogs #tunnel #gogsownz #credentials
    #suid #git #ssh-agent-hijack #cron #htb-reddish

    ![](/img/ghoul-cover.png)

    Ghoul was a long box, that involved pioviting between multiple
    docker containers exploiting things and collecting information to
    move to the next step. With a level of pivoting not seen in
    HackTheBox since [Reddish](/htb-reddish.md), I'll need
    to pay careful attention to various passwords and other bits of
    information as I move through the containers. I'll exploit a webapp
    using the ZipSlip vulnerability to get a webshell up and get a shell
    as www-data, only to find that the exploited webserver is running as
    root, and with another ZipSlip, I can escalate to root. Still with
    no flags, I'll crack an ssh key and pivot to the second container.
    From there, I can access a third container hosting the self hosted
    git solution, gogs. With some password reuse and the gogsownz
    exploit, I'll get a shell on that container, and use a suid binary
    to get root. That provides access to a git repo that has a password
    I can use for root on the second container. As root, I can see ssh
    sessions connecting through this container and to the main host
    using ssh agent forwarding, and I'll hijack that to get root on the
    final host. In beyond root, I'll explore the ssh situation on the
    final host and get myself persistence, look at the crons running to
    simulate the user using ssh agent forwarding, and show a network map
    of the entire system.

-   Oct 4, 2019

    ### [Flare-On 2019: DNS Chess](/flare-on-2019/dnschess.md)

    #flare-on #ctf #flare-on-dnschess #peda #gdb #wireshark #python #dns
    #ida #reverse-engineering

    ![](/img/flare2019-4-cover.png)

    DNS Chess was really fun. I'm given a pcap, and elf executable, and
    an elf shared library. The two binaries form a game of chess, where
    commands are sent to an AI over DNS. I'll need to figure out how to
    spoof valid moves by reversing the binary, and then use valid moves
    to win the game.

-   Oct 2, 2019

    ### [Flare-On 2019: Flarebear](/flare-on-2019/flarebear.md)

    #flare-on #ctf #flare-on-flarebear #apk #genymotion #android #jadx
    #algebra #reverse-engineering

    ![](/img/flare2019-3-cover.png)

    Flarebear wsa the first Android challenge, and I'm glad to see it at
    the beginning while it's still not too hard. I'll use GenyMotion
    cloud to emunlate the application, and then jadx to decompile it and
    see what the win condition is. Once I find that, I can get the flag.

-   Sep 30, 2019

    ### [Flare-On 2019: Overlong](/flare-on-2019/overlong.md)

    #flare-on #ctf #flare-on-overlong #x64dbg #reverse-engineering

    ![](/img/flare2019-2-cover.png)

    Overlong was a challenge that could lead to complex rabbit holes,
    or, with some intelligent guess work, be solved quite quickly. From
    the start, with the title and the way that the word *overlong* was
    bolded in the prompt, I was looking for an integer to overflow or
    change in some way. That, plus additional clues, made this one
    pretty quick work.

-   Sep 28, 2019

    ### [HTB: SwagShop](/htb-swagshop.md)

    #ctf #hackthebox #htb-swagshop #nmap #magento #gobuster
    #deserialization #webshell #sudo #oscp-like

    ![](/img/swagshop-cover.png)

    SwagShop was a nice beginner / easy box centered around a Magento
    online store interface. I'll use two exploits to get a shell. The
    first is an authentication bypass that allows me to add an admin
    user to the CMS. Then I can use an authenticated PHP Object
    Injection to get RCE. I'll also show how got RCE with a malicious
    Magento package. RCE leads to shell and user. To privesc to root,
    it's a simple exploit of `sudo vi`.

-   Sep 28, 2019

    ### [Flare-On 2019: Memecat Battlestation \[Shareware Demo Edition\]](/flare-on-2019/memecat-battlestation.md)

    #flare-on #ctf #flare-on-memecat-battlestation #dnspy #dotnet
    #reverse-engineering

    ![](/img/flare2019-1-cover.png)

    Memecat Battlestation \[Shareware Demo Edition\] was a really simple
    challenge that really involved opening a .NET executable in a
    debugger and reading the correct phrases from the code. It was a
    good beginner challenge.

-   Sep 21, 2019

    ### [HTB: Kryptos](/htb-kryptos.md)

    #ctf #hackthebox #htb-kryptos #nmap #gobuster #php #burp #mysql
    #wireshark #hashcat #rc4 #crypto #python #python-cmd
    #php-disable-functions #sqli #webshell #sqlite #vimcrypt #ssh
    #tunnel #python-eval #filter

    ![](/img/kryptos-cover.png)

    Kryptos feels different from most insane boxes. It brought an
    element of math / crypt into most of the challenges in a way that I
    really enjoyed. But it still layered challenges so that each step
    involved multiple exploits / bypasses, like all good insane boxes
    do. I'll start by getting access to a web page by telling the page
    to validate logins against a database on my box. The website gives
    me that ability to return encrypted webpage content that Kryptos can
    retrieve. I'll break the encryption to access pages I'm not able to
    access on my own, finding a sqlite test page that I can inject into
    to write a webshell that can access the file system. With file
    system access, I'll retrieve a Vim-crypted password backup, and
    crack that to get ssh access to the system. On the system, I'll
    access an API available only on localhost and take advantage of a
    weak random number generator to sign my own commands, bypassing
    python protections to get code execution as root.

-   Sep 14, 2019

    ### [HTB: Luke](/htb-luke.md)

    #hackthebox #ctf #htb-luke #nmap #gobuster #credentials #api #nodejs
    #jwt #wfuzz #ajenti #hydra

    ![](/img/luke-cover.png)

    Luke was a recon heavy box. In fact, the entire writeup for Luke
    could reasonably go into the Recon section. I'm presented with three
    different web interfaces, which I enumerate and bounce between to
    eventually get credentials for an Ajenti administrator login. Once
    I'm in Ajenti, I have access to a root shell, and both flags.

-   Sep 11, 2019

    ### [HTB: Holiday](/htb-holiday.md)

    #ctf #htb-holiday #hackthebox #nmap #nodejs #gobuster #dirsearch
    #burp #xss #filter #sqli #command-injection #npm #sudo #oswe-plus

    ![](/img/holiday-cover.png)

    Holiday was a fun, hard, old box. The path to getting a shell
    involved SQL injection, cross site scripting, and command injection.
    The root was a bit simpler, taking advantage of a sudo on node
    package manager install to install a malicious node package.

-   Sep 7, 2019

    ### [HTB: Bastion](/htb-bastion.md)

    #htb-bastion #hackthebox #ctf #nmap #smbmap #smbclient #smb #vhd
    #mount #guestmount #secretsdump #crackstation #ssh #windows
    #mremoteng #oscp-like

    ![](/img/bastion-cover.png)

    Bastion was a solid easy box with some simple challenges like
    mounting a VHD from a file share, and recovering passwords from a
    password vault program. It starts, somewhat unusually, without a
    website, but rather with vhd images on an SMB share, that, once
    mounted, provide access to the registry hive necessary to pull out
    credentials. These creds provide the ability to ssh into the host as
    the user. To get administrator access, I'll exploit the mRemoteNG
    installation, pulling the profile data and encrypted data, and show
    several ways to decrypt those. Once I break out the administrator
    password, I can ssh in as administrator.

-   Aug 31, 2019

    ### [HTB: OneTwoSeven](/htb-onetwoseven.md)

    #ctf #htb-onetwoseven #hackthebox #nmap #sftp #tunnel #ssh #chroot
    #vim #crackstation #php #webshell #apt #mitm

    ![](/img/onetwoseven-cover.png)

    OneTwoSeven was a very cleverly designed box. There were lots of
    steps, some enumeration, all of which was do-able and fun. I'll
    start by finding a hosting provider that gives me SFTP access to
    their system. I'll use that to tunnel into the box, and gain access
    to the admin panel. I'll find creds for that using symlinks over
    SFTP. From there, I'll exploit a logic error in the plugin upload to
    install a webshell. To get root, I'll take advantage of my user's
    ability to run apt update and apt upgrade as root, and
    man-in-the-middle the connection to install a backdoored package.

-   Aug 24, 2019

    ### [HTB: Unattended](/htb-unattended.md)

    #ctf #htb-unattended #hackthebox #nmap #gobuster #sqli #sqlmap
    #nginx #nginx-aliases #lfi #session-poisoning #socat #hidepid
    #noexec #mysql #initrd #cpio #ida #reverse-engineering #oswe-like

    ![](/img/unattended-cover.png)

    Users rated Unattended much harder than the Medium rating it was
    released under. I think that's because the SQLI vulnerability was
    easy to find, but dumping the database would take forever. So the
    trick was knowing when to continue looking and identify the NGINX
    vulnerability to leak the source code. At that point, the SQLI was
    much more manageable, providing LFI which I used with PHP session
    variables to get RCE and a shell. From there, it was injecting into
    some commands being taken from the database to move to the next
    user. And in the final step, examining an initrd file to get the
    root password. In Beyond Root, I'll reverse the binary that
    generates the password, and give some references for initrd
    backdoors.

-   Aug 17, 2019

    ### [HTB: Helpline](/htb-helpline.md)

    #ctf #hackthebox #htb-helpline #nmap #manageengine #servicedesk
    #default-creds #excel #cve-2017-9362 #xxe #responder #cve-2017-11511
    #lfi #hashcat

    ![](/img/helpline-cover.png) Helpline
    was a really difficult box, and it was an even more difficult
    writeup. It has *so* many paths, and yet all were difficult in some
    way. It was also one that really required Windows as an attack
    platform to do the intended way. I got lucky in that this was the
    box I had chosen to try out [Commando
    VM](/commando-vm-lessons.md). Give the two completely
    different attack paths on Windows and Kali, I'll break this into
    three posts. In the first post, I'll do enumeration up to an initial
    shell. Then in one post I'll show how I solved it from Commando
    (Windows) using the intended paths. In the other post, I'll show how
    to go right to a shell as SYSTEM, and work backwards to get the root
    flag and eventually the user flag.

-   Aug 10, 2019

    ### [HTB: Arkham](/htb-arkham.md)

    #ctf #hackthebox #htb-arkham #nmap #gobuster #faces #jsf
    #deserialization #smb #smbclient #smbmap #luks #bruteforce-luks
    #cryptsetup #hmac #htb-canape #ysoserial #python #burp #crypto #nc
    #http.server #smbserver #ost #readpst #mbox #mutt #pssession #rlwrap
    #winrm #chisel #evil-winrm #uac #meterpreter #greatsct #msbuild
    #metasploit #cmstp #systempropretiesadvanced #dll #mingw32
    #oswe-plus #htb-sizzle

    ![](/img/arkham-cover.png)

    In my opinion, Arkham was the most difficult Medium level box on
    HTB, as it could have easily been Hard and wouldn't have been out of
    place at Insane. But it is still a great box. I'll start with an
    encrypted LUKZ disk image, which I have to crack. On it I'll find
    the config for a Java Server Faces (JSF) site, which provides the
    keys that allow me to perform a deserialization attack on the
    ViewState, providing an initial shell. I'll find an email file with
    the password for a user in the administrators group. Once I have
    that shell, I'll have to bypass UAC to grab root.txt.

-   Aug 3, 2019

    ### [HTB: Fortune](/htb-fortune.md)

    #ctf #htb-fortune #hackthebox #certificate #certificate-authority
    #sslyze #command-injection #burp #burp-repeater #firewall #python
    #python-cmd #authpf #openssl #ssh #nfs #pgadmin #postgresql
    #credentials #sqlite #pfctl #tcpdump #htb-lacasadepapel

    ![](/img/fortune-cover.png)

    Fortune was a different kind of insane box, focused on taking
    advantage things like authpf and nfs. I'll start off using command
    injection to find a key and certificate that allow access to an
    HTTPS site. On that site, I get instructions and an ssh key to
    connect via authpf, which doesn't provide a shell, but opens up new
    ports in the firewall. From there I can find nfs access to `/home`,
    which I can use with uid spoofing to get ssh access. For privesc,
    I'll find credentials in pgadmin's database which I can use to get a
    root shell. In Beyond Root, I'll look the firewall configuration and
    why I couldn't turn command injection into a shell.

-   Aug 2, 2019

    ### [Bypassing PHP disable_functions with Chankro](/bypassing-php-disable_functions-with-chankro.md)

    #ctf #hackthebox #htb-lacasadepapel #chankro #php
    #php-disable-functions #htb-hackback

    ![](/img/chankro-cover.png)I was reading
    [Alamot's LaCasaDePapel
    writeup](https://alamot.github.io/lacasadepapel_writeup/#getting-dali-shell-by-escaping-php-restrictions),
    and they went a different way once they got the php shell. Instead
    of just using the php functions to find the certificate and key
    needed to read the private members https page, Alamot uses Chankro
    to bypass the disabled execution functions and run arbitrary code
    anyway. I had to try it.

-   Jul 27, 2019

    ### [HTB: LaCasaDePapel](/htb-lacasadepapel.md)

    #hackthebox #htb-lacasadepapel #ctf #vsftpd #searchsploit #python
    #psy #php #php-disable-functions #certificate #client-certificate
    #openssl #directory-traversal #lfi #ssh #pspy #supervisord #cron
    #metasploit #ida #iptables #js #certificate-authority
    #reverse-engineering #oscp-plus #youtube

    ![](/img/lacasadepapel-cover.png)

    LaCasaDePapel was a fun easy box that required quite a few steps for
    a 20 point box, but none of which were too difficult. I'll start off
    exploiting a classic backdoor bug in VSFTPd 2.3.4 which has been
    modified to return a shell in Psy, a php based debugging tool. From
    there, I can collect a key file which I'll use to sign a client
    certificate, gaining access to the private website. I'll exploit a
    path traversal bug in the site to get an ssh key for one of the
    users. To privesc, I'll find a file that's controlling how a cron is
    being run by root. The file is not writable and owned by root, but
    sits in a directory my current user owns, which allows me to delete
    the file and then create a new one. In Beyond Root, I'll look at the
    modified VSFTPd server and show an alternative path that allows me
    to skip the certificate generation to get access to the private
    website.

-   Jul 20, 2019

    ### [HTB: CTF](/htb-ctf.md)

    #ctf #htb-ctf #hackthebox #nmap #ldap #ldap-injection #second-order
    #second-order-ldap-injection #python-cmd #python #totp #stoken #7z
    #listfile #wildcard #htb-nightmare #htb-stratosphere

    ![](/img/ctf-cover.png)

    CTF was hard in a much more straight-forward way than some of the
    recent insane boxes. It had steps that were difficult to pull off,
    and not even that many. But it was still quite challenging. I'll
    start using ldap injection to determine a username and a seed for a
    one time password token. Then I'll use that to log in. On seeing a
    command page, I'll need to go back and log-in again, this time with
    a username that allows me a second-order ldap injection to bypass
    the user check. Once I do, I can run commands, and find a user
    password in the php pages. With an SSH shell, I'll find a backup
    script that uses Sevenzip in a way that I can hijack to read the
    root flag. In Beyond root, I'll look at little bit at SELinux, build
    a small shell to make running commands over the webpage easier, and
    look at the actual ldap queries I injected into.

-   Jul 13, 2019

    ### [HTB: FriendZone](/htb-friendzone.md)

    #htb-friendzone #ctf #hackthebox #nmap #smbmap #smbclient #gobuster
    #zone-transfer #dns #dig #lfi #php #wfuzz #credentials #ssh #pspy
    #python-library-hijack #oscp-like

    ![](/img/friendzone-cover.png)

    FriendZone was a relatively easy box, but as far as easy boxes go,
    it had a lot of enumeration and garbage trolls to sort through. In
    all the enumeration, I'll find a php page with an LFI, and use SMB
    to read page source and upload a webshell. I'll uprivesc to the next
    user with creds from a database conf file, and then to root using a
    writable python module to exploit a root cron job calling a python
    script.

-   Jul 6, 2019

    ### [HTB: Hackback](/htb-hackback.md)

    #ctf #hackthebox #htb-hackback #nmap #wfuzz #jq #gophish #php
    #php-disable-functions #aspx #rot13 #javascript #gobuster #tio-run
    #log-poisoning #python #python-cmd #regeorge #winrm #proxychains
    #cron #named-pipe #seimpersonate #command-injection #service
    #arbitrary-write #diaghub #visual-studio #dll
    #alternative-data-streams #webshell #rdesktop #rdp #oswe-plus
    #htb-flujab

    ![](/img/hackback-cover.png)

    Hackback is the hardest box that I've done on HTB. By far. Without
    question. If you'd like data to back that up, the first blood times
    of over 1.5 and 2.5 days! I remember vividly working on this box
    with all my free time, and being the 5th to root it (7th root
    counting the two box authors) in the 6th day. I'll start by finding
    a hosts whose main attack point is a GoPhish interface. This
    interface gives up some domain names for fake phishing sites on the
    same host, which I can use to find an admin interface which I can
    abuse to get file system access via log poisoning. Unfortunately,
    all the functions I need to get RCE via PHP or ASPX are disabled. I
    can however upload reGeorge and use it to tunnel a connection to
    WinRM, where I can use some creds I find in a config file. I'll then
    use a named pipe to execute nc as the next user. From there I can
    abuse a faulty service that allows me to write as SYSTEM wherever I
    want to overwrite a file in SYSTEM32, and then use DiagHub to get a
    SYSTEM shell. In Beyond Root, I'll look at an unintended way to get
    root.txt as hacker, explore why an aspx webshell fails and find a
    work around to get it working, check out the PowerShell source for
    the web server listening on 6666, and look into an RDP connection.

-   Jul 1, 2019

    ### [Darling: Running MacOS Binaries on Linux](/darling-running-macos-binaries-on-linux.md)

    #tools #bsides-london #ctf #darling #python #mach-o #macos

    \`![](/img/darling-cover.png)I attended
    BSides London almost a month ago now, and of course took a look at
    the CTF. There were a handful of reversing challenges, but multiple
    of them were MacOS (Mach-O) binaries. As I looked down at my Windows
    laptop and my Kali VM, I felt at a bit of a disadvantage. While I
    was able to solve one of the challenges just with IDA, I went
    looking for a way to run Mac binaries on a Linux OS. And I found
    Darwin. It took basically the rest of the day to install, so I
    didn't get to any of the additional challenges, but I am happy to be
    semi-equiped the next time the need comes up.

-   Jun 29, 2019

    ### [HTB: Netmon](/htb-netmon.md)

    #htb-netmon #hackthebox #ctf #nmap #ftp #password-reuse #prtg
    #command-injection #psexec-py #oscp-plus #htb-jerry

    ![](/img/netmon-cover.png)

    Netmon rivals [Jerry](/htb-jerry.md) and Blue for the
    shortest box I've done. The user first blood went in less than 2
    minutes, and that's probably longer than it should have been as the
    hackthebox page crashed right at open with so many people trying to
    submit flags. The host presents the full file system over anonymous
    FTP, which is enough to grab the user flag. It also hosts an
    instance of PRTG Network Monitor on port 80. I'll use the FTP access
    to find old creds in a backup configuration file, and use those to
    guess the current creds. From there, I can use a command injection
    vulnerability in PRTG to get a shell as SYSTEM, and the root flag.

-   Jun 22, 2019

    ### [HTB: Querier](/htb-querier.md)

    #ctf #htb-querier #hackthebox #nmap #windows #smb #smbclient #olevba
    #macros #vba #mssql #mssqlclient #xp-dirtree #net-ntlmv2 #responder
    #hashcat #xp-cmdshell #powerup #gpp #smbserver #nc #wmiexec #service
    #oscp-plus #htb-giddy

    ![](/img/querier-cover.png)

    Querier was a fun medium box that involved some simple document
    forensices, mssql access, responder, and some very basic Windows
    Privesc steps. I'll show how to grab the Excel macro-enabled
    workbook from an open SMB share, and find database credentials in
    the macros. I'll use those credentials to connect to the host's
    MSSQL as a limited user. I can use that limited access to get a
    Net-NTLMv2 hash with responder, which provides enough database
    access to run commands. That's enough to provide a shell. For
    privesc, running PowerUp.ps1 provides administrator credentials from
    a GPP file. In Beyond Root, I'll look at the other four things that
    PowerUp points out, and show how one of them will also provide a
    shell as SYSTEM.

-   Jun 15, 2019

    ### [HTB: FluJab](/htb-flujab.md)

    #htb-flujab #ctf #hackthebox #nmap #openssl #wfuzz #cookies #python
    #scripting #sqli #injection #python-cmd #python #ajenti #ssh
    #cve-2008-0166 #tcp-wrapper #rbash #gtfobins #make #screen
    #arbitrary-write

    ![](/img/flujab-cover.png)

    FluJab was a long and difficult box, with several complicated steps
    which require multiple pieces working together and careful
    enumeration. I'll start by enumerating a host that hosts websites
    for many different customers, and is meant to be like a CloudFlare
    ip. Once identifying the host I'm targeting, I'll find some weird
    cookie values that I can manipulate to get access to configuration
    pages. There I can configure the SMTP to go through my host, and use
    an SQL injection in one of the forms where I can read the results
    over email. Information in the database credentials and new
    subdomain, where I can access an instance of Ajenti server admin
    panel. That allows me to identify weak ssh keys, and to add my host
    to an ssh TCP Wrapper whitelist. Then I can ssh in with the weak
    private key. From there, I'll find a vulnerable version of screen
    which I can use to get a root shell. In Beyond Root, I'll show an
    unintended path to get a shell through Ajenti using the API, look at
    the details of the screen exploit, explore the box's clean up crons,
    and point out an oddity with nurse jackie.

-   Jun 8, 2019

    ### [HTB: Help](/htb-help.md)

    #htb-help #hackthebox #ctf #nmap #graphql #curl #crackstation
    #gobuster #helpdeskz #searchsploit #exploit-db #sqli #blindsqli
    #sqlmap #ssh #credentials #filter #php #webshell #exploit
    #cve-2017-16995 #cve-2017-5899 #oswe-like

    ![](/img/help-cover.png)

    Help was an easy box with some neat challenges. As far as I can
    tell, most people took the unintended route which allowed for
    skipping the initial section. I'll either enumerate a GraphQL API to
    get credentials for a HelpDeskZ instance. I'll use those creds to
    exploit an authenticated SQLi vulnerability and dump the database.
    In the database, I'll find creds which work to ssh into the box.
    Alternatively, I can use an unauthenticated upload bypass in
    HelpDeskZ to upload a webshell and get a shell from there. For root,
    it's kernel exploits.

-   Jun 1, 2019

    ### [HTB: Sizzle](/htb-sizzle.md)

    #hackthebox #htb-sizzle #ctf #nmap #gobuster #smbmap #smbclient #smb
    #ftp #regex #regex101 #responder #scf #net-ntlmv2 #hashcat
    #ldapdomaindump #ldap #certsrv #certificate #firefox #openssl #winrm
    #constrained-language-mode #psbypassclm #metasploit #meterpreter
    #installutil #msbuild #msfvenom #kerberoast #tunnel #rubeus #chisel
    #bloodhound #smbserver #dcsync #secretsdump #crackmapexec #wmiexec
    #cron #ntlm-http #burp #htb-active #htb-reel #certificate-authority
    #client-certificate #oscp-plus #adcs #htb-giddy #htb-bighead

    ![](/img/sizzle-cover.png)

    I *loved* Sizzle. It was just a really tough box that reinforced
    Windows concepts that I hear about from pentesters in the real
    world. I'll start with some SMB access, use a .scf file to capture a
    users NetNTLM hash, and crack it to get creds. From there I can
    create a certificate for the user and then authenticate over WinRM.
    I'll Kerberoast to get a second user, who is able to run the DCSync
    attack, leading to an admin shell. I'll have two beyond root
    sections, the first to show two unintended paths, and the second to
    exploit NTLM authentication over HTTP, and how Burp breaks it.

-   May 25, 2019

    ### [HTB: Chaos](/htb-chaos.md)

    #htb-chaos #ctf #hackthebox #nmap #webmin #gobuster #wordpress
    #wpscan #imap #openssl #roundcube #wfuzz #crypto #python #latex
    #pdftex #rbash #gtfobins #tar #password-reuse #firefox

    ![](/img/chaos-cover.png)

    Choas provided a couple interesting aspects that I had not worked
    with before. After some web enumeration and password guessing, I
    found myself with webmail credentials, which I could use on a
    webmail domain or over IMAP to get access to the mailbox. In the
    mailbox was an encrypted message, that once broken, directed me to a
    secret url where I could exploit an instance of pdfTeX to get a
    shell. From there, I used a shared password to switch to another
    user, performed an restricted shell escape, and found the root
    password in the user's firefox saved passwords. That password was
    actually for a Webmin instance, which I'll exploit in Beyond Root.

-   May 22, 2019

    ### [Malware Analysis: Pivoting In VT](/emotet-pivot.md)

    #malware #emotet #olevba #oledump #powershell #virus-total

    ![](/img/emotet0-pivot-cover.png) After
    pulling apart an Emotet phishing doc in the [previous
    post](/malware-analysis-unnamed-emotet-doc.md), I
    wanted to see if I could find similar docs from the same phishing
    campaign, and perhaps even different docs from previous phishing
    campaigns based on artifacts in the seed document. With access to a
    paid VirusTotal account, this is not difficult to do.

-   May 21, 2019

    ### [Malware Analysis: Unnamed Emotet Doc](/malware-analysis-unnamed-emotet-doc.md)

    #malware #emotet #olevba #oledump #powershell #virus-total
    #cyberchef #urlscan

    ![](/img/emotet-20190521-cover.png) I
    decided to do some VT roulette and check out some recent phishing
    docs in VT. I searched for documents with only few (5-12)
    detections, and the top item was an Emotet word doc. The Emotet
    group continues to tweak their strategy to avoid AV. In this doc,
    they use TextBox objects to hold both the base64 encoded PowerShell
    and the PowerShell command line itself, in a way that actually makes
    it hard to follow with olevba. I'll use oledump to show the parts
    that olevba misses.

-   May 18, 2019

    ### [HTB: Conceal](/htb-conceal.md)

    #ctf #hackthebox #htb-conceal #nmap #snmp #snmpwalk #ike #ipsec
    #ike-scan #strongswan #iis #gobuster #webshell #upload #nishang
    #juicypotato #potato #watson #windows #windows10 #oscp-like
    #htb-mischief #htb-bounty

    ![](/img/conceal-cover.png)

    Conceal brought something to HTB that I hadn't seen before -
    connecting via an IPSEC VPN to get access to the host. I'll use
    clues from SNMP and a lot of guessing and trial and error to get
    connected, and then it's a relatively basic Windows host, uploading
    a webshell over FTP, and then using JuicyPotato to get SYSTEM priv.
    The box is very much unpatched, so I'll show Watson as well, and
    leave exploiting those vulnerabilities as an exercise for the
    reader. It actually blows my mind that it only took 7 hours for user
    first blood, but then an additional 16.5 hours to root.

-   May 11, 2019

    ### [HTB: Lightweight](/htb-lightweight.md)

    #ctf #hackthebox #htb-lightweight #nmap #php #linux #centos #ssh
    #fail2ban #ldap #tcpdump #wireshark #credentials #bruteforce
    #hashcat #capabilities #openssl #htb-ethereal #sudoers
    #arbitrary-write #oscp-plus

    ![](/img/lightweight-cover.png)

    Lightweight was relatively easy for a medium box. The biggest trick
    was figuring out that you needed to capture ldap traffic on
    localhost to get credentials, and getting that traffic to generate.
    The box actually starts off with creating an ssh account for me when
    I visit the webpage. From there I can capture plaintext creds from
    ldap to escalate to the first user. I'll crack a backup archive to
    get creds to the second user, and finally use a copy of `openssl`
    with full Linux capabilities assigned to it to escalate to root. In
    Beyond root, I'll look at the backup site and the real one, and how
    they don't match, as well as look at the script for creating users
    based on http visits.

-   May 4, 2019

    ### [HTB: BigHead](/htb-bighead.md)

    #ctf #hackthebox #htb-bighead #nmap #windows #2k8sp2 #gobuster
    #wfuzz #phpinfo #dirsearch #nginx #github #john #hashcat #zip #7z
    #bof #exploit #python #bitvise #reg #plink #chisel #tunnel #ssh
    #bvshell #webshell #keepass #bash #kpcli #alternative-data-streams

    ![](/img/bighead-cover.png)

    BigHead required you to earn your 50 points. The enumeration was a
    ton. There was an really fun but challenging buffer overflow to get
    initial access. Then some pivoting across the same host using SSH
    and the a php vulnerability. And then finding a hidden KeePass
    database with a keyfile in an ADS stream which gave me the root
    flag.

-   May 4, 2019

    ### [BigHead Exploit Dev](/htb-bighead-bof.md)

    #ctf #hackthebox #htb-bighead #bof #exploit #python #pwntools
    #immunity #mona #ida #reverse-engineering #mingw #nginx
    #pattern-create #egg-hunter

    ![](/img/bighead-bof-cover.png) As my
    buffer overflow experience on Windows targets is relatively limited
    (only the basic vulnserver jmp esp type exploit previously),
    BigHeadWebSrv was probably the most complicate exploit chain I've
    written for a Windows target. The primary factor that takes this
    above something like a basic jmp esp is the space I have to write to
    is small. I got to learn a new technique, Egg Hunter, which is a
    small amount of code that will look for a marker I drop into memory
    earlier and run the shellcode after it.

-   Apr 27, 2019

    ### [HTB: Irked](/htb-irked.md)

    #ctf #hackthebox #htb-irked #nmap #searchsploit #exploit-db #hexchat
    #irc #python #steganography #steghide #ssh #su #password-reuse
    #metasploit #exim #oscp-like

    ![](/img/irked-cover.png)

    Irked was another beginner level box from HackTheBox that provided
    an opportunity to do some simple exploitation without too much
    enumeration. First blood for user fell in minutes, and root in 19.
    I'll start by exploring an IRC server, and not finding any
    conversation, I'll exploit it with some command injection. That
    leads me to a hint to look for steg with a password, which I'll find
    on the image on the web server. That password gets me access as the
    user. I'll find an setuid binary that's trying to run a script out
    of /tmp that doesn't exist. I'll add code to that to get a shell. In
    Beyond Root, I'll look at the Metasploit Payload for the IRC
    exploit, as well as some failed privesc exploits.

-   Apr 20, 2019

    ### [HTB: Teacher](/htb-teacher.md)

    #htb-teacher #ctf #hackthebox #debian #stretch #nmap #gobuster
    #skipfish #hydra #python #cve-2018-1133 #crackstation #mysql #pspy
    #su #cron #chmod #passwd #arbitrary-write #moodle

    ![](/img/teacher-cover.png)

    Teacher was 20-point box (despite the yellow avatar). At the start,
    it required enumerating a website and finding a png file that was
    actually a text file that revealed most of a password. I'll use
    hydra to brute force the last character of the password, and gain
    access to a Moodle instance, software designed for online learning.
    I'll abuse a PHP injection in the quiz feature to get code execution
    and a shell on the box. Then, I'll find an md5 in the database that
    is the password for the main user on the box. From there, I'll take
    advantage of a root cron that's running a backup script, and give
    myself write access to whatever I want, which I'll use to get root.

-   Apr 15, 2019

    ### [Commando VM: Lessons Learned](/commando-vm-lessons.md)

    #home-lab #commando #fireeye #smb #net-view #net-use #firewall
    #python #winrm #responder #htb-ethereal

    ![](/img/commando-lessons-cover.png) I
    worked a HackTheBox target over the last week using CommandoVM as my
    attack station. I was pleasantly surprised with how much I liked it.
    In fact, only once on this box did I need to fire up my Kali
    workstation. Because the target was Windows, there we parts that
    were made easier (and in one case made possible!). There were a
    couple additional struggles that arose, and I'm still in search of a
    good tmux equivalent. I'll walk through some of the lessons learned
    from working in this distro.

-   Apr 13, 2019

    ### [HTB: RedCross](/htb-redcross.md)

    #ctf #htb-redcross #hackthebox #ssh #nmap #wfuzz #linux #debian #php
    #cookies #gobuster #xss #sqli #sqlmap #command-injection #injection
    #postgresql #haraka #exploit-db #searchsploit #suid #sudo #sudoers
    #nss #jail #bof #exploit #python #pwntools #socat #rop #aslr
    #htb-frolic #htb-october

    ![](/img/redcross-cover.png)

    RedCross was a maze, with a lot to look at and multiple paths at
    each stage. I'll start by enumerating a website, and showing two
    different ways to get a cookie to use to gain access to the admin
    panel. Then, I'll get a shell on the box as penelope, either via an
    exploit in the Haraka SMTP server or via injection in the webpage
    and the manipulation of the database that controls the users in the
    ssh jail. Finally, I'll show escalation to root three different
    ways, using the database again in two different ways, and via a
    buffer overflow in a setuid binary. In Beyond Root, I'll dig into
    the SQL injection and check out how the ssh jail is configured.

-   Apr 10, 2019

    ### [Commando VM: Looking Around](/commando-vm-overview.md)

    #home-lab #commando #fireeye #openvpn #burp #7z #winrar #cmder
    #greenshot #windump #payloadsallthethings #seclists #fuzzdb
    #foxyproxy #x64dbg #dnspy #ida #ghidra #gobuster #wfuzz

    ![](/img/commando-overview-cover.png)Having
    built my CommandoVM in a [previous
    post](/commando-vm-installation.md), now I am going to
    look at what's installed, and what else I might want to add to the
    distribution. I'll start with some tweaks I made to get the box into
    shape, check out what tools are present, and add some that I notice
    missing. After this, in I'll use the VM to work a HTB target, and
    report back on in a future post.

-   Apr 9, 2019

    ### [Commando VM: Installation](/commando-vm-installation.md)

    #home-lab #commando #fireeye #youtube

    ![](/img/commando-install-cover.png)Ever
    since Fireeye announced their new CommandoVM, the "Complete Mandiant
    Offensive VM", I'd figured next time I had an occasion to target a
    Windows host, I would try to build a VM and give it a spin. This
    post is focused on getting up and running. I suspect additional
    posts on how it works out will follow.

-   Apr 6, 2019

    ### [HTB: Vault](/htb-vault.md)

    #ctf #htb-vault #hackthebox #nmap #gobuster #php #upload #webshell
    #ssh #credentials #pivot #qemu #spice #openvpn #tunnel #rbash #gpg
    #remmina #ubuntu #linux #iptables #sudo #filter #oswe-like

    ![](/img/vault-cover.png)

    Vault was a a really neat box in that it required pivoting from a
    host into various VMs to get to the vault, at least the intended
    way. There's an initial php upload filter bypass that gives me
    execution. Then a pivot with an OpenVPN config RCE. From there I'll
    find SSH creds, and need to figure out how to pass through a
    firewall to get to the vault. Once in the vault, I find the flag
    encrypted with GPG, and I'll need to move it back to the host to get
    the decryption keys to get the flag. In Beyond Root, I'll look at a
    couple of unintended paths, including a firewall bypass by adding an
    IP address, and a way to bypass the entire thing by connecting to
    the Spice ports, rebooting the VMs into recovery, resetting the root
    password, and then logging in.

-   Apr 3, 2019

    ### [Wizard Labs: DevLife](/wl-devlife.md)

    #ctf #wizard-labs #wl-devlife #linux #debian #nmap #gobuster #python
    #credentials #swp #vim #nano

    ![](/img/wl-devlife-cover.png)

    Another Wizard Lab's host retired, DevLife. This was another really
    easy box, that required some simple web enumeration to find a python
    panel that would run python commands, and display the output. From
    there, I could get a shell and the first flag. Then, more
    enumeration to find a python script in a hidden directory that
    contained the root password. With that, I can escalate to root.
    There was also a swp file in the hidden directory that I'll attempt
    to recover (and then figure out is actually nano), and I'll look at
    how the php page runs python commands, and show an injection in
    that.

-   Mar 30, 2019

    ### [HTB: Curling](/htb-curling.md)

    #ctf #hackthebox #htb-curling #nmap #joomla #searchsploit #webshell
    #cron #pspy #curl #suid #cve-2019-7304 #dirty-sock #ubuntu #exploit
    #htb-sunday #arbitrary-write

    ![](/img/curling-cover.png)

    Curling was a solid box easy box that provides a chance to practice
    some basic enumeration to find a password, using that password to
    get access to a Joomla instance, and using the access to get a
    shell. With a shell, I'll find a compressed and encoded backup file,
    that after a bit of unpacking, gives a password to privesc to the
    next user. As that user, I'll find a root cron running curl with the
    option to use a configuration file. It happens that I can control
    that file, and use it to get the root flag and a root shell. In
    Beyond root, I'll look at how setuid applies to scripts on most
    Linux flavors (and how it's different from Solaris as I showed with
    Sunday), and how the Dirty Sock snapd vulnerability from a couple
    months ago will work here to go to root.

-   Mar 27, 2019

    ### [Analyzing Document Macros with Yara](/analyzing-document-macros-with-yara.md)

    #phishing #vbscript #yara #documents #metasploit #powershell

    ![](/img/yara-cover.png) This post is
    actually inspired by a box I'm building for HTB, so if it ever gets
    released, some of you may see this post again. But Yara is also
    something I've used a ton professionally, and it is super useful.
    I'll introduce Yara, a pattern matching tool which is super useful
    for malware analysis, and just a general use tool that's useful to
    know. I'll also look at the file format for both Microsoft Office
    and Libre Office documents, and how to decompress them to identify
    their contents. I'll show how for Libre Office files, Yara can be
    applied to the unzipped document to identify macro contents.

-   Mar 26, 2019

    ### [HTB: October](/htb-october.md)

    #hackthebox #ctf #htb-october #webshell #ubuntu #linux #bof #exploit
    #upload #nmap #oscp-plus #aslr #aslr-bruteforce #htb-frolic

    ![](/img/october-cover.png)

    October was interesting because it paired a very straight-forward
    initial access with a simple buffer overflow for privesc. To gain
    access, I'll learn about a extension blacklist by pass against the
    October CMS, allowing me to upload a webshell and get execution.
    Then I'll find a SetUID binary that I can overflow to get root.
    While the buffer overflow exploit was on the more straight-forward
    side, it still requires a level of skill beyond many of the other
    easy early boxes I've done so far.

-   Mar 23, 2019

    ### [HTB: Frolic](/htb-frolic.md)

    #htb-frolic #hackthebox #ctf #nmap #smbmap #smbclient #nodered
    #gobuster #php #playsms #javascript #ook! #python #brainfuck
    #fcrackzip #xxd #cve-2017-9101 #webshell #bof #ret2libc #peda
    #metasploit #oscp-like #htb-reddish

    ![](/img/frolic-cover.png)

    Frolic was more a string of challenges and puzzles than the more
    typical HTB experiences. Enumeration takes me through a series of
    puzzles that eventually unlock the credentials to a PlaySMS web
    interface. With that access, I can exploit the service to get
    execution and a shell. To gain root, I'll find a setuid binary owned
    by root, and overflow it with a simple ret2libc attack. In Beyond
    Root, I'll at the Metasploit version of the PlaySMS exploit and
    reverse it's payload. I'll also glance through the Bash history
    files of the two users on the box and see how the author built the
    box.

-   Mar 16, 2019

    ### [HTB: Carrier](/htb-carrier.md)

    #ctf #hackthebox #htb-carrier #injection #command-injection
    #bgp-hijack #nmap #gobuster #snmp #snmpwalk #pivot #container
    #tcpdump #lxc #lxd #ssh

    ![](/img/carrier-cover.png)

    Carrier was awesome, not because it super hard, but because it
    provided an opportunity to do something that I hear about all the
    time in the media, but have never been actually tasked with doing -
    BGP Hijacking. I'll use SMNP to find a serial number which can be
    used to log into a management status interface for an ISP network.
    From there, I'll find command injection which actually gives me
    execution on a router. The management interface also reveals tickets
    indicting some high value FTP traffic moving between two other ASNs,
    so I'll use BGP hijacking to route the traffic through my current
    access, gaining access to the plaintext credentials. In Beyond Root,
    I'll look at an unintended way to skip the BGP hijack, getting a
    root shell and how the various containers were set up, why I only
    had to hijack one side of the conversation to get both sides, the
    website and router interaction and how to log commands sent over
    ssh, and what "secretdata" really was.

-   Mar 15, 2019

    ### [Applocker Bypass: COR Profiler](/htb-ethereal-cor.md)

    #ctf #hackthebox #htb-ethereal #windows #applocker #meterpreter
    #metasploit #beryllium #visual-studio #dotnet #cor-profiler

    ![](/img/ethereal-cor-cover.png)On of
    the challenges in Ethereal was having to use a shell comprised of
    two OpenSSL connections over different ports. And each time I wanted
    to exploit some user action, I had to set my trap in place, kill my
    shell, start two listeners, and wait. Things would have been a lot
    better if I could have just gotten a shell to connect back to me
    over one of the two open ports, but AppLocker made that nearly
    impossible. IppSec demoed a method to bypass those filters using COR
    Profiling. I wanted to play with it myself, and get some notes down
    (in the form of this post).

-   Mar 12, 2019

    ### [HTB: Bastard](/htb-bastard.md)

    #hackthebox #htb-bastard #ctf #web #drupal #drupalgeddon2
    #drupalgeddon3 #droopescan #dirsearch #nmap #windows #searchsploit
    #nishang #ms15-051 #smbserver #htb-devel #htb-granny #php #webshell
    #oscp-like

    ![](/img/bastard-cover.png)

    Bastard was the 7th box on HTB, and it presented a Drupal instance
    with a known vulnerability at the time it was released. I'll play
    with that one, as well as two more, Drupalgeddon2 and Drupalgeddon3,
    and use each to get a shell on the box. The privesc was very similar
    to other early Windows challenges, as the box is unpatched, and
    vulnerable to kernel exploits.

-   Mar 9, 2019

    ### [HTB: Ethereal](/htb-ethereal.md)

    #ctf #hackthebox #htb-ethereal #nmap #pbox #credentials #injection
    #hydra #python #shell #dns-c2 #firewall #nslookup #openssl #lnk
    #pylnker #lnkup #wfuzz #ca #msi #windows

    ![](/img/ethereal-cover.png)

    Ethereal was quite difficult, and up until a few weeks ago,
    potentially the hardest on HTB. Still, it was hard in a fun way. The
    path through the box was relatively clear, and yet, each step
    presented a technical challenge to figure out what was going on and
    how I could use it to get what I wanted. I'll start by breaking into
    an old password vault that I find on FTP, and using that to
    authenticate to a website. That site has code injection, and I'll
    use that to get exfil and eventually a weak shell over DNS. I'll
    discover OpenSSL, and use that to get a more stable shell. From
    there, I'll replace a shortcut to escalate to the next user. Then
    I'll user CA certs that I find on target to sign an MSI file to give
    me shell as the administrator. I'll also attach two additional
    posts, one going into how I attacked pbox, and another on how I
    developed a shell over blind command injection and dns.

-   Mar 9, 2019

    ### [HTB: Ethereal Attacking Password Box](/htb-ethereal-pbox.md)

    #ctf #hackthebox #htb-ethereal #windows #pbox #freebasic #bruteforce
    #credentials #basic #source-code

    ![](/img/ethereal-pbox-cover.png)For
    Ethereal, I found a DOS application, `pbox.exe`, and a `pbox.dat`
    file. These were associated with a program called PasswordBox, which
    was an early password manager program. To solve this box, most
    people likely just guessed the password, "password". But what if I
    had needed to brute force it? The program was not friendly to taking
    input from stdin, or from running inside python. So I downloaded the
    source code, installed the FreeBasic compiler, and started hacking
    at the source until it ran in a way that I could brute force test
    1000 passwords in 5 seconds. I'll walk through my steps and thought
    process in this post.

-   Mar 9, 2019

    ### [HTB: Ethereal Shell Development](/htb-ethereal-shell.md)

    #ctf #hackthebox #htb-ethereal #windows #dns-c2 #python #pdb
    #python-cmd #python-scapy #injection #python-requests

    ![](/img/ethereal-shell-cover.png)It
    would have been possible to get through the initial enumeration of
    Ethereal with just Burp Repeater and tcpdump, or using responder to
    read the DNS requests. But writing a shell is much more fun and good
    coding practice. I'll develop around primary two modules from
    Python, scapy to listen for and process DNS packets, and cmd to
    create a shell user interface, with requests to make the http
    injections. In this post I'll show how I built the shell step by
    step.

-   Mar 6, 2019

    ### [HTB: Granny](/htb-granny.md)

    #htb-granny #ctf #hackthebox #webdav #aspx #webshell #htb-devel
    #meterpreter #windows #ms14-058 #local_exploit_suggester #pwk
    #cadaver #oscp-like

    ![](/img/granny-cover.png)

    As I'm continuing to work through older boxes, I came to Granny,
    another easy Windows host involving webshells. In this case, I'll
    use WebDAV to get a webshell on target, which is something I haven't
    written about before, but that I definitely ran into while doing
    PWK. In this case, WebDav blocks aspx uploads, but it doesn't
    prevent me from uploading as a txt file, and then using the HTTP
    Move to move the file to an aspx. I'll show how to get a simple
    webshell, and how to get meterpreter. For privesc, I'll use a
    Windows local exploit to get SYSTEM access.

-   Mar 5, 2019

    ### [HTB: Devel](/htb-devel.md)

    #ctf #htb-devel #hackthebox #webshell #aspx #meterpreter #metasploit
    #msfvenom #ms11-046 #ftp #nishang #nmap #watson #smbserver #upload
    #windows #oscp-like

    ![](/img/devel-cover.png)

    Another one of the first boxes on HTB, and another simple beginner
    Windows target. In this case, I'll use anonymous access to FTP that
    has it's root in the webroot of the machine. I can upload a
    webshell, and use it to get execution and then a shell on the
    machine. Then I'll use one of many available Windows kernel exploits
    to gain system. I'll do it all without Metasploit, and then with
    Metasploit.

-   Mar 2, 2019

    ### [HTB: Access](/htb-access.md)

    #htb-access #hackthebox #ctf #mdbtools #readpst #mutt #telnet #runas
    #cached-creds #dpapi #mimikatz #pylnker

    ![](/img/access-cover.png)

    Access was an easy Windows box, which is really nice to have around,
    since it's hard to find places for beginners on Windows. And, unlike
    most Windows boxes, it didn't involve SMB. I'll start using
    anonymous FTP access to get a zip file and an Access database. I'll
    use command line tools to find a password in the database that works
    for the zip file, and find an Outlook mail file inside. I'll read
    the email to find the password for an account on the box, and
    connect with telnet. From there, I'll take advantage of cached
    administrator credentials two different ways to get root.txt. In
    Beyond Root, I'll look at ways to get more details out of lnk files,
    both with PowerShell and pylnker.

-   Feb 27, 2019

    ### [Playing with Jenkins RCE Vulnerability](/playing-with-jenkins-rce-vulnerability.md)

    #exploit #cve-2019-1003000 #jenkins #jeeves #powershell #nishang
    #windows

    ![](/img/jenkins-exploit-cover.jpg)Orange
    Tsai published a really interesting writeup on their discovery of
    CVE-2019-1003000, an Unauthenticated remote code execution (RCE) in
    Jenkins. There was a box from HackTheBox.eu that ran Jenkins, and
    while the configuration wasn't perfect for this kind of test, I
    decided to play with it and see what I could figure out. I'll get
    the exploit working with a new payload so that it runs on the
    Windows environment.

-   Feb 23, 2019

    ### [HTB: Zipper](/htb-zipper.md)

    #ctf #htb-zipper #hackthebox #nmap #zabbix #api #credentials
    #path-hijack #docker #ltrace #service-hijack #exploit-db #jq
    #openssl #php #pivot #ssh #linux #ubuntu #oswe-like

    ![](/img/zipper-cover.png)

    Zipper was a pretty straight-forward box, especially compared to
    some of the more recent 40 point boxes. The main challenge involved
    using the API for a product called Zabbix, used to manage and
    inventory computers in an environment. I'll show way too many ways
    to abuse Zabbix to get a shell. Then for privesc, I'll show two
    methods, using a suid binary that makes a call to system without
    providing a full path, allowing me to change the path and get a root
    shell, and identifying a writable service file that I can hijack to
    gain root privilege. In Beyond Root, I'll dig into the shell from
    Exploit-DB, figure out how it works, and make a few improvements.

-   Feb 22, 2019

    ### [Wizard Labs: Dummy](/wl-dummy.md)

    #ctf #wizard-labs #wl-dummy #nmap #smbmap #auto-blue #windows
    #ms17-010 #smb #msfvenom #metasploit #htb-legacy

    ![](/img/wl-dummy-cover.png)

    I had an opportunity to check out [Wizard
    Labs](https://labs.wizard-security.net) recently. It's a recently
    launched service much like HackTheBox. Their user interface isn't as
    polished or feature rich as HTB, but they have 16 vulnerable
    machines online right now to attack. The box called Dummy recently
    retired from their system, so I can safely give it a walk-through.
    It's a bit of bad luck that I looked at this just after doing
    [Legacy](/htb-legacy.md), as they were very similar
    boxes. Seems popular to start a service with a Windows SMB
    vulnerability. This was a Windows 7 box, vulnerable to MS17-010.
    I'll use a different python script, and give the Metasploit exploit
    a spin and fail.

-   Feb 21, 2019

    ### [HTB: Legacy](/htb-legacy.md)

    #ctf #hackthebox #htb-legacy #windows #ms08-067 #ms17-010 #smb
    #msfvenom #xp #oscp-like

    ![](/img/legacy-cover.png)

    Since I'm caught up on all the live boxes, challenges, and labs,
    I've started looking back at retired boxes from before I joined HTB.
    The top of the list was legacy, a box that seems like it was one of
    the first released on HTB. It's a very easy Windows box, vulnerable
    to two SMB bugs that are easily exploited with Metasploit. I'll show
    how to exploit both of them without Metasploit, generating shellcode
    and payloads with msfvenom, and modifying public scripts to get
    shells. In beyond root, I'll take a quick look at the lack of whoami
    on XP systems.

-   Feb 16, 2019

    ### [HTB: Giddy](/htb-giddy.md)

    #hackthebox #ctf #htb-giddy #sqli #sqlmap #winrm #net-ntlmv2
    #responder #hashcat #unifivideo #defender #ebowla #smbserver
    #applocker #powershell-web-access

    ![](/img/giddy-cover.png)I thought Giddy
    was a ton of fun. It was a relateively straight forward box, but I
    learned two really neat things working it (each of which inspired
    [other](/powershell-history-file.md)
    [posts](/getting-net-ntlm-hases-from-windows.md)). The
    box starts with some enumeration that leads to a site that gives
    inventory. I'll abuse an SQL-Injection vulnerability to get the host
    to make an SMB connect back to me, where I can collect Net-NTLMv2
    challenge response, and crack it to get a password. I can then use
    either the web PowerShell console or WinRM to get a shell. To get
    system, I'll take advantage of a vulnerability in Ubiquiti UniFi
    Video.

-   Feb 13, 2019

    ### [Playing with Dirty Sock](/playing-with-dirty-sock.md)

    #snapd #cve-2019-7304 #hackthebox #ubuntu #exploit #dirty-sock
    #htb-canape

    ![](/img/dirtysock-cover.png) A local
    privilege escalation exploit against a vulnerability in the snapd
    server on Ubuntu was released today by Shenanigans Labs under the
    name Dirty Sock. Snap is an attempt by Ubuntu to simplify packaging
    and software distribution, and there's a vulnerability in the REST
    API which is attached to a local UNIX socket that allowed multiple
    methods to get root access. I decided to give it a run, both on a VM
    locally and on some of the
    [HackTheBox.eu](https://www.hackthebox.eu) machines.

-   Feb 9, 2019

    ### [HTB: Ypuffy](/htb-ypuffy.md)

    #htb-ypuffy #hackthebox #ctf #ldap #ssh #ssh-keygen #doas #sudo
    #certificate #certificate-authority #wireshark #cve-2018-14665
    #python #flask #wsgi #authorizedkeyscommand #htb-dab

    ![](/img/ypuffy-cover.gif)Ypuffy was an
    OpenBSD box, but the author said it could have really been any OS,
    and I get that. The entire thing was about protocols that operate on
    any environment. I'll use ldap to get a hash, which I can use to
    authenticate an SMB share. There I find an SSH key that gets me a
    user shell. From there, I'll abuse my doas privilege with ssh-keygen
    to create a signed certificate that I can use to authenticate to the
    box as root for ssh. In Beyond root, I'll look at the Xorg privesc
    vulnerability that became public a month or so after Ypuffy was
    released, and also explore the web server configuration used in the
    ssh auth.

-   Feb 2, 2019

    ### [HTB: Dab](/htb-dab.md)

    #ctf #htb-dab #hackthebox #flask #python #nginx #wsgi #memcached
    #bruteforce #hydra #wfuzz #hashcat #ssh #ldd #ldconfig
    #reverse-engineering #ida

    ![](/img/dab-cover.png)Dab had some
    really neat elements, with a few trolls thrown in. I'll start by
    ignoring a steg troll in an open FTP and looking at two web apps. As
    I'm able to brute force my way into one, it populates a memcached
    instance, that I'm then able to query using the other as a proxy.
    From that instance, I'm able to dump users with md5 password hashes.
    After cracking twelve of them, one gives me ssh access to the box.
    From there, I'll take advantage of my having root level access to
    the tool that configures how dynamic run-time linking occurs, and
    use that to pivot to a root shell. In Beyond Root, I'll look at the
    web apps and how they are configured, one of the troll binaries, and
    a cleanup cron job I found but managed to avoid by accident.

-   Jan 28, 2019

    ### [PWK Notes: Tunneling and Pivoting \[Updated\]](/pwk-notes-tunneling-update1.md)

    #pwk #oscp #pivot #ssh #tunnel #sshuttle #meterpreter #htb-reddish

    ![](/img/tunneling-cover.jpg) That
    beautiful feeling of shell on a box is such a high. But once you
    realize that you need to pivot through that host deeper into the
    network, it can take you a bit out of your comfort zone. I've run
    into this in Sans Netwars, Hackthebox, and now in PWK. In this post
    I'll attempt to document the different methods I've used for
    pivoting and tunneling, including different ways to use SSH,
    sshuttle, and meterpreter, as well as some strategies for how to
    live from the host you are currently working through. Updated on 28
    Jan 2018 to add references to two additional tools, Chisel and SSF.

-   Jan 26, 2019

    ### [HTB: Reddish](/htb-reddish.md)

    #htb-reddish #hackthebox #ctf #node-red #nodejs #tunnel #php #redis
    #rsync #wildcard #docker

    ![](/img/reddish-cover.png)Reddish is
    one of my favorite boxes on HTB. The exploitation wasn't that
    difficult, but it required tunneling communications through multiple
    networks, and operate in bare-bones environments without the tools
    I've come to expect. Reddish was initially released as a medium
    difficulty (30 point) box, and after the initial user blood took 9.5
    hours, and root blood took 16.5 hours, it was raised to hard (40).
    Later, it was upped again to insane (50). To get root on this box,
    I'll start with an instance of node-red, a javascript browser-based
    editor to set up flows for IoT. I'll use that to get a remote shell
    into a container. From there I'll pivot using three other
    containers, escalating privilege in one, before eventually ending up
    in the host system. Throughout this process, I'll only have
    connectivity to the initial container, so I'll have to maintain
    tunnels for communication.

-   Jan 19, 2019

    ### [HTB: SecNotes](/htb-secnotes.md)

    #hackthebox #ctf #htb-secnotes #csrf #second-order-sqli
    #second-order #smb #wsl #bash.exe #winexe #smbclient #webshell
    #oscp-like #htb-nightmare

    ![](/img/secnotes-cover.png)SecNotes is
    a bit different to write about, since I built it. The goal was to
    make an easy Windows box that, though the HTB team decided to
    release it as a medium Windows box. It was the first box I ever
    submitted to HackTheBox, and overall, it was a great experience.
    I'll talk about what I wanted to box to look like from the HTB
    user's point of view in Beyond Root. SecNotes had a neat XSRF in the
    site that was completely bypassed by most people using an
    unintentional second order SQL injection. Either way, after gaining
    SMB credentials, it allowed the attacker to upload a webshell, and
    get a shell on the host. Privesc involved diving into the Linux
    Subsystem for Windows, finding the history file, and getting the
    admin creds from there.

-   Jan 15, 2019

    ### [Holiday Hack 2018: KringleCon](/holidayhack2018/)

    #ctf #sans-holiday-hack

    ![](/img/hh18-cover.png) The [Sans
    Holiday Hack](https://www.holidayhackchallenge.com) is one of the
    events I most look forward to each year. This year's event is based
    around [KringleCon](https://kringlecon.com/), an infosec conference
    organized by Santa as a response to the fact that there have been so
    many attempts to hack Christmas over the last few years. This
    conference even has a [bunch of
    talks](https://www.youtube.com/channel/UCNiR-C_VXv_TCFgww5Vczag),
    some quite useful for completing the challenge, but others that as
    just interesting as on their own. To complete the Holiday Hack
    Challenge, I'm asked to enter this virtual conference, walk around,
    and solve a series of technical challenges. As usual, the challenges
    were interesting and set up in such a way that it was very beginner
    friendly, with lots of hints and talks to ensure that you learned
    something while solving. The designers also implemented several more
    defensive / forensic challenges this year, which was neat to see.

-   Jan 13, 2019

    ### [Getting Creds via NTLMv2](/getting-net-ntlm-hases-from-windows.md)

    #responder #mitm #net-ntlmv2 #hashcat #llmnr #wpad #xp-dirtree

    ![](/img/responder-cover.png)

    One of the authentication protocols Windows machines use to
    authenticate across the network is a challenge / response /
    validation called Net-NTLMv2. If can get a Windows machine to engage
    my machine with one of these requests, I can perform an offline
    cracking to attempt to retrieve their password. In some cases, I
    could also do a relay attack to authenticate directly to some other
    server in the network. I've run into an interesting case of this
    recently that were worth sharing. In this post, I'll focus on ways
    to get a host to send you a challenge / response. If you're
    interested in relaying, leave a command and I'll consider that too.

-   Jan 12, 2019

    ### [HTB: Oz](/htb-oz.md)

    #htb-oz #hackthebox #ctf #api #sqli #hashcat #ssti #jinja2
    #payloadsallthethings #docker #container #pivot #ssh #port-knocking
    #portainer #tplmap #jwt #htb-olympus

    ![](/img/oz-cover.png)

    Oz was long. There was a bunch of enumeration at the front, but once
    you get going, it presented a relatively straight forward yet
    technically interesting path through two websites, a Server-Side
    Template Injection, using a database to access an SSH key, and then
    using the key to get access to the main host. To privesc, I'll go
    back into a different container and take advatnage of a vulnarbility
    in the docker management software to get root access.

-   Jan 8, 2019

    ### [HTB: Mischief Additional Roots](/htb-mischief-more-root.md)

    #htb-mischief #hackthebox #ctf #cve-2018-18955 #policykit #polkit
    #pkexec #pkttyagent #metasploit #msf-local

    Since publishing my [write-up on
    Mischief](/htb-mischief.md) from HackTheBox, I've
    learned of two additional ways to privesc to root once I have access
    as loki. The first is another method to get around the fact the `su`
    was blocked on the host using PolicyKit with the root password. The
    second was to take advantage of a kernel bug that was publicly
    released in November, well after Mischief went live. I'll quickly
    show both those methods.

-   Jan 5, 2019

    ### [HTB: Mischief](/htb-mischief.md)

    #hackthebox #ctf #htb-mischief #ipv6 #snmp #snmpwalk #enyx
    #command-injection #hydra #filter #facl #getfacl #systemd-run #lxc
    #lxd #wfuzz #xxd #iptables #color-print #htb-olympus

    ![](/img/mischief-cover.png)Mishcief was
    one of the easier 50 point boxes, but it still provided a lot of
    opportunity to enumerate things, and forced the attacker to think
    about and work with IPv6, which is something that likely don't come
    naturally to most of us. I'll use snmp to get both the IPv6 address
    of the host and credentials from the webserver. From there, I can
    use those creds to log in and get more creds. The other creds work
    on a website hosted only on IPv6. That site has command injection,
    which gives me code execution, a shell as www-data, and creds for
    loki. loki's bash history gives me the root password, which I can
    use to get root, once I get around the fact that file access control
    lists are used to prevent loki from running su. In beyond root, I'll
    look at how I could get RCE without the creds to the website, how I
    might have exfiled data via ping if there wasn't a way to see
    output, the filtering that site did, and the iptables rules.

-   Dec 31, 2018

    ### [Hackvent 2018: Days 1-12](/hackvent2018/)

    #ctf #hackvent #jab #qrcode #14-segment-display #javascript
    #dial-a-pirate #certificate-transparency #piet #perl #deobfuscation
    #steganography #stegsolve #nodejs #sandbox-escape #crypto #telegram
    #sqli

    ![](/img/hackvent2018-cover.png)
    Hackvent is a great CTF, where a different challenge is presented
    each day, and the techniques necessary to solve each challenge vary
    widely. Like Advent of Code, I only made it through the first half
    before a combination of increased difficulty, travel for the
    holidays, and Holiday Hack (and, of course, [winning NetWars
    TOC](https://twitter.com/0xdf_/status/1074880711285448705)) all led
    to my stopping Hackvent mid-way. Still, even the first 12 challenges
    has some neat stuff, and were interesting enough to write up.

-   Dec 19, 2018

    ### [You Need To Know jq](/jq.md)

    #ctf #sans-holiday-hack #hackthebox #jq #htb-waldo #ja3 #malware

    ![](/img/jq-cover.png)jq is such a nifty
    tool that not nealry enough people know about. If you're working
    with json data, even just small bits here and there, it's worth
    knowing the basics to make some simple data manipulations possible.
    And if you want to become a full on jq wizard, all the better. In
    this post, I'll walk through three examples of varying levels of
    complexity to show off jq. I'll detail what I did in Waldo, show an
    example from the 2017 Sans Holiday Hack Challenge, and conclude with
    a real-world example where I'm looking at SSL/TLS fingerprints.

-   Dec 15, 2018

    ### [HTB: Waldo](/htb-waldo.md)

    #ctf #hackthebox #htb-waldo #docker #php #ssh #rbash #capabilities

    ![](/img/waldo-cover.png) Waldo was a
    pretty straight forward box, with a few twists that weren't too
    difficult to circumvent. First, I'll take advantage of a php
    website, that allows me to leak its source. I'll use that to bypass
    filters to read files outside the webroot. In doing so, I'll find an
    ssh key that gets me into a container. I'll notice that I can
    actually ssh back into localhost again to get out of the container,
    but with a restricted rbash shell. After escaping, I'll find the tac
    program will the linux capability set to allow for full system read,
    giving me full read access over the entire system, including the
    flag.

-   Dec 12, 2018

    ### [Advent of Code 2018: Days 1-12](/adventofcode2018/)

    #ctf #advent-of-code #python

    ![](/img/aoc2018-cover.png)Advent of
    Code is a fun CTF because it forces you to program, and to think
    about data structures and efficiency. It starts off easy enough, and
    gets really hard by the end. It's also a neat learning opportunity,
    as it's one of the least competitive CTFs I know of. After the first
    20 people solve and the leaderboard is full, people start to post
    answers on reddit on other places, and you can see how others solved
    it, or help yourself when you get stuck. I'm going to create one
    post and just keep updating it with my answers as far as I get.

-   Dec 8, 2018

    ### [HTB: Active](/htb-active.md)

    #ctf #hackthebox #htb-active #active-directory #gpp-password
    #gpp-decrypt #smb #smbmap #smbclient #enum4linux #getuserspns
    #kerberoast #hashcat #psexec-py #oscp-like

    ![](/img/active-cover.png) Active was an
    example of an easy box that still provided a lot of opportunity to
    learn. The box was centered around common vulnerabilities associated
    with Active Directory. There's a good chance to practice SMB
    enumeration. It also gives the opportunity to use Kerberoasting
    against a Windows Domain, which, if you're not a pentester, you may
    not have had the chance to do before.

-   Dec 2, 2018

    ### [PWK Notes: SMB Enumeration Checklist \[Updated\]](/pwk-notes-smb-enumeration-checklist-update1.md)

    #oscp #pwk #enumeration #smb #nmblookup #smbclient #rpcclient #nmap
    #enum4linux #smbmap

    **🚨\[Updated for 2024\] Check out the latest version of this post
    [here](/smb-cheat-sheet.md).🚨**

-   Nov 30, 2018

    ### [HTB: Hawk](/htb-hawk.md)

    #hackthebox #ctf #htb-hawk #drupal #ftp #openssl #openssl-bruteforce
    #php #credentials #h2 #oscp-plus #htb-smasher

    ![](/img/hawk-cover.png)Hawk was a
    pretty easy box, that provided the challenge to decrypt a file with
    openssl, then use those credentials to get admin access to a Drupal
    website. I'll use that access to gain execution on the host via php.
    Credential reuse by the daniel user allows me to escalate to that
    user. From there, I'll take advantage of a H2 database to first get
    arbitrary file read as root, and then target a different
    vulnerability to get RCE and a root shell. In Beyond Root, I'll
    explore the two other listening ports associated with H2, 5435 and
    9092.

-   Nov 24, 2018

    ### [HTB: Smasher](/htb-smasher.md)

    #ctf #hackthebox #htb-smasher #bof #pwntools #timing-attack
    #padding-oracle #aes #directory-traversal

    ![](/img/smasher-cover.png) Smasher is a
    really hard box with three challenges that require a detailed
    understanding of how the code you're intereacting with works. It
    starts with an instance of shenfeng tiny-web-server running on
    port 1111. I'll use a path traversal vulnerability to access to the
    root file system. I'll use that to get a copy of the source and
    binary for the running web server. With that, I'll write a buffer
    overflow exploit to get a reverse shell. Next, I'll exploit a
    padding oracle vulnerability to get a copy of the smasher user's
    password. From there, I'll take advantage of a timing vulnerability
    in setuid binary to read the contents of root.txt. I think it's
    possible to get a root shell exploiting a buffer overflow, but I
    wasn't able to pull it off (yet). In Beyond Root, I'll check out the
    AES script, and show how I patched the checker binary.

-   Nov 24, 2018

    ### [Buffer Overflow in HTB Smasher](/htb-smasher-bof.md)

    #ctf #hackthebox #htb-smasher #gdb #bof #pwntools

    ![](/img/smasher-bof-cover.jpg) There
    was so much to write about for Smasher, it seemed that the buffer
    overflow in tiny deserved its own post. I'll walk through my
    process, code analysis and debugging, through development of a small
    ROP chain, and show how I trouble shot when things didn't work. I'll
    also show off pwntools along the way.

-   Nov 17, 2018

    ### [HTB: Jerry](/htb-jerry.md)

    #hackthebox #htb-jerry #ctf #nmap #tomcat #war #msfvenom #jar #jsp
    #oscp-like

    ![](/img/jerry-cover.png) Jerry is quite
    possibly the easiest box I've done on HackTheBox (maybe rivaled only
    by Blue). In fact, it was rooted in just over 6 minutes! There's a
    Tomcat install with a default password for the Web Application
    Manager. I'll use that to upload a malicious war file, which returns
    a system shell, and access to both flags.

-   Nov 13, 2018

    ### [Malware Analysis: Phishing Docs from HTB Reel](/malware-analysis-phishing-docs-from-htb-reel.md)

    #hackthebox #ctf #htb-reel #malware #rtf #hta #msfvenom #rtfdump
    #oledump #scdbg #powershell #vbscript #shellcode

    ![](/img/reel-malware-cover.png)I
    regularly use tools like msfvenom or scripts from GitHub to create
    attacks in HackTheBox or PWK. I wanted to take a minute and look
    under the hood of the phishing documents I generated to gain access
    to Reel in HTB, to understand what they are doing. By the end, we'll
    understand how the RTF abuses a COM object to download and launch a
    remote HTA. In the HTA, we'll see layers of script calling each
    other, until I find some shellcode loaded into memory by PowerShell
    and run. I'll do some initial analysis of that shellcode to see the
    network connection attempts.

-   Nov 10, 2018

    ### [HTB: Reel](/htb-reel.md)

    #hackthebox #htb-reel #ctf #ftp #cve-2017-0199 #rtf #hta #phishing
    #ssh #bloodhound #powerview #active-directory #metasploit #htb-bart

    ![](/img/reel-cover.png)Reel was an
    awesome box because it presents challenges rarely seen in CTF
    environments, phishing and Active Directory. Rather than initial
    access coming through a web exploit, to gain an initial foothold on
    Reel, I'll use some documents collected from FTP to craft a
    malicious rtf file and phishing email that will exploit the host and
    avoid the protections put into place. Then I'll pivot through
    different AD users and groups, taking advantage of their different
    rights to eventually escalate to administrator. In Beyond Root, I'll
    explore remnants of a second path to root that didn't make the final
    cut, look at the ACLs on root.txt, examine the script that opens
    attachments as nico.

-   Nov 8, 2018

    ### [PowerShell History File](/powershell-history-file.md)

    #powershell #psreadline #history

    I came across a situation where I discovered a user's PSReadline
    ConsoleHost_history.txt file, and it ended up giving me the
    information I needed at the time. Most people are aware of the
    `.bash_history` file. But did you know that the PowerShell
    equivalent is enabled by default starting in PowerShell v5 on
    Windows 10? This means this file will become more present over time
    as systems upgrade.

-   Nov 3, 2018

    ### [HTB: Dropzone](/htb-dropzone.md)

    #hackthebox #htb-dropzone #ctf #xp #tftp #mof #wmi #stuxnet
    #alternative-data-streams #sysinternals

    ![](/img/Parachute-win.png) Dropzone was
    unique in many ways. Right off the bat, an initial nmap scan shows
    no TCP ports open. I'll find unauthenticated TFTP on UDP 69, and use
    that access identify the host OS as Windows XP. From there, I'll use
    TFTP to drop a malicious mof file where it will automatically
    compiled, giving me code execution, in a technique made well know by
    Stuxnet (though not via TFTP, but rather a SMB 0-day). This
    technique provides a system shell, but there's one more twist, as
    I'll have to find the flags in alternative data streams of a text
    file on the desktop. I'll also take this opportunity to dive in on
    WMI / MOF and how they were used in Stuxnet.

-   Oct 27, 2018

    ### [HTB: Bounty](/htb-bounty.md)

    #hackthebox #htb-bounty #ctf #asp #upload #nishang #lonelypotato
    #potato #meterpreter #ms10-051 #ms16-014 #web.config #sherlock
    #watson #oscp-like

    ![](/img/bounty-cover.png) Bounty was
    one of the easier boxes I've done on HTB, but it still showcased a
    neat trick for initial access that involved embedding ASP code in a
    web.config file that wasn't subject to file extension filtering.
    Initial shell provides access as an unprivileged user on a
    relatively unpatched host, vulnerable to several kernel exploits, as
    well as a token privilege attack. I'll show a handful of ways to
    enumerate and to escalate privilege, including a really neat new
    tool, Watson. When I first wrote this post, Watson wouldn't run on
    Bounty, but thanks to some quick work from Rasta Mouse and Mark S, I
    was able to update the post to include it.

-   Oct 21, 2018

    ### [HTB TartarSauce: backuperer Follow-Up](/htb-tartarsauce-part-2-backuperer-follow-up.md)

    #ctf #hackthebox #htb-tartarsauce #tar #diff

    I always watch IppSec's videos on the retired box, because even if I
    completed the box, I typically learn something. Watching [IppSec's
    TartarSauce video](https://www.youtube.com/watch?v=9MeBiP637ZA)
    yesterday left me with three things I wanted to play with a bit more
    in depth, each related to the `backuperer` script. First, the issue
    of a bash if statement, and how it evaluates on exit status. Next,
    how Linux handles permissions and ownership between hosts and in and
    out of archives. Finally, I was wrong in thinking there wasn't a way
    to get a root shell... so of course I have to do that.

-   Oct 20, 2018

    ### [HTB: TartarSauce](/htb-tartarsauce.md)

    #ctf #htb-tartarsauce #hackthebox #wordpress #wpscan #php #webshell
    #rfi #sudo #tar #pspy #monstra #cron #oscp-like

    ![](/img/tartar-cover.png)TartarSauce
    was a box with lots of steps, and an interesting focus around two
    themes: trolling us, and the tar binary. For initial access, I'll
    find a barely functional WordPress site with a plugin vulnerable to
    remote file include. After abusing that RFI to get a shell, I'll
    privesc twice, both times centered around tar; once through sudo
    tar, and once needing to manipulate an archive before a sleep runs
    out. In beyond root, I'll look at some of the rabbit holes I went
    down, and show a short script I created to quickly get initial
    access and do the first privesc in one step.

-   Oct 13, 2018

    ### [HTB: DevOops](/htb-devoops.md)

    #ctf #hackthebox #htb-devoops #xxe #ssh #git #pickle
    #deserialization #htb-canape #rss #oscp-plus

    ![](/img/devoops-cover.png)DevOops was a
    really fun box that did a great job of providing interesting
    challenges that weren't too difficult to solve. I'll show how to
    gain access using XXE to leak the users SSH key, and then how I get
    root by discovering the root SSH key in an old git commit. In Beyond
    Root, I'll show an alternative path to user shell exploiting a
    python pickle deserialization bug.

-   Oct 11, 2018

    ### [PWK Notes: Post-Exploitation Windows File Transfers with SMB](/pwk-notes-post-exploitation-windows-file-transfers.md)

    #pwk #oscp #smb #impacket #exfil #upload

    Moving files to and from a compromised Linux machine is, in general,
    pretty easy. You've got nc, wget, curl, and if you get really
    desperate, base64 copy and paste. Windows, is another issue all
    together. PowerShell makes this somewhat easier, but for a lot of
    the PWK labs, the systems are too old to have PowerShell. The course
    material goes over a few ways to achieve this, but they don't cover
    my favorite - SMB. This may be less realistic in an environment
    where you have to connect from a victim machine back to your
    attacker box over the public internet (where SMB could be blocked),
    but for environments like PWK labs and HTB where you are vpned into
    the same LAN as your targets, it works great.

-   Sep 29, 2018

    ### [HTB: Sunday](/htb-sunday.md)

    #ctf #hackthebox #htb-sunday #finger #hashcat #sudo #wget #shadow
    #sudoers #gtfobins #arbitrary-write #oscp-like

    Sunday is definitely one of the easier boxes on HackTheBox. It had a
    lot of fun concepts, but on a crowded server, they step on each
    other. We start by using finger to brute-force enumerate users,
    though once once person logs in, the answer is given to anyone
    working that host. I'm never a huge fan of asking people to just
    guess obvious passwords, but after that, there are a couple more
    challenges, including a troll that proves useful later, some
    password cracking, and a ton of neat opportunities to complete the
    final privesc using wget. I'll show 6 ways to use wget to get root.
    Finally, in Beyond Root, I'll explore the overwrite script being run
    by root, finger for file transfer, and execution without read.

-   Sep 22, 2018

    ### [HTB: Olympus](/htb-olympus.md)

    #hackthebox #htb-olympus #ctf #zone-transfer #xdebug #aircrack-ng
    #802-11 #ssh #port-knocking #docker #cve-2018-15473

    Olympus was, for the most part, a really fun box, where we got to
    bounce around between different containers, and a clear path of
    challenges was presented to us. The creator did a great job of
    getting interesting challenges such as dns and wifi cracking into a
    HTB format. There was one jump I wasn't too excited to have to make,
    but overall, this box was a lot of fun to attack.

-   Sep 15, 2018

    ### [HTB: Canape](/htb-canape.md)

    #hackthebox #python #pickle #deserialization #couchdb #ctf
    #htb-canape #flask #pip #sudo #cve-2017-12635 #cve-1017-12636
    #cve-2018-8007 #erl #erlang

    Canape is one of my favorite boxes on HTB. There is a flask website
    with a pickle deserialization bug. I find that bug by taking
    advantage of an exposed git repo on the site. With a user shell, we
    can exploit CouchDB to gain admin access, where we get homer's
    password. I went down several rabbit holes trying to get code
    execution through couchdb, succeeding with EMPD, succeeding with one
    config change as root for CVE-2018-8007, and failing with
    CVE-2017-12636. Finally, I'll take advantage of our user having sudo
    rights to run pip, and first get a copy of the flag, and then take
    it all the way to root shell.

-   Sep 15, 2018

    ### [Malware Analysis: BMW_Of_Sterlin.doc](/malware-analysis-bmw_of_sterlindoc.md)

    #malware #vba #doc #powershell #dosfuscation #olevba

    Someone on an InfoSec group I participate in asked for help looking
    at a potentially malicious word doc. I took a quick look, and when I
    sent back the command line that came out, he asked if I could share
    how I was able to de-obfuscate quickly. In writing it up for him, I
    figured it might help others as well, so I'll post it here as an
    example.

-   Sep 12, 2018

    ### [Malware Analysis: YourExploit.pdf](/malware-analysis-yourexploitpdf.md)

    #malware #pdf #pdf-parser #pdfid #nanocore #vbscript

    Pretty simple PDF file was uploaded to VT today, and only 11 of our
    59 vendors mark is as malicious, despite it's being pretty tiny and
    clearly bad. The file makes no effort at showing any real cover, and
    could even be a test upload from the malicious actor. The file
    writes a vbs script which downloads the next stage, and then runs
    the script and then the resulting binary. The stage two is still up,
    so I got a copy, which I was able to identify as nanocore, and do
    some basic dynamic analysis of that as well.

-   Sep 8, 2018

    ### [HTB: Poison](/htb-poison.md)

    #hackthebox #ctf #htb-poison #log-poisoning #lfi #webshell #vnc
    #oscp-like

    Poison was one of the first boxes I attempted on HTB. The discovery
    of a relatively obvious local file include vulnerability drives us
    towards a web shell via log poisoning. From there, we can find a
    users password out in the clear, albeit lightly obfuscated, and use
    that to get ssh access. With our ssh access, we find VNC listening
    as root on localhost, and

-   Sep 1, 2018

    ### [HTB: Stratosphere](/htb-stratosphere.md)

    #ctf #htb-stratosphere #hackthebox #python #struts #cve-2017-9805
    #cve-2017-5638 #mkfifo-shell #forward-shell

    Stratosphere is a super fun box, with an Apache Struts vulnerability
    that we can exploit to get single command execution, but not a legit
    full shell. I'll use the Ippsec mkfifo pipe method to write my own
    shell. Then there's a python script that looks like it will give us
    the root flag if we only crack some hashes. However, we actually
    have to exploit the script, to get a root shell.

-   Aug 25, 2018

    ### [SecNotes now live on HackTheBox](/secnotes-now-live-on-hackthebox.md)

    #ctf #htb-secnotes #hackthebox #windows

    My first submission to HTB, SecNotes, went live today! I was aiming
    for an easy (20 pt) Windows box, but it released as a medium (30 pt)
    box. First blood for user just fell, 1 hour and 9 minutes in. Still
    waiting on root. I hope people enjoy, and if you do the box, please
    reach out to me on the forums or direct message and let me know what
    you thought of it, and how you solved it. I'd be very excited to
    hear if there were any unintended paths discovered.

-   Aug 25, 2018

    ### [HTB: Celestial](/htb-celestial.md)

    #hackthebox #htb-celestial #ctf #nodejs #deserialization #htb-aragog
    #pspy #cron #oswe-like

    Celestial is a fairly easy box that gives us a chance to play with
    deserialization vulnerabilities in Node.js. Weather it's in struts,
    or python's pickle, or in Node.js, deserialization of user input is
    almost always a bad idea, and here's we'll show why. To escalate,
    we'll take advantage of a cron running the user's code as root.

-   Aug 9, 2018

    ### [Malware Analysis: dotanFile.doc](/malware-analysis-dotanfiledoc.md)

    #malware #word-doc #vba #phishing #virus-total

    On first finding this sample, I was excited to think that I had
    found something interesting, rarely detected, and definitely
    malicious so close to when it was potentially used in a phishing
    attack. The more analysis I did, the more it became clear this was
    more likely a testing document, used by a security team evaluating
    their employees or an endpoint product. Still, it was an interesting
    sample to play with, and understand how it does interesting things
    like C2 protocol detection and Sandbox detection.

-   Aug 7, 2018

    ### [Malware Analysis: Penn National Health and Wellness Program 2018.doc](/malware-analysis-penn-national-health-and-wellness-program-2018doc.md)

    #malware #doc #vba #msbuild #csproj #dns #document-variables #crypto
    #c# #oledump

    This word document contains a short bit of VBA that's obfuscated
    using Word document variables to store the strings that might be
    identified in email filters and by AV. This seems to be effective,
    given the VT detection ratio. In fact, I came across this sample in
    conversation with someone who worked for one of the few products
    that was catching this sample. The VBA drops a Visual Basic C#
    project file, and runs it with msbuild, which executes a compilation
    Task. This code uses DNS TXT records to decrypt a next stage
    payload. Unfortunately, since the DNS record is no longer present.

-   Aug 6, 2018

    ### [Malware Analysis: inovoice-019338.pdf](/malware-analysis-inovoice-019338pdf.md)

    #malware #pdf #pdfid #pdf-parser #powershell #settingcontent-ms
    #flawedammyy

    This is a neat PDF sample that I saw mentioned on
    [\@c0d3inj3cT](https://twitter.com/c0d3inj3cT/status/1017553433128103936)'s
    Twitter, and wanted to take a look for myself. As
    [\@c0d3inj3cT](https://twitter.com/c0d3inj3cT/status/1017553433128103936)
    says, it is a PDF that drops a SettingsContent-ms file, which then
    uses PowerShell to download and execute the next stage. I had been
    on the lookout for PDFs that try to run code to play with, so this
    seemed like a good place to dive in.

-   Aug 4, 2018

    ### [HTB: Silo](/htb-silo.md)

    #htb-silo #hackthebox #ctf #oracle #odat #sqlplus #nishang #aspx
    #webshell #volatility #passthehash #rottenpotato #potato #oscp-like

    Silo was the first time I've had the opportunity to play around with
    exploiting a Oracle database. After the struggle of getting the
    tools installed and learning the ins and outs of using them, we can
    take advantage of this database to upload a webshell to the box.
    Then with the webshell, we can get a powershell shell access as a
    low-priv user. To privesc, we'll have to break out our memory
    forensics skillset to get a hash out of a memory dump, which then we
    can pass back in a pass the hash attack to get a system shell.
    That's all if we decided not to take the shortcut and just use the
    Oracle database (running as system) to read both flag files.

-   Jul 31, 2018

    ### [Malware Analysis: mud.doc](/malware-analysis-muddoc.md)

    #doc #vba #malware #crypto #phishing #wmi

    This phishing document was interesting for not only its lure /
    cover, but also for the way it used encryption to target users who
    had a domain with certain key words in it. While brute forcing the
    domains only results in some potentially financial key words, the
    stage 2 domain acts as a pivot to find an original phish email in
    VT, which shows this was quite targeted after all.

-   Jul 28, 2018

    ### [HTB: Valentine](/htb-valentine.md)

    #hackthebox #htb-valentine #ctf #heartbleed #tmux #dirtycow
    #oscp-like

    Valentine was one of the first hosts I solved on hack the box. We'll
    use heartbleed to get the password for an SSH key that we find
    through enumeration. There's two paths to privesc, but I'm quite
    partial to using the root tmux session. The box is very much on the
    easier side for HTB.

-   Jul 24, 2018

    ### [SANS SEC599 Review](/sans-sec599-review.md)

    #training #review #purple-team

    I had the chance to take [SANS
    SEC599](https://www.sans.org/course/defeating-advanced-adversaries-kill-chain-defenses),
    "Defeating Advanced Adversaries - Purple Team Tactics & Kill Chain
    Defenses" last week at SANSFIRE. The class is one of the newer SANS
    offerings, and so I suspect it will be changing and updating
    rapidly. There are some things I would change about the class, but
    overall, I enjoyed the class, definitely learned things that I
    didn't know before, and got to meet some really smart people.

-   Jul 21, 2018

    ### [HTB: Aragog](/htb-aragog.md)

    #ctf #htb-aragog #hackthebox #xxe #ssh #pspy #wordpress #cron

    Aragog provided a chance to play with XML External Entity (XXE)
    vulnerabilities, as well as a chance to modify a running website to
    capture user credentials.

-   Jul 15, 2018

    ### [HTB: Bart](/htb-bart.md)

    #hackthebox #htb-bart #ctf #nmap #gobuster #wfuzz #cewl #bruteforce
    #log-poisoning #php #webshell #nishang #winlogon #powershell-run-as
    #oscp-plus

    Bart starts simple enough, only listening on port 80. Yet it ends up
    providing a path to user shell that requires enumeration of two
    different sites, bypassing two logins, and then finding a file
    upload / LFI webshell. The privesc is relateively simple, yet I ran
    into an interesting issue that caused me to miss it at first.
    Overall, a fun box with lots to play with.

-   Jul 7, 2018

    ### [Second Order SQL-Injection on HTB Nightmare](/second-order-sql-injection-on-htb-nightmare.md)

    #hackthebox #htb-nightmare #ctf #sqli #sqlmap #tamper
    #second-order-sqli #second-order

    Nightmare just retired, and it was a insanely difficult box. Rather
    than do a full walkthrough, I wanted to focus on a write-up of the
    second-order SQL injection necessary as a first step for this host.

-   Jul 7, 2018

    ### [Malware Analysis: Faktura_VAT_115590300178.js](/malware-analysis-faktura_vat_115590300178js.md)

    #malware #javascript #procmon #procdot #process-hacker #logging
    #powershell

    I spent some time looking at this javascript sample from VT. Based
    on both the file extension and the fact that I couldn't get it to
    run in `spidermonkey` or `internet explorer`, it seems likely that
    this was a `.js` file sent as a phishing attachment that acts as a
    downloader to get the next stage from the c2 server. I show how to
    use Process Hacker, ProcMon, ProcDot, and Windows loggings to
    observer the PowerShell commands, and thus determine what the
    mawlare was doing.

-   Jun 30, 2018

    ### [HTB: Nibbles](/htb-nibbles.md)

    #hackthebox #htb-nibbles #ctf #meterpreter #sudo #cve-2015-6967
    #oscp-like

    Nibbles is one of the easier boxes on HTB. It hosts a vulnerable
    instance of [nibbleblog](http://www.nibbleblog.com/). There's a
    Metasploit exploit for it, but it's also easy to do without MSF, so
    I'll show both. The privesc involves abusing `sudo` on a file that
    is world-writable.

-   Jun 23, 2018

    ### [HTB: Falafel](/htb-falafel.md)

    #hackthebox #htb-falafel #ctf #wfuzz #sqlmap #sqli #type-juggling
    #php #upload #webshell #framebuffer #/dev/fb0 #debugfs #oscp-plus
    #oswe-like

    Falafel is one of the best put together boxes on HTB. The author
    does a great job of creating a path with lots of technical
    challenges that are both not that hard and require a good deal of
    learning and understanding what's going on. And there are hints
    distributed to us along the way.

-   Jun 18, 2018

    ### [HTB: Chatterbox](/htb-chatterbox.md)

    #hackthebox #htb-chatterbox #ctf #msfvenom #meterpreter #achat
    #autorunscript #nishang #oscp-like

    Chatterbox is one of the easier rated boxes on HTB. Overall, this
    box was both easy and frustrating, as there was really only one
    exploit to get all the way to system, but yet there were many
    annoyances along the way. While I typically try to avoid
    Meterpreter, I'll use it here because it's an interesting chance to
    learn / play with the Metasploit AutoRunScript to migrate
    immediately after exploitation, so that I could maintain a stable
    shell.

-   Jun 10, 2018

    ### [Intro to SSH Tunneling](/intro-to-ssh-tunneling.md)

    #hackthebox #ssh #tunnel

    I came across a situation on a [htb](https://www.hackthebox.eu) box
    today where I needed IE to get a really slow, older, OWA page to
    fully function and do what I needed to do. I had a Windows vm
    around, but it was relatively isolated, and no able to talk directly
    to my kali vm. SSH tunneling turned out to be the easiest solution
    here, and since I get questions about SSH tunneling all the time, I
    figured it would be good to write up a short description.

-   Jun 8, 2018

    ### [PSDecode, follow-on analysis of Emotet samples](/malware-analysis-facture-impayee-30-mai0730-04071885doc.md)

    #emotet #malware #doc #powershell #invoke-obfuscation #psdecode

    In [my analysis of an emotet
    sample](/emotet-doc-sample.md), I came across
    [PSDecode](https://github.com/R3MRUM/PSDecode), and, after some back
    and forth with the author and a couple updates, got it working on
    this sample. The tool is very cool. What follows is analysis of a
    different emotet phishing document similar to the other one I was
    looking at, as well as `PSDecode` output for the previous sample.

-   Jun 4, 2018

    ### [Malware: Facture-impayee-30-mai#0730-04071885.doc](/emotet-doc-sample.md)

    #malware #doc #vba #powershell #emotet #invoke-obfuscation

    Interesting sample from VT which ends up being a phishing document
    for the Emotet malware.

-   Jun 3, 2018

    ### [HTB: CrimeStoppers](/htb-crimestoppers.md)

    #ctf #hackthebox #htb-crimestoppers #php #php-wrapper #lfi #ida
    #reverse-engineering

    This is one of my favorite boxes on HTB. It's got a good flow, and I
    learned a bunch doing it. We got to tackle an LFI that allows us to
    get source for the site, and then we turn that LFI into RCE toget
    access. From there we get access to a Mozilla profile, which allows
    privesc to a user, and from there we find someone's already left a
    modified rootme apache module in place. We can RE that mod to get
    root on the system.

-   May 12, 2018

    ### [HTB: FluxCapacitor](/htb-fluxcapacitor.md)

    #ctf #hackthebox #htb-fluxcapacitor #waf #wfuzz #sudo

    Probably my least favorite box on HTB, largely because it involved a
    lot of guessing. I did enjoy looking for privesc without having a
    shell on the host.

-   Apr 29, 2018

    ### [HTB: Bashed](/htb-bashed.md)

    #ctf #hackthebox #htb-bashed #php #sudo #cron #oscp-like

    Bashed retired from hackthebox.eu today. Here's my notes transformed
    into a walkthrough. These notes are from a couple months ago, and
    they are a bit raw, but posting here anyway.

-   Jan 15, 2018

    ### [Home Lab On The Super Cheap - ESXi](/home-lab-on-the-super-cheap-esxi.md)

    #macpro #home-lab #esxi

    Getting the hypervisor installed is the next step.

-   Jan 15, 2018

    ### [Home Lab On The Super Cheap - The Hardware](/home-lab-on-the-super-cheap-the-hardware.md)

    #ebay #macpro #home-lab

    The benefits of a home lab are numerous to anyone into infosec,
    CTFs, and/or malware analysis. Here's how I approached it on the
    cheap.

subscribe [via RSS](/feed.xml)


