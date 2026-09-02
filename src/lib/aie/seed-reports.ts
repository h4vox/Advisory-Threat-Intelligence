export const SEED_REPORTS: {
  id: string;
  sourceId: string;
  title: string;
  url: string;
  publishedAt: string;
  text: string;
}[] = [
  {
    id: "rpt_seed_lynx",
    sourceId: "src_dfir",
    title: "Lynx ransomware via a single valid RDP logon",
    url: "https://thedfirreport.com/2025/12/17/cats-got-your-files-lynx-ransomware/",
    publishedAt: "2025-12-17",
    text: `Case summary
The intrusion began with a single successful Remote Desktop Protocol (RDP) logon to an internet-exposed host. There was no evidence of password spraying or brute force from the source IP. Valid credentials were the initial access vector.

Infection chain
1. Initial Access — RDP with valid credentials (T1078, T1021.001).
2. Execution — Living-off-the-land binaries including PowerShell (T1059.001) and cmd.exe.
3. Credential Access — LSASS memory access and NTDS.dit staging (T1003.001, T1003.003).
4. Discovery — Active Directory enumeration with built-in tools (T1087, T1018).
5. Lateral Movement — RDP and SMB admin shares to additional hosts (T1021.001, T1021.002).
6. Collection and exfiltration — Archives staged, then transferred with rclone-like utilities (T1560, T1048).
7. Impact — Lynx ransomware deployed against file servers and backups (T1486, T1490).

Technical analysis
Stage 1. The first authentication was a successful domain user logon over TCP 3389. No failed logons preceded it. This matches a credential-first playbook: infostealer logs or an initial access broker rather than exploitation.

Stage 2. After logon the operator used PowerShell to run reconnaissance scripts. Command lines included Get-ADComputer and net group queries. Parent process was explorer.exe then powershell.exe.

Stage 3. Credential dumping targeted LSASS. A renamed ProcDump-style binary wrote a dump to C:\\Users\\Public. Later, ntdsutil or volume shadow copy was used on a domain controller to copy NTDS.dit.

Stage 4–5. Lateral movement blended into IT operations: RDP, WMI, and administrative SMB. Defense evasion included disabling a subset of EDR services (T1562.001).

Stage 6–7. Backup jobs were deleted before encryption. The ransomware note claimed double extortion. MITRE ATT&CK coverage includes TA0001, TA0002, TA0006, TA0008, TA0010, TA0040.

Detection opportunities
Process creation for powershell.exe with AD enumeration, LSASS access, ntdsutil, rclone, and mass file rename. Hunt for first-time RDP from rare external ASNs using valid accounts.

This seed record is a structured stand-in so the retrieval library is immediately usable. Live ingest of the original URL will replace or sit alongside it after hash comparison.`,
  },
  {
    id: "rpt_seed_akira",
    sourceId: "src_dfir",
    title: "SEO-poisoned installer to Akira ransomware",
    url: "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/",
    publishedAt: "2026-06-29",
    text: `Overview
A user searching for a legitimate IT management product was redirected to a lookalike domain. The downloaded MSI dropped Bumblebee via DLL side-loading. The intrusion later installed AdaptixC2, stole credentials, exfiltrated data, and deployed Akira ransomware across the root domain.

Infection chain
Initial Access — Drive-by / trojanized software (T1189, T1204.002).
Execution — Side-loaded loader and subsequent beacons (T1574.002, T1059).
Persistence — Scheduled tasks and service installation (T1053.005).
Credential Access — Browser data and LSASS (T1555.003, T1003.001).
Discovery — Network and AD recon (T1046, T1482).
Lateral Movement — Remote services with stolen hashes (T1021, T1550.002).
Command and Control — AdaptixC2 over HTTPS (T1071.001).
Exfiltration — Cloud file host and FTP (T1567).
Impact — Akira encryptor, including a return two days later against a child domain (T1486).

Technical analysis
The MSI executed a signed-looking helper that loaded a malicious DLL. Bumblebee established C2, then operators switched to AdaptixC2 for interactive work. Approximately 44 hours after initial compromise, encryption began on the backup server first.

Observed tools included Bumblebee, AdaptixC2, Rclone, and Akira. Infrastructure used bulletproof hosting and Cloudflare-fronted domains. IOCs in the public case typically include SHA-256 hashes of the MSI and loader DLLs, C2 domains, and the encryptor hash.

Hunting hypotheses
Look for MSI installs from newly registered domains after search-engine referrals. Alert on DLL side-loading pairs and unusual rclone.exe command lines talking to public cloud storage.

MITRE mapping (observed): T1189, T1204.002, T1574.002, T1059.001, T1003.001, T1021.001, T1486.`,
  },
  {
    id: "rpt_seed_mandiant_ttps",
    sourceId: "src_mandiant",
    title: "Ransomware TTPs: credentials and RDP still dominate",
    url: "https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape",
    publishedAt: "2026-03-16",
    text: `Mandiant consulting telemetry for 2025 ransomware intrusions shows a structural shift toward identity abuse.

Initial access
In 21% of cases with a known vector, operators used compromised legitimate credentials against VPN or RDP. Vulnerability exploitation remains important but is no longer the default story.

Privilege escalation
Mimikatz appeared in about 18% of ransomware intrusions, continuing a slow decline as operators lean on built-in authentication. Active Directory abuse and over-privileged service accounts remain the path to domain admin.

Lateral movement
RDP with stolen or attacker-created accounts was used in approximately 85% of intrusions. SMB and SSH followed. Tunneling and proxy utilities hide inbound access without exposing firewall ports.

Virtualization
About 43% of 2025 ransomware cases targeted virtualization infrastructure, up from 29% the year before. ESXi encryption after an IT foothold is now a standard impact stage.

Data theft
Confirmed or suspected theft occurred in 77% of ransomware cases (up from 57%). Double extortion is the default, not the exception.

ATT&CK techniques repeatedly observed: T1078, T1021.001, T1003, T1486, T1490, T1567, T1048.

This summary is stored as retrieved knowledge for simulation planning. Full vendor article should be ingested live when reachable.`,
  },
  {
    id: "rpt_seed_msft_msp",
    sourceId: "src_msft",
    title: "Third-party IT provider compromise to domain-wide access",
    url: "https://www.microsoft.com/en-us/security/blog/2026/05/12/undermining-the-trust-boundary-investigating-a-stealthy-intrusion-through-third-party-compromise/",
    publishedAt: "2026-05-12",
    text: `The actor gained initial access by compromising a third-party IT services provider, then operated through trusted remote support channels so execution did not immediately look hostile.

Timeline
Days 9–14: Credential interception on domain infrastructure. Harvested credentials reused across devices (T1557, T1558, T1078).
Days 24–32: Web-based persistence on internet-facing servers (T1505.003).
Days 40–60: Lateral movement using valid credentials, remote management protocols, and ngrok tunnels for inbound RDP without exposed ports (T1021.001, T1572).
Days 54–55: Additional credential interception deployed.

Defense evasion included log manipulation and dual-actor noise in one environment. Expected telemetry: new inbound tunnels, unusual RDP from jump hosts, and credential dumping on DCs.

Simulation relevance
High for purple teams that assume a trusted MSP. Prerequisite is a valid account on a remote-support jump box. Cleanup must revoke tunnels and rotate privileged credentials.

Mapped techniques: T1199, T1078, T1003, T1021.001, T1572, T1505.003.`,
  },
];
