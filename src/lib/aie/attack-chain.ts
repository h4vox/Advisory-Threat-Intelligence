import type { AttackStep, IntelAnalysis } from "./types";

const KNOWN_ACTORS = [
  "APT28", "Fancy Bear",
  "APT29", "Cozy Bear", "Midnight Blizzard", "NOBELIUM",
  "APT33", "Elfin",
  "APT34", "OilRig",
  "APT38", "Lazarus Group", "HIDDEN COBRA",
  "APT39", "Chafer",
  "APT41", "Double Dragon", "Brass Typhoon",
  "Sandworm", "Seashell Blizzard", "TeleBots",
  "FIN7", "Carbon Spider",
  "FIN8",
  "LockBit", "LockBit 3.0",
  "BlackCat", "ALPHV",
  "Akira",
  "Scattered Spider", "Star Blizzard",
  "Volt Typhoon", "Vanguard Panda",
  "Flax Typhoon",
  "Wizard Spider",
  "CL0P", "FIN11",
  "Black Basta",
  "Rhysida",
  "BianLian",
  "Play Ransomware",
];

const KNOWN_MALWARE_AND_TOOLS = [
  "Cobalt Strike",
  "Mimikatz",
  "Qakbot", "Qbot",
  "Bumblebee",
  "AdaptixC2",
  "SystemBC",
  "IcedID",
  "Emotet",
  "Sliver",
  "Havoc C2",
  "Brute Ratel",
  "Chisel",
  "Ligolo-ng",
  "Ngrok",
  "BloodHound",
  "SharpHound",
  "Impacket",
  "PsExec",
  "Rubeus",
  "Certify",
  "AnyDesk",
  "TeamViewer",
  "ScreenConnect",
  "MegaSync",
  "Rclone",
  "7-Zip",
  "AdFind",
  "PowerView",
  "Seatbelt",
  "SharpUp",
  "LaZagne",
  "Responder",
];

const TACTIC_TECHNIQUE_MAP: { [tactic: string]: { id: string; name: string; pattern: RegExp }[] } = {
  "Initial Access": [
    { id: "T1190", name: "Exploit Public-Facing Application", pattern: /\b(exploit public|web exploit|apache activemq|cve-\d{4}-\d+|vulnerability exploitation)\b/i },
    { id: "T1566.001", name: "Phishing: Spearphishing Attachment", pattern: /\b(phishing email|malicious attachment|iso file|zip attachment|macro)\b/i },
    { id: "T1566.002", name: "Phishing: Spearphishing Link", pattern: /\b(phishing link|malicious url|seo poisoning|malvertising)\b/i },
    { id: "T1078.002", name: "Valid Accounts: Domain Accounts", pattern: /\b(valid rdp credentials|stolen domain credentials|compromised account|valid credentials)\b/i },
    { id: "T1133", name: "External Remote Services", pattern: /\b(rdp|vpn access|citrix|remote desktop gateway)\b/i },
  ],
  "Execution": [
    { id: "T1059.001", name: "Command and Scripting: PowerShell", pattern: /\b(powershell|powershell\.exe|encodedcommand|-enc|-noni)\b/i },
    { id: "T1059.003", name: "Command and Scripting: Windows Command Shell", pattern: /\b(cmd\.exe|batch script|\.bat|\.cmd)\b/i },
    { id: "T1059.005", name: "Command and Scripting: Visual Basic", pattern: /\b(wscript|cscript|vbs|vba)\b/i },
    { id: "T1204.002", name: "User Execution: Malicious File", pattern: /\b(user executed|double-clicked|opened document|extracted archive)\b/i },
    { id: "T1047", name: "Windows Management Instrumentation", pattern: /\b(wmic|wmi execution|wmic process call)\b/i },
  ],
  "Persistence": [
    { id: "T1547.001", name: "Boot or Logon Autostart: Registry Run Keys", pattern: /\b(registry run|runonce|currentversion\\run)\b/i },
    { id: "T1053.005", name: "Scheduled Task/Job: Scheduled Task", pattern: /\b(schtasks|scheduled task|task scheduler)\b/i },
    { id: "T1543.003", name: "Create or Modify System Process: Windows Service", pattern: /\b(create service|sc\.exe create|new-service)\b/i },
    { id: "T1136.001", name: "Create Account: Local Account", pattern: /\b(net user \/add|created local user|new admin account)\b/i },
  ],
  "Privilege Escalation": [
    { id: "T1068", name: "Exploitation for Privilege Escalation", pattern: /\b(privilege escalation|kernel exploit|cve-\d+.*privilege)\b/i },
    { id: "T1548.002", name: "Abuse Elevation Control: Bypass UAC", pattern: /\b(bypass uac|fodhelper|eventvwr|uac bypass)\b/i },
    { id: "T1078.001", name: "Valid Accounts: Default Accounts", pattern: /\b(system account|nt authority\\system|elevated token)\b/i },
  ],
  "Defense Evasion": [
    { id: "T1562.001", name: "Impair Defenses: Disable Tools", pattern: /\b(disable defender|stopped edr|tamper protection|mpcmdrun|sc stop)\b/i },
    { id: "T1070.001", name: "Indicator Removal: Clear Windows Event Logs", pattern: /\b(wevtutil cl|clear-eventlog|cleared event log)\b/i },
    { id: "T1027", name: "Obfuscated Files or Information", pattern: /\b(obfuscated|base64 encoded|xor encrypted|string encryption)\b/i },
    { id: "T1055", name: "Process Injection", pattern: /\b(process injection|hollow|reflective dll|create remotethread)\b/i },
  ],
  "Credential Access": [
    { id: "T1003.001", name: "OS Credential Dumping: LSASS Memory", pattern: /\b(lsass|procdump|mimikatz|sekurlsa|comsvcs\.dll|minidump)\b/i },
    { id: "T1003.003", name: "OS Credential Dumping: NTDS", pattern: /\b(ntds\.dit|volume shadow copy|vssadmin|ntdsutil)\b/i },
    { id: "T1558.003", name: "Steal or Forge Kerberos Tickets: Kerberoasting", pattern: /\b(kerberoasting|rubeus|tgsqry|spn query)\b/i },
    { id: "T1555.003", name: "Credentials from Web Browsers", pattern: /\b(browser credentials|chrome passwords|login data|sqlite database)\b/i },
  ],
  "Discovery": [
    { id: "T1087.002", name: "Account Discovery: Domain Account", pattern: /\b(net user \/domain|adfind|powerview|get-aduser|nltest)\b/i },
    { id: "T1018", name: "Remote System Discovery", pattern: /\b(advanced ip scanner|ping sweep|net view|port scan)\b/i },
    { id: "T1069.002", name: "Permission Groups: Domain Groups", pattern: /\b(net group "domain admins"|get-adgroupmember|bloodhound)\b/i },
  ],
  "Lateral Movement": [
    { id: "T1021.001", name: "Remote Services: Remote Desktop Protocol", pattern: /\b(rdp connection|mstsc|rdp lateral movement|remote desktop session)\b/i },
    { id: "T1021.002", name: "Remote Services: SMB/Windows Admin Shares", pattern: /\b(admin\$|c\$|smb exec|psexec|wmi lateral)\b/i },
    { id: "T1570", name: "Lateral Tool Transfer", pattern: /\b(copied binary|transferred tool|smb copy|curl download to share)\b/i },
  ],
  "Collection": [
    { id: "T1560.001", name: "Archive Collected Data: Archive via Utility", pattern: /\b(7z\.exe|winrar|tar czf|archive created|compressed files)\b/i },
    { id: "T1005", name: "Data from Local System", pattern: /\b(staged files|collected documents|sensitive directory)\b/i },
  ],
  "Command and Control": [
    { id: "T1071.001", name: "Application Layer Protocol: Web Protocols", pattern: /\b(c2 over https|http beacon|post request|c2 traffic)\b/i },
    { id: "T1572", name: "Protocol Tunneling", pattern: /\b(chisel tunnel|ngrok|reverse proxy|socks5 proxy|cloudflared)\b/i },
    { id: "T1105", name: "Ingress Tool Transfer", pattern: /\b(certutil -urlcache|bitsadmin|invoke-webrequest|download cradle)\b/i },
  ],
  "Exfiltration": [
    { id: "T1567.002", name: "Exfiltration Over Web Service: Cloud Storage", pattern: /\b(rclone|megasync|exfiltration to mega|dropbox upload|aws s3)\b/i },
    { id: "T1048", name: "Exfiltration Over Alternative Protocol", pattern: /\b(ftp exfiltration|sftp upload|encrypted c2 exfil)\b/i },
  ],
  "Impact": [
    { id: "T1486", name: "Data Encrypted for Impact", pattern: /\b(ransomware encryption|encrypted files|ransom note|vssadmin delete shadows)\b/i },
    { id: "T1490", name: "Inhibit System Recovery", pattern: /\b(delete shadows|bcedit|wbadmin delete catalog|disabled recovery)\b/i },
  ],
};

export function analyzeThreatIntelligence(text: string, title: string, classification: string): IntelAnalysis {
  const fullText = `${title}\n${text}`;

  // 1. Extract Threat Actors
  const threatActors: string[] = [];
  for (const actor of KNOWN_ACTORS) {
    const re = new RegExp(`\\b${actor.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
    if (re.test(fullText) && !threatActors.includes(actor)) {
      threatActors.push(actor);
    }
  }

  // 2. Extract Malware and Tools
  const malware: string[] = [];
  for (const tool of KNOWN_MALWARE_AND_TOOLS) {
    const re = new RegExp(`\\b${tool.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
    if (re.test(fullText) && !malware.includes(tool)) {
      malware.push(tool);
    }
  }

  // 3. Extract Vulnerabilities
  const vulnerabilities = Array.from(
    new Set((fullText.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).map((c) => c.toUpperCase())),
  );

  // 4. Map ATT&CK Tactics, Techniques, and Sequence
  const ttps: string[] = [];
  const ioas: string[] = [];
  const attackChain: AttackStep[] = [];
  let order = 1;

  for (const [tactic, techList] of Object.entries(TACTIC_TECHNIQUE_MAP)) {
    const matchedTechniques: string[] = [];

    for (const tech of techList) {
      if (tech.pattern.test(fullText) || new RegExp(`\\b${tech.id}\\b`, "i").test(fullText)) {
        const entry = `${tech.id} - ${tech.name}`;
        if (!matchedTechniques.includes(entry)) {
          matchedTechniques.push(entry);
          ttps.push(entry);
        }
      }
    }

    if (matchedTechniques.length > 0) {
      let summary = "";
      if (tactic === "Initial Access") {
        summary = "Adversary achieves foothold via exploit, valid accounts, or phishing artifact.";
        ioas.push("Unusual parent-process spawning web servers or spearphishing attachment execution");
      } else if (tactic === "Execution") {
        summary = "Malicious command execution via encoded PowerShell, Command Shell, or WMI.";
        ioas.push("PowerShell spawned with -EncodedCommand or -WindowStyle Hidden");
      } else if (tactic === "Persistence") {
        summary = "Persistence established via scheduled tasks or autostart registry keys.";
        ioas.push("Non-standard scheduled tasks created via schtasks.exe or COM handlers");
      } else if (tactic === "Credential Access") {
        summary = "LSASS memory dumped or NTDS.dit exfiltrated for credential harvesting.";
        ioas.push("Process accessing LSASS with PROCESS_VM_READ permissions or minidump API");
      } else if (tactic === "Lateral Movement") {
        summary = "Internal pivoting using SMB/Admin shares, PsExec, or RDP sessions.";
        ioas.push("Remote service creation or atypical RDP connections across workstation subnets");
      } else if (tactic === "Command and Control") {
        summary = "C2 beacons established with encrypted egress traffic or reverse tunneling.";
        ioas.push("Anomalous outbound TLS connections with high beaconing frequency or tunneling binaries");
      } else if (tactic === "Impact") {
        summary = "Shadow copies inhibited and files encrypted with custom ransom note deployed.";
        ioas.push("Volume shadow copies deleted via vssadmin.exe or bcdedit tampering");
      } else {
        summary = `Observed actions mapped to ${tactic} phase.`;
      }

      attackChain.push({
        order: order++,
        tactic,
        techniques: matchedTechniques,
        summary,
      });
    }
  }

  // 5. Generate Detection Rules & Emulation Guidance
  const detections: string[] = [];
  const hunting: string[] = [];
  const emulation: string[] = [];

  if (ttps.some((t) => t.includes("T1059.001"))) {
    detections.push("Sigma: Suspicious PowerShell Process with Encoded Arguments (EventID 4688 / Sysmon 1)");
    hunting.push("Hunting: Search for powershell.exe where CommandLine contains base64 patterns or DownloadString");
    emulation.push("Atomic Test: powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Write-Host 'Emulated Execution'\"");
  }
  if (ttps.some((t) => t.includes("T1003.001"))) {
    detections.push("Sigma: LSASS Memory Access and Dump Creation (Sysmon EventID 10 / CallTrace comsvcs)");
    hunting.push("Hunting: Audit process handles granted to lsass.exe from untrusted binary directories");
    emulation.push("Atomic Test: rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (LSASS PID) dump.dmp full");
  }
  if (ttps.some((t) => t.includes("T1021.002") || t.includes("T1021.001"))) {
    detections.push("Sigma: Lateral Movement via Remote SMB Admin Share or PSEXESVC creation (EventID 7045)");
    hunting.push("Hunting: Correlate EventID 4624 (Logon Type 3) followed by administrative file writes in ADMIN$ or C$");
    emulation.push("Atomic Test: Invoke-Command -ComputerName (Target) -ScriptBlock { whoami /all }");
  }
  if (ttps.some((t) => t.includes("T1486") || t.includes("T1490"))) {
    detections.push("Sigma: Shadow Copy Deletion via Vssadmin or Wmic (EventID 4688)");
    hunting.push("Hunting: Query for vssadmin.exe delete shadows /all /quiet or bcdedit /set recoveryenabled no");
    emulation.push("Atomic Test: vssadmin.exe list shadows (Safe verification test without destructive action)");
  }

  // Fallbacks if list is short
  if (detections.length === 0) {
    detections.push("Sigma: Generic Suspicious Process Lineage / Attack Behavior Indicator");
  }
  if (hunting.length === 0) {
    hunting.push("Hunting: Baseline high-entropy process executions and unverified outbound egress ports");
  }
  if (emulation.length === 0) {
    emulation.push("Adversary Emulation: Generate Atomic Red Team micro-emulation plan matching extracted TTPs");
  }

  return {
    method: "heuristic",
    classification,
    threatActors,
    malware,
    vulnerabilities,
    ttps,
    ioas,
    attackChain,
    detections,
    hunting,
    emulation,
  };
}

export function extractStructuredEntities(
  text: string,
  title: string,
  classification: string,
  analysis: IntelAnalysis,
): import("./types").ExtractedEntities {
  // Extract execution procedures and commands from code blocks or command patterns
  const procedureMatches = text.match(
    /(?:(?:powershell|cmd|wmic|rundll32|certutil|curl|bitsadmin|reg|schtasks|net|nltest|vssadmin|whoami|procdump|mimikatz|rubeus|adfind|powerview|chisel|rclone|megasync|psexec|wevtutil|sc)\b[^\r\n]{5,130})/gi,
  ) || [];

  const uniqueProcedures = Array.from(
    new Set(
      procedureMatches
        .map((p) => p.trim().replace(/^[`'"]+|[`'"]+$/g, ""))
        .filter((p) => p.length > 8 && !p.includes("<") && !p.includes(">")),
    ),
  ).slice(0, 15);

  // Extract mitigations
  const mitigationMatches = text.match(
    /(?:(?:disable|enforce|restrict|block|patch|isolate|rotate|audit|configure|enable)\b[^\r\n.]{10,120}\.)/gi,
  ) || [];

  const uniqueMitigations = Array.from(
    new Set(
      mitigationMatches
        .map((m) => m.trim())
        .filter((m) => m.length > 15),
    ),
  ).slice(0, 6);

  const tactics = analysis.attackChain.map((s) => s.tactic);
  const techniques = analysis.attackChain.flatMap((s) =>
    s.techniques.map((t) => ({ id: t.id, name: t.name, tactic: s.tactic })),
  );

  const detectionRules = [
    ...analysis.detections.map((d) => ({
      type: "sigma" as const,
      title: d.replace(/^Sigma:\s*/i, ""),
      query: d,
    })),
    ...analysis.hunting.map((h) => ({
      type: "hunting" as const,
      title: h.replace(/^Hunting:\s*/i, ""),
      query: h,
    })),
  ];

  // Infer campaign name if present
  const campaignMatch = title.match(/(?:Campaign\s+[A-Z0-9_-]+|Operation\s+[A-Z0-9_-]+|\b(?:202[3-6]|Q[1-4])\s+[A-Z0-9_-]+\s+Campaign)/i);
  const campaign = campaignMatch ? campaignMatch[0] : null;

  return {
    threatActors: analysis.threatActors,
    malwareFamilies: analysis.malware,
    cves: analysis.vulnerabilities,
    tactics,
    techniques,
    procedures: uniqueProcedures,
    detectionRules,
    mitigations: uniqueMitigations,
    campaign,
  };
}
