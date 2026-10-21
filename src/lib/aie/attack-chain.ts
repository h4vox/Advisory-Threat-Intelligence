import type { AttackStep, IntelAnalysis } from "./types";
import { getActiveAIProvider, extractJsonFromLlmText, resolveProviderModels } from "./ai-manager";
import { getProviderAdapter } from "./providers";
import { runAgentPromptInSandbox } from "./agent-sandbox";
import { UNTRUSTED_CONTENT_NOTICE, wrapUntrustedContent } from "./agent-framework/types";
import { warmAgentService } from "./warm-agent-service";
import { logger } from "./logger";
import { buildEvidence, isMitigationSentence, labelSentences, PROCEDURE_RE } from "./evidence";
import { lookupAttackTechnique } from "./mitre-matrix";

/** Collapse whitespace and cap length for display summaries. */
function clip(s: string, max: number): string {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length <= max ? t : `${t.slice(0, max - 1).trimEnd()}…`;
}

const ADVERSARY_LABELS = new Set(["observed", "inferred"]);

/**
 * Detection / hunting / emulation ideas keyed on techniques the report actually
 * supports with observed/inferred evidence. These are starting points, not rules.
 */
const TECHNIQUE_GUIDANCE: Array<{ ids: string[]; detection: string; hunting: string; emulation: string }> = [
  // --- Initial Access ---
  {
    ids: ["T1190"],
    detection: "Detection idea (T1190): a web/app-server or appliance process (w3wp.exe, httpd, java, node) spawning cmd/powershell/sh, or new webshell files under web roots (Sysmon 1/11)",
    hunting: "Hunting: review edge-device and web-server logs for POSTs to known-vulnerable endpoints followed by child shells or script file writes",
    emulation: "Atomic Test: against an isolated lab instance, run the target CVE's PoC and confirm the EDR flags the resulting child shell / webshell drop",
  },
  {
    ids: ["T1566.001"],
    detection: "Detection idea (T1566.001): Office/PDF readers (winword.exe, excel.exe, acrord32.exe) spawning script interpreters or LOLBins (Sysmon 1)",
    hunting: "Hunting: correlate mail-gateway attachment delivery with Office apps writing to %TEMP% or launching powershell/wscript/mshta",
    emulation: "Atomic Test: open a benign macro document in a lab that launches calc.exe and verify parent-child alerting",
  },
  {
    ids: ["T1566.002"],
    detection: "Detection idea (T1566.002): navigation to newly-registered or look-alike domains from mail/browser, then an executable or archive download (proxy/DNS)",
    hunting: "Hunting: search proxy logs for first-seen domains opened from email, then exe/archive downloads within minutes",
    emulation: "Atomic Test: send a lab email linking to an internal benign payload host and confirm URL-detonation / download alerting",
  },
  {
    ids: ["T1078.002", "T1078.001"],
    detection: "Detection idea (T1078): successful logons (EventID 4624) from unusual sources, impossible-travel, or service/default accounts logging on interactively",
    hunting: "Hunting: baseline per-account logon source hosts and flag new host/geo or Logon Type changes for privileged accounts",
    emulation: "Atomic Test: authenticate a test domain account from an unusual lab subnet and confirm the anomaly surfaces",
  },
  {
    ids: ["T1133"],
    detection: "Detection idea (T1133): VPN/Citrix/RDP-gateway authentications from new ASNs or without MFA (gateway and IdP logs)",
    hunting: "Hunting: review external remote-access logs for successful logons from hosting-provider IPs or MFA-disabled accounts",
    emulation: "Atomic Test: connect to the lab VPN/RDP gateway from an external test IP and verify geo/ASN alerting",
  },
  // --- Execution ---
  {
    ids: ["T1059.001"],
    detection: "Detection idea (T1059.001): PowerShell with encoded/hidden-window arguments, or Script Block Logging high-entropy blocks (EventID 4688/4104, Sysmon 1)",
    hunting: "Hunting: search powershell.exe command lines for -enc/-EncodedCommand, DownloadString, FromBase64String, -w hidden",
    emulation: "Atomic Test: powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Write-Host 'Emulated Execution'\"",
  },
  {
    ids: ["T1059.003"],
    detection: "Detection idea (T1059.003): cmd.exe spawned by Office/browser/web-server parents, or chained &&/|| / for-loop command lines (EventID 4688 / Sysmon 1)",
    hunting: "Hunting: hunt for cmd.exe /c with download, copy to ADMIN$, or for /f loops launched by non-admin parents",
    emulation: "Atomic Test: cmd.exe /c \"echo Emulated && whoami\" (benign)",
  },
  {
    ids: ["T1059.005"],
    detection: "Detection idea (T1059.005): wscript.exe/cscript.exe executing .vbs/.vbe, or Office spawning script hosts (Sysmon 1)",
    hunting: "Hunting: hunt for wscript/cscript launching from %TEMP%, %APPDATA% or mounted ISO/ZIP paths",
    emulation: "Atomic Test: cscript.exe //B //Nologo emulated.vbs where the script only shows a MsgBox (lab)",
  },
  {
    ids: ["T1204.002"],
    detection: "Detection idea (T1204.002): exe/LNK launched from an archive/ISO mount or Downloads folder shortly after a browser/mail download (Sysmon 1/11)",
    hunting: "Hunting: correlate Mark-of-the-Web downloads with first execution from \\Downloads or a mounted .iso/.img",
    emulation: "Atomic Test: mount a benign lab ISO containing a LNK that runs calc.exe and confirm detection",
  },
  {
    ids: ["T1047"],
    detection: "Detection idea (T1047): wmic.exe process call create, or WmiPrvSE.exe spawning shells (Sysmon 1 / WMI-Activity 5861)",
    hunting: "Hunting: search for wmic /node: process call create and permanent WMI event-consumer subscriptions",
    emulation: "Atomic Test: wmic.exe process call create \"calc.exe\" (lab host)",
  },
  // --- Persistence ---
  {
    ids: ["T1547.001"],
    detection: "Detection idea (T1547.001): writes to HKLM/HKCU ...\\CurrentVersion\\Run or RunOnce (Sysmon 13 / EventID 4657)",
    hunting: "Hunting: review Run/RunOnce values pointing to %TEMP%, %APPDATA% or script interpreters",
    emulation: "Atomic Test: reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Emulated /d calc.exe, then delete the value (lab)",
  },
  {
    ids: ["T1053.005"],
    detection: "Detection idea (T1053.005): scheduled-task creation (EventID 4698 / schtasks.exe in Sysmon 1) with actions in user-writable paths",
    hunting: "Hunting: search for schtasks /create with /ru SYSTEM or action binaries under %APPDATA%/%TEMP%",
    emulation: "Atomic Test: schtasks /create /tn Emulated /tr calc.exe /sc once /st 00:00, then schtasks /delete /tn Emulated (lab)",
  },
  {
    ids: ["T1543.003"],
    detection: "Detection idea (T1543.003): service install (EventID 7045) with an image path in a user-writable directory or a short random name (PSEXESVC-like)",
    hunting: "Hunting: review 7045 installs for cmd/powershell image paths and services created right after remote logons",
    emulation: "Atomic Test: sc.exe create EmulatedSvc binPath= \"cmd /c echo test\", then sc delete EmulatedSvc (lab)",
  },
  {
    ids: ["T1136.001"],
    detection: "Detection idea (T1136.001): local account creation (EventID 4720) and addition to Administrators (EventID 4732)",
    hunting: "Hunting: search for net user /add and net localgroup administrators /add outside provisioning windows",
    emulation: "Atomic Test: net user emulated P@ssw0rd! /add, then net user emulated /del (lab host)",
  },
  // --- Privilege Escalation ---
  {
    ids: ["T1068"],
    detection: "Detection idea (T1068): SYSTEM-level child processes from a user-context parent, or known-vulnerable / unsigned driver loads (BYOVD) (Sysmon 1/6)",
    hunting: "Hunting: hunt for vulnerable-driver loads and token-elevation anomalies following exploit attempts",
    emulation: "Atomic Test: in a lab, run a known LPE PoC against an unpatched build and confirm driver/exploit alerting",
  },
  {
    ids: ["T1548.002"],
    detection: "Detection idea (T1548.002): auto-elevating binaries (fodhelper.exe, eventvwr.exe, computerdefaults.exe) spawning child processes (Sysmon 1)",
    hunting: "Hunting: search for registry writes to HKCU\\Software\\Classes\\ms-settings or \\mscfile\\shell\\open\\command",
    emulation: "Atomic Test: the fodhelper registry-hijack to launch cmd.exe on a lab host, reverting the keys after",
  },
  // --- Defense Evasion ---
  {
    ids: ["T1562.001"],
    detection: "Detection idea (T1562.001): Defender/EDR tampering such as Set-MpPreference -DisableRealtimeMonitoring or security-service stop (EventID 7036/4688)",
    hunting: "Hunting: search for Set-MpPreference, sc stop/Stop-Service, or driver-unload events against security products",
    emulation: "Atomic Test: Get-MpPreference | Select DisableRealtimeMonitoring (read-only verification)",
  },
  {
    ids: ["T1070.001"],
    detection: "Detection idea (T1070.001): event log cleared (Security EventID 1102 / System EventID 104)",
    hunting: "Hunting: search for wevtutil cl or Clear-EventLog command lines and 1102/104 pairs",
    emulation: "Atomic Test: wevtutil.exe cl Application (lab host only)",
  },
  {
    ids: ["T1027"],
    detection: "Detection idea (T1027): powershell -EncodedCommand, very long base64 blobs, or high-entropy script arguments (Script Block Logging 4104)",
    hunting: "Hunting: flag command lines with base64 >500 chars, FromBase64String, char-array joins or -enc",
    emulation: "Atomic Test: powershell -EncodedCommand <base64 of 'Write-Host Emulated'> (benign)",
  },
  {
    ids: ["T1055"],
    detection: "Detection idea (T1055): CreateRemoteThread or VirtualAllocEx+WriteProcessMemory into lsass/explorer/trusted processes (Sysmon 8/10)",
    hunting: "Hunting: hunt for remote-thread creation into trusted processes from recently-written binaries",
    emulation: "Atomic Test: use a lab injector (Atomic Red Team T1055) to inject a benign MessageBox into notepad.exe",
  },
  // --- Credential Access ---
  {
    ids: ["T1003.001"],
    detection: "Detection idea (T1003.001): LSASS memory access or dump creation (Sysmon EventID 10 / comsvcs MiniDump, procdump)",
    hunting: "Hunting: audit process handles granted to lsass.exe from untrusted binary directories",
    emulation: "Atomic Test: rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (LSASS PID) dump.dmp full (lab host)",
  },
  {
    ids: ["T1003.003"],
    detection: "Detection idea (T1003.003): ntdsutil / shadow-copy access to NTDS.dit on domain controllers",
    hunting: "Hunting: query for ntdsutil.exe \"ac i ntds\" \"ifm\" or vssadmin create shadow on domain controllers",
    emulation: "Atomic Test: ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full C:\\Temp\\ntds_emulation\" q q (lab DC only)",
  },
  {
    ids: ["T1558.003"],
    detection: "Detection idea (T1558.003): bursts of Kerberos TGS requests with RC4 encryption (EventID 4769, Ticket Encryption 0x17) across many SPNs",
    hunting: "Hunting: correlate a single account requesting many service tickets in a short window",
    emulation: "Atomic Test: Rubeus kerberoast /stats, or Get-DomainSPNTicket in a lab domain",
  },
  {
    ids: ["T1555.003"],
    detection: "Detection idea (T1555.003): non-browser processes reading Chrome/Edge 'Login Data' / 'Local State' SQLite files (Sysmon 11 / file reads)",
    hunting: "Hunting: hunt for access to \\User Data\\*\\Login Data by processes other than the browser",
    emulation: "Atomic Test: copy a lab profile's 'Login Data' file with esentutl/copy and confirm file-access alerting (no decryption)",
  },
  // --- Discovery ---
  {
    ids: ["T1087.002"],
    detection: "Detection idea (T1087.002): net.exe/AdFind/nltest enumeration of domain users and trusts shortly after initial access (Sysmon 1)",
    hunting: "Hunting: search for net user /domain, net group \"Domain Admins\" /domain, nltest /dclist, Get-ADUser bursts",
    emulation: "Atomic Test: net group \"Domain Admins\" /domain (read-only, lab domain)",
  },
  {
    ids: ["T1018"],
    detection: "Detection idea (T1018): ping sweeps, net view, or scanner binaries (Advanced IP Scanner) generating broad short-lived connections (NetFlow/Sysmon 3)",
    hunting: "Hunting: flag one host connecting to many internal IPs on 445/3389 in a short window",
    emulation: "Atomic Test: net view /all, or a bounded ping sweep of a lab /24",
  },
  {
    ids: ["T1069.002"],
    detection: "Detection idea (T1069.002): BloodHound/SharpHound collection (large LDAP bursts) or Get-ADGroupMember of privileged groups",
    hunting: "Hunting: detect high LDAP query volumes and SharpHound output files (*.json, *_BloodHound.zip)",
    emulation: "Atomic Test: Get-ADGroupMember \"Domain Admins\" (read-only, lab domain)",
  },
  // --- Lateral Movement ---
  {
    ids: ["T1021.002", "T1021.001"],
    detection: "Detection idea (T1021): lateral movement via SMB admin share, PSEXESVC service creation (EventID 7045) or RDP (EventID 4624 Logon Type 3/10)",
    hunting: "Hunting: correlate EventID 4624 (Logon Type 3/10) with administrative file writes in ADMIN$ or C$",
    emulation: "Atomic Test: Invoke-Command -ComputerName <lab target> -ScriptBlock { whoami /all }",
  },
  {
    ids: ["T1570"],
    detection: "Detection idea (T1570): executable writes to ADMIN$/C$ shares (EventID 5145) or SMB copies of tools between hosts",
    hunting: "Hunting: correlate remote file creation in \\\\host\\ADMIN$ with subsequent service/task creation on the target",
    emulation: "Atomic Test: copy a benign file to \\\\labhost\\C$\\Windows\\Temp and confirm 5145 share-access logging",
  },
  // --- Collection ---
  {
    ids: ["T1560.001"],
    detection: "Detection idea (T1560.001): 7z/WinRAR/tar creating large password-protected archives in staging directories (Sysmon 1/11)",
    hunting: "Hunting: hunt for 7z a -p / rar a -hp with large output files just before egress",
    emulation: "Atomic Test: 7z a -pEmulated test.7z C:\\lab\\sampledata (lab)",
  },
  {
    ids: ["T1005"],
    detection: "Detection idea (T1005): scripted enumeration and reads of document directories (dir /s, findstr, Get-ChildItem -Recurse) before archiving",
    hunting: "Hunting: flag recursive document searches by script interpreters staging to a single folder",
    emulation: "Atomic Test: Get-ChildItem -Recurse -Include *.docx C:\\lab | Copy-Item -Destination C:\\lab\\stage (lab)",
  },
  // --- Command and Control ---
  {
    ids: ["T1071.001"],
    detection: "Detection idea (T1071.001): periodic beacon HTTP(S) to a single host with low jitter and uniform request sizes (proxy/NetFlow)",
    hunting: "Hunting: hunt for regular-interval connections, rare user-agents, and long-lived sessions to newly-seen domains",
    emulation: "Atomic Test: run a C2 framework (Sliver/Mythic) HTTP listener against a lab implant and tune beacon detection",
  },
  {
    ids: ["T1572"],
    detection: "Detection idea (T1572): tunneling tools (chisel, ngrok, cloudflared, plink) or long-lived encrypted sessions on non-standard ports (Sysmon 1/3)",
    hunting: "Hunting: search process creation for chisel/ngrok/cloudflared and outbound SOCKS/relay connections",
    emulation: "Atomic Test: establish a chisel or ngrok tunnel between two lab hosts and confirm tool and flow detection",
  },
  {
    ids: ["T1105"],
    detection: "Detection idea (T1105): LOLBins downloading payloads — certutil -urlcache, bitsadmin /transfer, curl, Invoke-WebRequest (Sysmon 1)",
    hunting: "Hunting: search for certutil -urlcache -f, bitsadmin /transfer, or powershell DownloadString to external hosts",
    emulation: "Atomic Test: certutil.exe -urlcache -split -f http://labhost/benign.txt out.txt (lab)",
  },
  // --- Exfiltration ---
  {
    ids: ["T1567.002"],
    detection: "Detection idea (T1567.002): rclone/megacmd/MegaSync processes or large uploads to mega.nz/dropbox/drive (proxy bytes-out, Sysmon 1)",
    hunting: "Hunting: flag rclone.exe command lines and sustained outbound volume to consumer cloud-storage domains",
    emulation: "Atomic Test: rclone copy C:\\lab\\sampledata lab-remote: to a controlled bucket and measure egress alerting",
  },
  {
    ids: ["T1048"],
    detection: "Detection idea (T1048): bulk FTP/SFTP uploads or DNS/encrypted egress to non-corporate endpoints (NetFlow, DNS answer sizes)",
    hunting: "Hunting: hunt for large outbound FTP/SFTP transfers and anomalous DNS volume to a single domain",
    emulation: "Atomic Test: sftp upload of a benign file from a lab host to a controlled server and verify egress detection",
  },
  // --- Impact ---
  {
    ids: ["T1486", "T1490"],
    detection: "Detection idea (T1486/T1490): rapid mass file modification with ransom-note writes, and shadow-copy deletion via vssadmin/wmic/bcdedit (EventID 4688)",
    hunting: "Hunting: query for vssadmin.exe delete shadows /all /quiet, bcdedit /set recoveryenabled no, and bursts of file renames to a new extension",
    emulation: "Atomic Test: vssadmin.exe list shadows (safe verification only — no destructive action)",
  },
];

export function analyzeThreatIntelligence(text: string, title: string, classification: string): IntelAnalysis {
  const evidence = buildEvidence(text, { title, lookup: lookupAttackTechnique });

  const adversaryTechniques = evidence.techniques.filter((t) => ADVERSARY_LABELS.has(t.label));
  const ttps = adversaryTechniques.map((t) => `${t.id} - ${t.name}`);
  const threatActors = evidence.actors.filter((a) => ADVERSARY_LABELS.has(a.label)).map((a) => a.value);
  const malware = evidence.malware.filter((m) => ADVERSARY_LABELS.has(m.label)).map((m) => m.value);
  const vulnerabilities = Array.from(
    new Set((`${title}\n${text}`.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).map((c) => c.toUpperCase())),
  );

  const techName = new Map(evidence.techniques.map((t) => [t.id, t.name]));
  const attackChain: AttackStep[] = evidence.chain.steps.map((step) => ({
    order: step.order,
    tactic: step.tactic,
    techniques: step.techniques.map((id) => `${id} - ${techName.get(id) ?? id}`),
    // The report's own words for this step; never canned text.
    summary: step.evidence[0] ? clip(step.evidence[0].quote, 240) : "",
  }));

  // IOAs: the behaviour the report describes, quoted, per supported technique.
  const ioas = adversaryTechniques.slice(0, 12).map((t) => `${t.id} ${t.name}: "${clip(t.evidence[0]?.quote ?? "", 160)}"`);

  const supported = new Set(adversaryTechniques.map((t) => t.id));
  const detections: string[] = [];
  const hunting: string[] = [];
  const emulation: string[] = [];
  for (const g of TECHNIQUE_GUIDANCE) {
    if (!g.ids.some((id) => supported.has(id))) continue;
    detections.push(g.detection);
    hunting.push(g.hunting);
    emulation.push(g.emulation);
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
    evidence,
  };
}

export function extractStructuredEntities(
  text: string,
  title: string,
  classification: string,
  analysis: IntelAnalysis,
): import("./types").ExtractedEntities {
  const sentences = labelSentences(text);

  // Procedures only from sentences that report adversary activity.
  const procedures: string[] = [];
  for (const s of sentences) {
    if (s.label !== "observed") continue;
    for (const m of s.text.match(new RegExp(PROCEDURE_RE.source, "gi")) ?? []) {
      const p = m.trim().replace(/^[`'"]+|[`'"]+$/g, "");
      if (p.length > 8 && !p.includes("<") && !p.includes(">") && !procedures.includes(p)) procedures.push(p);
    }
    if (procedures.length >= 15) break;
  }

  // Mitigations only from defender-advice sentences (never adversary actions or rule syntax).
  const mitigations: string[] = [];
  for (const s of sentences) {
    if (!isMitigationSentence(s)) continue;
    const t = s.text.replace(/\s+/g, " ").trim();
    if (!mitigations.includes(t)) mitigations.push(t);
    if (mitigations.length >= 6) break;
  }

  const evidence = analysis.evidence;
  const techniques = evidence
    ? evidence.techniques
        .filter((t) => ADVERSARY_LABELS.has(t.label))
        .map((t) => ({ id: t.id, name: t.name, tactic: t.tactic }))
    : analysis.attackChain.flatMap((s) =>
        s.techniques.map((t) => {
          const m = /^(T\d{4}(?:\.\d{3})?)\s*(?:[-:]\s*(.*))?$/.exec(String(t).trim());
          return { id: m?.[1] ?? String(t), name: m?.[2] || m?.[1] || String(t), tactic: s.tactic };
        }),
      );
  const tactics = analysis.attackChain.map((s) => s.tactic);

  // Detection *ideas* and hunting leads, not authored rules.
  const detectionRules = [...analysis.detections, ...analysis.hunting].map((d) => ({
    type: "hunting" as const,
    title: d.replace(/^(?:Sigma|Hunting|Detection idea(?: \([^)]*\))?):\s*/i, ""),
    query: d,
  }));

  const campaignMatch = title.match(/(?:Campaign\s+[A-Z0-9_-]+|Operation\s+[A-Z0-9_-]+|\b(?:202[3-6]|Q[1-4])\s+[A-Z0-9_-]+\s+Campaign)/i);
  const campaign = campaignMatch ? campaignMatch[0] : null;

  return {
    threatActors: analysis.threatActors,
    malwareFamilies: analysis.malware,
    cves: analysis.vulnerabilities,
    tactics,
    techniques,
    procedures,
    detectionRules,
    mitigations,
    campaign,
  };
}

/**
 * AI-Powered Attack Chain Re-synthesizer
 *
 * Employs the active AI provider (Gemini REST, Claude REST, OpenAI, or AGY Sandbox)
 * to perform deep chronological kill-chain reconstruction, extraction of concrete command lines,
 * generation of production-ready Sigma YAML detection rules, and Atomic Red Team test plans.
 *
 * Guarantees zero-SPOF: if AI times out or errors, automatically falls back to heuristic analysis.
 */
export async function synthesizeThreatIntelligenceWithAI(
  text: string,
  title: string,
  classification: string = "THREAT_REPORT",
  options?: { model?: string; timeoutSeconds?: number; providerId?: string }
): Promise<IntelAnalysis> {
  const heuristicFallback = analyzeThreatIntelligence(text, title, classification);
  const active = await getActiveAIProvider();
  const providerId = options?.providerId || active.providerId;
  const { restModel: rawModel, agyModel } = resolveProviderModels(active, options?.model);
  const timeoutSeconds = options?.timeoutSeconds || active.timeoutSeconds;
  const snippet = text.slice(0, 4800);

  const prompt = `You are the Lead Adversary Emulation & CTI Reconstruction Specialist operating under the AIE platform.
Analyze this threat intelligence report and synthesize a high-fidelity, chronological multi-stage attack chain with concrete procedures, MITRE ATT&CK techniques, detection rules, and purple team emulation commands.

${UNTRUSTED_CONTENT_NOTICE}
REPORT (title and content snippet):
${wrapUntrustedContent(`TITLE: ${title}\nCONTENT SNIPPET:\n${snippet}`)}

INSTRUCTIONS:
1. Reconstruct the CHRONOLOGICAL ATTACK CHAIN in sequential order (Stage 1 to N, e.g. Initial Access -> Execution -> Persistence -> Lateral Movement -> Impact).
2. For each stage, identify the exact MITRE ATT&CK tactic, technique IDs (e.g. T1059.001), and a technical summary.
3. Identify threat actors, malware families, CVEs, concrete procedures/commands, IOAs (Indicators of Attack), detection rules (Sigma/hunting), and emulation actions.

OUTPUT FORMAT:
Return pure valid JSON with this exact structure:
{
  "classification": "${classification}",
  "threatActors": ["Threat Actor Name"],
  "malware": ["Malware or Tool Name"],
  "vulnerabilities": ["CVE-YYYY-XXXXX"],
  "ttps": ["T1190: Exploit Public-Facing Application", "T1059.001: PowerShell"],
  "ioas": ["High-entropy process spawned from w3wp.exe"],
  "attackChain": [
    {
      "order": 1,
      "tactic": "Initial Access",
      "techniques": ["T1190"],
      "summary": "Weaponization of CVE-2023-46805 in perimeter gateway"
    },
    {
      "order": 2,
      "tactic": "Execution",
      "techniques": ["T1059.001"],
      "summary": "Execution of obfuscated base64 PowerShell downloader scriptlet"
    }
  ],
  "detections": [
    "Sigma: Suspicious PowerShell execution with encoded command arguments",
    "Hunting: Query for outbound C2 beacons to unclassified IP addresses"
  ],
  "hunting": [
    "Hunting: Inspect process handles granted to lsass.exe by non-system accounts"
  ],
  "emulation": [
    "Atomic Test: powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \\"Write-Host 'Emulated Execution'\\""
  ]
}
Return pure JSON only.`;

  try {
    const adapter = getProviderAdapter(providerId);
    let outputText = "";

    if (adapter && active.isRest) {
      const res = await adapter.generate({
        prompt,
        model: rawModel,
        apiKey: active.apiKey,
        timeoutMs: timeoutSeconds * 1000,
        responseFormat: "json",
      });
      if (res.success && res.text) {
        outputText = res.text;
      }
    } else {
      try {
        const warmRes = await warmAgentService.executeSkill({
          skill: "ATTACK_CHAIN",
          payload: `TITLE: ${title}\nCONTENT SNIPPET:\n${snippet}`,
          model: agyModel,
          timeoutMs: timeoutSeconds * 1000,
        });
        if (warmRes.success && warmRes.text) {
          outputText = warmRes.text;
        }
      } catch {
        // fall through to the sandbox / fallback path
      }

      if (!outputText) {
        const res = await runAgentPromptInSandbox(prompt, {
          model: agyModel,
          timeoutMs: timeoutSeconds * 1000,
          category: "agent",
        });
        if (res.success && res.text) {
          outputText = res.text;
        }
      }
    }

    if (outputText) {
      const parsed = extractJsonFromLlmText(outputText);
      if (parsed && Array.isArray(parsed.attackChain) && parsed.attackChain.length > 0) {
        const orderSteps: AttackStep[] = parsed.attackChain.map((s: any, idx: number) => ({
          order: typeof s.order === "number" ? s.order : idx + 1,
          tactic: String(s.tactic || "Unknown"),
          techniques: Array.isArray(s.techniques) ? s.techniques.map(String) : [],
          summary: String(s.summary || ""),
        }));

        logger.agent(
          "SYNTHESIS",
          `AI synthesized attack chain for "${title.slice(0, 40)}" (${orderSteps.length} stages via ${active.isRest ? rawModel : agyModel})`
        );

        // Take each list from the model when it returned one; otherwise fall back to the
        // heuristic and record that, so the result is never labelled purely "llm".
        const LIST_FIELDS = ["threatActors", "malware", "vulnerabilities", "ttps", "ioas", "detections", "hunting", "emulation"] as const;
        const fieldOrigins: NonNullable<IntelAnalysis["fieldOrigins"]> = {};
        const lists = {} as Record<(typeof LIST_FIELDS)[number], string[]>;
        for (const field of LIST_FIELDS) {
          const fromModel = parsed[field];
          if (Array.isArray(fromModel) && fromModel.length > 0) {
            lists[field] = fromModel.map(String);
            fieldOrigins[field] = "llm";
          } else {
            lists[field] = heuristicFallback[field];
            fieldOrigins[field] = "heuristic";
          }
        }
        const usedHeuristic = Object.values(fieldOrigins).includes("heuristic");

        return {
          method: usedHeuristic ? "mixed" : "llm",
          fieldOrigins,
          classification: parsed.classification || heuristicFallback.classification,
          ...lists,
          attackChain: orderSteps,
          // Fact-level evidence always comes from the deterministic analyzer.
          evidence: heuristicFallback.evidence,
        };
      }
    }
  } catch (err: any) {
    logger.agent("FAILSAFE", `AI attack chain synthesis failed (${err.message}), returned heuristic analysis.`);
  }

  return heuristicFallback;
}

/**
 * Generates a production-ready Sigma YAML detection rule for observed adversary procedures
 */
export async function generateSigmaRuleWithAI(params: {
  title: string;
  techniques: string[];
  procedures?: string[];
  textSnippet?: string;
  model?: string;
}): Promise<{ success: boolean; sigmaYaml: string; title: string; level: string; error?: string }> {
  const active = await getActiveAIProvider();
  const { restModel: rawModel, agyModel } = resolveProviderModels(active, params.model);
  const prompt = `You are a Lead Detection Engineer.
Generate a valid, production-ready Sigma detection rule in standard Sigma YAML format based on the following threat intelligence report and adversary techniques.

${UNTRUSTED_CONTENT_NOTICE}
${wrapUntrustedContent(
  `TITLE: ${params.title}\nTECHNIQUES: ${params.techniques.join(", ")}\nOBSERVED PROCEDURES: ${(params.procedures || []).join("\n")}\nCONTEXT: ${(params.textSnippet || "").slice(0, 2000)}`
)}

INSTRUCTIONS:
1. Output MUST be valid Sigma YAML (logsource: category: process_creation, detection, condition, tags, level: high/critical).
2. Include concrete command-line substrings or process image matches matching the observed tradecraft.
3. Return pure JSON with:
{
  "title": "Rule Title",
  "level": "high",
  "sigmaYaml": "title: ...\\nlogsource: ...\\ndetection: ...\\ncondition: ...\\nlevel: high"
}
Return pure JSON only.`;

  try {
    const adapter = getProviderAdapter(active.providerId);
    let output = "";
    if (adapter && active.isRest) {
      const res = await adapter.generate({
        prompt,
        model: rawModel,
        apiKey: active.apiKey,
        responseFormat: "json",
      });
      if (res.success) output = res.text;
    } else {
      try {
        const warmRes = await warmAgentService.executePrompt(prompt, {
          model: agyModel,
          timeoutMs: 35000,
        });
        if (warmRes.success && warmRes.text) {
          output = warmRes.text;
        }
      } catch {
        // fall through to the sandbox / fallback path
      }

      if (!output) {
        const res = await runAgentPromptInSandbox(prompt, {
          model: agyModel,
          timeoutMs: 35000,
          category: "agent",
        });
        if (res.success) output = res.text;
      }
    }

    if (output) {
      const parsed = extractJsonFromLlmText(output);
      return {
        success: true,
        sigmaYaml: parsed.sigmaYaml || output,
        title: parsed.title || `Detection for ${params.title}`,
        level: parsed.level || "high",
      };
    }
  } catch (err: any) {
    return {
      success: false,
      sigmaYaml: "",
      title: params.title,
      level: "medium",
      error: err.message,
    };
  }

  return {
    success: false,
    sigmaYaml: "",
    title: params.title,
    level: "medium",
    error: "Model did not return Sigma rule output.",
  };
}

/**
 * Generates an Atomic Red Team adversary emulation blueprint with concrete execution commands
 */
export async function generateEmulationPlanWithAI(params: {
  title: string;
  techniques: string[];
  procedures?: string[];
  platform?: "windows" | "linux" | "macos";
  model?: string;
}): Promise<{ success: boolean; testName: string; executor: string; command: string; cleanupCommand?: string; description: string }> {
  const active = await getActiveAIProvider();
  const { restModel: rawModel, agyModel } = resolveProviderModels(active, params.model);
  const platform = params.platform || "windows";

  const prompt = `You are a Red Team / Adversary Emulation Specialist.
Generate a safe, executable Atomic Red Team style emulation test procedure targeting the adversary TTPs described below.

PLATFORM: ${platform}
${UNTRUSTED_CONTENT_NOTICE}
${wrapUntrustedContent(
  `TITLE: ${params.title}\nTECHNIQUES: ${params.techniques.join(", ")}\nPROCEDURES: ${(params.procedures || []).join("\n")}`
)}

INSTRUCTIONS:
1. Provide a non-destructive emulation command line that exercises the telemetry detection opportunity without harming systems.
2. Provide executor ("powershell" or "bash" or "sh").
3. Provide cleanup command if artifacts are created.
4. Return pure JSON:
{
  "testName": "Emulate T1059.001 Execution",
  "executor": "powershell",
  "command": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \\"Write-Host 'Emulated adversary telemetry execution'\\"",
  "cleanupCommand": "",
  "description": "Validates EDR and Sysmon EventID 1 process creation logging for high-entropy arguments."
}
Return pure JSON only.`;

  try {
    const adapter = getProviderAdapter(active.providerId);
    let output = "";
    if (adapter && active.isRest) {
      const res = await adapter.generate({
        prompt,
        model: rawModel,
        apiKey: active.apiKey,
        responseFormat: "json",
      });
      if (res.success) output = res.text;
    } else {
      try {
        const warmRes = await warmAgentService.executePrompt(prompt, {
          model: agyModel,
          timeoutMs: 35000,
        });
        if (warmRes.success && warmRes.text) {
          output = warmRes.text;
        }
      } catch {
        // fall through to the sandbox / fallback path
      }

      if (!output) {
        const res = await runAgentPromptInSandbox(prompt, {
          model: agyModel,
          timeoutMs: 35000,
          category: "agent",
        });
        if (res.success) output = res.text;
      }
    }

    if (output) {
      const parsed = extractJsonFromLlmText(output);
      return {
        success: true,
        testName: parsed.testName || `Emulation of ${params.techniques[0] || params.title}`,
        executor: parsed.executor || (platform === "windows" ? "powershell" : "bash"),
        command: parsed.command || `echo "Emulating ${params.techniques[0]}"`,
        cleanupCommand: parsed.cleanupCommand || "",
        description: parsed.description || "Adversary emulation procedure generated by AI specialist.",
      };
    }
  } catch {
    // fall through to the default fallback below
  }

  return {
    success: false,
    testName: `Emulation of ${params.techniques[0] || "TTP"}`,
    executor: platform === "windows" ? "powershell" : "bash",
    command: `echo "Emulating ${params.techniques[0] || "TTP"}"`,
    description: "Default fallback emulation placeholder.",
  };
}

