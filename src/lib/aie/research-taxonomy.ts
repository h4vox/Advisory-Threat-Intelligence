/**
 * Research taxonomy: the kinds of public research an adversary emulation and simulation platform
 * needs, from campaign reports to purple-team results (docs: README "Advisory Emulation &
 * Simulation Research"). Pure and unit-tested; it drives two things:
 *
 *  - discovery: every category carries search queries, and the crawler rotates through them so
 *    each kind of research is looked for, the thinnest categories first;
 *  - labelling: every stored report gets the categories its text supports, each with the terms
 *    that matched, so analysts can filter the library and see coverage gaps.
 *
 * Categories are "core" (threat behaviour) or "bas" (detection, telemetry and emulation material
 * that supports breach-and-attack simulation). BAS categories are optional: off by default in
 * discovery, always available as labels.
 *
 * Labels describe what a report is about; they never decide whether it is threat intelligence.
 * The library gates do that, unchanged.
 */

export type ResearchScope = "core" | "bas";

export type ResearchCategoryId =
  | "actors"
  | "campaigns"
  | "attack_chains"
  | "ttps"
  | "malware"
  | "exploitation"
  | "phishing"
  | "identity"
  | "c2"
  | "impact"
  | "cloud"
  | "ir_forensics"
  | "lessons"
  | "trends"
  | "detection_telemetry"
  | "detection_content"
  | "emulation";

/** One weighted signal: `re` must be global; matches in the title count three times. */
type Signal = { re: RegExp; w: number; term: string; cap?: number };

export type ResearchCategory = {
  id: ResearchCategoryId;
  /** Full name, e.g. "Campaigns and threat operations". */
  label: string;
  /** Chip label, e.g. "Campaigns". */
  short: string;
  scope: ResearchScope;
  /** Why it matters for emulation, one line. */
  purpose: string;
  /** Research types to look for (README §3 and the analyst's lists). */
  types: readonly string[];
  /** Search queries for discovery. Plain strings, no placeholders. */
  queries: readonly string[];
  signals: readonly Signal[];
  /** Minimum score for the label. */
  threshold: number;
  /** A defining phrase the text must contain, for categories whose loose words are everywhere. */
  requires?: RegExp;
  /**
   * Thin by nature (most such pages are not technical enough for the library): searched in
   * rotation only, never in the thinnest-first slots, so it cannot starve the others.
   */
  noGapBoost?: boolean;
};

const s = (re: RegExp, w: number, term: string, cap = 4): Signal => ({ re, w, term, cap });

export const RESEARCH_CATEGORIES: readonly ResearchCategory[] = [
  {
    id: "campaigns",
    label: "Campaigns and threat operations",
    short: "Campaigns",
    scope: "core",
    purpose: "Establish the real-world operation an emulation is modelled on.",
    types: [
      "Threat campaign reports",
      "Campaign timelines",
      "Multi-stage intrusion reports",
      "Long-running espionage campaigns",
      "Ransomware campaigns",
      "Cybercrime and eCrime operations",
      "Phishing and initial-access campaigns",
      "Supply-chain attack campaigns",
      "Cloud and identity compromise campaigns",
      "Mass exploitation campaigns",
      "Campaign infrastructure changes",
    ],
    queries: [
      "ransomware campaign technical analysis",
      "espionage campaign intrusion analysis TTPs",
      "phishing campaign initial access technical analysis",
      "supply chain attack campaign technical analysis",
      "mass exploitation campaign threat research",
      "cloud identity compromise campaign analysis",
      "eCrime operation technical threat report",
      "campaign infrastructure changes threat actor tracking",
    ],
    signals: [
      s(/\bcampaigns?\b/gi, 3, "campaign", 6),
      s(/\boperations?\s+(?:named|dubbed|called)\b|\boperation\s+[A-Z][a-z]+/g, 3, "named operation"),
      s(/\bespionage\b/gi, 2, "espionage"),
      s(/\b(?:e-?crime|cybercrime|cybercriminal)s?\b/gi, 2, "cybercrime"),
      s(/\bsupply[\s-]chain\s+(?:attack|compromise)s?\b/gi, 3, "supply-chain attack"),
      s(/\bmass[\s-]exploitation\b/gi, 3, "mass exploitation"),
      s(/\b(?:activity|threat)\s+cluster\b/gi, 2, "activity cluster"),
      s(/\b(?:since|between|from)\s+(?:early|mid|late\s+)?(?:January|February|March|April|May|June|July|August|September|October|November|December)\b/g, 1, "timeline"),
      s(/\btargeting\b|\btargeted\s+(?:organizations|entities|sectors|victims)\b/gi, 1, "targeting"),
      s(/\bwaves?\s+of\b/gi, 2, "attack waves"),
    ],
    threshold: 12,
  },
  {
    id: "attack_chains",
    label: "Attack chains and intrusion narratives",
    short: "Attack chains",
    scope: "core",
    purpose: "Give the order of steps, from initial access to impact, that an emulation replays.",
    types: [
      "Cyber Kill Chain breakdowns",
      "End-to-end attack-chain reports",
      "Initial access to impact narratives",
      "Intrusion timelines",
      "Step-by-step incident reconstruction",
      "Attack-path diagrams",
      "Process execution chains",
      "Lateral movement paths",
      "Credential theft to privilege escalation chains",
      "Exfiltration and impact sequences",
      "Failed and interrupted attack chains",
    ],
    queries: [
      "attack chain analysis initial access lateral movement",
      "infection chain technical analysis process tree",
      "intrusion timeline incident reconstruction",
      "kill chain breakdown threat report",
      "end-to-end attack chain ransomware intrusion",
      "multistage intrusion step by step analysis",
    ],
    signals: [
      s(/\b(?:attack|infection|intrusion|kill|execution)\s+chains?\b/gi, 5, "attack chain", 5),
      s(/\battack\s+(?:flow|path|sequence)s?\b/gi, 4, "attack flow"),
      s(/\bmulti-?stage\b/gi, 3, "multistage"),
      s(/\b(?:process|parent)\s+tree\b|\bparent\s+process\b|\bchild\s+process(?:es)?\b|\bspawn(?:s|ed|ing)\b/gi, 2, "process tree"),
      s(/\b(?:stage|step)\s+(?:one|two|three|1|2|3|4)\b|\b(?:first|second|third|final)\s+stage\b/gi, 2, "stages"),
      s(/\btimeline\b/gi, 2, "timeline"),
      s(/\bintrusions?\b/gi, 1, "intrusion"),
      s(/\binitial\s+access\b/gi, 1, "initial access"),
      s(/\blateral(?:ly)?\s+mov(?:e|ed|ement|ing)\b/gi, 1, "lateral movement"),
      s(/\bexfiltrat\w*/gi, 1, "exfiltration"),
    ],
    threshold: 12,
  },
  {
    id: "ttps",
    label: "TTPs and ATT&CK technique research",
    short: "TTPs",
    scope: "core",
    purpose: "Explain how each behaviour works, so it can be mapped to ATT&CK and reproduced safely.",
    types: [
      "Tactic and technique deep dives",
      "ATT&CK procedure examples",
      "Technique implementation analyses",
      "Sub-technique-specific research",
      "Technique variations and evasion methods",
      "Living-off-the-land activity",
      "Defense evasion studies",
      "Persistence and privilege escalation",
      "Discovery and lateral movement",
      "Command-and-control methods",
      "Collection and exfiltration techniques",
    ],
    queries: [
      "ATT&CK technique procedure examples analysis",
      "living off the land binaries abuse threat actor",
      "defense evasion technique research malware",
      "persistence technique analysis threat actor",
      "new attack technique abused by threat actors",
    ],
    signals: [
      s(/\bT1\d{3}(?:\.\d{3})?\b/g, 2, "ATT&CK technique id", 10),
      s(/\b(?:MITRE\s+)?ATT&CK\b/g, 3, "ATT&CK"),
      s(/\btechniques?\b/gi, 1, "technique", 6),
      s(/\bsub-?techniques?\b/gi, 3, "sub-technique"),
      s(/\bliving[\s-]off[\s-]the[\s-]land\b|\bLOLBins?\b|\bLOLBAS\b/gi, 4, "living off the land"),
      s(/\bdefen[cs]e\s+evasion\b|\bevad(?:e|es|ing)\s+detection\b/gi, 2, "defense evasion"),
      s(/\bpersistence\b/gi, 1, "persistence"),
      s(/\bprocedures?\b/gi, 1, "procedure"),
    ],
    threshold: 14,
  },
  {
    id: "malware",
    label: "Malware and tool-family analysis",
    short: "Malware",
    scope: "core",
    purpose: "Describe the tools and their capabilities, artefacts and variants.",
    types: [
      "Malware technical reports",
      "Ransomware family analyses",
      "Loaders and droppers",
      "Downloaders and stagers",
      "RATs and backdoors",
      "Infostealers and credential stealers",
      "Rootkits and bootkits",
      "Wipers and destructive malware",
      "Botnets and cryptominers",
      "Web shells",
      "Post-exploitation frameworks",
      "Legitimate dual-use tools abused by attackers",
    ],
    queries: [
      "malware technical analysis backdoor",
      "loader dropper malware analysis",
      "infostealer technical analysis",
      "ransomware family analysis encryptor",
      "remote access trojan reverse engineering",
      "wiper malware analysis",
      "web shell analysis intrusion",
      "rootkit bootkit analysis",
    ],
    signals: [
      s(/\bmalware\b/gi, 2, "malware", 6),
      s(/\b(?:backdoor|implant|loader|dropper|downloader|stager)s?\b/gi, 3, "backdoor/loader", 5),
      s(/\b(?:info)?stealers?\b|\bRATs?\b|\bremote\s+access\s+trojans?\b/g, 3, "stealer/RAT", 5),
      s(/\b(?:wiper|rootkit|bootkit|botnet|cryptominer|web\s?shell|encryptor)s?\b/gi, 3, "wiper/botnet/web shell", 5),
      s(/\breverse[\s-]engineer\w*|\bdecompil\w*|\bdisassembl\w*/gi, 3, "reverse engineering"),
      s(/\bobfuscat\w*|\bpack(?:ed|er)\b|\banti-?(?:analysis|debug\w*|sandbox|VM)\b/gi, 2, "obfuscation"),
      s(/\b(?:sample|variant|strain)s?\b/gi, 1, "samples"),
      s(/\bconfig(?:uration)?\s+(?:file|block|data|extract\w*)\b/gi, 2, "config"),
      s(/\b[a-f0-9]{64}\b/gi, 1, "SHA-256", 3),
      s(/\b(?:anatomy|dissect\w*|unpack\w*|breaking\s+down)\b/gi, 2, "analysis title"),
    ],
    threshold: 14,
  },
  {
    id: "exploitation",
    label: "Vulnerability exploitation and initial access",
    short: "Exploitation",
    scope: "core",
    purpose: "Show how access was gained, with preconditions for a safe, non-destructive check.",
    types: [
      "Zero-day exploitation reports",
      "Known exploited vulnerability reports",
      "Exploit-chain analyses",
      "Proof-of-concept vulnerability write-ups",
      "Exploit weaponization timelines",
      "Internet-facing service exploitation",
      "VPN and edge-device compromises",
      "Browser and document exploitation",
      "Remote code execution chains",
      "Deserialization and authentication bypass research",
      "Vulnerability-to-intrusion case studies",
    ],
    queries: [
      "zero-day exploited in the wild analysis",
      "CVE exploitation post-exploitation activity",
      "edge device VPN compromise exploitation",
      "exploit chain root cause analysis",
      "known exploited vulnerability intrusion analysis",
      "authentication bypass remote code execution exploited",
    ],
    signals: [
      s(/\bCVE-\d{4}-\d{4,7}\b/gi, 3, "CVE", 5),
      s(/\bzero[\s-]?days?\b|\b0-?days?\b/gi, 4, "zero-day"),
      s(/\bexploit(?:s|ed|ing|ation)?\b/gi, 2, "exploitation", 6),
      s(/\bin\s+the\s+wild\b/gi, 3, "in the wild"),
      s(/\bremote\s+code\s+execution\b|\bRCE\b/g, 3, "remote code execution"),
      s(/\b(?:authentication|auth)\s+bypass\b|\bdeserialization\b|\b(?:command|SQL)\s+injection\b|\bpath\s+traversal\b/gi, 3, "vulnerability class"),
      s(/\bproof[\s-]of[\s-]concept\b|\bPoC\b/g, 2, "proof of concept"),
      s(/\b(?:edge|perimeter|VPN|firewall)\s+(?:devices?|appliances?|gateways?)\b|\binternet-facing\b/gi, 2, "edge device"),
      s(/\bpatch(?:ed|es)?\b|\bvulnerable\s+versions?\b/gi, 1, "patch"),
    ],
    threshold: 12,
  },
  {
    id: "phishing",
    label: "Phishing, social engineering and delivery",
    short: "Phishing & delivery",
    scope: "core",
    purpose: "Cover how payloads reach users and what each delivery step leaves behind.",
    types: [
      "Phishing campaign reports",
      "Spear-phishing case studies",
      "Malicious attachment analyses",
      "Link-based delivery chains",
      "Drive-by compromise reports",
      "Malvertising campaigns",
      "Fake software and trojanized installers",
      "Business email compromise (BEC)",
      "OAuth consent and identity phishing",
      "Lure and decoy document analyses",
      "Delivery infrastructure and redirect chains",
    ],
    queries: [
      "spear-phishing campaign lure analysis",
      "malicious attachment delivery chain analysis",
      "device code phishing OAuth consent abuse",
      "malvertising fake installer campaign analysis",
      "adversary-in-the-middle phishing session theft",
      "ClickFix social engineering campaign analysis",
    ],
    signals: [
      s(/\b(?:spear-?)?phish\w*/gi, 3, "phishing", 6),
      s(/\blures?\b|\bdecoy\s+documents?\b/gi, 3, "lure"),
      s(/\bsocial\s+engineering\b|\bimpersonat\w*/gi, 2, "social engineering"),
      s(/\bmalvertising\b|\bSEO\s+poisoning\b|\bdrive-by\b/gi, 4, "malvertising"),
      s(/\b(?:fake|counterfeit|trojani[sz]ed)\s+(?:software|installers?|updates?|apps?)\b/gi, 4, "fake installer"),
      s(/\bbusiness\s+email\s+compromise\b|\bBEC\b/g, 4, "BEC"),
      s(/\b(?:OAuth\s+consent|device\s+code)\s+phish\w*|\badversary-in-the-middle\b|\bAiTM\b/gi, 4, "identity phishing"),
      s(/\bClickFix\b|\bHTML\s+smuggling\b|\bQR\s+codes?\b|\bquishing\b/gi, 4, "delivery technique"),
      s(/\b(?:malicious|weaponi[sz]ed)\s+(?:attachments?|links?|documents?|emails?)\b/gi, 3, "malicious attachment"),
      s(/\bredirect(?:s|ion|or)?\s+chains?\b/gi, 3, "redirect chain"),
    ],
    threshold: 12,
  },
  {
    id: "identity",
    label: "Identity, credentials and privilege escalation",
    short: "Identity & credentials",
    scope: "core",
    purpose: "Describe credential and identity abuse, the path to higher privilege.",
    types: [
      "Credential theft investigations",
      "Password spraying and brute-force campaigns",
      "Kerberos abuse analyses",
      "Token and session theft reports",
      "Active Directory attack paths",
      "Entra ID and cloud identity compromises",
      "MFA bypass and fatigue campaigns",
      "Privilege escalation case studies",
      "Secrets and API-key theft",
      "Federation and trust abuse",
      "Identity persistence and account takeover",
    ],
    queries: [
      "Kerberos abuse Active Directory attack path",
      "token theft session hijacking cloud identity",
      "password spraying campaign identity compromise",
      "MFA fatigue bypass attack analysis",
      "credential theft privilege escalation intrusion",
      "service principal abuse identity compromise",
    ],
    signals: [
      s(/\bcredentials?\b/gi, 1, "credentials", 6),
      s(/\bpassword\s+spray\w*|\bbrute[\s-]forc\w*/gi, 4, "password spraying"),
      s(/\bKerbero\w*|\bgolden\s+ticket\b|\bpass-the-(?:hash|ticket)\b|\bDCSync\b/gi, 4, "Kerberos abuse"),
      s(/\b(?:access|refresh|session|primary\s+refresh)\s+tokens?\b|\btoken\s+theft\b|\bsession\s+(?:hijack\w*|cookies?)\b/gi, 3, "token theft"),
      s(/\bMFA\b|\bmulti-?factor\b/g, 2, "MFA"),
      s(/\bEntra(?:\s+ID)?\b|\bAzure\s+AD\b|\bActive\s+Directory\b|\bOkta\b/g, 2, "identity provider"),
      s(/\bprivilege\s+escalation\b|\bescalat\w+\s+privileges?\b/gi, 3, "privilege escalation"),
      s(/\bservice\s+principals?\b|\bmanaged\s+identit\w*|\bOAuth\s+app\w*/gi, 3, "workload identity"),
      s(/\bLSASS\b|\bMimikatz\b|\bcredential\s+dump\w*/gi, 3, "credential dumping"),
      s(/\baccount\s+takeover\b|\bfederat\w*\s+(?:trust|abuse|domain)\b|\bSAML\b/gi, 3, "account takeover"),
    ],
    threshold: 12,
  },
  {
    id: "c2",
    label: "Infrastructure and command-and-control",
    short: "C2 & infrastructure",
    scope: "core",
    purpose: "Capture the network side: protocols, infrastructure and their telemetry.",
    types: [
      "C2 protocol analyses",
      "Malicious domain and IP infrastructure reports",
      "DNS tunneling research",
      "HTTP/S beaconing studies",
      "Proxy and relay infrastructure",
      "Fast-flux and domain rotation",
      "Bulletproof hosting analyses",
      "Compromised infrastructure reports",
      "Botnet communication patterns",
      "C2 framework and protocol profiles",
      "Infrastructure reuse across campaigns",
    ],
    queries: [
      "command and control protocol analysis malware",
      "C2 infrastructure analysis threat actor domains",
      "DNS tunneling malware analysis",
      "Cobalt Strike Sliver infrastructure tracking",
      "operational relay box network threat actor",
      "bulletproof hosting threat infrastructure",
    ],
    signals: [
      s(/\bcommand[\s-]and[\s-]control\b|\bC2\b|\bC&C\b/g, 3, "C2", 6),
      s(/\bbeacon(?:s|ing)?\b/gi, 3, "beaconing"),
      s(/\bDNS\s+tunnel\w*|\bdomain\s+generation\s+algorithm\b|\bDGA\b|\bfast[\s-]flux\b/gi, 4, "DNS tunnelling/DGA"),
      s(/\binfrastructure\b/gi, 1, "infrastructure", 6),
      s(/\b(?:bulletproof|BPH)\s+hosting\b|\b(?:operational\s+relay|ORB)\s+networks?\b|\bredirectors?\b|\breverse\s+(?:tunnel|proxy)\b/gi, 4, "relay infrastructure"),
      s(/\bCobalt\s+Strike\b|\bSliver\b|\bHavoc\b|\bBrute\s+Ratel\b|\bMythic\b|\bMetasploit\b/g, 3, "C2 framework"),
      s(/\bTLS\s+certificates?\b|\bJA3S?\b|\bJARM\b/g, 3, "TLS fingerprint"),
      s(/\bdead[\s-]drop\b|\bTelegram\s+bot\b/gi, 3, "dead drop"),
    ],
    threshold: 12,
  },
  {
    id: "impact",
    label: "Post-compromise activity and impact",
    short: "Post-compromise & impact",
    scope: "core",
    purpose: "Describe what happens after the foothold, with safe substitutes for destructive steps.",
    types: [
      "Lateral movement narratives",
      "Remote service abuse",
      "Internal reconnaissance",
      "Data staging and collection",
      "Exfiltration methods",
      "Ransomware deployment chains",
      "Backup destruction and recovery inhibition",
      "Mass file encryption behavior",
      "Wiper and destructive operations",
      "Business disruption and operational impact",
      "Extortion and double-extortion campaigns",
    ],
    queries: [
      "lateral movement ransomware deployment analysis",
      "data exfiltration techniques intrusion analysis",
      "backup deletion recovery inhibition ransomware",
      "double extortion ransomware intrusion analysis",
      "destructive wiper attack operational impact",
    ],
    signals: [
      s(/\blateral(?:ly)?\s+mov(?:e|ed|ement|ing)\b/gi, 3, "lateral movement"),
      s(/\bexfiltrat\w*|\bdata\s+(?:staging|theft|leak)\b/gi, 3, "exfiltration"),
      s(/\bencrypt(?:s|ed|ing|ion)?\s+(?:files?|data|systems?|hosts?)\b|\bransom\s+notes?\b/gi, 4, "encryption"),
      s(/\b(?:double|triple)\s+extortion\b|\bleak\s+sites?\b|\bextort\w*/gi, 3, "extortion"),
      s(/\bshadow\s+cop(?:y|ies)\b|\bvssadmin\b|\bbackups?\s+(?:deletion|destruction|deleted)\b|\binhibit\w*\s+(?:system\s+)?recovery\b/gi, 4, "recovery inhibition"),
      s(/\bwip(?:er|ing)\b|\bdestructive\b/gi, 3, "destructive"),
      s(/\bPsExec\b|\bremote\s+desktop\b|\bRDP\b|\bWMI\b|\bSMB\b|\bWinRM\b/g, 2, "remote services"),
      s(/\b(?:internal\s+)?reconnaissance\b|\bnetwork\s+discovery\b/gi, 1, "reconnaissance"),
    ],
    threshold: 12,
  },
  {
    id: "cloud",
    label: "Cloud, SaaS and enterprise platforms",
    short: "Cloud & SaaS",
    scope: "core",
    purpose: "Cover control-plane and SaaS attacks, CI/CD and software supply chain.",
    types: [
      "AWS account compromise reports",
      "Azure and Entra ID attack investigations",
      "Google Cloud compromise reports",
      "Microsoft 365 intrusion reports",
      "SaaS token theft",
      "Cloud privilege escalation",
      "Cloud persistence and IAM abuse",
      "Kubernetes and container attacks",
      "CI/CD pipeline compromise",
      "Software supply-chain incidents",
      "Hybrid identity attack paths",
    ],
    queries: [
      "AWS account compromise investigation",
      "Microsoft 365 tenant intrusion investigation",
      "Kubernetes attack container compromise analysis",
      "CI/CD pipeline compromise supply chain",
      "SaaS token theft compromise investigation",
      "malicious npm PyPI package supply chain compromise",
    ],
    signals: [
      s(/\bAWS\b|\bAmazon\s+Web\s+Services\b|\bIAM\s+(?:roles?|users?|polic\w*)\b|\bS3\s+buckets?\b|\bEC2\b|\bLambda\b/g, 3, "AWS"),
      s(/\bAzure\b|\bMicrosoft\s+365\b|\bExchange\s+Online\b|\bSharePoint\b|\btenants?\b/g, 2, "Azure/M365"),
      s(/\bGoogle\s+Cloud\b|\bGCP\b|\bGoogle\s+Workspace\b/g, 3, "Google Cloud"),
      s(/\bKubernetes\b|\bkubelet\b|\bcontainers?\s+escape\b|\bDocker\b/g, 3, "Kubernetes/containers"),
      s(/\bCI\/CD\b|\bGitHub\s+Actions\b|\bbuild\s+pipelines?\b|\bpipeline\s+compromise\b/gi, 3, "CI/CD"),
      s(/\bnpm\b|\bPyPI\b|\bpackages?\s+(?:registry|maintainers?)\b|\bpostinstall\b|\bdependency\s+confusion\b/g, 3, "package supply chain"),
      s(/\bSaaS\b|\bcloud\s+(?:environments?|accounts?|tenants?|control\s+plane|workloads?)\b/gi, 2, "cloud/SaaS"),
      s(/\bcontrol[\s-]plane\b|\baudit\s+logs?\b|\bCloudTrail\b/gi, 2, "cloud audit"),
      s(/\bcloud\s+(?:attacks?|compromises?|intrusions?|resources?|infrastructure|identit(?:y|ies))\b/gi, 4, "cloud attack"),
      s(/\b(?:subscriptions?|resource\s+groups?|Key\s+Vaults?|storage\s+accounts?|app\s+registrations?)\b|\bMicrosoft\s+Graph\b/gi, 2, "cloud resources"),
    ],
    threshold: 12,
  },
  {
    id: "ir_forensics",
    label: "Incident response and forensic reports",
    short: "Incident response",
    scope: "core",
    purpose: "Establish what happened on real hosts, with artefacts and timings.",
    types: [
      "Incident-response reports",
      "Digital-forensics case studies",
      "Host and memory forensics",
      "Process trees and command-line evidence",
      "File, registry, service and scheduled-task artifacts",
      "Intrusion timelines from investigations",
      "Dwell time and time-to-detect analyses",
    ],
    queries: [
      "incident response report intrusion forensic analysis",
      "DFIR case study ransomware intrusion",
      "forensic investigation threat actor timeline",
      "memory forensics intrusion investigation",
    ],
    signals: [
      s(/\bincident\s+response\b|\bDFIR\b|\bIR\s+engagements?\b/g, 4, "incident response"),
      s(/\bforensic\w*/gi, 4, "forensics"),
      s(/\b(?:our|the)\s+investigation\b|\bwe\s+(?:observed|investigated|responded)\b/gi, 2, "investigation"),
      s(/\binvestigat(?:e|es|ed|ing|ion|ions)\b/gi, 2, "investigating"),
      s(/\bEvent\s+ID\s+\d{3,5}\b|\bSysmon\b|\bWindows\s+Event\s+Logs?\b/g, 2, "event logs"),
      s(/\bprefetch\b|\bamcache\b|\bshimcache\b|\$MFT\b|\bUSN\s+journal\b|\bmemory\s+(?:dump|image|forensics)\b/gi, 4, "host artefacts"),
      s(/\bdwell\s+time\b|\btime[\s-]to[\s-](?:detect|ransom)\b|\bpatient\s+zero\b/gi, 4, "dwell time"),
      s(/\bscheduled\s+tasks?\b|\bregistry\s+(?:keys?|run\s+keys?)\b|\bservices?\s+(?:created|installed)\b/gi, 1, "host artefacts"),
    ],
    threshold: 12,
    requires: /\bincident\s+response\b|\bDFIR\b|\bforensic|\binvestigat/i,
  },
  {
    id: "lessons",
    label: "Incident lessons and defensive response",
    short: "Lessons learned",
    scope: "core",
    purpose: "Show what was missed and what changed, to test the same gaps.",
    types: [
      "Post-incident reviews",
      "Root-cause analyses",
      "Breach investigation reports",
      "Lessons-learned reports",
      "Containment and eradication timelines",
      "Detection gaps and missed alerts",
      "Security control failure analyses",
      "Remediation recommendations",
      "Threat-informed defense assessments",
      "Purple-team improvement reports",
    ],
    queries: [
      "post-incident review lessons learned breach",
      "root cause analysis security incident report",
      "breach investigation report detection gaps",
      "containment eradication timeline incident",
    ],
    signals: [
      s(/\blessons?\s+learn(?:ed|t)\b|\bpost-?(?:incident|mortem)\b|\bafter-action\b/gi, 5, "lessons learned"),
      s(/\broot[\s-]cause\b/gi, 4, "root cause"),
      s(/\bcontainment\b|\beradicat\w*/gi, 2, "containment"),
      s(/\bdetection\s+gaps?\b|\bmissed\s+(?:alerts?|detections?)\b|\bcontrol\s+failures?\b/gi, 4, "detection gap"),
      s(/\bremediat\w*/gi, 1, "remediation", 3),
      s(/\bbreach\s+(?:investigation|review|report)\b/gi, 4, "breach investigation"),
    ],
    threshold: 12,
    noGapBoost: true,
    requires: /\blessons?\s+learn|\bpost-?(?:incident|mortem)|\bafter-action|\broot[\s-]cause|\bdetection\s+gaps?|\bmissed\s+(?:alerts?|detections?)|\bbreach\s+(?:investigation|review|report)/i,
  },
  {
    id: "actors",
    label: "Threat actors and intrusion sets",
    short: "Threat actors",
    scope: "core",
    purpose: "Profile who operates, their aliases, targets and preferred tradecraft.",
    types: [
      "Threat actor and APT profiles",
      "Intrusion-set analyses",
      "Actor aliases and alias conflicts",
      "Attribution assessments and confidence",
      "Targeted sectors and regions",
      "Actor evolution and tradecraft changes",
      "Actor tooling and relationships",
    ],
    queries: [
      "threat actor profile TTPs tooling",
      "APT group intrusion set analysis",
      "state-sponsored threat actor new tradecraft",
      "threat actor attribution assessment overlaps",
    ],
    signals: [
      s(/\bAPT\s?\d{1,3}\b|\bUNC\d{3,5}\b|\bFIN\d{1,2}\b|\bTA\d{3,4}\b|\bStorm-\d{3,4}\b|\bDEV-\d{4}\b/g, 3, "actor designation", 4),
      s(/\b[A-Z][a-z]+\s(?:Blizzard|Typhoon|Sandstorm|Sleet|Tempest|Dust|Hail|Flood|Tsunami|Cyclone)\b/g, 3, "actor name", 4),
      s(/\b[A-Z][a-z]+\s(?:Bear|Panda|Kitten|Chollima|Spider|Jackal|Tiger|Buffalo|Leopard|Ocelot)\b/g, 3, "actor name", 4),
      s(/\bthreat\s+actors?\b|\bintrusion\s+sets?\b|\bAPT\s+groups?\b/gi, 1, "threat actor", 5),
      s(/\battribut\w*/gi, 3, "attribution"),
      s(/\bnation-?state\b|\bstate-sponsored\b|\bstate-backed\b/gi, 3, "nation-state"),
      s(/\btracked\s+as\b|\balso\s+known\s+as\b|\baliases?\b|\boverlaps?\s+with\b/gi, 3, "aliases"),
      s(/\b(?:high|moderate|low|medium)\s+confidence\b/gi, 2, "confidence"),
      s(/\btradecraft\b/gi, 2, "tradecraft"),
    ],
    threshold: 13,
  },
  {
    id: "trends",
    label: "Threat trends and comparative studies",
    short: "Trends",
    scope: "core",
    purpose: "Show what is common now, to choose which behaviours to emulate first.",
    types: [
      "Annual and quarterly threat reports",
      "Ransomware ecosystem studies",
      "Sector-specific threat landscape reports",
      "Regional threat reports",
      "Emerging TTP trend analyses",
      "Actor technique comparisons",
      "Malware-family comparisons",
    ],
    queries: ["annual threat report technical findings", "ransomware ecosystem trends report", "threat landscape report sector attacks"],
    signals: [
      s(/\bthreat\s+landscape\b|\b(?:year\s+)?in\s+review\b|\bretrospective\b|\bstate\s+of\b/gi, 4, "threat landscape"),
      s(/\btrends?\b/gi, 2, "trends", 5),
      s(/\b(?:annual|quarterly|half-year|mid-year)\b|\bQ[1-4]\s+20\d\d\b|\bH[12]\s+20\d\d\b/g, 3, "periodic report"),
      s(/\byear[\s-]over[\s-]year\b|\bcompared\s+(?:to|with)\s+(?:last|the\s+previous)\s+(?:year|quarter)\b|\b\d{1,3}(?:\.\d)?\s?%\s+(?:increase|decrease|rise|drop)\b/gi, 3, "statistics"),
      s(/\bDigital\s+Defense\s+Report\b|\bM-Trends\b|\bDBIR\b|\bThreat\s+Report\s+20\d\d\b/g, 6, "named annual report"),
    ],
    threshold: 12,
    requires: /\bthreat\s+landscape\b|\bin\s+review\b|\bretrospective\b|\btrends?\b|\b(?:annual|quarterly)\b|\bQ[1-4]\s+20\d\d\b/i,
    noGapBoost: true,
  },
  {
    id: "detection_telemetry",
    label: "Detection, telemetry and hunting",
    short: "Detection & telemetry",
    scope: "bas",
    purpose: "Expected telemetry and hunts: what a simulation should produce and where to look.",
    types: [
      "Endpoint telemetry analyses",
      "Sysmon and Windows Event Log analyses",
      "Linux audit and process telemetry",
      "Network, DNS and proxy log studies",
      "Detection-engineering blogs",
      "Threat-hunting queries and case studies",
      "Cloud audit and control-plane logs",
      "Missing-log and telemetry-gap investigations",
    ],
    queries: [
      "threat hunting queries KQL detection threat actor",
      "Sysmon telemetry detection engineering technique",
      "detection engineering blog technique telemetry",
      "cloud audit log detection attack",
    ],
    signals: [
      s(/\bhunting\s+quer(?:y|ies)\b|\badvanced\s+hunting\b|\bthreat\s+hunt\w*/gi, 4, "hunting queries"),
      s(/\bdetection\s+(?:engineering|opportunit\w+|logic|coverage)\b/gi, 4, "detection engineering"),
      s(/\btelemetry\b/gi, 2, "telemetry"),
      s(/\bKQL\b|\bKusto\b|\bSPL\b|\bSplunk\b|\bSigma\b|\bEQL\b/g, 3, "query language"),
      s(/\bEvent\s+ID\s+\d{3,5}\b|\bSysmon\b|\bauditd\b|\bETW\b/g, 2, "event sources"),
      s(/\bdetections?\b/gi, 1, "detection", 6),
    ],
    threshold: 12,
  },
  {
    id: "detection_content",
    label: "Detection content and analytics",
    short: "Detection rules",
    scope: "bas",
    purpose: "Rules and queries to validate during a simulation.",
    types: [
      "Sigma detection rules",
      "YARA and YARA-L rules",
      "SIEM analytics and correlation rules",
      "KQL and SPL hunting queries",
      "Suricata and Snort signatures",
      "Detection-coverage mappings",
      "False-positive analysis and tuning",
    ],
    queries: ["Sigma rule detection threat report", "YARA rules malware family analysis", "detection rules hunting query threat report"],
    signals: [
      s(/\blogsource:\s|\bdetection:\s+selection\b|\bcondition:\s+selection\b/g, 6, "Sigma rule body"),
      s(/\brule\s+\w+\s*(?::\s*\w+\s*)?\{[\s\S]{0,400}?\bstrings:/g, 6, "YARA rule body"),
      s(/\b(?:Device(?:Process|Network|File|Registry|Logon)Events|SigninLogs|AuditLogs|SecurityEvent|CommonSecurityLog|EmailEvents|CloudAppEvents)\b/g, 3, "KQL table", 5),
      s(/\|\s*where\b|\|\s*summarize\b|\|\s*project\b/g, 2, "KQL pipeline", 5),
      s(/\bindex\s*=\s*\S+|\|\s*stats\s+count\b|\bsourcetype\s*=/g, 3, "SPL search"),
      s(/\balert\s+(?:tcp|udp|http|dns|tls)\s+\$?\w+/g, 5, "Suricata/Snort"),
      s(/\b(?:Sigma|YARA(?:-L)?|Suricata|Snort)\s+rules?\b|\bdetection\s+rules?\b/gi, 3, "rule reference"),
    ],
    threshold: 12,
    requires: /\blogsource:|\bstrings:\s|\bcondition:\s|\|\s*(?:where|summarize|project|stats)\b|\bindex\s*=|\balert\s+(?:tcp|udp|http|dns|tls)\b/i,
  },
  {
    id: "emulation",
    label: "Emulation, simulation and purple-team evidence",
    short: "Emulation & purple team",
    scope: "bas",
    purpose: "Existing tests, plans and exercise results to reuse in planning.",
    types: [
      "Adversary emulation plans",
      "Atomic technique test definitions",
      "Purple-team exercise reports",
      "Red-team engagement summaries",
      "Breach-and-attack simulation results",
      "Tabletop and attack-path exercises",
      "Detection validation case studies",
      "Telemetry replay datasets",
      "Attack simulation evaluation reports",
      "Expected-versus-observed event examples",
      "Control validation and coverage gaps",
    ],
    queries: [
      "adversary emulation plan threat actor",
      "purple team exercise report detection validation",
      "Atomic Red Team test technique",
      "breach and attack simulation results control validation",
    ],
    signals: [
      s(/\badversary\s+emulation\b|\bemulation\s+plans?\b/gi, 6, "emulation plan"),
      s(/\bpurple[\s-]team\w*|\bred[\s-]team\w*/gi, 4, "purple/red team"),
      s(/\bAtomic\s+Red\s+Team\b|\batomic\s+tests?\b|\bCALDERA\b|\bInvoke-AtomicRedTeam\b/gi, 5, "atomic tests"),
      s(/\bbreach[\s-]and[\s-]attack\s+simulation\b|\bBAS\b|\battack\s+simulation\b/g, 4, "attack simulation"),
      s(/\b(?:detection|control|security)\s+validation\b|\bcoverage\s+gaps?\b/gi, 4, "validation"),
      s(/\btabletop\b|\bexpected\s+(?:vs\.?|versus)\s+observed\b|\breplay\w*\s+(?:datasets?|telemetry|logs)\b/gi, 4, "exercise"),
    ],
    threshold: 12,
    requires: /\bemulat|\bpurple[\s-]team|\bred[\s-]team|\batomic\s+(?:red\s+team|tests?)|\bCALDERA\b|\bbreach[\s-]and[\s-]attack|\bsimulation\b|\bvalidation\b/i,
  },
];

const BY_ID = new Map(RESEARCH_CATEGORIES.map((c) => [c.id, c]));

export function researchCategory(id: string): ResearchCategory | undefined {
  return BY_ID.get(id as ResearchCategoryId);
}

export const RESEARCH_CATEGORY_IDS = RESEARCH_CATEGORIES.map((c) => c.id) as readonly ResearchCategoryId[];
export const BAS_CATEGORY_IDS = RESEARCH_CATEGORIES.filter((c) => c.scope === "bas").map((c) => c.id) as readonly ResearchCategoryId[];

// ---------------------------------------------------------------------------
// Labelling
// ---------------------------------------------------------------------------

export type ResearchLabel = {
  id: ResearchCategoryId;
  score: number;
  /** The terms that matched, strongest first (at most 4). */
  evidence: string[];
};

export type ResearchLabels = {
  /** Version of the labeller: stored labels from an older version are recomputed. */
  version: number;
  labels: ResearchLabel[];
  /** The best-supported category, or null when none reaches its threshold. */
  primary: ResearchCategoryId | null;
};

export const RESEARCH_LABELS_VERSION = 1;

/** At most this many labels per report (core + BAS): past that a label says little. */
const MAX_CORE_LABELS = 4;
const MAX_BAS_LABELS = 2;
/** A label must be at least this share as strong (relative to its threshold) as the best one. */
const RELATIVE_FLOOR = 0.3;
/** Body text past this length adds nothing to the labels and only costs time. */
const MAX_TEXT = 60_000;

function countMatches(re: RegExp, text: string, cap: number): number {
  re.lastIndex = 0;
  let n = 0;
  while (n < cap && re.exec(text)) n++;
  re.lastIndex = 0;
  return n;
}

export function scoreCategory(category: ResearchCategory, title: string, body: string): ResearchLabel {
  const hits: Array<{ term: string; points: number }> = [];
  let score = 0;
  for (const sig of category.signals) {
    const cap = sig.cap ?? 4;
    const inTitle = countMatches(sig.re, title, 2);
    const inBody = countMatches(sig.re, body, cap);
    const points = sig.w * (Math.min(inBody, cap) + 3 * inTitle);
    if (points > 0) {
      score += points;
      hits.push({ term: sig.term, points });
    }
  }
  const evidence = [...new Map(hits.sort((a, b) => b.points - a.points).map((h) => [h.term, h])).keys()].slice(0, 4);
  return { id: category.id, score, evidence };
}

/**
 * The research categories a report's title and text support, strongest first. Deterministic and
 * cheap (regexes over at most 60k characters), so it runs at ingest and in backfills.
 */
export function classifyResearch(input: { title: string; text: string }): ResearchLabels {
  const title = String(input.title ?? "").slice(0, 400);
  const body = String(input.text ?? "").slice(0, MAX_TEXT);
  const both = `${title}\n${body}`;
  const scored = RESEARCH_CATEGORIES.map((c) => ({ c, label: scoreCategory(c, title, body), ratio: 0 }))
    .filter(({ c, label }) => label.score >= c.threshold && (!c.requires || c.requires.test(both)))
    .map((x) => ({ ...x, ratio: x.label.score / x.c.threshold }))
    .sort((a, b) => b.ratio - a.ratio);
  const best = scored.find((x) => x.c.scope === "core")?.ratio ?? scored[0]?.ratio ?? 0;
  const strong = scored.filter((x) => x.ratio >= best * RELATIVE_FLOOR);
  // Core labels say what the report is about; BAS labels say what detection or emulation material
  // it carries. Separate caps, so hunting queries never push "incident response" off the list.
  const core = strong.filter((x) => x.c.scope === "core").slice(0, MAX_CORE_LABELS);
  const bas = strong.filter((x) => x.c.scope === "bas").slice(0, MAX_BAS_LABELS);
  const labels = [...core, ...bas].map(({ label }) => label);
  return { version: RESEARCH_LABELS_VERSION, labels, primary: core[0]?.label.id ?? bas[0]?.label.id ?? null };
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

export type ResearchQuery = { category: ResearchCategoryId; query: string };

/** Crawl settings for taxonomy discovery (CrawlConfig.researchDiscovery). */
export type ResearchDiscoveryConfig = {
  enabled: boolean;
  /** Taxonomy web searches per crawl run, on top of the analyst's own keywords. */
  queriesPerRun: number;
  /** Optional BAS categories to search for as well. */
  bas: ResearchCategoryId[];
};

export const DEFAULT_RESEARCH_DISCOVERY: ResearchDiscoveryConfig = { enabled: true, queriesPerRun: 6, bas: [] };
export const MAX_RESEARCH_QUERIES_PER_RUN = 12;

/** Stored settings, made safe: unknown categories dropped, the query count clamped. */
export function normalizeResearchDiscovery(raw: unknown): ResearchDiscoveryConfig {
  const r = raw && typeof raw === "object" ? (raw as Partial<ResearchDiscoveryConfig>) : {};
  const n = Number(r.queriesPerRun);
  return {
    enabled: typeof r.enabled === "boolean" ? r.enabled : DEFAULT_RESEARCH_DISCOVERY.enabled,
    queriesPerRun: Number.isFinite(n) ? Math.max(0, Math.min(MAX_RESEARCH_QUERIES_PER_RUN, Math.round(n))) : DEFAULT_RESEARCH_DISCOVERY.queriesPerRun,
    bas: Array.isArray(r.bas) ? [...new Set(r.bas.filter((id): id is ResearchCategoryId => BAS_CATEGORY_IDS.includes(id as ResearchCategoryId)))] : [],
  };
}

/**
 * The analyst's "targeted threat keywords" setting as separate phrases: split on commas and new
 * lines, quotes kept only around multi-word phrases ("attack chain"), duplicates dropped.
 */
export function splitKeywordPhrases(raw: string, max = 12): string[] {
  const out: string[] = [];
  for (const part of String(raw ?? "").split(/[,\n]+/)) {
    const bare = part.replace(/["“”]/g, "").replace(/\s+/g, " ").trim();
    if (bare.length < 2 || bare.length > 80) continue;
    const phrase = /\s/.test(bare) ? `"${bare}"` : bare;
    if (!out.some((p) => p.toLowerCase() === phrase.toLowerCase())) out.push(phrase);
    if (out.length >= max) break;
  }
  return out;
}

/**
 * Discovery queries for one crawl: `count` queries spread over the enabled categories, the ones
 * with the fewest reports first, rotating through each category's queries from run to run so the
 * whole taxonomy is searched over time.
 *
 * `counts` are library report counts per category (missing = 0). `round` advances every run.
 */
export function pickResearchQueries(opts: {
  round: number;
  count: number;
  counts?: Partial<Record<ResearchCategoryId, number>>;
  includeBas?: boolean | readonly ResearchCategoryId[];
}): ResearchQuery[] {
  const bas = opts.includeBas;
  const enabled = RESEARCH_CATEGORIES.filter(
    (c) => c.scope === "core" || bas === true || (Array.isArray(bas) && bas.includes(c.id)),
  );
  if (!enabled.length || opts.count <= 0) return [];
  const round = Math.max(0, Math.floor(opts.round));
  const n = enabled.length;
  const out: ResearchQuery[] = [];
  const take = (c: ResearchCategory, pass: number) => {
    const q = c.queries[(round + pass) % c.queries.length];
    if (out.length < opts.count && !out.some((o) => o.query === q)) out.push({ category: c.id, query: q });
  };
  // Half the slots go to the thinnest categories (ties take turns by round)…
  const thinnest = enabled
    .map((c, i) => ({ c, n: opts.counts?.[c.id] ?? 0, tie: (i + round) % n }))
    .filter((x) => !x.c.noGapBoost)
    .sort((a, b) => a.n - b.n || a.tie - b.tie)
    .map((x) => x.c);
  for (const c of thinnest.slice(0, Math.ceil(opts.count / 2))) take(c, 0);
  // …the rest rotate through every enabled category, so each one is searched over time.
  for (let pass = 0; out.length < opts.count && pass < 8; pass++) {
    for (let i = 0; i < n && out.length < opts.count; i++) {
      const c = enabled[(i + round * Math.ceil(opts.count / 2) + pass) % n];
      if (!out.some((o) => o.category === c.id) || pass > 0) take(c, pass);
    }
  }
  return out;
}

/** Library coverage per category, for the coverage view and for discovery priority. */
export function researchCoverage(reports: ReadonlyArray<{ research?: { labels?: ReadonlyArray<{ id: string }> } | null }>) {
  const counts = Object.fromEntries(RESEARCH_CATEGORY_IDS.map((id) => [id, 0])) as Record<ResearchCategoryId, number>;
  let labelled = 0;
  for (const r of reports) {
    const labels = r.research?.labels ?? [];
    if (labels.length) labelled++;
    for (const l of labels) if (l.id in counts) counts[l.id as ResearchCategoryId]++;
  }
  return { counts, labelled, total: reports.length };
}
