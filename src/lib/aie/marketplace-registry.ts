import type {
  CuratedResourceCatalogItem,
  IntegrationItem,
  PlaybookBlockItem,
  PowerupItem,
} from "./marketplace-types";

export const DEFAULT_INTEGRATIONS: IntegrationItem[] = [
  {
    id: "agy_agent",
    name: "Antigravity AGY Agent",
    category: "Intelligence",
    type: "cli_agent",
    provider: "Google",
    version: "v3.8.2",
    releaseDate: "2026-09-01",
    status: "installed",
    isDefault: true,
    description:
      "Autonomous CTI research and adversary emulation agent powered by Google Gemini and the local agy CLI runtime.",
    overview:
      "Antigravity AGY Agent provides deep cognitive research for the AIE crawler. It traverses threat blogs, uncovers hidden advisory endpoints, extracts technical procedure command-lines, and cross-references behaviors directly with MITRE ATT&CK techniques with zero single point of failure.",
    installCommand: "curl -fsSL https://antigravity.google/cli/install.sh | bash",
    authUrl: "https://antigravity.google/oauth/authorize?client_id=agy-cli&scope=gemini.models",
    actions: [
      {
        id: "source_discovery",
        name: "Autonomous CTI Endpoint Discovery",
        description: "Scans search engines and seed domains for unindexed threat lab and advisory endpoints.",
      },
      {
        id: "attack_tagging",
        name: "Adversary TTP Qualification & Tagging",
        description: "Evaluates extracted reports and applies MITRE ATT&CK technique IDs with cryptographic evidence snippets.",
      },
      {
        id: "killchain_reconstruction",
        name: "Chronological Kill-Chain Ordering",
        description: "Reconstructs multi-stage intrusion timelines (Initial Access → Execution → Credential Access → Impact).",
      },
      {
        id: "adversary_scoring",
        name: "Quality Scoring & Approval Recommendation",
        description: "Calculates a 0–100 fidelity score based on operational adversary procedure depth.",
      },
    ],
    connectors: [
      {
        type: "oauth_cli",
        label: "Google Account OAuth (Browser Flow)",
        description: "Runs `agy auth login` to obtain scoped credentials from Google Cloud / Gemini AI.",
        authUrl: "https://antigravity.google/oauth/authorize?client_id=agy-cli&scope=gemini.models",
      },
      {
        type: "binary",
        label: "Local CLI Binary (`agy`)",
        description: "Spawns the local Node/Bash child process `agy` located in PATH or ~/.gemini/bin.",
      },
    ],
    tags: ["AI Security", "Google Gemini", "CLI Agent", "Autonomous", "Adversary Emulation"],
    supportedModels: [
      "AGY: gemini-3.8-flash-low",
      "AGY: gemini-3.8-flash-medium",
      "AGY: gemini-3.8-flash-high",
      "AGY: gemini-3.8-pro",
      "AGY: gemini-2.5-flash",
    ],
    config: {
      selectedModel: "AGY: gemini-3.8-flash-low",
      installedAt: "2026-09-01T00:00:00.000Z",
      isConfigured: true,
    },
  },
  {
    id: "claude_code_agent",
    name: "Claude Code Agent",
    category: "Intelligence",
    type: "cli_agent",
    provider: "Anthropic",
    version: "v1.4.0",
    releaseDate: "2026-08-20",
    status: "not_installed",
    isDefault: false,
    description:
      "Anthropic's agentic CLI tool capable of autonomous reasoning, code parsing, and threat research workflows.",
    overview:
      "Claude Code Agent leverages Claude 3.7 Sonnet for complex multi-file reasoning, deobfuscation of adversary scriptlets (PowerShell, VBScript, Bash), and parsing intricate incident report narratives into structured adversary procedures.",
    installCommand: "npm install -g @anthropic-ai/claude-code",
    authUrl: "https://console.anthropic.com/settings/keys",
    actions: [
      {
        id: "script_deobfuscation",
        name: "Adversary Script & Payload Deobfuscation",
        description: "Unrolls encoded PowerShell commands, reflective DLL loaders, and obfuscated shell commands.",
      },
      {
        id: "technique_analysis",
        name: "Deep ATT&CK Technique Mapping",
        description: "Applies nuanced semantic matching for advanced persistent threat (APT) tradecraft.",
      },
      {
        id: "detection_opportunity",
        name: "Detection Engineering Generation",
        description: "Generates candidate Sigma and YARA rules from observed adversary artifacts.",
      },
    ],
    connectors: [
      {
        type: "oauth_cli",
        label: "Anthropic Console OAuth",
        description: "Authenticates via browser OAuth redirect or CLI token.",
        authUrl: "https://console.anthropic.com/settings/keys",
      },
      {
        type: "binary",
        label: "Local CLI Binary (`claude`)",
        description: "Spawns the globally installed `@anthropic-ai/claude-code` binary.",
      },
    ],
    tags: ["AI Security", "Anthropic", "CLI Agent", "Deep Reasoning", "Code Analysis"],
    supportedModels: [
      "Claude Code: claude-3-7-sonnet",
      "Claude Code: claude-3-5-haiku",
    ],
  },
  {
    id: "codex_agent",
    name: "Codex Agent",
    category: "Intelligence",
    type: "cli_agent",
    provider: "OpenAI",
    version: "v2.1.0",
    releaseDate: "2026-08-10",
    status: "not_installed",
    isDefault: false,
    description:
      "OpenAI Codex & reasoning agent CLI for threat intelligence automation, procedure parsing, and script analysis.",
    overview:
      "Codex Agent provides high-precision syntax extraction, payload structure parsing, and automated mapping of Windows API abuse patterns into executable purple-team emulation steps.",
    installCommand: "npm install -g @openai/codex-cli",
    authUrl: "https://platform.openai.com/api-keys",
    actions: [
      {
        id: "api_abuse_mapping",
        name: "Win32/NT API Abuse Identification",
        description: "Maps observed API calls (e.g. OpenProcess, VirtualAllocEx, WriteProcessMemory) to injection techniques.",
      },
      {
        id: "ioc_normalization",
        name: "Automated IOC Normalization",
        description: "Extracts and standardizes file hashes, registry keys, and network C2 indicators.",
      },
    ],
    connectors: [
      {
        type: "oauth_cli",
        label: "OpenAI Account OAuth",
        description: "Performs device code or browser-based OAuth authorization.",
        authUrl: "https://platform.openai.com/api-keys",
      },
      {
        type: "binary",
        label: "Local CLI Binary (`codex`)",
        description: "Spawns the local `codex` CLI runtime.",
      },
    ],
    tags: ["AI Security", "OpenAI", "CLI Agent", "API Parsing", "Reasoning"],
    supportedModels: [
      "Codex Agent: gpt-4o",
      "Codex Agent: o3-mini",
    ],
  },
  {
    id: "gemini_api",
    name: "Google Gemini API",
    category: "Intelligence",
    type: "api_provider",
    provider: "Google DeepMind",
    version: "v2.5.0",
    releaseDate: "2026-08-28",
    status: "not_installed",
    isDefault: false,
    description:
      "Direct high-speed REST integration with Google Gemini Generative Language APIs without requiring local CLI binaries.",
    overview:
      "The direct Gemini API integration provides server-to-server zero-binary threat evaluation. It executes sub-second semantic classification, rapid IOC extraction, and automated ATT&CK candidate tagging using Google AI Studio API credentials.",
    authUrl: "https://aistudio.google.com/app/apikey",
    actions: [
      {
        id: "rapid_eval",
        name: "Sub-Second Threat Classification",
        description: "High-throughput evaluation of candidate threat URLs and content feeds.",
      },
      {
        id: "ioc_extraction",
        name: "Zero-Binary Entity Extraction",
        description: "Direct REST-based extraction of threat actors, malware, and CVEs.",
      },
    ],
    connectors: [
      {
        type: "api_key",
        label: "Google AI Studio API Key",
        description: "Requires `GEMINI_API_KEY` for direct HTTPS REST communication.",
        authUrl: "https://aistudio.google.com/app/apikey",
        requiredEnvVar: "GEMINI_API_KEY",
      },
    ],
    tags: ["API Key", "Zero-Binary", "High Throughput", "Google Gemini", "Direct REST"],
    supportedModels: [
      "Gemini API: gemini-2.5-flash",
      "Gemini API: gemini-2.5-pro",
    ],
  },
  {
    id: "claude_api",
    name: "Anthropic Claude API",
    category: "Intelligence",
    type: "api_provider",
    provider: "Anthropic",
    version: "v3.7.0",
    releaseDate: "2026-08-25",
    status: "not_installed",
    isDefault: false,
    description:
      "Direct HTTP API integration for Claude 3.7 Sonnet & 3.5 Haiku with structured reasoning and markdown generation.",
    overview:
      "Enables serverless and direct API invocation of Claude 3.7 Sonnet without any CLI installation. Excellent for environments where Node child process execution or local binary installation is restricted by security policy.",
    authUrl: "https://console.anthropic.com/settings/keys",
    actions: [
      {
        id: "narrative_parsing",
        name: "Complex Incident Narrative Parsing",
        description: "Transforms long-form vendor whitepapers into structured, chronological attack stages.",
      },
      {
        id: "adversary_profiling",
        name: "Adversary Dossier Generation",
        description: "Synthesizes multi-report observations into a unified threat group profile.",
      },
    ],
    connectors: [
      {
        type: "api_key",
        label: "Anthropic API Key",
        description: "Requires `ANTHROPIC_API_KEY` passed via HTTP header x-api-key.",
        authUrl: "https://console.anthropic.com/settings/keys",
        requiredEnvVar: "ANTHROPIC_API_KEY",
      },
    ],
    tags: ["API Key", "Zero-Binary", "Deep Reasoning", "Anthropic", "Serverless"],
    supportedModels: [
      "Claude API: claude-3-7-sonnet",
      "Claude API: claude-3-5-haiku",
    ],
  },
];

export const DEFAULT_CURATED_RESOURCES: CuratedResourceCatalogItem[] = [
  {
    id: "res_dfir",
    name: "The DFIR Report Feed",
    provider: "The DFIR Report",
    category: "Case Studies & Intrusion Timelines",
    description: "Real-world intrusion case studies with minute-by-minute execution timelines, LOLBin commands, and forensics.",
    endpointUrl: "https://thedfirreport.com/feed/",
    format: "RSS/Atom",
    cadence: "Weekly",
    trustScore: 98,
    status: "active",
    tags: ["Timelines", "Forensics", "Atomic Commands"],
  },
  {
    id: "res_mandiant",
    name: "Google Threat Intelligence Group",
    provider: "Mandiant / Google",
    category: "APT & Nation-State Intelligence",
    description: "In-depth dossiers on state-sponsored threat actors (APT29, APT41, Sandworm) and zero-day exploitation campaigns.",
    endpointUrl: "https://cloud.google.com/feeds/threat-intelligence.xml",
    format: "RSS/Atom",
    cadence: "Daily",
    trustScore: 99,
    status: "active",
    tags: ["Nation-State", "Zero-Days", "APT Campaigns"],
  },
  {
    id: "res_cisa_kev",
    name: "CISA Known Exploited Vulnerabilities (KEV)",
    provider: "CISA",
    category: "Vulnerability Catalog",
    description: "Authoritative catalog of vulnerabilities exploited in active enterprise intrusions with mandatory remediation deadlines.",
    endpointUrl: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    format: "JSON-LD",
    cadence: "Daily",
    trustScore: 100,
    status: "active",
    tags: ["CVEs", "Active Exploits", "Federal Advisories"],
  },
  {
    id: "res_mitre_cti",
    name: "MITRE ATT&CK Enterprise STIX Bundle",
    provider: "MITRE",
    category: "Knowledge Base",
    description: "The authoritative MITRE ATT&CK framework dataset containing all tactics, techniques, sub-techniques, and mitigations.",
    endpointUrl: "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    format: "STIX 2.1",
    cadence: "Weekly",
    trustScore: 100,
    status: "active",
    tags: ["ATT&CK", "Taxonomy", "Enterprise Matrix"],
  },
];

export const DEFAULT_POWERUPS: PowerupItem[] = [
  {
    id: "pwr_sigma_export",
    name: "Sigma Detection Rule Exporter",
    author: "AIE Purple Team Labs",
    category: "Exporters",
    description: "Converts extracted adversary attack stage procedures and LOLBin commands into ready-to-deploy YAML Sigma rules.",
    version: "v1.2.0",
    status: "installed",
    tags: ["Sigma", "Detection", "YAML"],
  },
  {
    id: "pwr_slack_alerts",
    name: "SOC Alerting Webhook Relay",
    author: "AIE Integrations",
    category: "Alerting",
    description: "Streams critical qualified threat discoveries and high-confidence attack chains to Slack or Microsoft Teams channels.",
    version: "v1.0.4",
    status: "available",
    tags: ["Slack", "Teams", "Webhooks"],
  },
  {
    id: "pwr_stix_bundle",
    name: "STIX 2.1 Threat Bundle Generator",
    author: "AIE Intelligence Layer",
    category: "Exporters",
    description: "Packages ingested threat reports, observed IOCs, and ATT&CK attack paths into OASIS STIX 2.1 compliant JSON bundles.",
    version: "v2.0.1",
    status: "installed",
    tags: ["STIX 2.1", "TAXII", "Standardized"],
  },
];

export const DEFAULT_PLAYBOOKS: PlaybookBlockItem[] = [
  {
    id: "pb_ransomware_pre_encrypt",
    name: "Ransomware Pre-Encryption Infiltration Block",
    framework: "Atomic Red Team",
    tactics: ["Execution", "Defense Evasion", "Credential Access"],
    techniques: ["T1059.001", "T1003.001", "T1562.001"],
    difficulty: "Intermediate",
    description: "Simulates adversary behavior prior to ransomware detonation: volume shadow copy deletion, defender disabling, and LSASS memory dumping.",
    status: "ready",
    stepsCount: 6,
    tags: ["Ransomware", "LSASS", "Shadow Copies"],
  },
  {
    id: "pb_ad_kerberoasting",
    name: "Active Directory Kerberoasting & Lateral Pivoting",
    framework: "MITRE ATT&CK",
    tactics: ["Credential Access", "Lateral Movement"],
    techniques: ["T1558.003", "T1021.002"],
    difficulty: "Advanced",
    description: "Simulates requesting Kerberos TGS service tickets for SPNs, offline cracking, and SMB lateral movement to domain member servers.",
    status: "ready",
    stepsCount: 8,
    tags: ["Active Directory", "Kerberos", "SMB"],
  },
  {
    id: "pb_c2_cobalt_beacon",
    name: "Cobalt Strike Malleable C2 Beaconing Emulation",
    framework: "Custom AIE",
    tactics: ["Command and Control"],
    techniques: ["T1071.001", "T1573.002"],
    difficulty: "Beginner",
    description: "Emulates periodic jittered HTTP/HTTPS beaconing mimicking Cobalt Strike malleable C2 profiles against internal perimeter firewalls.",
    status: "available",
    stepsCount: 4,
    tags: ["Cobalt Strike", "C2", "Beaconing"],
  },
];
