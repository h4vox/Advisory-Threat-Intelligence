import type {
  CuratedResourceCatalogItem,
  IntegrationItem,
  PlaybookBlockItem,
  PowerupItem,
} from "./marketplace-types";

function rightRotate(value: number, amount: number): number {
  return (value >>> amount) | (value << (32 - amount));
}

function computeSha256Hex(input: string): string {
  const bytes = new TextEncoder().encode(input);
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  let H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
  let H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;

  const bitLength = bytes.length * 8;
  const newByteLength = (((bytes.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(newByteLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(newByteLength - 4, bitLength, false);

  const W = new Uint32Array(64);

  for (let i = 0; i < newByteLength; i += 64) {
    for (let t = 0; t < 16; t++) {
      W[t] = view.getUint32(i + t * 4, false);
    }
    for (let t = 16; t < 64; t++) {
      const s0 = rightRotate(W[t - 15], 7) ^ rightRotate(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      const s1 = rightRotate(W[t - 2], 17) ^ rightRotate(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
    }

    let a = H0, b = H1, c = H2, d = H3, e = H4, f = H5, g = H6, h = H7;

    for (let t = 0; t < 64; t++) {
      const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[t] + W[t]) | 0;
      const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    H0 = (H0 + a) | 0;
    H1 = (H1 + b) | 0;
    H2 = (H2 + c) | 0;
    H3 = (H3 + d) | 0;
    H4 = (H4 + e) | 0;
    H5 = (H5 + f) | 0;
    H6 = (H6 + g) | 0;
    H7 = (H7 + h) | 0;
  }

  const hashWords = [H0, H1, H2, H3, H4, H5, H6, H7];
  return hashWords.map((w) => (w >>> 0).toString(16).padStart(8, "0")).join("");
}

function hexToBase64Url(hex: string): string {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function generateRandomBase64Url(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  if (typeof globalThis !== "undefined" && globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < byteLength; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export interface AgyOAuthSession {
  authUrl: string;
  state: string;
  codeVerifier: string;
  codeChallenge: string;
  createdAt: string;
}

/**
 * Generates a dynamic PKCE authorization URL for Google Cloud OAuth 2.0.
 * Automatically computes a unique high-entropy code_verifier, derives the
 * S256 code_challenge, and embeds a cryptographically random session state.
 */
export function generateAgyOAuthSession(options?: { state?: string; codeVerifier?: string }): AgyOAuthSession {
  const codeVerifier = options?.codeVerifier || generateRandomBase64Url(32);
  const codeChallenge = hexToBase64Url(computeSha256Hex(codeVerifier));
  const state = options?.state || generateRandomBase64Url(16);

  const params = new URLSearchParams({
    access_type: "offline",
    client_id: "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    prompt: "consent",
    redirect_uri: "https://antigravity.google/oauth-callback",
    response_type: "code",
    scope:
      "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/cclog https://www.googleapis.com/auth/experimentsandconfigs https://www.googleapis.com/auth/aicode openid",
    state,
  });

  return {
    authUrl: `https://accounts.google.com/o/oauth2/auth?${params.toString()}`,
    state,
    codeVerifier,
    codeChallenge,
    createdAt: new Date().toISOString(),
  };
}

export function generateAgyOAuthUrl(options?: { state?: string; codeVerifier?: string }): string {
  return generateAgyOAuthSession(options).authUrl;
}

export const OFFICIAL_AGY_OAUTH_URL = generateAgyOAuthUrl();

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
    authUrl: generateAgyOAuthUrl(),
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
        label: "Google Account OAuth (PKCE Flow)",
        description: "Authenticates `agy` CLI via dynamic Google Cloud OAuth 2.0 PKCE challenge.",
        authUrl: generateAgyOAuthUrl(),
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
