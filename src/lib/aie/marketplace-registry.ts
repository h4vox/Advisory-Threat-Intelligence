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

// Server-side only: the OAuth URL is built on the server, so the browser never
// needs the client id or secret.
export const AGY_OAUTH_CLIENT_ID =
  (typeof process !== "undefined" &&
    (process.env?.AGY_OAUTH_CLIENT_ID || process.env?.AGY_CLIENT_ID || process.env?.VITE_AGY_CLIENT_ID)) ||
  "";

export const AGY_OAUTH_CLIENT_SECRET =
  (typeof process !== "undefined" &&
    (process.env?.AGY_OAUTH_CLIENT_SECRET || process.env?.AGY_CLIENT_SECRET || process.env?.GOOGLE_CLIENT_SECRET)) ||
  "";

/**
 * Generates a dynamic PKCE authorization URL for Google Cloud OAuth 2.0.
 * Automatically computes a unique high-entropy code_verifier, derives the
 * S256 code_challenge, and embeds a cryptographically random session state.
 */
export function generateAgyOAuthSession(options?: { state?: string; codeVerifier?: string }): AgyOAuthSession {
  // RFC 7636: a fresh high-entropy verifier per authorization attempt. The
  // server keeps it (never the browser) and presents it at code exchange.
  const codeVerifier = options?.codeVerifier || generateRandomBase64Url(48);
  const codeChallenge = hexToBase64Url(computeSha256Hex(codeVerifier));
  const state = options?.state || generateRandomBase64Url(16);

  const params = new URLSearchParams({
    access_type: "offline",
    client_id: AGY_OAUTH_CLIENT_ID,
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

export async function exchangeOAuthCodeForToken(
  code: string,
  codeVerifier?: string
): Promise<{
  success: boolean;
  token?: any;
  error?: string;
}> {
  try {
    let authCode = code.trim();
    if (authCode.includes("code=")) {
      try {
        const u = new URL(authCode.startsWith("http") ? authCode : `https://dummy.com/${authCode}`);
        authCode = u.searchParams.get("code") || authCode;
      } catch {
        // Not a parseable URL: use the raw code as entered.
      }
    }

    if (authCode.includes("%2F") || authCode.includes("%2f")) {
      try {
        authCode = decodeURIComponent(authCode);
      } catch {
        // Malformed percent-encoding: keep the code as entered.
      }
    }

    const verifier = codeVerifier;
    const bodyParams: Record<string, string> = {
      client_id: AGY_OAUTH_CLIENT_ID,
      client_secret: AGY_OAUTH_CLIENT_SECRET,
      code: authCode,
      grant_type: "authorization_code",
      redirect_uri: "https://antigravity.google/oauth-callback",
    };

    if (verifier) {
      bodyParams.code_verifier = verifier;
    }

    const res = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(bodyParams).toString(),
    });

    const data = await res.json();
    if (!res.ok || data.error) {
      return { success: false, error: data.error_description || data.error || "OAuth token exchange failed" };
    }

    const expiryDate = new Date(Date.now() + (data.expires_in || 3600) * 1000).toISOString();
    const tokenPayload = {
      token: {
        access_token: data.access_token,
        token_type: data.token_type || "Bearer",
        refresh_token: data.refresh_token || "",
        expiry: expiryDate,
      },
      auth_method: "consumer",
      id_token: data.id_token || "",
    };

    return { success: true, token: tokenPayload };
  } catch (err: any) {
    return { success: false, error: err?.message || "Failed to contact Google OAuth endpoint" };
  }
}

export const DEFAULT_INTEGRATIONS: IntegrationItem[] = [
  {
    id: "agy_agent",
    name: "Autonomous AI Agent Engine",
    category: "Intelligence",
    type: "cli_agent",
    provider: "Google Gemini / Container Sandbox",
    version: "v3.8.2",
    releaseDate: "2026-09-01",
    status: "installed",
    isDefault: true,
    description:
      "Built-in autonomous agent for CTI research, report qualification, and ATT&CK mapping. Runs in an isolated sandbox with no API key — the default when no direct provider is set.",
    overview:
      "The built-in autonomous agent researches public threat intelligence, qualifies and scores candidate reports, maps adversary behaviour to MITRE ATT&CK, and drafts detection rules. It runs in an isolated sandbox and is the zero-configuration fallback used whenever no direct API provider is active.",
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
        label: "Google Account OAuth 2.0 (PKCE Flow)",
        description: "Authenticates the containerized agent via dynamic Google Cloud OAuth 2.0 PKCE challenge.",
        authUrl: generateAgyOAuthUrl(),
      },
    ],
    tags: ["AI Security", "Google Gemini", "Container Agent", "Autonomous", "Adversary Emulation"],
    supportedModels: [
      "gemini-3.8-flash-low",
      "gemini-3.8-flash-medium",
      "gemini-3.8-flash-high",
      "gemini-3.7-flash-low",
      "gemini-3.7-flash-medium",
      "gemini-3.7-flash-high",
      "gemini-3.6-flash-low",
      "gemini-3.6-flash-medium",
      "gemini-3.6-flash-high",
      "gemini-3.1-pro-low",
      "gemini-3.1-pro-high",
      "claude-sonnet-4-6",
      "claude-opus-4-6-thinking",
      "gpt-oss-120b-medium",
    ],
    config: {
      selectedModel: "gemini-3.8-flash-low",
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
    category: "AI Providers",
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
    category: "AI Providers",
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
  {
    id: "openai_api",
    name: "OpenAI API",
    category: "AI Providers",
    type: "api_provider",
    provider: "OpenAI",
    version: "v1.0.0",
    releaseDate: "2026-09-01",
    status: "not_installed",
    isDefault: false,
    description: "Direct REST access to OpenAI chat models (GPT-4o family and o-series) with your own API key.",
    overview:
      "Server-to-server calls to the OpenAI Chat Completions API — no CLI, no container. Use it for report evaluation, attack-chain synthesis and the analyst chat. Supports a custom base URL for Azure OpenAI or OpenAI-compatible gateways on the host allowlist.",
    authUrl: "https://platform.openai.com/api-keys",
    actions: [
      { id: "report_eval", name: "Report evaluation", description: "Classify and score candidate reports and feed content." },
      { id: "chain_synth", name: "Attack-chain synthesis", description: "Turn long reports into structured ATT&CK stages." },
    ],
    connectors: [
      { type: "api_key", label: "OpenAI API key", description: "Sent as a Bearer token to api.openai.com.", authUrl: "https://platform.openai.com/api-keys", requiredEnvVar: "OPENAI_API_KEY" },
    ],
    tags: ["API Key", "Direct REST", "OpenAI", "GPT-4o"],
    supportedModels: ["OpenAI API: gpt-4o", "OpenAI API: gpt-4o-mini", "OpenAI API: o3-mini"],
  },
  {
    id: "openrouter",
    name: "OpenRouter",
    category: "AI Providers",
    type: "api_provider",
    provider: "OpenRouter",
    version: "v1.0.0",
    releaseDate: "2026-09-01",
    status: "not_installed",
    isDefault: false,
    description: "One API key for many models (OpenAI, Anthropic, Google, Meta, xAI and more) through OpenRouter.",
    overview:
      "OpenRouter routes to dozens of models behind a single OpenAI-compatible endpoint. Pick any model in the vendor/model form (for example openai/gpt-4o or anthropic/claude-3.7-sonnet). Good for trying models without a separate account per vendor.",
    authUrl: "https://openrouter.ai/keys",
    actions: [
      { id: "model_routing", name: "Model routing", description: "Reach many vendors' models with one key." },
      { id: "report_eval", name: "Report evaluation", description: "Classify and score reports with the chosen model." },
    ],
    connectors: [
      { type: "api_key", label: "OpenRouter API key", description: "Sent as a Bearer token to openrouter.ai.", authUrl: "https://openrouter.ai/keys", requiredEnvVar: "OPENROUTER_API_KEY" },
    ],
    tags: ["API Key", "Multi-model", "OpenAI-compatible", "OpenRouter"],
    supportedModels: ["OpenRouter: openai/gpt-4o", "OpenRouter: openai/gpt-4o-mini", "OpenRouter: anthropic/claude-3.7-sonnet", "OpenRouter: google/gemini-2.5-flash", "OpenRouter: x-ai/grok-2"],
  },
  {
    id: "xai",
    name: "xAI Grok",
    category: "AI Providers",
    type: "api_provider",
    provider: "xAI",
    version: "v1.0.0",
    releaseDate: "2026-09-01",
    status: "not_installed",
    isDefault: false,
    description: "Direct REST access to xAI Grok models with your own xAI API key.",
    overview:
      "Calls the xAI API (OpenAI-compatible) directly for report evaluation, synthesis and chat. Uses an xAI API key — this is the standard pay-as-you-go API, not a SuperGrok consumer subscription.",
    authUrl: "https://console.x.ai",
    actions: [
      { id: "report_eval", name: "Report evaluation", description: "Classify and score reports with Grok." },
      { id: "chat", name: "Analyst chat", description: "Grounded Q&A over the library." },
    ],
    connectors: [
      { type: "api_key", label: "xAI API key", description: "Sent as a Bearer token to api.x.ai.", authUrl: "https://console.x.ai", requiredEnvVar: "XAI_API_KEY" },
    ],
    tags: ["API Key", "Direct REST", "xAI", "Grok"],
    supportedModels: ["xAI Grok: grok-2-latest", "xAI Grok: grok-2", "xAI Grok: grok-beta"],
  },
  {
    id: "deepseek",
    name: "DeepSeek",
    category: "AI Providers",
    type: "api_provider",
    provider: "DeepSeek",
    version: "v1.0.0",
    releaseDate: "2026-09-01",
    status: "not_installed",
    isDefault: false,
    description: "Direct REST access to DeepSeek chat and reasoning models with your own API key.",
    overview:
      "Calls the DeepSeek API (OpenAI-compatible) directly. deepseek-chat for general evaluation, deepseek-reasoner for step-by-step reasoning on complex reports.",
    authUrl: "https://platform.deepseek.com/api_keys",
    actions: [
      { id: "report_eval", name: "Report evaluation", description: "Classify and score reports." },
      { id: "reasoning", name: "Deep reasoning", description: "Step-by-step analysis with deepseek-reasoner." },
    ],
    connectors: [
      { type: "api_key", label: "DeepSeek API key", description: "Sent as a Bearer token to api.deepseek.com.", authUrl: "https://platform.deepseek.com/api_keys", requiredEnvVar: "DEEPSEEK_API_KEY" },
    ],
    tags: ["API Key", "Direct REST", "DeepSeek", "Reasoning"],
    supportedModels: ["DeepSeek: deepseek-chat", "DeepSeek: deepseek-reasoner"],
  },
  {
    id: "slack_webhook",
    name: "Slack",
    category: "Messaging",
    type: "plugin",
    provider: "Slack",
    version: "v1.0.0",
    releaseDate: "2026-10-01",
    status: "not_installed",
    isDefault: false,
    description: "Send advisories, findings and alerts to a Slack channel through an incoming webhook.",
    overview:
      "Post AIE notifications to Slack. Create an Incoming Webhook for the target channel in your Slack workspace and paste its URL — AIE sends messages as a JSON payload to that webhook. The URL is stored encrypted and never returned to the browser.",
    authUrl: "https://api.slack.com/messaging/webhooks",
    actions: [{ id: "send_alert", name: "Send alert", description: "Deliver an advisory, finding or status message to the channel." }],
    connectors: [{ type: "webhook", label: "Slack incoming webhook", description: "https://hooks.slack.com/services/… — posts a { text } payload." }],
    tags: ["Messaging", "Webhook", "Slack", "Alerts"],
    supportedModels: [],
  },
  {
    id: "teams_webhook",
    name: "Microsoft Teams",
    category: "Messaging",
    type: "plugin",
    provider: "Microsoft",
    version: "v1.0.0",
    releaseDate: "2026-10-01",
    status: "not_installed",
    isDefault: false,
    description: "Send advisories, findings and alerts to a Microsoft Teams channel via an incoming webhook.",
    overview:
      "Post AIE notifications to a Teams channel. Add an Incoming Webhook connector to the channel and paste its URL here. AIE posts a text payload to it; the URL is stored encrypted on the server.",
    authUrl: "https://learn.microsoft.com/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook",
    actions: [{ id: "send_alert", name: "Send alert", description: "Deliver a message to the Teams channel." }],
    connectors: [{ type: "webhook", label: "Teams incoming webhook", description: "https://…webhook.office.com/… — posts a { text } payload." }],
    tags: ["Messaging", "Webhook", "Microsoft Teams", "Alerts"],
    supportedModels: [],
  },
  {
    id: "discord_webhook",
    name: "Discord",
    category: "Messaging",
    type: "plugin",
    provider: "Discord",
    version: "v1.0.0",
    releaseDate: "2026-10-01",
    status: "not_installed",
    isDefault: false,
    description: "Send advisories, findings and alerts to a Discord channel through a channel webhook.",
    overview:
      "Post AIE notifications to Discord. Create a channel webhook (Channel settings → Integrations → Webhooks) and paste its URL. AIE posts a { content } payload; the URL is stored encrypted.",
    authUrl: "https://support.discord.com/hc/articles/228383668-Intro-to-Webhooks",
    actions: [{ id: "send_alert", name: "Send alert", description: "Deliver a message to the Discord channel." }],
    connectors: [{ type: "webhook", label: "Discord channel webhook", description: "https://discord.com/api/webhooks/… — posts a { content } payload." }],
    tags: ["Messaging", "Webhook", "Discord", "Alerts"],
    supportedModels: [],
  },
  {
    id: "webhook_generic",
    name: "Generic webhook",
    category: "Messaging",
    type: "plugin",
    provider: "Custom",
    version: "v1.0.0",
    releaseDate: "2026-10-01",
    status: "not_installed",
    isDefault: false,
    description: "POST advisories, findings and alerts as JSON to any https endpoint — SIEM, SOAR or a custom receiver.",
    overview:
      "A provider-agnostic destination: AIE POSTs a JSON body ({ text, source }) to the https URL you configure. Use it for a SOAR playbook, a SIEM ingest endpoint or an internal bot. The endpoint must be https on a public host (private, loopback and metadata addresses are rejected).",
    actions: [{ id: "send_alert", name: "Send alert", description: "POST a JSON message to the endpoint." }],
    connectors: [{ type: "webhook", label: "HTTPS endpoint", description: "Any https URL on a public host — receives a { text, source } JSON payload." }],
    tags: ["Messaging", "Webhook", "SOAR", "SIEM"],
    supportedModels: [],
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
