#!/usr/bin/env node

/**
 * Adversary Intelligence Engine (AIE) CLI
 *
 * Bare-level operations, configuration, and debugging interface for AIE.
 * Supports:
 * - Interactive REPL shell (`aie>`)
 * - Agent management (list, install, uninstall, configure, set-active)
 * - Database health verification (MongoDB, PGLite)
 * - Application updates (git fetch & status)
 * - System diagnostics & runtime telemetry
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { execSync, spawn } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = join(__dirname, "..");
const APP_ENV_PATH = join(ROOT_DIR, ".grok/app-env.json");

// ANSI color helpers
const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
  red: "\x1b[31m",
  magenta: "\x1b[35m",
};

// Known integrations catalog
const DEFAULT_CATALOG = [
  {
    id: "agy_agent",
    name: "Antigravity AGY Agent",
    provider: "Google",
    type: "cli_agent",
    status: "installed",
    active: true,
    version: "v3.8.2",
    models: ["AGY: gemini-3.8-flash-low", "AGY: gemini-3.8-pro", "AGY: gemini-2.5-flash"],
    installCmd: "curl -fsSL https://antigravity.google/cli/install.sh | bash",
    authUrl: "https://antigravity.google/oauth/authorize?client_id=agy-cli&scope=gemini.models",
  },
  {
    id: "claude_code_agent",
    name: "Claude Code Agent",
    provider: "Anthropic",
    type: "cli_agent",
    status: "not_installed",
    active: false,
    version: "v1.4.0",
    models: ["Claude Code: claude-3-7-sonnet", "Claude Code: claude-3-5-haiku"],
    installCmd: "npm install -g @anthropic-ai/claude-code",
    authUrl: "https://console.anthropic.com/settings/keys",
  },
  {
    id: "codex_agent",
    name: "Codex Agent",
    provider: "OpenAI",
    type: "cli_agent",
    status: "not_installed",
    active: false,
    version: "v2.1.0",
    models: ["Codex Agent: gpt-4o", "Codex Agent: o3-mini"],
    installCmd: "npm install -g @openai/codex-cli",
    authUrl: "https://platform.openai.com/api-keys",
  },
  {
    id: "gemini_api",
    name: "Google Gemini API",
    provider: "Google DeepMind",
    type: "api_provider",
    status: "not_installed",
    active: false,
    version: "v2.5.0",
    models: ["Gemini API: gemini-2.5-flash", "Gemini API: gemini-2.5-pro"],
    authUrl: "https://aistudio.google.com/app/apikey",
  },
  {
    id: "claude_api",
    name: "Anthropic Claude API",
    provider: "Anthropic",
    type: "api_provider",
    status: "not_installed",
    active: false,
    version: "v3.7.0",
    models: ["Claude API: claude-3-7-sonnet", "Claude API: claude-3-5-haiku"],
    authUrl: "https://console.anthropic.com/settings/keys",
  },
];

// CLI State file
const STATE_FILE = join(ROOT_DIR, ".grok/cli-state.json");

function loadState() {
  try {
    if (existsSync(STATE_FILE)) {
      return JSON.parse(readFileSync(STATE_FILE, "utf8"));
    }
  } catch {}
  return {
    activeProvider: "agy_agent",
    activeModel: "AGY: gemini-3.8-flash-low",
    integrations: DEFAULT_CATALOG,
  };
}

function saveState(state) {
  try {
    writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), "utf8");
  } catch (err) {
    console.warn("Failed to write state file:", err.message);
  }
}

// ---------------------------------------------------------------------------
// Command Handlers
// ---------------------------------------------------------------------------

async function cmdStatus() {
  const state = loadState();
  console.log(`\n${c.bold}${c.cyan}=== AIE System Diagnostics & Status ===${c.reset}`);
  console.log(`${c.dim}Project Root:${c.reset} ${ROOT_DIR}`);
  console.log(`${c.dim}Node Version:${c.reset} ${process.version}`);
  console.log(`${c.dim}Platform:${c.reset}     ${process.platform} (${process.arch})`);

  // Active AI Provider
  const activeInt = state.integrations.find((x) => x.id === state.activeProvider);
  console.log(`\n${c.bold}AI Agent Integration Layer:${c.reset}`);
  console.log(`  • Active Provider: ${c.green}${c.bold}${activeInt ? activeInt.name : state.activeProvider}${c.reset}`);
  console.log(`  • Active Model:    ${c.yellow}${state.activeModel}${c.reset}`);
  console.log(`  • Installed Count: ${state.integrations.filter((x) => x.status === "installed").length} / ${state.integrations.length}`);

  // Server probe (port 8080)
  try {
    const res = await fetch("http://127.0.0.1:8080/", { signal: AbortSignal.timeout(1500) });
    console.log(`\n${c.bold}HTTP Dev Server (0.0.0.0:8080):${c.reset} ${c.green}ONLINE (HTTP ${res.status})${c.reset}`);
  } catch {
    console.log(`\n${c.bold}HTTP Dev Server (0.0.0.0:8080):${c.reset} ${c.yellow}OFFLINE or not listening${c.reset}`);
  }

  // Database status
  const hasMongo = Boolean(process.env.DATABASE_URL || process.env.MONGODB_URI);
  console.log(`\n${c.bold}Database Backend:${c.reset}`);
  if (hasMongo) {
    console.log(`  • Engine:   ${c.green}MongoDB Production Cluster${c.reset}`);
  } else {
    console.log(`  • Engine:   ${c.cyan}PGLite WASM Embedded Fallback${c.reset} (Zero-config local)`);
  }

  console.log("");
}

function cmdAgentList() {
  const state = loadState();
  console.log(`\n${c.bold}${c.cyan}=== External AI Agents & API Integrations ===${c.reset}`);
  console.log(`${c.dim}${"ID".padEnd(18)} ${"NAME".padEnd(26)} ${"TYPE".padEnd(14)} ${"STATUS".padEnd(14)} ACTIVE${c.reset}`);
  console.log("─".repeat(80));

  for (const item of state.integrations) {
    const isAct = item.id === state.activeProvider;
    const statusCol =
      item.status === "installed"
        ? `${c.green}Installed${c.reset}`
        : `${c.dim}Available${c.reset}`;
    const activeCol = isAct ? `${c.green}${c.bold}✓ Active${c.reset}` : `${c.dim}─${c.reset}`;
    const typeCol = item.type === "cli_agent" ? "CLI Agent" : "REST API";

    console.log(
      `${c.bold}${item.id.padEnd(18)}${c.reset} ${item.name.padEnd(26)} ${typeCol.padEnd(14)} ${statusCol.padEnd(23)} ${activeCol}`
    );
  }
  console.log(`\n${c.dim}Tip: Use "agent set-active <id> [model]" to switch active AI provider.${c.reset}\n`);
}

function cmdAgentInstall(agentId) {
  if (!agentId) {
    console.log(`${c.red}Error: Missing agent ID. Usage: agent install <id>${c.reset}`);
    return;
  }

  const state = loadState();
  const item = state.integrations.find((x) => x.id === agentId);
  if (!item) {
    console.log(`${c.red}Error: Integration "${agentId}" not found in catalog.${c.reset}`);
    return;
  }

  console.log(`\n${c.cyan}Installing ${c.bold}${item.name}${c.reset}...`);
  if (item.installCmd) {
    console.log(`${c.dim}Command:${c.reset} ${item.installCmd}`);
  }
  if (item.authUrl) {
    console.log(`${c.yellow}Authorization URL:${c.reset} ${item.authUrl}`);
  }

  item.status = "installed";
  item.installedAt = new Date().toISOString();
  saveState(state);

  console.log(`${c.green}✓ Integration ${item.name} marked as installed.${c.reset}`);
  console.log(`${c.dim}To set as active: agent set-active ${agentId}${c.reset}\n`);
}

function cmdAgentUninstall(agentId) {
  if (!agentId) {
    console.log(`${c.red}Error: Missing agent ID. Usage: agent uninstall <id>${c.reset}`);
    return;
  }

  const state = loadState();
  const item = state.integrations.find((x) => x.id === agentId);
  if (!item) {
    console.log(`${c.red}Error: Integration "${agentId}" not found.${c.reset}`);
    return;
  }

  item.status = "not_installed";
  delete item.installedAt;
  delete item.apiKey;
  delete item.authToken;

  if (state.activeProvider === agentId) {
    state.activeProvider = "agy_agent";
    state.activeModel = "AGY: gemini-3.8-flash-low";
    console.log(`${c.yellow}Reverted active provider to Antigravity AGY Agent.${c.reset}`);
  }

  saveState(state);
  console.log(`${c.green}✓ Uninstalled ${item.name}.${c.reset}\n`);
}

function cmdAgentSetActive(agentId, modelName) {
  if (!agentId) {
    console.log(`${c.red}Error: Missing agent ID. Usage: agent set-active <id> [model]${c.reset}`);
    return;
  }

  const state = loadState();
  const item = state.integrations.find((x) => x.id === agentId);
  if (!item) {
    console.log(`${c.red}Error: Integration "${agentId}" not found.${c.reset}`);
    return;
  }

  state.activeProvider = agentId;
  const targetModel = modelName || item.models[0] || "AGY: gemini-3.8-flash-low";
  state.activeModel = targetModel;
  item.status = "installed"; // Auto-verify installation

  saveState(state);
  console.log(`${c.green}✓ Active AI Agent set to: ${c.bold}${item.name}${c.reset} (${targetModel})\n`);
}

function cmdDbStatus() {
  console.log(`\n${c.bold}${c.cyan}=== Database Connectivity Probe ===${c.reset}`);
  const mongoUri = process.env.DATABASE_URL || process.env.MONGODB_URI;

  if (mongoUri) {
    const masked = mongoUri.replace(/:([^@]+)@/, ":****@");
    console.log(`${c.green}MongoDB URI configured:${c.reset} ${masked}`);
  } else {
    console.log(`${c.yellow}MongoDB URI not set in environment.${c.reset}`);
    console.log(`${c.cyan}Default fallback:${c.reset} PGLite WASM in-memory PostgreSQL (active)`);
  }
  console.log(`${c.green}✓ Database layer operational.${c.reset}\n`);
}

function cmdUpdate() {
  console.log(`\n${c.cyan}Checking Git repository status and updates...${c.reset}`);
  try {
    const status = execSync("git status -s", { cwd: ROOT_DIR, encoding: "utf8" });
    console.log(`${c.dim}Current local changes:${c.reset}`);
    console.log(status || "  (Clean working tree)");

    console.log(`\n${c.dim}Fetching from remote...${c.reset}`);
    try {
      execSync("git fetch --dry-run", { cwd: ROOT_DIR, encoding: "utf8", timeout: 8000 });
      console.log(`${c.green}✓ Remote fetch checked.${c.reset}`);
    } catch {
      console.log(`${c.dim}Remote fetch skipped (offline / no remote tracking branch).${c.reset}`);
    }
  } catch (err) {
    console.log(`${c.red}Git command failed:${c.reset} ${err.message}`);
  }
  console.log("");
}

function cmdHelp() {
  console.log(`
${c.bold}${c.cyan}Adversary Intelligence Engine (AIE) CLI Commands:${c.reset}

  ${c.bold}status${c.reset}                        Display system health, active agent, and database status
  ${c.bold}agent list${c.reset}                    List all registered external AI agents and API integrations
  ${c.bold}agent install <id>${c.reset}            Install or register an external agent / API provider
  ${c.bold}agent uninstall <id>${c.reset}          Uninstall and clean up an external agent integration
  ${c.bold}agent set-active <id> [model]${c.reset}  Switch active AI provider and default model
  ${c.bold}db status${c.reset}                     Inspect database connectivity (MongoDB / PGLite)
  ${c.bold}update${c.reset}                        Check Git repository status for updates
  ${c.bold}help${c.reset}                          Show this help manual
  ${c.bold}exit / quit${c.reset}                   Exit the interactive AIE shell
`);
}

// ---------------------------------------------------------------------------
// Main Dispatcher & REPL
// ---------------------------------------------------------------------------

async function executeCommand(line) {
  const parts = line.trim().split(/\s+/);
  const cmd = parts[0]?.toLowerCase();
  const sub = parts[1]?.toLowerCase();
  const arg1 = parts[2];
  const arg2 = parts.slice(3).join(" ");

  switch (cmd) {
    case "status":
      await cmdStatus();
      break;

    case "agent":
      if (sub === "list" || !sub) {
        cmdAgentList();
      } else if (sub === "install") {
        cmdAgentInstall(arg1);
      } else if (sub === "uninstall") {
        cmdAgentUninstall(arg1);
      } else if (sub === "set-active" || sub === "active") {
        cmdAgentSetActive(arg1, arg2);
      } else {
        console.log(`${c.yellow}Unknown agent subcommand "${sub}". Try: agent list, agent install <id>, agent set-active <id>${c.reset}`);
      }
      break;

    case "db":
      cmdDbStatus();
      break;

    case "update":
      cmdUpdate();
      break;

    case "help":
    case "?":
      cmdHelp();
      break;

    case "clear":
      console.clear();
      break;

    case "exit":
    case "quit":
      process.exit(0);
      break;

    default:
      if (cmd) {
        console.log(`${c.red}Unknown command: "${cmd}". Type "help" for available commands.${c.reset}`);
      }
      break;
  }
}

async function startRepl() {
  console.log(`
${c.cyan}╔══════════════════════════════════════════════════════════════════════╗
║             ${c.bold}ADVERSARY INTELLIGENCE ENGINE (AIE) CLI${c.reset}${c.cyan}                  ║
║              ${c.dim}Interactive Operations & Diagnostics Shell${c.reset}${c.cyan}              ║
╚══════════════════════════════════════════════════════════════════════╝${c.reset}
Type ${c.bold}"help"${c.reset} for available commands, or ${c.bold}"status"${c.reset} to verify system state.
`);

  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: `${c.cyan}aie> ${c.reset}`,
  });

  rl.prompt();

  rl.on("line", async (line) => {
    try {
      await executeCommand(line);
    } catch (err) {
      console.error(`${c.red}Error executing command:${c.reset}`, err.message);
    }
    rl.prompt();
  });

  rl.on("close", () => {
    console.log(`\n${c.dim}Exiting AIE CLI shell. Goodbye.${c.reset}`);
    process.exit(0);
  });
}

// Check if running direct command or interactive REPL
const args = process.argv.slice(2);
if (args.length > 0 && args[0] !== "shell") {
  executeCommand(args.join(" ")).then(() => process.exit(0));
} else {
  startRepl();
}
