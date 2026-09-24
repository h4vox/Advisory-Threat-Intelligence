#!/usr/bin/env node

/**
 * Adversary Intelligence Engine (AIE) - Cognitive AI Library Audit Engine
 *
 * Runs genuine cognitive LLM-based audits against threat intelligence resources in
 * MongoDB Atlas using the containerized Antigravity (AGY) agent in `aie-agent-sandbox`.
 *
 * Evaluates candidates against the strict 5-dimensional adversary emulation tradecraft rubric:
 *   1. Procedural Depth (0-30 pts)
 *   2. Attack Progression & Chain Completeness (0-25 pts)
 *   3. Attribution & Threat Context (0-15 pts)
 *   4. Emulation & Detection Utility (0-20 pts)
 *   5. IOC & Telemetry Verifiability (0-10 pts)
 *
 * Usage:
 *   node scripts/cognitive-ai-audit.mjs [--dry-run | --prune] [--limit <n>] [--all] [--model <model>]
 */

import { MongoClient } from "mongodb";
import { spawn, execSync } from "node:child_process";
import dns from "node:dns";
import { writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = join(__dirname, "..");

try {
  if (typeof dns.setDefaultResultOrder === "function") {
    dns.setDefaultResultOrder("ipv4first");
  }
  dns.setServers(["8.8.8.8", "1.1.1.1", "8.8.4.4"]);
} catch {}

const DEFAULT_MONGO_URI =
  process.env.MONGODB_URI ||
  "mongodb://threatintel_app:UsvyDIqA5d5YztAf@ac-0e7499a-shard-00-00.gr9ihel.mongodb.net:27017,ac-0e7499a-shard-00-01.gr9ihel.mongodb.net:27017,ac-0e7499a-shard-00-02.gr9ihel.mongodb.net:27017/threat-intel-DB?ssl=true&replicaSet=atlas-ekdr6v-shard-0&authSource=admin&appName=Cluster0";

const DB_NAME = process.env.MONGODB_DATABASE || "threat-intel-DB";
const COLLECTION_NAME = process.env.MONGODB_COLLECTION || "threat-intel";

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  magenta: "\x1b[35m",
};

// Check if container sandbox is available
function checkSandboxHealth() {
  try {
    const res = execSync("docker inspect -f '{{.State.Running}}' aie-agent-sandbox", {
      encoding: "utf-8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return res === "true";
  } catch {
    return false;
  }
}

function runAgyCli(args, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    let command = "docker";
    let finalArgs = ["exec", "-i", "aie-agent-sandbox", "agy", ...args];

    if (!checkSandboxHealth()) {
      if (existsSync("/home/havox/.local/bin/agy")) {
        command = "/home/havox/.local/bin/agy";
        finalArgs = args;
      } else {
        return reject(new Error("No AGY CLI agent available (aie-agent-sandbox container offline)"));
      }
    }

    let proc = null;
    let stdout = "";
    let stderr = "";

    try {
      proc = spawn(command, finalArgs, {
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (spawnErr) {
      return reject(spawnErr);
    }

    const timer = setTimeout(() => {
      try {
        proc.kill("SIGKILL");
      } catch {}
      reject(new Error(`AGY CLI process timed out after ${Math.round(timeoutMs / 1000)}s`));
    }, timeoutMs);

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf-8");
    });

    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf-8");
    });

    proc.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });

    proc.on("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code });
    });
  });
}

function extractJsonPayload(text) {
  if (!text) throw new Error("Empty response from AGY agent");
  const raw = text.trim();

  // If inside an agy JSON envelope
  try {
    const envelope = JSON.parse(raw);
    if (envelope && typeof envelope === "object") {
      if (envelope.structured_output) return envelope.structured_output;
      if (typeof envelope.response === "string") {
        return extractJsonPayload(envelope.response);
      }
    }
  } catch {
    /* not an envelope, parse directly */
  }

  // Strip markdown code fences if present
  let clean = raw;
  const fenceMatch = raw.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
  if (fenceMatch) {
    clean = fenceMatch[1].trim();
  }

  // Find outermost JSON brackets
  const firstBrace = clean.indexOf("{");
  const firstBracket = clean.indexOf("[");

  let start = -1;
  let end = -1;
  if (firstBracket !== -1 && (firstBrace === -1 || firstBracket < firstBrace)) {
    start = firstBracket;
    end = clean.lastIndexOf("]");
  } else if (firstBrace !== -1) {
    start = firstBrace;
    end = clean.lastIndexOf("}");
  }

  if (start !== -1 && end !== -1 && end > start) {
    clean = clean.slice(start, end + 1);
  }

  return JSON.parse(clean);
}

async function runCognitiveAiAudit() {
  const args = process.argv.slice(2);
  const doPrune = args.includes("--prune");
  const auditAll = args.includes("--all");
  let limit = 10;

  const limitIdx = args.indexOf("--limit");
  if (limitIdx !== -1 && args[limitIdx + 1]) {
    limit = parseInt(args[limitIdx + 1], 10) || 10;
  }

  const modelIdx = args.indexOf("--model");
  const model = modelIdx !== -1 && args[modelIdx + 1] ? args[modelIdx + 1] : "gemini-3.8-flash-low";

  console.log(`\n${c.bold}${c.cyan}================================================================================${c.reset}`);
  console.log(`${c.bold}${c.cyan}     ADVERSARY INTELLIGENCE ENGINE (AIE) - COGNITIVE AI LIBRARY AUDIT           ${c.reset}`);
  console.log(`${c.bold}${c.cyan}================================================================================${c.reset}`);
  console.log(`  • Execution Mode:    ${doPrune ? `${c.red}${c.bold}PRUNE (Delete rejected junk)${c.reset}` : `${c.yellow}DRY-RUN (Flag only)${c.reset}`}`);
  console.log(`  • AI Evaluation:     ${c.green}Containerized AGY Agent (${model})${c.reset}`);
  console.log(`  • Audit Target:      ${auditAll ? "All reports" : "Unverified / Pending reports"}`);
  console.log(`  • AI Batch Limit:    ${limit} documents`);

  const sandboxReady = checkSandboxHealth();
  if (!sandboxReady) {
    console.error(`\n${c.red}Error: Docker container 'aie-agent-sandbox' is not running!${c.reset}`);
    console.error(`Please start it with: ${c.bold}docker compose -f docker-compose.agent-sandbox.yml up -d${c.reset}\n`);
    process.exit(1);
  }
  console.log(`  • Sandbox Status:    ${c.green}Online (aie-agent-sandbox healthy)${c.reset}\n`);

  console.log(`Connecting to MongoDB Atlas (${DB_NAME})...`);
  const client = new MongoClient(DEFAULT_MONGO_URI, { serverSelectionTimeoutMS: 15000 });
  await client.connect();
  const db = client.db(DB_NAME);
  const col = db.collection(COLLECTION_NAME);

  const query = auditAll
    ? { docType: "report" }
    : { docType: "report", aiVerified: { $ne: true }, status: { $ne: "rejected" } };
  const candidateDocs = await col
    .find(query, {
      projection: {
        id: 1,
        title: 1,
        url: 1,
        publisher: 1,
        sourceDomain: 1,
        qualityScore: 1,
        wordCount: 1,
        extractedText: 1,
        iocs: 1,
        analysis: 1,
        status: 1,
        aiVerified: 1,
      },
    })
    .limit(limit)
    .toArray();

  console.log(`Found ${candidateDocs.length} candidates for cognitive AI evaluation.\n`);

  let approvedCount = 0;
  let rejectedCount = 0;
  const auditResults = [];

  for (let i = 0; i < candidateDocs.length; i++) {
    const doc = candidateDocs[i];
    const title = (doc.title || "Untitled").trim();
    const url = doc.url || "";
    const textSnippet = (doc.extractedText || "").slice(0, 4500);

    console.log(`[${i + 1}/${candidateDocs.length}] ${c.bold}${title.slice(0, 70)}${c.reset}`);
    console.log(`    ${c.dim}URL: ${url}${c.reset}`);

    const prompt = `You are the Senior Threat Intelligence Analysis & Adversary Emulation Evaluation Agent operating under the domain-resource-discovery-intel skill.
Analyze the following threat intelligence report snippet and determine whether it contains actionable adversary tradecraft, multi-stage attack chains, or emulation utility using a strict 5-dimensional scoring rubric.

TITLE: ${title}
URL: ${url}
CONTENT SNIPPET:
${textSnippet}

INSTRUCTIONS:
1. Evaluate against the 5-DIMENSIONAL RUBRIC (Total 100 points):
   - Dimension 1: Procedural Depth (0 to 30 pts): Concrete execution commands (PowerShell, cmd, LOLBins, bash), API call sequences, registry keys, process injection, DLL sideloading, or driver tampering.
   - Dimension 2: Attack Progression & Chain Completeness (0 to 25 pts): Multi-stage sequential intrusion flow (Initial Access -> Loader -> Execution -> Lateral Movement -> C2 -> Impact).
   - Dimension 3: Attribution & Threat Context (0 to 15 pts): Identified threat actor (APT, cybercrime syndicate), campaign timeline, targeted sectors, or weaponized CVE references.
   - Dimension 4: Emulation & Detection Utility (0 to 20 pts): Direct utility for purple teams/SOC: Sigma rules, YARA rules, EDR/Sysmon telemetry queries, or Atomic Red Team / Caldera replay commands.
   - Dimension 5: IOC & Telemetry Verifiability (0 to 10 pts): Defanged network indicators (C2 IPs, domains), file hashes (SHA256), Windows Event IDs, Sysmon events.
   - Total Score = sum of the 5 dimensions (0 - 100).
   - recommendApproval: true if Total Score >= 50, false if < 50.

2. Assign Classification: "ADVERSARY_EMULATION", "ADVERSARY_SIMULATION", "ATTACK_CHAIN_REPORT", "INTRUSION_REPORT", "MALWARE_ANALYSIS", "THREAT_ACTOR_REPORT", "CAMPAIGN_REPORT", "VULNERABILITY_REPORT", "DETECTION_RESEARCH", "SECURITY_ADVISORY", or "OTHER".
3. Assign ResourceKind: "FULL_ATTACK_CHAIN", "CAMPAIGN_INTEL", "PROCEDURE_DEEPDIVE", "MALWARE_ANALYSIS", "DETECTION_GUIDANCE", "VULNERABILITY_ADVISORY", or "THREAT_ACTOR_DOSSIER".
4. Extract MITRE ATT&CK technique IDs (e.g., T1059.001, T1055, T1078).
5. Extract named threat actors, malware families, and CVEs.

OUTPUT FORMAT:
Return pure JSON only:
{
  "passScore": 85,
  "recommendApproval": true,
  "classification": "ATTACK_CHAIN_REPORT",
  "resourceKind": "FULL_ATTACK_CHAIN",
  "threatActors": ["Lazarus"],
  "malwareFamilies": ["ComeBackCode"],
  "cves": ["CVE-2024-38193"],
  "mitreTechniques": ["T1059.001", "T1055.012"],
  "scoreBreakdown": {
    "proceduralDepth": 25,
    "attackProgression": 22,
    "attributionContext": 14,
    "emulationUtility": 16,
    "iocVerifiability": 8,
    "totalScore": 85
  },
  "rationale": "High-fidelity intrusion flow with concrete PowerShell commands and DLL sideloading mechanics."
}`;

    const startTime = Date.now();
    let evalOutput = null;
    try {
      const { stdout } = await runAgyCli(
        [
          "--print",
          prompt,
          "--output-format",
          "json",
          "--model",
          model,
          "--dangerously-skip-permissions",
          "--print-timeout",
          "45s",
        ],
        60000
      );
      evalOutput = extractJsonPayload(stdout);
    } catch (err) {
      console.log(`    ${c.yellow}AI Agent query error:${c.reset} ${err.message}`);
    }

    const elapsedMs = Date.now() - startTime;

    if (evalOutput && typeof evalOutput.passScore === "number") {
      const score = evalOutput.passScore;
      const isApproved =
        Boolean(evalOutput.recommendApproval) &&
        score >= 50 &&
        evalOutput.classification !== "OTHER" &&
        evalOutput.classification !== "GENERIC_NEWS";

      const breakdown = evalOutput.scoreBreakdown || {};
      console.log(
        `    ${c.bold}Verdict:${c.reset} ${isApproved ? `${c.green}APPROVED (${score}/100)${c.reset}` : `${c.red}REJECTED (${score}/100)${c.reset}`} [${(elapsedMs / 1000).toFixed(1)}s]`
      );
      console.log(
        `    ${c.dim}Rubric: Procedural ${breakdown.proceduralDepth ?? "?"}/30 | AttackChain ${breakdown.attackProgression ?? "?"}/25 | Attribution ${breakdown.attributionContext ?? "?"}/15 | Emulation ${breakdown.emulationUtility ?? "?"}/20 | IOCs ${breakdown.iocVerifiability ?? "?"}/10${c.reset}`
      );
      console.log(`    ${c.cyan}Kind:${c.reset} ${evalOutput.resourceKind || "CAMPAIGN_INTEL"} | ${c.cyan}Class:${c.reset} ${evalOutput.classification}`);
      if (evalOutput.mitreTechniques?.length) {
        console.log(`    ${c.magenta}MITRE TTPs:${c.reset} ${evalOutput.mitreTechniques.join(", ")}`);
      }
      if (evalOutput.threatActors?.length) {
        console.log(`    ${c.magenta}Actors:${c.reset} ${evalOutput.threatActors.join(", ")}`);
      }
      console.log(`    ${c.dim}Rationale: ${evalOutput.rationale}${c.reset}`);

      auditResults.push({
        id: doc.id,
        title,
        url,
        score,
        isApproved,
        evalOutput,
        elapsedMs,
      });

      if (isApproved) {
        approvedCount++;
        const updatedAnalysis = { ...(doc.analysis || {}) };
        if (evalOutput.threatActors?.length) {
          const s = new Set(updatedAnalysis.threatActors || []);
          evalOutput.threatActors.forEach((a) => s.add(a));
          updatedAnalysis.threatActors = Array.from(s);
        }
        if (evalOutput.mitreTechniques?.length) {
          const s = new Set(updatedAnalysis.techniques || []);
          evalOutput.mitreTechniques.forEach((t) => s.add(t));
          updatedAnalysis.techniques = Array.from(s);
        }

        await col.updateOne(
          { id: doc.id, docType: "report" },
          {
            $set: {
              status: "acquired",
              classification: evalOutput.classification || doc.classification,
              resourceKind: evalOutput.resourceKind || doc.resourceKind,
              aiVerified: true,
              aiQualityScore: score,
              aiAuditReason: `AI Cognitive Approval (${score}/100): ${evalOutput.rationale}`,
              analysis: updatedAnalysis,
              updatedAt: new Date().toISOString(),
            },
          }
        );
        console.log(`    ${c.green}✓ Updated in MongoDB: status=acquired, aiVerified=true${c.reset}\n`);
      } else {
        rejectedCount++;
        if (doPrune) {
          await col.deleteOne({ id: doc.id, docType: "report" });
          console.log(`    ${c.red}✗ Permanently PRUNED from MongoDB${c.reset}\n`);
        } else {
          await col.updateOne(
            { id: doc.id, docType: "report" },
            {
              $set: {
                status: "rejected",
                classification: evalOutput.classification || "OTHER",
                aiVerified: false,
                aiQualityScore: score,
                aiAuditReason: `Rejected by AI Cognitive Gate (${score}/100): ${evalOutput.rationale}`,
                updatedAt: new Date().toISOString(),
              },
            }
          );
          console.log(`    ${c.yellow}⚠ Marked as rejected in MongoDB: status=rejected, aiVerified=false${c.reset}\n`);
        }
      }
    } else {
      console.log(`    ${c.yellow}⚠ AI Agent returned non-JSON or timeout; preserving doc in pending state${c.reset}\n`);
    }
  }

  // Save audit log
  const logFile = join(ROOT_DIR, "docs/cognitive-ai-audit-log.json");
  writeFileSync(
    logFile,
    JSON.stringify(
      {
        auditedAt: new Date().toISOString(),
        model,
        totalAudited: candidateDocs.length,
        approvedCount,
        rejectedCount,
        results: auditResults,
      },
      null,
      2
    ),
    "utf8"
  );

  console.log("--------------------------------------------------------------------------------");
  console.log(`Cognitive AI Audit Run Finished:`);
  console.log(`  • Total Evaluated: ${candidateDocs.length}`);
  console.log(`  • Approved:        ${c.green}${approvedCount}${c.reset}`);
  console.log(`  • Rejected:        ${c.red}${rejectedCount}${c.reset}`);
  console.log(`  • Audit Log:       ${logFile}`);
  console.log("--------------------------------------------------------------------------------\n");

  await client.close();
}

runCognitiveAiAudit().catch((err) => {
  console.error("Cognitive AI audit failed:", err);
  process.exit(1);
});
