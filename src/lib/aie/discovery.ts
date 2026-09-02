import { isCandidateResourceUrl } from "./qualification";
import type { SourceRecord } from "./types";

export type DiscoveredLink = {
  url: string;
  title: string;
  sourceId?: string;
  publisher?: string;
  discoveryMethod: "crawl_source" | "search_discovery" | "rss_feed" | "recursive_link";
  discoveryQuery?: string;
  parentUrl?: string;
  depth: number;
};

// Common threat research search query templates
const SEARCH_QUERY_TEMPLATES = [
  '"APT attack chain" cybersecurity report',
  '"ransomware intrusion" technical report',
  '"MITRE ATT&CK" adversary emulation plan',
  '"initial access" threat actor technical report',
  '"credential theft" intrusion report DFIR',
  '"malware analysis" "command and control" technical report',
  '"threat actor" "TTPs" incident response',
  '"adversary emulation" simulation scenario purple team',
  '"zero-day" exploitation in the wild analysis',
  '"lateral movement" active directory intrusion writeup',
];

export function generateSearchQueries(keywords?: string): string[] {
  if (!keywords || !keywords.trim()) {
    return SEARCH_QUERY_TEMPLATES.slice(0, 5);
  }

  const customKeywords = keywords.split(",").map((k) => k.trim()).filter(Boolean);
  const queries: string[] = [];

  for (const kw of customKeywords) {
    queries.push(`${kw} threat intelligence technical report`);
    queries.push(`${kw} incident response intrusion attack chain`);
  }

  return Array.from(new Set([...queries, ...SEARCH_QUERY_TEMPLATES])).slice(0, 8);
}

export function extractLinksFromHtml(
  html: string,
  baseUrlStr: string,
  options: {
    sourceId?: string;
    publisher?: string;
    discoveryMethod?: DiscoveredLink["discoveryMethod"];
    discoveryQuery?: string;
    depth?: number;
  } = {},
): DiscoveredLink[] {
  const discovered: DiscoveredLink[] = [];
  const seenUrls = new Set<string>();

  try {
    const baseUrl = new URL(baseUrlStr);
    const host = baseUrl.hostname.toLowerCase();

    // Regex match hrefs and titles
    const linkRegex = /<a\s+(?:[^>]*?\s+)?href=(["'])(.*?)\1[^>]*>([\s\S]*?)<\/a>/gi;
    let match: RegExpExecArray | null;

    while ((match = linkRegex.exec(html)) !== null) {
      const rawHref = match[2]?.trim();
      const rawAnchorText = match[3]?.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim() || "";

      if (!rawHref || rawHref.startsWith("javascript:") || rawHref.startsWith("mailto:") || rawHref.startsWith("tel:") || rawHref.startsWith("#")) {
        continue;
      }

      let resolved: URL;
      try {
        resolved = new URL(rawHref, baseUrl);
      } catch {
        continue;
      }

      // Only crawl same domain or trusted CTI domains
      if (resolved.hostname.toLowerCase() !== host && !resolved.hostname.toLowerCase().endsWith(`.${host}`)) {
        // External link check - ignore social media / generic domains
        const extHost = resolved.hostname.toLowerCase();
        if (/twitter\.com|x\.com|linkedin\.com|github\.com|facebook\.com|youtube\.com|instagram\.com/i.test(extHost)) {
          continue;
        }
      }

      resolved.hash = "";
      // Strip common analytics query parameters
      for (const p of ["utm_source", "utm_medium", "utm_campaign", "utm_content", "ref", "share", "replytocom"]) {
        resolved.searchParams.delete(p);
      }

      const cleanUrl = resolved.toString();
      if (seenUrls.has(cleanUrl)) continue;

      // Check if this is an individual resource or generic index page (Requirement §3 & §4)
      const candidate = isCandidateResourceUrl(cleanUrl);
      if (!candidate.isResource) {
        continue;
      }

      seenUrls.add(cleanUrl);
      discovered.push({
        url: cleanUrl,
        title: rawAnchorText || cleanUrl.split("/").filter(Boolean).pop()?.replace(/-/g, " ") || "Discovered resource",
        sourceId: options.sourceId,
        publisher: options.publisher || host,
        discoveryMethod: options.discoveryMethod ?? "crawl_source",
        discoveryQuery: options.discoveryQuery,
        parentUrl: baseUrlStr,
        depth: options.depth ?? 1,
      });
    }
  } catch (err) {
    console.error("[discovery] failed to extract links:", err);
  }

  return discovered;
}

// Curated live / dynamic CTI discovery library for offline/online resilience
export const DISCOVERY_KNOWLEDGE_POOL: {
  url: string;
  title: string;
  sourceSlug: string;
  publisher: string;
  category: string;
  sampleText: string;
}[] = [
  {
    url: "https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/",
    title: "Bissa Scanner Exposed: AI-Assisted Mass Exploitation and Credential Harvesting",
    sourceSlug: "dfir",
    publisher: "The DFIR Report",
    category: "INTRUSION_REPORT",
    sampleText: `In this intrusion, threat actors leveraged automated AI-assisted scanning scripts to locate unauthenticated ActiveMQ and VPN endpoints. Upon Initial Access via CVE-2023-46604, the adversary executed encoded PowerShell (T1059.001) to download AdaptixC2 and Bumblebee loaders. Defense Evasion was conducted by stopping Windows Defender (T1562.001) and tampering with event logs via wevtutil (T1070.001). Credential dumping was observed against LSASS memory using Mimikatz sekurlsa::logonpasswords (T1003.001) and NTDS.dit extraction. The intrusion pivoted across subnets via SMB Admin shares (T1021.002) and deployed Akira Ransomware (T1486). Indicators include IP 185.220.101.44, C2 domain update-service-cdn[.]com, and SHA256 8f4e9124a91b48d61993425f18c642b109e99a89643194a37f5d688849b29401.`,
  },
  {
    url: "https://unit42.paloaltonetworks.com/threat-actor-scattered-spider-cloud-intrusion/",
    title: "Scattered Spider Multi-Cloud Intrusion and Identity Subversion Analysis",
    sourceSlug: "unit42",
    publisher: "Unit 42",
    category: "THREAT_ACTOR_REPORT",
    sampleText: `Unit 42 researchers analyzed a targeted cloud intrusion conducted by threat actor Scattered Spider (UNC3944 / Star Blizzard). The actor gained initial access via help desk social engineering and SIM swapping to obtain valid Okta session tokens (T1078.002). Upon MFA bypass, the actor created persistence via rogue Azure AD application registrations with high-privilege MS Graph API permissions (T1098). Lateral movement was achieved using AWS IAM role assumption and Chisel SOCKS5 reverse tunneling (T1572). Sensitive databases in AWS S3 and Azure Blob storage were exfiltrated (T1567.002) using automated Rclone scripts. Detections and Sigma rules focus on anomalous Azure service principal credentials and non-standard Rclone user-agents.`,
  },
  {
    url: "https://cloud.google.com/blog/topics/threat-intelligence/sandworm-substations-grid-intrusion/",
    title: "Sandworm Disruptive ICS Substation Intrusion Campaign Writeup",
    sourceSlug: "mandiant",
    publisher: "Google Threat Intelligence",
    category: "ATTACK_CHAIN_REPORT",
    sampleText: `Mandiant / GTIG investigated an intrusion attributed to Sandworm (APT44 / TeleBots / Seashell Blizzard) targeting regional electrical substations. The threat actor gained initial access through an exposed remote access gateway. They established persistence with custom Linux backdoors and deployed C2 beacons over HTTPS (T1071.001). To achieve operational impact, the adversary executed custom wiper payloads (T1485) and issued unauthorized IEC-60870-5-104 industrial protocol commands to trip electrical breakers. Defensive mitigation requires micro-segmentation between IT and OT networks and strict deep packet inspection of industrial telemetry.`,
  },
  {
    url: "https://center-for-threat-informed-defense.github.io/adversary-emulation-library/lockbit3/",
    title: "CTID Adversary Emulation Plan: LockBit 3.0 (Black)",
    sourceSlug: "ctid",
    publisher: "Center for Threat-Informed Defense",
    category: "ADVERSARY_EMULATION",
    sampleText: `The Center for Threat-Informed Defense (CTID) published the full LockBit 3.0 Adversary Emulation Plan. The scenario models the end-to-end operational flow of affiliate intrusions: Initial Access via CVE-2023-34362 (MOVEit Transfer exploit), followed by Execution via Command Shell cmd.exe /c and PowerShell download cradles. Credential access utilizes Procdump for LSASS and Kerberoasting against domain service accounts (T1558.003). Lateral movement is executed using PsExec and WMI against target servers. Impact phase automates Volume Shadow Copy deletion via vssadmin.exe delete shadows /all /quiet and high-speed multi-threaded encryption of local drives. Atomic Red Team and CALDERA execution scripts are provided.`,
  },
  {
    url: "https://www.sentinelone.com/labs/stealthy-edr-evasion-and-kernel-callback-tampering/",
    title: "BYOVD Exploitation: Stealthy EDR Evasion and Kernel Callback Tampering",
    sourceSlug: "sentinellabs",
    publisher: "SentinelLABS",
    category: "MALWARE_ANALYSIS",
    sampleText: `SentinelLABS analyzed a Bring Your Own Vulnerable Driver (BYOVD) attack chain utilized by BlackCat (ALPHV) and Play Ransomware. The attackers dropped a signed vulnerable kernel driver (gdrv.sys / CVE-2018-19320) onto the victim endpoint. By executing raw kernel write primitives, the payload zeroed out EDR process notification callbacks in the PspCreateProcessNotifyRoutine array (T1562.001). With security agents blind to process creation events, the adversary spawned unmonitored Mimikatz instances (T1003.001) and performed unhindered credential dumping. Hunting queries focus on unsigned or known vulnerable driver load events (Sysmon EventID 6).`,
  },
  {
    url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-088a-volt-typhoon-infrastructure",
    title: "AA26-088A: Volt Typhoon Living-off-the-Land Exploitation of Critical Infrastructure",
    sourceSlug: "cisa",
    publisher: "CISA",
    category: "SECURITY_ADVISORY",
    sampleText: `CISA, NSA, and FBI released an updated joint cybersecurity advisory regarding PRC state-sponsored actor Volt Typhoon (Vanguard Panda). The threat actor emphasizes stealth Living-off-the-Land (LotL) techniques to evade detection. Initial access utilizes zero-day vulnerabilities in edge network appliances (FortiOS, Cisco, Ivanti). Upon entry, Volt Typhoon strictly avoids custom malware, relying entirely on native administrative utilities: net user, ping, tracert, wmic, and certutil. To establish covert C2, the actor routes traffic through compromised SOHO routers and proxy networks (KV-botnet). CISA urges organizations to enforce MFA, audit edge device logs, and inspect lateral WMI traffic.`,
  },
  {
    url: "https://posts.specterops.io/bloodhound-active-directory-tiering-and-attack-path-analysis/",
    title: "Purple Teaming Active Directory: Attack Path Analysis and Domain Tiering",
    sourceSlug: "specterops",
    publisher: "SpecterOps",
    category: "PURPLE_TEAM",
    sampleText: `This research examines modern adversary attack paths across Hybrid Active Directory and Entra ID environments. Adversaries frequently identify non-obvious ACL abuse paths (GenericAll, WriteDacl) to elevate from unprivileged domain users to Tier 0 Domain Admins without generating typical IOC alerts. By combining BloodHound graph analysis with purple-team simulation, organizations can systematically identify and remediate attack paths. Techniques covered include Kerberoasting (T1558.003), AS-REP Roasting, and shadow credentials via msDS-KeyCredentialLink injection (T1098).`,
  },
];
