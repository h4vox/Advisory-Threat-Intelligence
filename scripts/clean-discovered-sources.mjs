import { MongoClient } from "mongodb";
import { SOURCE_SEED } from "../src/lib/aie/catalog.ts";

const MONGO_URI =
  "mongodb://threatintel_app:UsvyDIqA5d5YztAf@ac-0e7499a-shard-00-00.gr9ihel.mongodb.net:27017,ac-0e7499a-shard-00-01.gr9ihel.mongodb.net:27017,ac-0e7499a-shard-00-02.gr9ihel.mongodb.net:27017/threat-intel-DB?ssl=true&replicaSet=atlas-ekdr6v-shard-0&authSource=admin&appName=Cluster0";

// Curated domains to purge from discovered_source
const CURATED_DOMAINS = new Set();
for (const s of SOURCE_SEED) {
  try {
    const u = new URL(s.homepageUrl);
    CURATED_DOMAINS.add(u.hostname.toLowerCase().replace(/^www\./, ""));
  } catch {}
}
// Add variations
[
  "paloaltonetworks.com",
  "unit42.paloaltonetworks.com",
  "talosintelligence.com",
  "blog.talosintelligence.com",
  "ahnlab.com",
  "asec.ahnlab.com",
  "jp.ahnlab.com",
  "checkpoint.com",
  "research.checkpoint.com",
  "sophos.com",
  "news.sophos.com",
  "sekoia.io",
  "blog.sekoia.io",
  "welivesecurity.com",
  "eset.com",
  "redcanary.com",
  "sentinelone.com",
  "huntress.com",
  "cisa.gov",
  "bleepingcomputer.com",
  "trendmicro.com",
  "microsoft.com",
  "cloud.google.com",
  "mandiant.com",
  "sans.edu",
  "isc.sans.edu",
  "rapid7.com",
  "specterops.io",
  "posts.specterops.io",
  "attackiq.com",
  "center-for-threat-informed-defense.github.io",
  "elastic.co"
].forEach(d => CURATED_DOMAINS.add(d.toLowerCase()));

// Noisy non-CTI domains to remove
const NOISY_DOMAINS = new Set([
  "mastodon.social",
  "commerce.gov",
  "infosec.exchange",
  "war.gov",
  "edit.dhs.gov",
  "security.com"
]);

// Verified external sources from Library reports with proper endpoint patterns
const VERIFIED_LIBRARY_SOURCES = [
  {
    domain: "securelist.com",
    name: "Securelist (Kaspersky GReAT)",
    homepageUrl: "https://securelist.com",
    crawlPattern: "https://securelist.com/*",
    whyCrawl: "Advanced persistent threat (APT) research, multi-stage loader reverse engineering, and in-depth TTP telemetry.",
    notes: "Active reports in Library: Mysterious Elephant APT TTPs and tools.",
    trustScore: 0.96,
    status: "verified",
    origin: "agent_discovery"
  },
  {
    domain: "krebsonsecurity.com",
    name: "Krebs on Security",
    homepageUrl: "https://krebsonsecurity.com",
    crawlPattern: "https://krebsonsecurity.com/*",
    whyCrawl: "Investigative cybercrime journalism, botnet operator tracking, and operational infrastructure breakdowns.",
    notes: "Active reports in Library: Kimwolf Botnet intrusion reports.",
    trustScore: 0.94,
    status: "verified",
    origin: "agent_discovery"
  },
  {
    domain: "zerotracelab.com",
    name: "ZeroTrace Lab",
    homepageUrl: "https://zerotracelab.com",
    crawlPattern: "https://zerotracelab.com/blog/*",
    whyCrawl: "Red-team offensive operations, DLL sideloading tradecraft, and command-and-control evasion procedures.",
    notes: "Active reports in Library: Chrome Remote Desktop Red Ops & DLL Sideloading.",
    trustScore: 0.95,
    status: "verified",
    origin: "agent_discovery"
  },
  {
    domain: "media.defense.gov",
    name: "NSA / CISA Defense Publications",
    homepageUrl: "https://media.defense.gov",
    crawlPattern: "https://media.defense.gov/*",
    whyCrawl: "Authoritative Joint Cybersecurity Advisories, Living off the Land (LotL) tradecraft, and nation-state defense guidance.",
    notes: "Active reports in Library: CSA Living off the Land advisory PDF.",
    trustScore: 0.99,
    status: "verified",
    origin: "agent_discovery"
  },
  {
    domain: "attack.mitre.org",
    name: "MITRE ATT&CK Framework",
    homepageUrl: "https://attack.mitre.org",
    crawlPattern: "https://attack.mitre.org/techniques/*",
    whyCrawl: "Global knowledge base of adversary tactics, techniques, and sub-techniques based on real-world observations.",
    notes: "Active reports in Library: T1608, T1566, T1204 technique references.",
    trustScore: 0.99,
    status: "verified",
    origin: "crawler_outlink"
  },
  {
    domain: "ncsc.gov.uk",
    name: "UK National Cyber Security Centre (NCSC)",
    homepageUrl: "https://www.ncsc.gov.uk",
    crawlPattern: "https://www.ncsc.gov.uk/blogs/*, https://www.ncsc.gov.uk/advisories/*",
    whyCrawl: "Official UK government CTI advisories, vulnerability alerts, and malware campaign guidance.",
    notes: "Active reports in Library: Vulnerability patch wave advisory.",
    trustScore: 0.97,
    status: "verified",
    origin: "agent_discovery"
  },
  {
    domain: "justice.gov",
    name: "US Department of Justice Cyber Operations",
    homepageUrl: "https://www.justice.gov",
    crawlPattern: "https://www.justice.gov/opa/pr/*",
    whyCrawl: "State-sponsored cyber disruption indictments, actor attributions, and C2 infrastructure takedowns.",
    notes: "Active reports in Library: Iranian Cyber Disruption operations.",
    trustScore: 0.96,
    status: "verified",
    origin: "crawler_outlink"
  },
  {
    domain: "github.com",
    name: "GitHub Threat Intelligence & PoC Repositories",
    homepageUrl: "https://github.com",
    crawlPattern: "https://github.com/*",
    whyCrawl: "Open-source offensive tools, exploit proof-of-concepts, and sigma/yara detection rules.",
    notes: "Active reports in Library: Open-source threat intelligence references.",
    trustScore: 0.92,
    status: "verified",
    origin: "crawler_outlink"
  }
];

async function main() {
  console.log("Connecting to MongoDB Atlas...");
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  const db = client.db("threat-intel-DB");
  const col = db.collection("threat-intel");

  // 1. Delete curated and noisy domains from discovered_source
  const domainsToDelete = [...CURATED_DOMAINS, ...NOISY_DOMAINS];
  const deleteRes = await col.deleteMany({
    docType: "discovered_source",
    domain: { $in: domainsToDelete }
  });
  console.log(`Deleted ${deleteRes.deletedCount} discovered_source docs matching curated/noisy domains.`);

  // 2. Count actual reports in Library per domain
  const reportCounts = await col.aggregate([
    { $match: { docType: "report" } },
    { $group: { _id: "$sourceDomain", count: { $sum: 1 } } }
  ]).toArray();

  const domainCountMap = new Map();
  for (const r of reportCounts) {
    if (r._id) domainCountMap.set(r._id.toLowerCase(), r.count);
  }

  // 3. Upsert verified library sources with accurate report counts
  for (const src of VERIFIED_LIBRARY_SOURCES) {
    const count = domainCountMap.get(src.domain) || 1;
    const docId = `src_disc_${src.domain.replace(/[^a-z0-9]/gi, "_")}`;
    await col.updateOne(
      { docType: "discovered_source", domain: src.domain },
      {
        $set: {
          docType: "discovered_source",
          id: docId,
          domain: src.domain,
          name: src.name,
          homepageUrl: src.homepageUrl,
          crawlPattern: src.crawlPattern,
          whyCrawl: src.whyCrawl,
          notes: src.notes,
          trustScore: src.trustScore,
          status: src.status,
          origin: src.origin,
          enabled: true,
          resourceCount: count,
          lastSeenAt: new Date().toISOString()
        },
        $setOnInsert: {
          firstDiscoveredAt: new Date().toISOString()
        }
      },
      { upsert: true }
    );
    console.log(`✓ Upserted verified source: ${src.domain} (${count} reports in Library)`);
  }

  // 4. Print remaining discovered sources
  const remaining = await col.find({ docType: "discovered_source" }).toArray();
  console.log(`\nRemaining discovered sources count: ${remaining.length}`);
  for (const r of remaining) {
    console.log(`- ${r.domain}: ${r.name} | count: ${r.resourceCount} | status: ${r.status} | pattern: ${r.crawlPattern}`);
  }

  await client.close();
}

main().catch(console.error);
