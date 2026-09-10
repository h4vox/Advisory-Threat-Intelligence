import { MongoClient } from "mongodb";
import dns from "node:dns";

if (typeof dns.setDefaultResultOrder === "function") {
  dns.setDefaultResultOrder("ipv4first");
}
try {
  dns.setServers(["8.8.8.8", "1.1.1.1", "8.8.4.4"]);
} catch {}

const MONGO_URI =
  "mongodb://threatintel_app:UsvyDIqA5d5YztAf@ac-0e7499a-shard-00-00.gr9ihel.mongodb.net:27017,ac-0e7499a-shard-00-01.gr9ihel.mongodb.net:27017,ac-0e7499a-shard-00-02.gr9ihel.mongodb.net:27017/threat-intel-DB?ssl=true&replicaSet=atlas-ekdr6v-shard-0&authSource=admin&appName=Cluster0";

const SOURCE_PATTERNS = {
  src_dfir: "https://thedfirreport.com/reports/*, https://thedfirreport.com/20*/*",
  src_unit42: "https://unit42.paloaltonetworks.com/*",
  src_sentinel: "https://www.sentinelone.com/labs/*",
  src_huntress: "https://www.huntress.com/blog/*",
  src_mandiant: "https://cloud.google.com/blog/topics/threat-intelligence/*",
  src_msft: "https://www.microsoft.com/en-us/security/blog/*",
  src_talos: "https://blog.talosintelligence.com/*",
  src_cisa: "https://www.cisa.gov/news-events/cybersecurity-advisories/*",
  src_mitre: "https://medium.com/mitre-attack/*",
  src_specterops: "https://posts.specterops.io/*",
  src_redcanary: "https://redcanary.com/blog/threat-research/*, https://redcanary.com/blog/*",
  src_bleeping: "https://www.bleepingcomputer.com/news/security/*",
  src_trendmicro: "https://www.trendmicro.com/en_us/research/*",
  src_ahnlab: "https://asec.ahnlab.com/en/*",
  src_checkpoint: "https://research.checkpoint.com/*",
  src_sans: "https://isc.sans.edu/*",
  src_sophos: "https://news.sophos.com/en-us/category/threat-research/*",
  src_sekoia: "https://blog.sekoia.io/*",
  src_eset: "https://www.welivesecurity.com/en/*",
  src_rapid7: "https://www.rapid7.com/blog/*",
};

async function main() {
  console.log("Connecting to MongoDB Atlas...");
  const client = new MongoClient(MONGO_URI, {
    connectTimeoutMS: 10000,
    serverSelectionTimeoutMS: 10000,
  });
  await client.connect();
  const db = client.db("threat-intel-DB");
  const col = db.collection("threat-intel");

  console.log("Updating Curated Sources crawl patterns...");
  for (const [id, pattern] of Object.entries(SOURCE_PATTERNS)) {
    const res = await col.updateMany(
      { docType: "source", id },
      { $set: { crawlPattern: pattern } }
    );
    console.log(`- ${id}: matched ${res.matchedCount}, modified ${res.modifiedCount}`);
  }

  console.log("Updating Discovered Sources missing crawlPattern...");
  const discoveredDocs = await col.find({ docType: "discovered_source" }).toArray();
  for (const doc of discoveredDocs) {
    if (!doc.crawlPattern) {
      const pattern = doc.homepageUrl && doc.homepageUrl.length > 8
        ? `${doc.homepageUrl.replace(/\/+$/, "")}/*`
        : `https://${doc.domain}/*`;
      await col.updateOne(
        { _id: doc._id },
        { $set: { crawlPattern: pattern } }
      );
      console.log(`- Discovered ${doc.domain}: set pattern to ${pattern}`);
    }
  }

  console.log("Done!");
  await client.close();
}

main().catch(console.error);
