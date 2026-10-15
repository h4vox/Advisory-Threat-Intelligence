import { MongoClient } from "mongodb";

const MONGO_URI = process.env.MONGODB_URI;
if (!MONGO_URI) {
  console.error("MONGODB_URI is not set. Export it in your environment (see .env.example); no built-in credentials are provided.");
  process.exit(1);
}

async function main() {
  console.log("Connecting to MongoDB Atlas...");
  const client = new MongoClient(MONGO_URI, { connectTimeoutMS: 15000 });
  await client.connect();
  console.log("Connected!");
  const db = client.db("threat-intel-DB");
  const col = db.collection("threat-intel");

  const totalReports = await col.countDocuments({ docType: "report" });
  console.log("Total reports in DB:", totalReports);

  const reportAgg = await col.aggregate([
    { $match: { docType: "report" } },
    {
      $group: {
        _id: { sourceId: "$sourceId", sourceDomain: "$sourceDomain" },
        count: { $sum: 1 },
        sampleUrl: { $first: "$canonicalUrl" },
        sampleTitle: { $first: "$title" }
      }
    },
    { $sort: { count: -1 } }
  ]).toArray();

  console.log("\nReports grouped by sourceId & sourceDomain:");
  for (const r of reportAgg) {
    console.log(`- sourceId: ${r._id.sourceId} | domain: ${r._id.sourceDomain} | count: ${r.count} | sample: ${r.sampleUrl}`);
  }

  const discoveredDocs = await col.find({ docType: "discovered_source" }).toArray();
  console.log(`\nDiscovered sources count in DB: ${discoveredDocs.length}`);
  for (const d of discoveredDocs) {
    console.log(`- id: ${d.id} | domain: ${d.domain} | name: ${d.name} | status: ${d.status} | pattern: ${d.crawlPattern || d.base_url || 'NONE'}`);
  }

  await client.close();
}

main().catch(console.error);
