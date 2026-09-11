import { MongoClient, type Db, type Collection } from "mongodb";
import dns from "node:dns";

// Fix Windows / local ISP DNS and IPv6 NAT64 issues: prefer IPv4 addresses first
try {
  if (typeof dns.setDefaultResultOrder === "function") {
    dns.setDefaultResultOrder("ipv4first");
  }
} catch {
  // Ignore in environments where setDefaultResultOrder is not supported
}

function applyDnsServersFallback() {
  try {
    dns.setServers(["8.8.8.8", "1.1.1.1", "8.8.4.4"]);
  } catch {
    // Ignore in sandboxes where setServers is restricted
  }
}

declare global {
  // eslint-disable-next-line no-var
  var __mongoClientPromise: Promise<MongoClient> | undefined;
}

const DEFAULT_DB_NAME = "threat-intel-DB";
const DEFAULT_COLLECTION_NAME = "threat-intel";

const DEFAULT_MONGO_URI =
  "mongodb://threatintel_app:UsvyDIqA5d5YztAf@ac-0e7499a-shard-00-00.gr9ihel.mongodb.net:27017,ac-0e7499a-shard-00-01.gr9ihel.mongodb.net:27017,ac-0e7499a-shard-00-02.gr9ihel.mongodb.net:27017/threat-intel-DB?ssl=true&replicaSet=atlas-ekdr6v-shard-0&authSource=admin&appName=Cluster0";

export function getMongoUri(): string | undefined {
  const envUri = process.env.MONGODB_URI;
  if (!envUri) return DEFAULT_MONGO_URI;
  if (envUri.includes("cluster0.gr9ihel.mongodb.net")) {
    const direct = getDirectSeedUri(envUri);
    if (direct) return direct;
  }
  return envUri;
}

export function getDatabaseName(): string {
  return process.env.MONGODB_DATABASE || DEFAULT_DB_NAME;
}

export function getCollectionName(): string {
  return process.env.MONGODB_COLLECTION || DEFAULT_COLLECTION_NAME;
}

export function isMongoConfigured(): boolean {
  const uri = getMongoUri();
  return Boolean(uri && uri.startsWith("mongodb"));
}

/**
 * Fallback to direct replica set seed nodes if local network/ISP blocks DNS SRV queries.
 */
function getDirectSeedUri(srvUri: string): string | null {
  try {
    if (!srvUri.includes("cluster0.gr9ihel.mongodb.net")) return null;
    const authMatch = srvUri.match(/mongodb\+srv:\/\/([^@]+)@/);
    if (!authMatch) return null;
    const auth = authMatch[1];
    const db = getDatabaseName();
    return `mongodb://${auth}@ac-0e7499a-shard-00-00.gr9ihel.mongodb.net:27017,ac-0e7499a-shard-00-01.gr9ihel.mongodb.net:27017,ac-0e7499a-shard-00-02.gr9ihel.mongodb.net:27017/${db}?ssl=true&replicaSet=atlas-ekdr6v-shard-0&authSource=admin&appName=Cluster0`;
  } catch {
    return null;
  }
}

export async function getMongoClient(): Promise<MongoClient> {
  const uri = getMongoUri();
  if (!uri) {
    throw new Error(
      "MONGODB_URI is not defined. Please configure MONGODB_URI in .env or your deployment environment variables.",
    );
  }

  if (globalThis.__mongoClientPromise) {
    try {
      const client = await globalThis.__mongoClientPromise;
      return client;
    } catch {
      // Previous promise rejected; clear cache and retry
      globalThis.__mongoClientPromise = undefined;
    }
  }

  const tryConnect = async (targetUri: string): Promise<MongoClient> => {
    const client = new MongoClient(targetUri, {
      maxPoolSize: 25,
      minPoolSize: 2,
      serverSelectionTimeoutMS: 15000,
      connectTimeoutMS: 15000,
      socketTimeoutMS: 45000,
      maxIdleTimeMS: 120000,
      waitQueueTimeoutMS: 15000,
      retryWrites: true,
      retryReads: true,
      tls: true,
      tlsAllowInvalidCertificates: true,
    });
    return await client.connect();
  };

  const connectPromise = (async () => {
    let lastErr: unknown;
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        return await tryConnect(uri);
      } catch (srvErr) {
        lastErr = srvErr;
        const isDnsOrTlsError =
          srvErr instanceof Error &&
          (srvErr.message.includes("querySrv") ||
            srvErr.message.includes("ECONNREFUSED") ||
            srvErr.message.includes("ENOTFOUND") ||
            srvErr.message.includes("tlsv1 alert") ||
            srvErr.message.includes("SSL alert"));

        if (isDnsOrTlsError) {
          applyDnsServersFallback();
        }

        const directUri: string | null = isDnsOrTlsError ? getDirectSeedUri(uri) : null;
        if (directUri && directUri !== uri) {
          console.warn("[mongodb] SRV connection failed; attempting direct replica-set seed nodes...");
          try {
            return await tryConnect(directUri);
          } catch (directErr) {
            lastErr = directErr;
          }
        }

        if (attempt < 2) {
          console.warn(
            `[mongodb] Connection attempt ${attempt} failed, retrying in 1s...`,
            srvErr instanceof Error ? srvErr.message : srvErr,
          );
          await new Promise((r) => setTimeout(r, 1000));
        }
      }
    }
    throw lastErr;
  })();

  globalThis.__mongoClientPromise = connectPromise;

  try {
    return await connectPromise;
  } catch (err) {
    globalThis.__mongoClientPromise = undefined;
    throw err;
  }
}

export async function getMongoDb(): Promise<Db> {
  const client = await getMongoClient();
  return client.db(getDatabaseName());
}

export async function getThreatIntelCollection<T extends import("mongodb").Document = import("mongodb").Document>(): Promise<Collection<T>> {
  const db = await getMongoDb();
  return db.collection<T>(getCollectionName());
}
