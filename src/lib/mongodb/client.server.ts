import { MongoClient, type Db, type Collection } from "mongodb";
import dns from "node:dns";

// Fix Windows / local ISP DNS SRV resolution issues (ECONNREFUSED on _mongodb._tcp)
try {
  dns.setServers(["8.8.8.8", "1.1.1.1", "8.8.4.4"]);
} catch {
  // Ignore in sandboxes where setServers is restricted
}

declare global {
  // eslint-disable-next-line no-var
  var __mongoClientPromise: Promise<MongoClient> | undefined;
}

const DEFAULT_DB_NAME = "threat-intel-DB";
const DEFAULT_COLLECTION_NAME = "threat-intel";

const DEFAULT_MONGO_URI =
  "mongodb+srv://threatintel_app:UsvyDIqA5d5YztAf@cluster0.gr9ihel.mongodb.net/?appName=Cluster0";

export function getMongoUri(): string | undefined {
  return process.env.MONGODB_URI || DEFAULT_MONGO_URI;
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
    return globalThis.__mongoClientPromise;
  }

  const connectWithUri = async (targetUri: string): Promise<MongoClient> => {
    const client = new MongoClient(targetUri, {
      maxPoolSize: 15,
      minPoolSize: 2,
      serverSelectionTimeoutMS: 8000,
      connectTimeoutMS: 10000,
    });
    return client.connect();
  };

  globalThis.__mongoClientPromise = connectWithUri(uri).catch(async (srvErr) => {
    const isDnsSrvError =
      srvErr instanceof Error &&
      (srvErr.message.includes("querySrv") ||
        srvErr.message.includes("ECONNREFUSED") ||
        srvErr.message.includes("ENOTFOUND"));

    const directUri = isDnsSrvError ? getDirectSeedUri(uri) : null;
    if (directUri) {
      console.warn("[mongodb] DNS SRV lookup failed; switching to direct replica-set connection nodes...");
      return connectWithUri(directUri).catch((directErr) => {
        globalThis.__mongoClientPromise = undefined;
        throw directErr;
      });
    }

    globalThis.__mongoClientPromise = undefined;
    throw srvErr;
  });

  return globalThis.__mongoClientPromise;
}

export async function getMongoDb(): Promise<Db> {
  const client = await getMongoClient();
  return client.db(getDatabaseName());
}

export async function getThreatIntelCollection<T extends import("mongodb").Document = import("mongodb").Document>(): Promise<Collection<T>> {
  const db = await getMongoDb();
  return db.collection<T>(getCollectionName());
}
