import { MongoClient, type Db, type Collection } from "mongodb";

declare global {
  // eslint-disable-next-line no-var
  var __mongoClientPromise: Promise<MongoClient> | undefined;
}

const DEFAULT_DB_NAME = "threat-intel-DB";
const DEFAULT_COLLECTION_NAME = "threat-intel";

export function getMongoUri(): string | undefined {
  return process.env.MONGODB_URI;
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

  const client = new MongoClient(uri, {
    maxPoolSize: 10,
    minPoolSize: 1,
    serverSelectionTimeoutMS: 8000,
    connectTimeoutMS: 10000,
  });

  globalThis.__mongoClientPromise = client.connect().catch((err) => {
    globalThis.__mongoClientPromise = undefined;
    throw err;
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
