import { MongoClient, type Db, type Collection } from "mongodb";
import dns from "node:dns";
import { isSrvLookupError, isSrvUri, resolveSeedListUri } from "./srv-fallback";

// Fix Windows / local ISP DNS and IPv6 NAT64 issues: prefer IPv4 addresses first
try {
  if (typeof dns.setDefaultResultOrder === "function") {
    dns.setDefaultResultOrder("ipv4first");
  }
} catch {
  // Ignore in environments where setDefaultResultOrder is not supported
}

declare global {
  // eslint-disable-next-line no-var
  var __mongoClientPromise: Promise<MongoClient> | undefined;
  /** Seed list found through public DNS for a mongodb+srv URI the local resolver could not look up. */
  var __mongoSeedList: { srv: string; seed: string } | undefined;
}

const DEFAULT_DB_NAME = "threat-intel-DB";
const DEFAULT_COLLECTION_NAME = "threat-intel";

const MISSING_URI_MESSAGE =
  "MONGODB_URI is not set. Add it to the server environment (or a .env file next to package.json) and restart; no built-in database credentials are provided.";

/**
 * The database connection comes only from the environment: MONGODB_URI (a `mongodb://` or
 * `mongodb+srv://` URI). There is no built-in default. In production a missing or placeholder value
 * stops the app with a clear message (fail closed); in development it falls back to the built-in
 * local database. MONGODB_URI=local (off / none) chooses that local database explicitly.
 */
export function getMongoUri(): string | undefined {
  // Heal a pasted "MONGODB_URI=MONGODB_URI=mongodb+srv://..." double prefix before validating.
  const raw = process.env.MONGODB_URI?.replace(/^(?:\s*MONGODB_URI\s*=\s*)+/i, "").trim();
  // Explicit opt-out keeps the built-in local database (offline / isolated development).
  if (raw && /^(?:local|off|none|disabled?)$/i.test(raw)) return undefined;
  const usable = Boolean(raw) && !(raw!.includes("<") && raw!.includes(">")) && !raw!.includes("NEW_PASSWORD") && /^mongodb(?:\+srv)?:\/\//i.test(raw!);
  if (usable) return raw;
  if (process.env.NODE_ENV === "production") throw new Error(MISSING_URI_MESSAGE);
  return undefined;
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
 * AIE is a shared, global product: one MongoDB is the mandatory home for the whole library, sources,
 * accounts and crawl history. In production that database MUST be configured — without it every
 * visitor would fall back to a private, empty, in-memory store and nothing would be saved or shared.
 * Locally (`npm run dev`) MongoDB stays optional so the app runs out of the box. The URI itself is
 * never committed; it is supplied once through the deploy environment (see .env.example).
 */
export function isMongoRequired(): boolean {
  return process.env.NODE_ENV === "production";
}

/** True when the shared database is mandatory here but has not been configured — a hard deploy error. */
export function isMongoMissingButRequired(): boolean {
  try {
    return isMongoRequired() && !isMongoConfigured();
  } catch {
    return true;
  }
}

export async function getMongoClient(): Promise<MongoClient> {
  const uri = getMongoUri();
  if (!uri) {
    throw new Error(MISSING_URI_MESSAGE);
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
      maxPoolSize: 50,
      minPoolSize: 5,
      serverSelectionTimeoutMS: 15000,
      connectTimeoutMS: 15000,
      socketTimeoutMS: 45000,
      maxIdleTimeMS: 120000,
      waitQueueTimeoutMS: 30000,
      retryWrites: true,
      retryReads: true,
    });
    return await client.connect();
  };

  const connectPromise = (async () => {
    let lastErr: unknown;
    for (let attempt = 1; attempt <= 2; attempt++) {
      const known = globalThis.__mongoSeedList?.srv === uri ? globalThis.__mongoSeedList.seed : undefined;
      try {
        return await tryConnect(known ?? uri);
      } catch (err) {
        lastErr = err;
        // Some ISP / corporate / VPN resolvers refuse the SRV lookup a mongodb+srv URI needs.
        // Ask public DNS for the cluster's host list instead (see ./srv-fallback).
        if (!known && isSrvUri(uri) && isSrvLookupError(err)) {
          try {
            const seed = await resolveSeedListUri(uri);
            if (seed) {
              const client = await tryConnect(seed);
              globalThis.__mongoSeedList = { srv: uri, seed };
              console.warn("[mongodb] This network's DNS refused the cluster's SRV lookup; connected using the host list from public DNS instead.");
              return client;
            }
          } catch (fallbackErr) {
            lastErr = fallbackErr;
            console.warn("[mongodb] Public-DNS fallback failed:", fallbackErr instanceof Error ? fallbackErr.message : fallbackErr);
          }
        }
        if (attempt < 2) {
          console.warn(
            `[mongodb] Connection attempt ${attempt} failed, retrying in 1s...`,
            err instanceof Error ? err.message : err,
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
