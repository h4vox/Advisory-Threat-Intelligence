/**
 * Connect to a `mongodb+srv://` cluster on networks whose DNS refuses SRV lookups.
 *
 * A `mongodb+srv://` connection string only names the cluster; the driver finds its servers with an
 * SRV lookup (and reads `authSource` / `replicaSet` from a TXT record). Some ISP, corporate and VPN
 * resolvers (and Node on some Windows setups) refuse SRV queries, which fails with
 * `querySrv ECONNREFUSED _mongodb._tcp.<cluster>`. When that happens we ask public resolvers for
 * the same records and connect with the equivalent `mongodb://` seed list — exactly what the driver
 * would have built. Nothing is hard-coded: hosts, ports and options all come from DNS and the
 * configured connection string.
 *
 * The parsing and URI building are pure and unit-tested; `resolveSeedListUri` does the lookups.
 */
import { Resolver } from "node:dns/promises";

export type SrvRecord = { name: string; port: number };

export const PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];

/** Options a cluster's TXT record may set (per the driver's SRV specification). */
const TXT_OPTIONS = new Set(["authSource", "replicaSet", "loadBalanced"]);

export function isSrvUri(uri: string): boolean {
  return uri.trim().toLowerCase().startsWith("mongodb+srv://");
}

/** True for failures of the SRV / TXT lookup the driver makes before connecting to a mongodb+srv cluster. */
export function isSrvLookupError(err: unknown): boolean {
  const e = err as { message?: unknown; code?: unknown; syscall?: unknown; hostname?: unknown } | null;
  const text = [e?.message, e?.code, e?.syscall, e?.hostname].filter((v) => typeof v === "string").join(" ");
  if (/\bquery(Srv|Txt)\b/i.test(text)) return true;
  return /_mongodb\._tcp\./i.test(text) && /\b(ECONNREFUSED|ETIMEOUT|ENOTFOUND|ESERVFAIL|EREFUSED|ENODATA)\b/.test(text);
}

export type ParsedSrvUri = { userinfo: string; host: string; path: string; params: URLSearchParams };

/** Splits a mongodb+srv URI. Credentials stay exactly as written (percent-encoded). */
export function parseSrvUri(uri: string): ParsedSrvUri | null {
  const m = /^mongodb\+srv:\/\/(?:([^@/?#]*)@)?([^/?#]+)(\/[^?#]*)?(?:\?([^#]*))?$/i.exec(uri.trim());
  if (!m) return null;
  const host = m[2].toLowerCase().replace(/\.$/, "");
  // An SRV connection string names exactly one host, without a port.
  if (host.includes(",") || host.includes(":") || host.split(".").length < 3) return null;
  return { userinfo: m[1] ?? "", host, path: m[3] || "/", params: new URLSearchParams(m[4] ?? "") };
}

/** SRV targets must sit under the cluster host's parent domain (the driver enforces the same rule). */
export function srvTargetAllowed(clusterHost: string, target: string): boolean {
  const parent = clusterHost.toLowerCase().split(".").slice(1).join(".");
  const t = target.toLowerCase().replace(/\.$/, "");
  return parent.split(".").length >= 2 && t.endsWith(`.${parent}`);
}

/** The `mongodb://` seed-list URI equivalent to a `mongodb+srv://` URI, given its SRV and TXT records. */
export function seedListUri(srvUri: string, records: SrvRecord[], txt: string[][]): string | null {
  const parsed = parseSrvUri(srvUri);
  if (!parsed) return null;
  const hosts = records
    .filter((r) => r && typeof r.name === "string" && Number.isInteger(r.port) && srvTargetAllowed(parsed.host, r.name))
    .map((r) => `${r.name.toLowerCase().replace(/\.$/, "")}:${r.port}`);
  if (hosts.length === 0) return null;
  const params = new URLSearchParams();
  // A cluster publishes at most one TXT record; options written in the connection string win.
  if (txt.length === 1) {
    for (const [k, v] of new URLSearchParams(txt[0].join(""))) if (TXT_OPTIONS.has(k)) params.set(k, v);
  }
  for (const [k, v] of parsed.params) params.set(k, v);
  // mongodb+srv implies TLS unless the string turns it off.
  if (!params.has("tls") && !params.has("ssl")) params.set("tls", "true");
  const auth = parsed.userinfo ? `${parsed.userinfo}@` : "";
  return `mongodb://${auth}${hosts.join(",")}${parsed.path}?${params.toString()}`;
}

/** Looks up the cluster's SRV and TXT records through public resolvers and returns the seed-list URI. */
export async function resolveSeedListUri(srvUri: string, servers: string[] = PUBLIC_RESOLVERS): Promise<string | null> {
  const parsed = parseSrvUri(srvUri);
  if (!parsed) return null;
  const resolver = new Resolver({ timeout: 4000, tries: 2 });
  resolver.setServers(servers);
  const records = await resolver.resolveSrv(`_mongodb._tcp.${parsed.host}`);
  const txt = await resolver.resolveTxt(parsed.host).catch(() => [] as string[][]);
  return seedListUri(srvUri, records, txt);
}

/** The connection string without credentials, for logs and messages. */
export function redactMongoUri(uri: string): string {
  return uri.replace(/^(mongodb(?:\+srv)?:\/\/)[^@/?#]*@/i, "$1<credentials>@");
}
