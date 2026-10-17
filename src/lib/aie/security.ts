import { lookup as dnsLookup } from "node:dns/promises";

export const MAX_BYTES = 1_500_000;
const DEFAULT_MAX_REDIRECTS = 5;

// Disallowed hostnames and domains
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  "::",
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
  "169.254.169.254",
]);

const BLOCKED_EXTENSIONS = [
  ".localhost",
  ".local",
  ".internal",
  ".lan",
  ".corp",
  ".home",
  ".arpa",
  ".test",
  ".example",
  ".invalid",
  ".nip.io",
  ".sslip.io",
  ".localtest.me",
  ".lvh.me",
];

const EMBEDDED_PRIVATE_IP_REGEX =
  /(^|\.)(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)(\.|$)/i;

/** Error thrown whenever a request is refused by the SSRF guard. Message always starts with "SSRF Blocked:". */
export class SsrfBlockedError extends Error {
  constructor(reason: string) {
    super(`SSRF Blocked: ${reason}`);
    this.name = "SsrfBlockedError";
  }
}

/**
 * Checks whether an IPv4 numeric representation falls into private, loopback,
 * link-local/cloud-metadata, carrier-grade NAT, or reserved address spaces.
 */
function isPrivateOrReservedIpv4(ipNum: number): boolean {
  // NOTE: JS bitwise operators yield SIGNED 32-bit results, so every masked value must be
  // coerced back to unsigned (>>> 0) before comparing; otherwise ranges >= 128.0.0.0
  // (172.16/12, 169.254/16, 192.168/16, multicast...) silently never match.
  const ip = ipNum >>> 0;
  const inRange = (base: number, prefix: number) => {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return ((ip & mask) >>> 0) === ((base & mask) >>> 0);
  };
  return (
    inRange(0x00000000, 8) || // 0.0.0.0/8 current network / unspecified
    inRange(0x0a000000, 8) || // 10.0.0.0/8 private
    inRange(0x64400000, 10) || // 100.64.0.0/10 carrier-grade NAT
    inRange(0x7f000000, 8) || // 127.0.0.0/8 loopback
    inRange(0xa9fe0000, 16) || // 169.254.0.0/16 link-local / cloud metadata
    inRange(0xac100000, 12) || // 172.16.0.0/12 private
    inRange(0xc0000000, 24) || // 192.0.0.0/24 IETF protocol assignments
    inRange(0xc0000200, 24) || // 192.0.2.0/24 TEST-NET-1
    inRange(0xc0586300, 24) || // 192.88.99.0/24 6to4 relay anycast (deprecated)
    inRange(0xc0a80000, 16) || // 192.168.0.0/16 private
    inRange(0xc6120000, 15) || // 198.18.0.0/15 benchmarking
    inRange(0xc6336400, 24) || // 198.51.100.0/24 TEST-NET-2
    inRange(0xcb007100, 24) || // 203.0.113.0/24 TEST-NET-3
    inRange(0xe0000000, 4) || // 224.0.0.0/4 multicast
    inRange(0xf0000000, 4) // 240.0.0.0/4 reserved + 255.255.255.255 broadcast
  );
}

/**
 * Parses dotted decimal or integer IPv4 string and returns 32-bit unsigned number.
 */
function parseIpv4ToNumber(host: string): number | null {
  if (host.startsWith("[") || host.includes(":")) return null;

  // Single integer (e.g. 2130706433 for 127.0.0.1) or hex
  if (/^0x[0-9a-fA-F]+$/i.test(host)) {
    const num = parseInt(host, 16);
    return num >= 0 && num <= 0xffffffff ? num >>> 0 : null;
  }
  if (/^\d+$/.test(host)) {
    const num = Number(host);
    return num >= 0 && num <= 0xffffffff ? num >>> 0 : null;
  }

  // Dotted notation: supports 2, 3, or 4 parts with decimal, octal (0...), or hex (0x...)
  const parts = host.split(".");
  if (parts.length >= 2 && parts.length <= 4) {
    const parsedParts: number[] = [];
    for (const part of parts) {
      let val: number;
      if (/^0x[0-9a-fA-F]+$/i.test(part)) {
        val = parseInt(part, 16);
      } else if (/^0[0-7]+$/.test(part)) {
        val = parseInt(part, 8); // Octal notation bypass protection
      } else if (/^\d+$/.test(part)) {
        val = parseInt(part, 10);
      } else {
        return null;
      }
      if (isNaN(val) || val < 0) return null;
      parsedParts.push(val);
    }

    if (parts.length === 4) {
      if (parsedParts.some((p) => p > 255)) return null;
      return (((parsedParts[0] << 24) | (parsedParts[1] << 16) | (parsedParts[2] << 8) | parsedParts[3]) >>> 0);
    } else if (parts.length === 3) {
      if (parsedParts[0] > 255 || parsedParts[1] > 255 || parsedParts[2] > 65535) return null;
      return (((parsedParts[0] << 24) | (parsedParts[1] << 16) | parsedParts[2]) >>> 0);
    } else if (parts.length === 2) {
      if (parsedParts[0] > 255 || parsedParts[1] > 16777215) return null;
      return (((parsedParts[0] << 24) | parsedParts[1]) >>> 0);
    }
  }

  return null;
}

/** Strict dotted-quad parser (used for IPv4 tails embedded in IPv6 literals and DNS answers). */
function parseStrictDottedIpv4(s: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const p = m.slice(1).map((x) => Number(x));
  if (p.some((x) => x > 255)) return null;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

/**
 * Parses an IPv6 literal (optionally bracketed, optionally with an embedded IPv4 tail)
 * into eight 16-bit groups. Returns null if the string is not a valid IPv6 address.
 */
function parseIpv6ToHextets(input: string): number[] | null {
  let s = input.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!s.includes(":")) return null;
  // Zone identifiers (fe80::1%eth0) only make sense for link-local scopes; strip for parsing.
  const pct = s.indexOf("%");
  if (pct !== -1) s = s.slice(0, pct);

  // Convert an embedded dotted IPv4 tail into two hextets.
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = parseStrictDottedIpv4(tail);
    if (v4 === null) return null;
    s = `${s.slice(0, lastColon + 1)}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }

  const doubleColonParts = s.split("::");
  if (doubleColonParts.length > 2) return null;

  const parseGroups = (part: string): number[] | null => {
    if (part === "") return [];
    const groups = part.split(":");
    const out: number[] = [];
    for (const g of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };

  if (doubleColonParts.length === 2) {
    const head = parseGroups(doubleColonParts[0]);
    const rest = parseGroups(doubleColonParts[1]);
    if (!head || !rest) return null;
    const missing = 8 - head.length - rest.length;
    if (missing < 1) return null;
    return [...head, ...new Array<number>(missing).fill(0), ...rest];
  }

  const all = parseGroups(s);
  if (!all || all.length !== 8) return null;
  return all;
}

/**
 * Checks whether an IPv6 address string is unspecified, loopback, IPv4-mapped/compatible
 * private, NAT64/6to4-embedded private, unique-local (fc00::/7), link-local (fe80::/10),
 * site-local (fec0::/10), multicast (ff00::/8), Teredo, documentation or discard-only.
 * Unparseable input is treated as unsafe.
 */
function isPrivateOrReservedIpv6(host: string): boolean {
  if (host.includes("%")) return true; // scoped (zone-id) addresses are link-local by definition
  const h = parseIpv6ToHextets(host);
  if (!h) return true;

  const embeddedV4 = (hi: number, lo: number) => (((hi << 16) | lo) >>> 0);

  // ::ffff:0:0/96 IPv4-mapped — classify the embedded IPv4 address
  if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0xffff) {
    return isPrivateOrReservedIpv4(embeddedV4(h[6], h[7]));
  }
  // ::ffff:0:0:0/96 IPv4-translated (RFC 2765) — classify the embedded address
  if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0xffff && h[5] === 0) {
    return isPrivateOrReservedIpv4(embeddedV4(h[6], h[7]));
  }
  // 64:ff9b::/96 NAT64 well-known prefix — classify the embedded IPv4 address
  if (h[0] === 0x64 && h[1] === 0xff9b && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0) {
    return isPrivateOrReservedIpv4(embeddedV4(h[6], h[7]));
  }
  // 64:ff9b:1::/48 local-use NAT64
  if (h[0] === 0x64 && h[1] === 0xff9b && h[2] === 1) return true;
  // 0000::/8 — unspecified (::), loopback (::1), IPv4-compatible (deprecated) and other reserved space
  if ((h[0] & 0xff00) === 0) return true;
  // 100::/64 discard-only
  if (h[0] === 0x100 && h[1] === 0 && h[2] === 0 && h[3] === 0) return true;
  // 2001::/32 Teredo (tunnels to arbitrary IPv4) and 2001:db8::/32 documentation
  if (h[0] === 0x2001 && (h[1] === 0 || h[1] === 0xdb8)) return true;
  // 2001:10::/28 ORCHID, 2001:20::/28 ORCHIDv2
  if (h[0] === 0x2001 && (h[1] & 0xfff0) === 0x10) return true;
  if (h[0] === 0x2001 && (h[1] & 0xfff0) === 0x20) return true;
  // 2002::/16 6to4 — classify the embedded IPv4 address
  if (h[0] === 0x2002) return isPrivateOrReservedIpv4(embeddedV4(h[1], h[2]));
  // 3fff::/20 documentation
  if (h[0] === 0x3fff && (h[1] & 0xf000) === 0) return true;
  // fc00::/7 unique local
  if ((h[0] & 0xfe00) === 0xfc00) return true;
  // fe80::/10 link-local, fec0::/10 site-local (deprecated)
  if ((h[0] & 0xffc0) === 0xfe80 || (h[0] & 0xffc0) === 0xfec0) return true;
  // ff00::/8 multicast
  if ((h[0] & 0xff00) === 0xff00) return true;

  return false;
}

/**
 * Classifies a literal IP address (IPv4 or IPv6, optionally bracketed).
 * Returns true when the address is private / loopback / link-local / CGNAT / multicast /
 * unspecified / reserved, or when the string cannot be parsed as an IP at all
 * (fail-closed — callers should only pass values they expect to be IP literals,
 * such as DNS answers).
 */
export function isPrivateOrReservedIp(address: string): boolean {
  if (!address || typeof address !== "string") return true;
  const a = address.trim();
  if (a.includes(":") || a.startsWith("[")) return isPrivateOrReservedIpv6(a);
  const v4 = parseIpv4ToNumber(a);
  if (v4 === null) return true;
  return isPrivateOrReservedIpv4(v4);
}

/** True when the string is an IP literal (v4 in any WHATWG-accepted numeric form, or v6). */
function isIpLiteral(host: string): boolean {
  if (host.includes(":") || host.startsWith("[")) return parseIpv6ToHextets(host) !== null;
  return parseIpv4ToNumber(host) !== null;
}

export type SafeUrlValidationResult = {
  safe: boolean;
  error?: string;
  url?: URL;
};

/**
 * Validates that a given URL is safe for server-side fetching:
 * - Scheme must be http: or https:
 * - No user/pass credentials in URL
 * - Only standard web ports (80, 443, or default)
 * - Hostname cannot be localhost or internal domain
 * - IP cannot be loopback, private RFC1918, link-local/cloud-metadata, multicast, or reserved
 *
 * This is a purely syntactic check. It does NOT resolve DNS — use `assertPublicHost`
 * (or the `safeFetch*` / `probeUrlSafely` helpers, which call it on every hop) before
 * actually connecting.
 */
export function validateSafePublicUrl(rawUrl: string): SafeUrlValidationResult {
  if (!rawUrl || typeof rawUrl !== "string") {
    return { safe: false, error: "Missing or invalid URL string" };
  }

  const trimmed = rawUrl.trim();
  if (trimmed.length > 2048) {
    return { safe: false, error: "URL exceeds maximum length of 2048 characters" };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { safe: false, error: "Malformed URL syntax" };
  }

  // 1. Protocol check
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { safe: false, error: `Disallowed protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted.` };
  }

  // 2. Credentials check
  if (parsed.username || parsed.password) {
    return { safe: false, error: "URL contains credentials, which are rejected for security." };
  }

  // 3. Port check: allow standard ports only
  if (parsed.port && parsed.port !== "80" && parsed.port !== "443") {
    return { safe: false, error: `Disallowed port "${parsed.port}". Only standard ports (80, 443) are allowed.` };
  }

  // 4. Hostname check
  const host = parsed.hostname.toLowerCase().replace(/\.+$/, ""); // ignore trailing FQDN dot(s)
  if (!host || host.length === 0) {
    return { safe: false, error: "URL hostname cannot be empty" };
  }

  if (BLOCKED_HOSTNAMES.has(host)) {
    return { safe: false, error: `Access to internal hostname "${host}" is forbidden.` };
  }

  for (const ext of BLOCKED_EXTENSIONS) {
    if (host.endsWith(ext)) {
      return { safe: false, error: `Access to internal domain ending in "${ext}" is forbidden.` };
    }
  }

  if (EMBEDDED_PRIVATE_IP_REGEX.test(host)) {
    return { safe: false, error: "Access to domains embedding private, loopback, or metadata IP addresses is forbidden." };
  }

  // 5. IPv6 literal check
  if (host.includes(":") || (host.startsWith("[") && host.endsWith("]"))) {
    if (isPrivateOrReservedIpv6(host)) {
      return { safe: false, error: "Access to private or loopback IPv6 addresses is forbidden." };
    }
    return { safe: true, url: parsed };
  }

  // 6. IPv4 literal check
  const ipNum = parseIpv4ToNumber(host);
  if (ipNum !== null) {
    if (isPrivateOrReservedIpv4(ipNum)) {
      return { safe: false, error: "Access to private, loopback, or cloud-metadata IP addresses is forbidden." };
    }
  } else if (!host.includes(".")) {
    // Single-label hostnames (intranet names such as "router", "kubernetes") resolve via search domains.
    return { safe: false, error: `Single-label hostname "${host}" is not a public domain.` };
  }

  return { safe: true, url: parsed };
}

/**
 * Synchronous pre-validation of stored domains, URLs and crawl patterns
 * (e.g. "example.com", "https://example.com/research/*"). Bare domains are
 * interpreted as https://<domain>/. Does NOT resolve DNS.
 */
export function isSafePublicUrlString(s: string): boolean {
  if (!s || typeof s !== "string") return false;
  const trimmed = s.trim();
  if (!trimmed || /\s/.test(trimmed)) return false;
  const candidate = /^[a-z][a-z0-9+.-]*:/i.test(trimmed) ? trimmed : `https://${trimmed.replace(/^\/+/, "")}`;
  return validateSafePublicUrl(candidate).safe;
}

/**
 * Validates a stored crawl pattern, which may hold several comma / semicolon / newline
 * separated URL globs (e.g. "https://a.com/reports/*, https://a.com/20*\/*").
 * Every entry must be a safe public URL (or bare domain/path). "*" alone is allowed.
 */
export function isSafeCrawlPatternString(pattern: string): boolean {
  if (!pattern || typeof pattern !== "string") return false;
  const trimmed = pattern.trim();
  if (trimmed === "*") return true;
  const parts = trimmed
    .split(/[,;\n]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  return parts.length > 0 && parts.every((p) => isSafePublicUrlString(p));
}

export type ResolvedAddress = { address: string; family: number };

/**
 * Resolves the URL's hostname and throws `SsrfBlockedError` if the URL fails the
 * syntactic checks or if ANY resolved address is private / loopback / link-local /
 * CGNAT / multicast / unspecified / ULA / IPv4-mapped-private. Returns the vetted
 * addresses so the caller can pin the connection to them.
 */
export async function assertPublicHost(url: URL): Promise<ResolvedAddress[]> {
  const check = validateSafePublicUrl(url.toString());
  if (!check.safe) throw new SsrfBlockedError(check.error ?? "URL rejected");

  const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  if (isIpLiteral(host)) {
    if (isPrivateOrReservedIp(host)) throw new SsrfBlockedError("Access to private or reserved IP addresses is forbidden.");
    const family = host.includes(":") ? 6 : 4;
    // WHATWG URL already normalised numeric IPv4 forms to dotted-quad.
    return [{ address: host, family }];
  }

  let answers: ResolvedAddress[];
  try {
    answers = await dnsLookup(host, { all: true, verbatim: true });
  } catch (err) {
    throw new Error(`DNS resolution failed for "${host}": ${(err as Error).message}`);
  }
  if (!answers || answers.length === 0) {
    throw new Error(`DNS resolution for "${host}" returned no addresses.`);
  }
  for (const a of answers) {
    if (isPrivateOrReservedIp(a.address)) {
      throw new SsrfBlockedError(`Host "${host}" resolves to a non-public address (${a.address}).`);
    }
  }
  return answers.map((a) => ({ address: a.address, family: a.family }));
}

// ---------------------------------------------------------------------------
// Connection pinning
//
// Between `assertPublicHost` (DNS lookup) and the socket connect, a hostile DNS
// server could return a different (private) answer — classic DNS rebinding TOCTOU.
// The `undici` package is not installed, but Node's built-in fetch IS undici and
// accepts a `dispatcher` option. We obtain the bundled `Agent` class from the global
// dispatcher and give each hop an Agent whose `connect.lookup` only ever returns the
// addresses we already vetted, so the socket cannot connect anywhere else.
//
// Residual risk: if the runtime does not expose that Agent (non-Node runtime, a
// custom global dispatcher such as a proxy agent, or a future Node change), we fall
// back to plain fetch and the lookup→connect TOCTOU window remains open; the
// per-hop DNS validation still blocks static private records and the redirect
// re-validation still applies. Note also that when an HTTP(S) proxy dispatcher is
// in use, the proxy (not this process) resolves the name.
// ---------------------------------------------------------------------------

type DispatcherLike = { close(): Promise<void>; destroy(err?: Error | null): Promise<void> };
type AgentCtor = new (opts: { connect: { lookup: PinnedLookup } }) => DispatcherLike;
type PinnedLookup = (
  hostname: string,
  options: { family?: number; all?: boolean } | number | undefined,
  cb: (...args: unknown[]) => void,
) => void;

let cachedAgentCtor: AgentCtor | null | undefined;

async function getUndiciAgentCtor(): Promise<AgentCtor | null> {
  if (cachedAgentCtor !== undefined) return cachedAgentCtor;
  try {
    const sym = Symbol.for("undici.globalDispatcher.1");
    const g = globalThis as unknown as Record<symbol, unknown>;
    if (!g[sym]) {
      // Node initialises its global dispatcher lazily on first fetch.
      try {
        await fetch("data:text/plain,");
      } catch {
        /* ignore */
      }
    }
    const dispatcher = g[sym] as { constructor?: unknown } | undefined;
    const ctor = dispatcher?.constructor as (AgentCtor & { name?: string }) | undefined;
    cachedAgentCtor = typeof ctor === "function" && ctor.name === "Agent" ? ctor : null;
  } catch {
    cachedAgentCtor = null;
  }
  return cachedAgentCtor;
}

async function createPinnedDispatcher(addresses: ResolvedAddress[]): Promise<DispatcherLike | null> {
  const Agent = await getUndiciAgentCtor();
  if (!Agent || addresses.length === 0) return null;
  const lookup: PinnedLookup = (_hostname, options, cb) => {
    const opts = typeof options === "number" ? { family: options } : options ?? {};
    const family = opts.family === 4 || opts.family === 6 ? opts.family : undefined;
    const matching = family ? addresses.filter((a) => a.family === family) : addresses;
    const list = matching.length > 0 ? matching : addresses;
    if (opts.all) cb(null, list.map((a) => ({ address: a.address, family: a.family })));
    else cb(null, list[0].address, list[0].family);
  };
  try {
    return new Agent({ connect: { lookup } });
  } catch {
    return null;
  }
}

function closeDispatcher(d: DispatcherLike | null): void {
  if (!d) return;
  d.destroy().catch(() => {
    /* ignore */
  });
}

type SafeRequestOptions = {
  method?: "GET" | "HEAD";
  headers: Record<string, string>;
  maxRedirects?: number;
  signal: AbortSignal;
};

type SafeResponse = { res: Response; finalUrl: string; dispatcher: DispatcherLike | null };

/**
 * Issues a request with `redirect: "manual"`, validating the URL (syntax + DNS) before
 * the first hop and before every redirect hop. The caller owns the abort signal (so the
 * deadline can span the body read) and must call `closeDispatcher(result.dispatcher)`.
 */
async function safeRequest(targetUrl: string, opts: SafeRequestOptions): Promise<SafeResponse> {
  const maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  let currentUrl = targetUrl;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const check = validateSafePublicUrl(currentUrl);
    if (!check.safe || !check.url) throw new SsrfBlockedError(check.error ?? "URL rejected");
    const addresses = await assertPublicHost(check.url);
    if (opts.signal.aborted) throw new Error("Request timed out");

    const dispatcher = await createPinnedDispatcher(addresses);
    let res: Response;
    try {
      const init: RequestInit & { dispatcher?: unknown } = {
        method: opts.method ?? "GET",
        signal: opts.signal,
        redirect: "manual", // Handle redirects manually to inspect and validate each hop
        headers: opts.headers,
      };
      if (dispatcher) init.dispatcher = dispatcher;
      res = await fetch(check.url.toString(), init);
    } catch (err) {
      closeDispatcher(dispatcher);
      throw err;
    }

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const location = res.headers.get("location");
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      closeDispatcher(dispatcher);
      if (!location) throw new Error(`Redirect response HTTP ${res.status} missing Location header.`);
      if (hop + 1 > maxRedirects) throw new Error(`Exceeded maximum redirect limit of ${maxRedirects} hops.`);
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }

    return { res, finalUrl: currentUrl, dispatcher };
  }

  throw new Error("Failed to complete request within redirect limits.");
}

/** Reads a response body while enforcing a byte cap. The abort signal must still be live. */
async function readBodyCapped(res: Response, maxBytes: number): Promise<Uint8Array> {
  const tooLarge = () => new Error(`Document stream exceeded ${(maxBytes / 1_000_000).toFixed(1)} MB ingest limit`);

  const contentLengthHeader = res.headers.get("content-length");
  if (contentLengthHeader) {
    const contentLength = parseInt(contentLengthHeader, 10);
    if (!isNaN(contentLength) && contentLength > maxBytes) {
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      throw new Error(`Document exceeds size limit of ${(maxBytes / 1_000_000).toFixed(1)} MB`);
    }
  }

  const reader = res.body?.getReader();
  if (!reader) return new Uint8Array(0);

  const chunks: Uint8Array[] = [];
  let receivedBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        receivedBytes += value.byteLength;
        if (receivedBytes > maxBytes) {
          try {
            await reader.cancel();
          } catch {
            /* ignore */
          }
          throw tooLarge();
        }
        chunks.push(value);
      }
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      /* ignore */
    }
  }

  const combined = new Uint8Array(receivedBytes);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return combined;
}

const DEFAULT_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (compatible; AIE-Threat-Retrieval/3.0; +security-research)";
const DEFAULT_ACCEPT =
  "text/html,application/xhtml+xml,application/pdf,application/rss+xml,text/xml,text/plain;q=0.9,*/*;q=0.8";

export type SafeFetchResult = {
  contentType: string;
  body: string;
  bytes: Uint8Array;
  etag: string | null;
  lastModified: string | null;
  finalUrl: string;
};

/**
 * Performs a hardened HTTP GET request with SSRF validation (syntax + DNS resolution on
 * the initial URL and every redirect hop, with the connection pinned to the vetted
 * addresses where the runtime allows), manual redirect handling (max 5 hops), a
 * streaming response size cap, and a single deadline covering connect, redirects and
 * the full body read.
 */
export async function safeFetchResource(
  targetUrl: string,
  opts?: {
    timeoutMs?: number;
    userAgent?: string;
    maxBytes?: number;
    acceptHeader?: string;
    maxRedirects?: number;
  },
): Promise<SafeFetchResult> {
  const maxBytes = opts?.maxBytes ?? MAX_BYTES;
  const timeoutMs = opts?.timeoutMs ?? 18000;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error(`Request timed out after ${timeoutMs} ms`)), timeoutMs);
  let dispatcher: DispatcherLike | null = null;
  try {
    const result = await safeRequest(targetUrl, {
      method: "GET",
      signal: controller.signal,
      maxRedirects: opts?.maxRedirects,
      headers: {
        "user-agent": opts?.userAgent ?? DEFAULT_USER_AGENT,
        accept: opts?.acceptHeader ?? DEFAULT_ACCEPT,
      },
    });
    dispatcher = result.dispatcher;
    const { res, finalUrl } = result;

    if (!res.ok) {
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      throw new Error(`Source returned HTTP ${res.status}`);
    }

    // Body is read while the abort timer is still armed.
    const bytes = await readBodyCapped(res, maxBytes);
    const contentType = (res.headers.get("content-type") ?? "text/html").split(";")[0].trim();
    const body = new TextDecoder("utf-8", { fatal: false }).decode(bytes);

    return {
      contentType,
      body,
      bytes,
      etag: res.headers.get("etag"),
      lastModified: res.headers.get("last-modified"),
      finalUrl,
    };
  } finally {
    clearTimeout(timeout);
    closeDispatcher(dispatcher);
  }
}

/**
 * Convenience wrapper for crawler seed fetches (feeds, homepages, archives, search pages).
 * Returns the decoded body text, or null on any failure (SSRF block, DNS failure,
 * non-2xx, timeout, size cap). SSRF blocks are logged.
 */
export async function safeFetchText(
  url: string,
  opts?: {
    timeoutMs?: number;
    maxBytes?: number;
    userAgent?: string;
    acceptHeader?: string;
    maxRedirects?: number;
  },
): Promise<string | null> {
  try {
    const r = await safeFetchResource(url, opts);
    return r.body;
  } catch (err) {
    if (err instanceof SsrfBlockedError) {
      console.warn(`[security] ${err.message} (url=${url.slice(0, 200)})`);
    }
    return null;
  }
}

export type SafeConditionalFetchResult =
  | ({ status: number; notModified: false } & SafeFetchResult)
  | { status: 304; notModified: true; etag: string | null; lastModified: string | null; finalUrl: string };

/**
 * Conditional GET (If-None-Match / If-Modified-Since) through the same SSRF-guarded path as
 * safeFetchResource: DNS-validated hops, pinned connection, manual redirects, size cap and one
 * deadline. A 304 returns `notModified: true` without reading a body; any other non-2xx throws.
 */
export async function safeConditionalFetch(
  targetUrl: string,
  opts?: {
    etag?: string | null;
    lastModified?: string | null;
    timeoutMs?: number;
    userAgent?: string;
    maxBytes?: number;
    acceptHeader?: string;
    maxRedirects?: number;
  },
): Promise<SafeConditionalFetchResult> {
  const maxBytes = opts?.maxBytes ?? MAX_BYTES;
  const timeoutMs = opts?.timeoutMs ?? 18000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error(`Request timed out after ${timeoutMs} ms`)), timeoutMs);
  let dispatcher: DispatcherLike | null = null;
  const headers: Record<string, string> = {
    "user-agent": opts?.userAgent ?? DEFAULT_USER_AGENT,
    accept: opts?.acceptHeader ?? DEFAULT_ACCEPT,
  };
  // Header values come from earlier responses; drop anything that is not a plain header token.
  if (opts?.etag && /^[\x20-\x7e]{1,200}$/.test(opts.etag)) headers["if-none-match"] = opts.etag;
  if (opts?.lastModified && /^[\x20-\x7e]{1,100}$/.test(opts.lastModified)) headers["if-modified-since"] = opts.lastModified;
  try {
    const result = await safeRequest(targetUrl, { method: "GET", signal: controller.signal, maxRedirects: opts?.maxRedirects, headers });
    dispatcher = result.dispatcher;
    const { res, finalUrl } = result;
    if (res.status === 304) {
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      return { status: 304, notModified: true, etag: res.headers.get("etag"), lastModified: res.headers.get("last-modified"), finalUrl };
    }
    if (!res.ok) {
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      throw new Error(`Source returned HTTP ${res.status}`);
    }
    const bytes = await readBodyCapped(res, maxBytes);
    const contentType = (res.headers.get("content-type") ?? "text/html").split(";")[0].trim();
    return {
      status: res.status,
      notModified: false,
      contentType,
      body: new TextDecoder("utf-8", { fatal: false }).decode(bytes),
      bytes,
      etag: res.headers.get("etag"),
      lastModified: res.headers.get("last-modified"),
      finalUrl,
    };
  } finally {
    clearTimeout(timeout);
    closeDispatcher(dispatcher);
  }
}

export type SafeProbeResult = {
  ok: boolean;
  statusCode: number | null;
  contentType: string | null;
  latencyMs: number;
  finalUrl: string | null;
  error?: string;
};

/**
 * Probes a URL (HEAD or GET) through the SSRF-validated path: syntax + DNS check on the
 * initial URL and every redirect hop, `redirect: "manual"`, pinned connection, and the
 * response body is cancelled (never read). Never throws.
 */
export async function probeUrlSafely(
  url: string,
  opts?: {
    method?: "HEAD" | "GET";
    timeoutMs?: number;
    userAgent?: string;
    acceptHeader?: string;
    maxRedirects?: number;
  },
): Promise<SafeProbeResult> {
  const started = Date.now();
  const timeoutMs = opts?.timeoutMs ?? 8000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error(`Request timed out after ${timeoutMs} ms`)), timeoutMs);
  let dispatcher: DispatcherLike | null = null;
  try {
    const result = await safeRequest(url, {
      method: opts?.method ?? "HEAD",
      signal: controller.signal,
      maxRedirects: opts?.maxRedirects,
      headers: {
        "user-agent": opts?.userAgent ?? DEFAULT_USER_AGENT,
        accept: opts?.acceptHeader ?? DEFAULT_ACCEPT,
      },
    });
    dispatcher = result.dispatcher;
    const { res, finalUrl } = result;
    try {
      await res.body?.cancel();
    } catch {
      /* ignore */
    }
    return {
      ok: res.ok,
      statusCode: res.status,
      contentType: res.headers.get("content-type"),
      latencyMs: Date.now() - started,
      finalUrl,
      error: res.ok ? undefined : `HTTP ${res.status}`,
    };
  } catch (err) {
    return {
      ok: false,
      statusCode: null,
      contentType: null,
      latencyMs: Date.now() - started,
      finalUrl: null,
      error: controller.signal.aborted ? `Timed out after ${timeoutMs} ms` : (err as Error).message,
    };
  } finally {
    clearTimeout(timeout);
    closeDispatcher(dispatcher);
  }
}

/**
 * Hardens HTML content before storage or iframe presentation:
 * - Strips scripts, inline event handlers, javascript URIs, and dangerous elements
 * - Injects a strict Content-Security-Policy meta tag
 */
export function sanitizeDocumentHtml(rawHtml: string): string {
  if (!rawHtml || typeof rawHtml !== "string") return "";

  let cleaned = rawHtml
    // 1. Remove script tags and their content
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "")
    // 2. Remove style tags with dangerous imports
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, (match) => {
      if (/@import|behavior:|javascript:/i.test(match)) return "";
      return match;
    })
    // 3. Remove iframes, objects, embeds, applets, base tags, form tags
    .replace(/<(?:iframe|object|embed|applet|base|form)\b[^<]*(?:(?!<\/(?:iframe|object|embed|applet|base|form)>)<[^<]*)*<\/(?:iframe|object|embed|applet|base|form)>/gi, "")
    .replace(/<(?:iframe|object|embed|applet|base|meta\s+http-equiv=["']?refresh)["'][^>]*>/gi, "")
    // 4. Remove inline event handlers (onload, onerror, onclick, etc.)
    .replace(/\s+on[a-zA-Z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "")
    // 5. Remove javascript: and vbscript: URIs from href and src attributes
    .replace(/(href|src)\s*=\s*["']?\s*(?:javascript|vbscript):[^"'\s>]*/gi, '$1="#"');

  // If the document contains an <html> or <head> tag, inject a strict CSP meta tag
  const cspMeta = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data: https: http:; style-src 'unsafe-inline'; font-src data: https:;">`;
  if (/<head\b[^>]*>/i.test(cleaned)) {
    cleaned = cleaned.replace(/(<head\b[^>]*>)/i, `$1\n  ${cspMeta}`);
  } else if (/<html\b[^>]*>/i.test(cleaned)) {
    cleaned = cleaned.replace(/(<html\b[^>]*>)/i, `$1\n<head>\n  ${cspMeta}\n</head>`);
  } else {
    cleaned = `${cspMeta}\n${cleaned}`;
  }

  return cleaned;
}
