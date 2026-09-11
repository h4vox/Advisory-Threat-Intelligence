import { MAX_BYTES } from "./extract";

// Disallowed hostnames and domains
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  "::",
  "metadata.google.internal",
  "instance-data",
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
];

/**
 * Checks whether an IPv4 numeric representation falls into private, loopback,
 * link-local/cloud-metadata, carrier-grade NAT, or reserved address spaces.
 */
function isPrivateOrReservedIpv4(ipNum: number): boolean {
  // 0.0.0.0/8 (Current network)
  if ((ipNum & 0xff000000) === 0x00000000) return true;

  // 10.0.0.0/8 (Private Class A)
  if ((ipNum & 0xff000000) === 0x0a000000) return true;

  // 100.64.0.0/10 (Carrier-Grade NAT)
  if ((ipNum & 0xffc00000) === 0x64400000) return true;

  // 127.0.0.0/8 (Loopback)
  if ((ipNum & 0xff000000) === 0x7f000000) return true;

  // 169.254.0.0/16 (Link-Local / AWS/GCP/Azure Cloud Metadata: 169.254.169.254)
  if ((ipNum & 0xffff0000) === 0xa9fe0000) return true;

  // 172.16.0.0/12 (Private Class B: 172.16.0.0 - 172.31.255.255)
  if ((ipNum & 0xfff00000) === 0xac100000) return true;

  // 192.0.0.0/24 (IETF Protocol Assignments)
  if ((ipNum & 0xffffff00) === 0xc0000000) return true;

  // 192.0.2.0/24 (TEST-NET-1)
  if ((ipNum & 0xffffff00) === 0xc0000200) return true;

  // 192.168.0.0/16 (Private Class C)
  if ((ipNum & 0xffff0000) === 0xc0a80000) return true;

  // 198.18.0.0/15 (Benchmark Testing)
  if ((ipNum & 0xfffe0000) === 0xc6120000) return true;

  // 198.51.100.0/24 (TEST-NET-2)
  if ((ipNum & 0xffffff00) === 0xc6336400) return true;

  // 203.0.113.0/24 (TEST-NET-3)
  if ((ipNum & 0xffffff00) === 0xcb007100) return true;

  // 224.0.0.0/4 (Multicast: 224.0.0.0 - 239.255.255.255)
  if ((ipNum & 0xf0000000) === 0xe0000000) return true;

  // 240.0.0.0/4 (Reserved for future use: 240.0.0.0 - 255.255.255.255)
  if ((ipNum & 0xf0000000) === 0xf0000000) return true;

  // 255.255.255.255 (Broadcast)
  if (ipNum === 0xffffffff) return true;

  return false;
}

/**
 * Parses dotted decimal or integer IPv4 string and returns 32-bit unsigned number.
 */
function parseIpv4ToNumber(host: string): number | null {
  // Dotted decimal: 1.2.3.4
  const dotted = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (dotted) {
    const octets = [Number(dotted[1]), Number(dotted[2]), Number(dotted[3]), Number(dotted[4])];
    if (octets.some((o) => o > 255)) return null;
    return (((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0);
  }

  // Single integer (e.g. 2130706433 for 127.0.0.1) or hex/octal notation
  if (/^0x[0-9a-fA-F]+$/.test(host)) {
    const num = parseInt(host, 16);
    if (num >= 0 && num <= 0xffffffff) return num >>> 0;
  }

  if (/^\d+$/.test(host)) {
    const num = Number(host);
    if (num >= 0 && num <= 0xffffffff) return num >>> 0;
  }

  return null;
}

/**
 * Checks whether an IPv6 address string is loopback, unique-local, link-local, or IPv4-mapped.
 */
function isPrivateOrReservedIpv6(host: string): boolean {
  const clean = host.replace(/^\[|\]$/g, "").toLowerCase();

  // Loopback / unspecified
  if (clean === "::1" || clean === "::" || clean === "0:0:0:0:0:0:0:1" || clean === "0:0:0:0:0:0:0:0") {
    return true;
  }

  // Unique local (fc00::/7)
  if (clean.startsWith("fc") || clean.startsWith("fd")) {
    return true;
  }

  // Link local (fe80::/10)
  if (clean.startsWith("fe8") || clean.startsWith("fe9") || clean.startsWith("fea") || clean.startsWith("feb")) {
    return true;
  }

  // IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (clean.includes("::ffff:")) {
    const after = clean.split("::ffff:")[1];
    if (after) {
      const parsed = parseIpv4ToNumber(after);
      if (parsed !== null && isPrivateOrReservedIpv4(parsed)) return true;
    }
    return true;
  }

  return false;
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
  const host = parsed.hostname.toLowerCase();
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

  // 5. IPv4 check
  const ipNum = parseIpv4ToNumber(host);
  if (ipNum !== null) {
    if (isPrivateOrReservedIpv4(ipNum)) {
      return { safe: false, error: "Access to private, loopback, or cloud-metadata IP addresses is forbidden." };
    }
  }

  // 6. IPv6 check
  if (host.includes(":") || (host.startsWith("[") && host.endsWith("]"))) {
    if (isPrivateOrReservedIpv6(host)) {
      return { safe: false, error: "Access to private or loopback IPv6 addresses is forbidden." };
    }
  }

  return { safe: true, url: parsed };
}

export type SafeFetchResult = {
  contentType: string;
  body: string;
  bytes: Uint8Array;
  etag: string | null;
  lastModified: string | null;
  finalUrl: string;
};

/**
 * Performs a hardened HTTP GET request with SSRF validation, manual redirect
 * validation (max 5 hops), strict response size limits, and timeout controls.
 */
export async function safeFetchResource(
  targetUrl: string,
  opts?: {
    timeoutMs?: number;
    userAgent?: string;
    maxBytes?: number;
    acceptHeader?: string;
  },
): Promise<SafeFetchResult> {
  const maxBytes = opts?.maxBytes ?? MAX_BYTES;
  const timeoutMs = opts?.timeoutMs ?? 18000;
  const userAgent =
    opts?.userAgent ??
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (compatible; AIE-Threat-Retrieval/3.0; +security-research)";
  const acceptHeader =
    opts?.acceptHeader ??
    "text/html,application/xhtml+xml,application/pdf,application/rss+xml,text/xml,text/plain;q=0.9,*/*;q=0.8";

  let currentUrl = targetUrl;
  let redirectCount = 0;
  const maxRedirects = 5;

  while (redirectCount <= maxRedirects) {
    // Validate target URL at every hop
    const check = validateSafePublicUrl(currentUrl);
    if (!check.safe) {
      throw new Error(`SSRF Blocked: ${check.error}`);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    let res: Response;
    try {
      res = await fetch(currentUrl, {
        signal: controller.signal,
        redirect: "manual", // Handle redirects manually to inspect and validate each hop!
        headers: {
          "user-agent": userAgent,
          accept: acceptHeader,
        },
      });
    } finally {
      clearTimeout(timeout);
    }

    // Check for HTTP redirects (301, 302, 303, 307, 308)
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const location = res.headers.get("location");
      if (!location) {
        throw new Error(`Redirect response HTTP ${res.status} missing Location header.`);
      }

      redirectCount++;
      if (redirectCount > maxRedirects) {
        throw new Error(`Exceeded maximum redirect limit of ${maxRedirects} hops.`);
      }

      // Resolve relative or absolute redirect URL
      const nextUrl = new URL(location, currentUrl).toString();
      currentUrl = nextUrl;
      continue;
    }

    if (!res.ok) {
      throw new Error(`Source returned HTTP ${res.status}`);
    }

    // Pre-check Content-Length header to reject oversized payloads early
    const contentLengthHeader = res.headers.get("content-length");
    if (contentLengthHeader) {
      const contentLength = parseInt(contentLengthHeader, 10);
      if (!isNaN(contentLength) && contentLength > maxBytes) {
        throw new Error(`Document exceeds size limit of ${(maxBytes / 1_000_000).toFixed(1)} MB`);
      }
    }

    // Read response with chunk-level byte cap to prevent memory exhaustion
    const reader = res.body?.getReader();
    if (!reader) {
      // Fallback if reader not available
      const buf = new Uint8Array(await res.arrayBuffer());
      if (buf.byteLength > maxBytes) {
        throw new Error(`Document exceeds size limit of ${(maxBytes / 1_000_000).toFixed(1)} MB`);
      }
      const contentType = (res.headers.get("content-type") ?? "text/html").split(";")[0].trim();
      const body = new TextDecoder("utf-8", { fatal: false }).decode(buf);
      return {
        contentType,
        body,
        bytes: buf,
        etag: res.headers.get("etag"),
        lastModified: res.headers.get("last-modified"),
        finalUrl: currentUrl,
      };
    }

    const chunks: Uint8Array[] = [];
    let receivedBytes = 0;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          receivedBytes += value.byteLength;
          if (receivedBytes > maxBytes) {
            await reader.cancel();
            throw new Error(`Document stream exceeded ${(maxBytes / 1_000_000).toFixed(1)} MB ingest limit`);
          }
          chunks.push(value);
        }
      }
    } finally {
      reader.releaseLock();
    }

    const combinedBytes = new Uint8Array(receivedBytes);
    let offset = 0;
    for (const chunk of chunks) {
      combinedBytes.set(chunk, offset);
      offset += chunk.byteLength;
    }

    const contentType = (res.headers.get("content-type") ?? "text/html").split(";")[0].trim();
    const body = new TextDecoder("utf-8", { fatal: false }).decode(combinedBytes);

    return {
      contentType,
      body,
      bytes: combinedBytes,
      etag: res.headers.get("etag"),
      lastModified: res.headers.get("last-modified"),
      finalUrl: currentUrl,
    };
  }

  throw new Error("Failed to complete request within redirect limits.");
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
