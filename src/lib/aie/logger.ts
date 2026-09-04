/**
 * Adversary Intelligence Engine (AIE) - Unified Terminal Logger
 * High-visibility, structured ANSI color logging for monitoring and debugging.
 */

// ANSI Color Codes
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";

const FG_RED = "\x1b[31m";
const FG_GREEN = "\x1b[32m";
const FG_YELLOW = "\x1b[33m";
const FG_BLUE = "\x1b[34m";
const FG_MAGENTA = "\x1b[35m";
const FG_CYAN = "\x1b[36m";
const FG_WHITE = "\x1b[37m";
const FG_GRAY = "\x1b[90m";

function getTimestamp(): string {
  const d = new Date();
  const pad = (n: number, z = 2) => String(n).padStart(z, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

export const logger = {
  /**
   * HTTP Request Logging
   */
  http(method: string, url: string, statusCode: number, durationMs: number, ip?: string) {
    const time = getTimestamp();
    let statusColor = FG_GREEN;
    if (statusCode >= 500) statusColor = FG_RED;
    else if (statusCode >= 400) statusColor = FG_YELLOW;
    else if (statusCode >= 300) statusColor = FG_CYAN;

    const mColor =
      method === "GET"
        ? FG_BLUE
        : method === "POST"
          ? FG_MAGENTA
          : method === "DELETE"
            ? FG_RED
            : FG_YELLOW;

    const ipStr = ip ? ` ${FG_GRAY}[${ip}]${RESET}` : "";
    const msStr = durationMs < 50 ? `${FG_GRAY}(${durationMs}ms)${RESET}` : `${FG_YELLOW}(${durationMs}ms)${RESET}`;

    console.log(
      `${FG_GRAY}${time}${RESET} ${FG_CYAN}[HTTP]${RESET} ${mColor}${BOLD}${method.padEnd(6)}${RESET} ${FG_WHITE}${url}${RESET} ${statusColor}${BOLD}${statusCode}${RESET} ${msStr}${ipStr}`,
    );
  },

  /**
   * TanStack Start Server Function Logging
   */
  serverFn(name: string, phase: "START" | "DONE" | "ERROR", durationMs?: number, meta?: Record<string, unknown> | string) {
    const time = getTimestamp();
    let metaStr = "";
    if (typeof meta === "string") {
      metaStr = ` ${FG_GRAY}› ${meta}${RESET}`;
    } else if (meta && Object.keys(meta).length > 0) {
      try {
        metaStr = ` ${FG_GRAY}${JSON.stringify(meta)}${RESET}`;
      } catch {
        metaStr = "";
      }
    }

    if (phase === "START") {
      console.log(
        `${FG_GRAY}${time}${RESET} ${FG_MAGENTA}[SERVER-FN]${RESET} ${BOLD}${name}${RESET} ${DIM}invoked${RESET}${metaStr}`,
      );
    } else if (phase === "DONE") {
      const ms = typeof durationMs === "number" ? ` ${FG_GREEN}${durationMs}ms${RESET}` : "";
      console.log(
        `${FG_GRAY}${time}${RESET} ${FG_MAGENTA}[SERVER-FN]${RESET} ${BOLD}${name}${RESET} ${FG_GREEN}✓ completed${RESET}${ms}${metaStr}`,
      );
    } else {
      console.log(
        `${FG_GRAY}${time}${RESET} ${FG_RED}[SERVER-FN]${RESET} ${BOLD}${name}${RESET} ${FG_RED}✗ FAILED${RESET}${metaStr}`,
      );
    }
  },

  /**
   * MongoDB Database Telemetry Logging
   */
  mongo(op: string, collection: string, durationMs?: number, details?: string, isCacheHit?: boolean) {
    const time = getTimestamp();
    if (isCacheHit) {
      console.log(
        `${FG_GRAY}${time}${RESET} ${FG_BLUE}[MONGO:CACHE]${RESET} ${BOLD}${op}${RESET} on ${FG_CYAN}${collection}${RESET} ${FG_GREEN}⚡ memory-hit (0ms)${RESET} ${details ? `${FG_GRAY}› ${details}${RESET}` : ""}`,
      );
      return;
    }

    const ms = typeof durationMs === "number" ? `${durationMs}ms` : "—";
    const msColor = (durationMs ?? 0) > 200 ? FG_YELLOW : FG_GRAY;

    console.log(
      `${FG_GRAY}${time}${RESET} ${FG_BLUE}[MONGO]${RESET} ${BOLD}${op}${RESET} ${FG_CYAN}${collection}${RESET} ${msColor}(${ms})${RESET} ${details ? `${FG_GRAY}› ${details}${RESET}` : ""}`,
    );
  },

  /**
   * In-Memory Cache Invalidation / Hit Logging
   */
  cache(action: "HIT" | "MISS" | "INVALIDATE", key: string, details?: string) {
    const time = getTimestamp();
    const actColor = action === "HIT" ? FG_GREEN : action === "INVALIDATE" ? FG_YELLOW : FG_GRAY;
    console.log(
      `${FG_GRAY}${time}${RESET} ${actColor}[CACHE:${action}]${RESET} ${key} ${details ? `${FG_GRAY}› ${details}${RESET}` : ""}`,
    );
  },

  /**
   * Crawler Engine Pipeline Logging
   */
  crawler(step: string, message: string, meta?: Record<string, unknown> | string) {
    const time = getTimestamp();
    let metaStr = "";
    if (typeof meta === "string") {
      metaStr = ` ${FG_GRAY}› ${meta}${RESET}`;
    } else if (meta) {
      try {
        metaStr = ` ${FG_GRAY}${JSON.stringify(meta)}${RESET}`;
      } catch {
        metaStr = "";
      }
    }

    console.log(
      `${FG_GRAY}${time}${RESET} ${FG_GREEN}[CRAWLER]${RESET} ${BOLD}${step}${RESET}: ${message}${metaStr}`,
    );
  },

  /**
   * Heuristic Qualification Gate Logging
   */
  qualification(url: string, outcome: "PASS" | "REJECT", score: number, reason: string) {
    const time = getTimestamp();
    const outColor = outcome === "PASS" ? `${FG_GREEN}${BOLD}PASS${RESET}` : `${FG_RED}${BOLD}REJECT${RESET}`;
    console.log(
      `${FG_GRAY}${time}${RESET} ${FG_YELLOW}[QUALIFY]${RESET} ${outColor} [Score: ${score.toFixed(2)}] ${url} ${FG_GRAY}› ${reason}${RESET}`,
    );
  },

  /**
   * Content Ingest & PDF Generation Logging
   */
  ingest(action: string, titleOrUrl: string, details?: string) {
    const time = getTimestamp();
    console.log(
      `${FG_GRAY}${time}${RESET} ${FG_CYAN}[INGEST]${RESET} ${BOLD}${action}${RESET}: "${titleOrUrl}" ${details ? `${FG_GRAY}› ${details}${RESET}` : ""}`,
    );
  },

  /**
   * MITRE ATT&CK Matrix Mapping Logging
   */
  mitre(action: string, details: string) {
    const time = getTimestamp();
    console.log(
      `${FG_GRAY}${time}${RESET} \x1b[38;5;141m[MITRE]\x1b[0m ${action} ${FG_GRAY}› ${details}${RESET}`,
    );
  },

  /**
   * Standard Info Logging
   */
  info(tag: string, message: string, ...args: unknown[]) {
    const time = getTimestamp();
    console.log(`${FG_GRAY}${time}${RESET} ${FG_CYAN}[${tag}]${RESET} ${message}`, ...args);
  },

  /**
   * Warning Logging
   */
  warn(tag: string, message: string, ...args: unknown[]) {
    const time = getTimestamp();
    console.warn(`${FG_GRAY}${time}${RESET} ${FG_YELLOW}[${tag}] WARN:${RESET} ${message}`, ...args);
  },

  /**
   * Error Logging with Full Stack Trace
   */
  error(tag: string, message: string, err?: unknown) {
    const time = getTimestamp();
    console.error(`${FG_GRAY}${time}${RESET} ${FG_RED}${BOLD}[${tag}] ERROR:${RESET} ${message}`);
    if (err instanceof Error) {
      console.error(`${FG_RED}${err.stack || err.message}${RESET}`);
    } else if (err) {
      console.error(err);
    }
  },
};
