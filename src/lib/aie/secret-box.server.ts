import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { isSecretConfigKey } from "./redact.ts";

/**
 * At-rest encryption for integration secrets (API keys, tokens, PKCE
 * verifiers) stored in MongoDB. AES-256-GCM keyed from AIE_ENCRYPTION_KEY.
 *
 * Without the key: development stores plaintext with a warning; production
 * refuses to store a secret (fail closed) rather than write it in the clear.
 */

const PREFIX = "enc:v1:";

function key(): Buffer | null {
  const raw = process.env.AIE_ENCRYPTION_KEY?.trim();
  return raw ? createHash("sha256").update(raw).digest() : null;
}

export function encryptSecret(value: string): string {
  if (value.startsWith(PREFIX)) return value;
  const k = key();
  if (!k) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("AIE_ENCRYPTION_KEY is not set; refusing to store a credential in plaintext.");
    }
    console.warn("[secret-box] AIE_ENCRYPTION_KEY not set; storing credential unencrypted (development only).");
    return value;
  }
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", k, iv);
  const ct = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${PREFIX}${iv.toString("base64url")}.${tag.toString("base64url")}.${ct.toString("base64url")}`;
}

export function decryptSecret(value: string): string | undefined {
  if (!value.startsWith(PREFIX)) return value;
  const k = key();
  if (!k) return undefined;
  try {
    const [iv, tag, ct] = value.slice(PREFIX.length).split(".").map((p) => Buffer.from(p, "base64url"));
    const decipher = createDecipheriv("aes-256-gcm", k, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  } catch {
    return undefined;
  }
}

type Config = Record<string, unknown> | undefined;

function mapSecrets(config: Config, fn: (v: string) => string | undefined): Config {
  if (!config) return config;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(config)) {
    out[k] = typeof v === "string" && v && isSecretConfigKey(k) ? fn(v) : v;
  }
  return out;
}

export const encryptConfigSecrets = (config: Config) => mapSecrets(config, encryptSecret);
export const decryptConfigSecrets = (config: Config) => mapSecrets(config, decryptSecret);
