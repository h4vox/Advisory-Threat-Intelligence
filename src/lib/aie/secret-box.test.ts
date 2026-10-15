import { test } from "node:test";
import assert from "node:assert/strict";
import { decryptConfigSecrets, encryptConfigSecrets } from "./secret-box.server.ts";

test("secrets round-trip through AES-GCM and non-secrets are untouched", () => {
  process.env.AIE_ENCRYPTION_KEY = "test-key";
  const enc = encryptConfigSecrets({ apiKey: "sk-abc", selectedModel: "m" }) as Record<string, string>;
  assert.match(enc.apiKey, /^enc:v1:/);
  assert.equal(enc.selectedModel, "m");
  const dec = decryptConfigSecrets(enc) as Record<string, string>;
  assert.equal(dec.apiKey, "sk-abc");
});

test("a wrong key cannot decrypt", () => {
  process.env.AIE_ENCRYPTION_KEY = "key-one";
  const enc = encryptConfigSecrets({ apiKey: "sk-abc" }) as Record<string, string>;
  process.env.AIE_ENCRYPTION_KEY = "key-two";
  assert.equal((decryptConfigSecrets(enc) as Record<string, unknown>).apiKey, undefined);
});
