import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  assertPublicHost,
  isPrivateOrReservedIp,
  isSafePublicUrlString,
  probeUrlSafely,
  safeFetchResource,
  validateSafePublicUrl,
} from "./security.ts";

describe("isPrivateOrReservedIp", () => {
  it("rejects private, loopback, link-local, CGNAT, multicast and unspecified IPv4", () => {
    for (const ip of [
      "10.0.0.1",
      "172.16.5.4",
      "172.31.255.255",
      "192.168.1.1",
      "127.0.0.1",
      "127.8.9.10",
      "169.254.169.254",
      "100.64.0.1",
      "0.0.0.0",
      "224.0.0.1",
      "255.255.255.255",
    ]) {
      assert.equal(isPrivateOrReservedIp(ip), true, ip);
    }
  });

  it("rejects IPv6 loopback, unspecified, ULA, link-local, multicast and mapped-private", () => {
    for (const ip of [
      "::1",
      "::",
      "[::1]",
      "0:0:0:0:0:0:0:1",
      "fc00::1",
      "fd12:3456:789a::1",
      "fe80::1",
      "fe80::1%eth0",
      "ff02::1",
      "::ffff:127.0.0.1",
      "::ffff:7f00:1",
      "::ffff:169.254.169.254",
      "::ffff:a9fe:a9fe",
      "64:ff9b::a00:1",
      "2002:c0a8:0101::1",
      "::127.0.0.1",
      "64:ff9b:1::1",
    ]) {
      assert.equal(isPrivateOrReservedIp(ip), true, ip);
    }
  });

  it("accepts public addresses", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"]) {
      assert.equal(isPrivateOrReservedIp(ip), false, ip);
    }
  });

  it("fails closed on garbage", () => {
    assert.equal(isPrivateOrReservedIp("not-an-ip"), true);
    assert.equal(isPrivateOrReservedIp(""), true);
    assert.equal(isPrivateOrReservedIp("1:2:3"), true);
  });
});

describe("validateSafePublicUrl / isSafePublicUrlString", () => {
  it("rejects literal private IPs in any notation", () => {
    for (const u of [
      "http://10.1.2.3/",
      "http://192.168.0.10/admin",
      "http://169.254.169.254/latest/meta-data/",
      "http://2130706433/",
      "http://0x7f000001/",
      "http://0177.0.0.1/",
      "http://127.1/",
      "http://[::1]/",
      "http://[fd00::1]/",
      "http://[::ffff:127.0.0.1]/",
      "http://[::ffff:169.254.169.254]/",
    ]) {
      assert.equal(validateSafePublicUrl(u).safe, false, u);
    }
  });

  it("rejects localhost and internal names", () => {
    for (const u of [
      "http://localhost/",
      "http://LOCALHOST./",
      "http://foo.localhost/",
      "http://metadata.google.internal/",
      "http://intranet/",
      "http://10.0.0.1.nip.io/",
      "file:///etc/passwd",
      "http://user:pass@example.com/",
      "http://example.com:8080/",
    ]) {
      assert.equal(validateSafePublicUrl(u).safe, false, u);
    }
  });

  it("accepts public hosts", () => {
    assert.equal(validateSafePublicUrl("https://www.cisa.gov/news-events").safe, true);
    assert.equal(validateSafePublicUrl("http://[2606:4700:4700::1111]/").safe, true);
    assert.equal(isSafePublicUrlString("unit42.paloaltonetworks.com"), true);
    assert.equal(isSafePublicUrlString("https://www.mandiant.com/resources/blog/*"), true);
  });

  it("rejects unsafe stored domains / patterns", () => {
    assert.equal(isSafePublicUrlString("localhost"), false);
    assert.equal(isSafePublicUrlString("169.254.169.254"), false);
    assert.equal(isSafePublicUrlString("https://127.0.0.1/research/*"), false);
    assert.equal(isSafePublicUrlString("[::1]"), false);
    assert.equal(isSafePublicUrlString(""), false);
    assert.equal(isSafePublicUrlString("evil.com path"), false);
  });
});

describe("assertPublicHost (no network needed)", () => {
  it("rejects IP literals and localhost without resolving", async () => {
    await assert.rejects(assertPublicHost(new URL("http://169.254.169.254/")), /SSRF Blocked/);
    await assert.rejects(assertPublicHost(new URL("http://[::1]/")), /SSRF Blocked/);
    await assert.rejects(assertPublicHost(new URL("http://localhost/")), /SSRF Blocked/);
  });

  it("returns public IP literals unchanged", async () => {
    assert.deepEqual(await assertPublicHost(new URL("http://8.8.8.8/")), [{ address: "8.8.8.8", family: 4 }]);
  });
});

describe("fetch helpers refuse internal targets before connecting", () => {
  it("safeFetchResource throws SSRF Blocked", async () => {
    await assert.rejects(safeFetchResource("http://127.0.0.1/"), /SSRF Blocked/);
    await assert.rejects(safeFetchResource("http://[fd00::1]/"), /SSRF Blocked/);
  });

  it("probeUrlSafely reports a blocked probe without throwing", async () => {
    const r = await probeUrlSafely("http://169.254.169.254/latest/meta-data/", { method: "HEAD", timeoutMs: 1000 });
    assert.equal(r.ok, false);
    assert.equal(r.statusCode, null);
    assert.match(r.error ?? "", /SSRF Blocked/);
  });
});
