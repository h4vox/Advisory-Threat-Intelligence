import { test } from "node:test";
import assert from "node:assert/strict";
import { isSrvLookupError, isSrvUri, parseSrvUri, redactMongoUri, seedListUri, srvTargetAllowed } from "./srv-fallback.ts";

const SRV = "mongodb+srv://analyst:p%40ss%2Fword@cluster0.ab12cd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const RECORDS = [
  { name: "ac-1-shard-00-00.ab12cd.mongodb.net", port: 27017 },
  { name: "ac-1-shard-00-01.ab12cd.mongodb.net.", port: 27017 },
  { name: "ac-1-shard-00-02.ab12cd.mongodb.net", port: 27017 },
];
const TXT = [["authSource=admin&replicaSet=atlas-xyz-shard-0"]];

test("recognises SRV connection strings and SRV lookup failures", () => {
  assert.equal(isSrvUri(SRV), true);
  assert.equal(isSrvUri("mongodb://localhost:27017"), false);
  assert.equal(isSrvLookupError(Object.assign(new Error("querySrv ECONNREFUSED _mongodb._tcp.cluster0.ab12cd.mongodb.net"), { code: "ECONNREFUSED", syscall: "querySrv" })), true);
  assert.equal(isSrvLookupError({ message: "queryTxt ETIMEOUT cluster0.ab12cd.mongodb.net" }), true);
  assert.equal(isSrvLookupError({ code: "ENOTFOUND", hostname: "_mongodb._tcp.cluster0.ab12cd.mongodb.net" }), true);
  // Authentication or server-selection failures are not DNS problems.
  assert.equal(isSrvLookupError(new Error("bad auth : authentication failed")), false);
  assert.equal(isSrvLookupError(new Error("connect ECONNREFUSED 127.0.0.1:27017")), false);
  assert.equal(isSrvLookupError(null), false);
});

test("parses the SRV URI, keeping credentials as written", () => {
  const p = parseSrvUri(SRV)!;
  assert.equal(p.userinfo, "analyst:p%40ss%2Fword");
  assert.equal(p.host, "cluster0.ab12cd.mongodb.net");
  assert.equal(p.path, "/");
  assert.equal(p.params.get("appName"), "Cluster0");
  assert.equal(parseSrvUri("mongodb+srv://u:p@a.example.com,b.example.com/"), null);
  assert.equal(parseSrvUri("mongodb+srv://u:p@cluster0.example.com:27017/"), null);
  assert.equal(parseSrvUri("mongodb://u:p@cluster0.example.com/"), null);
  assert.equal(parseSrvUri("mongodb+srv://localhost/"), null);
  assert.equal(parseSrvUri("mongodb+srv://cluster0.ab12cd.mongodb.net/threat-intel-DB")?.path, "/threat-intel-DB");
});

test("SRV targets must share the cluster's parent domain", () => {
  assert.equal(srvTargetAllowed("cluster0.ab12cd.mongodb.net", "ac-1-shard-00-00.ab12cd.mongodb.net"), true);
  assert.equal(srvTargetAllowed("cluster0.ab12cd.mongodb.net", "ac-1-shard-00-00.ab12cd.mongodb.net."), true);
  assert.equal(srvTargetAllowed("cluster0.ab12cd.mongodb.net", "evil.example.com"), false);
  assert.equal(srvTargetAllowed("cluster0.ab12cd.mongodb.net", "ab12cd.mongodb.net.evil.com"), false);
});

test("builds the equivalent seed-list URI from SRV and TXT records", () => {
  const uri = seedListUri(SRV, RECORDS, TXT)!;
  assert.equal(
    uri,
    "mongodb://analyst:p%40ss%2Fword@ac-1-shard-00-00.ab12cd.mongodb.net:27017,ac-1-shard-00-01.ab12cd.mongodb.net:27017,ac-1-shard-00-02.ab12cd.mongodb.net:27017/?authSource=admin&replicaSet=atlas-xyz-shard-0&retryWrites=true&w=majority&appName=Cluster0&tls=true",
  );
});

test("connection-string options win over TXT, TXT is limited to its allowed keys, and TLS can be turned off explicitly", () => {
  const uri = seedListUri("mongodb+srv://cluster0.ab12cd.mongodb.net/db?authSource=other&tls=false", RECORDS.slice(0, 1), [["authSource=admin&replicaSet=rs0&w=0"]])!;
  const params = new URL(uri.replace(/^mongodb:/, "http:")).searchParams;
  assert.equal(params.get("authSource"), "other");
  assert.equal(params.get("replicaSet"), "rs0");
  assert.equal(params.get("w"), null);
  assert.equal(params.get("tls"), "false");
  assert.ok(uri.startsWith("mongodb://ac-1-shard-00-00.ab12cd.mongodb.net:27017/db?"));
});

test("drops foreign SRV targets; returns null when nothing usable is left", () => {
  const mixed = [...RECORDS.slice(0, 1), { name: "attacker.example.com", port: 27017 }];
  const uri = seedListUri(SRV, mixed, TXT)!;
  assert.ok(!uri.includes("attacker"));
  assert.equal(seedListUri(SRV, [{ name: "attacker.example.com", port: 27017 }], TXT), null);
  assert.equal(seedListUri(SRV, [], TXT), null);
  // Several TXT records are ambiguous: ignore them rather than guess.
  assert.ok(!seedListUri(SRV, RECORDS, [["authSource=admin"], ["replicaSet=x"]])!.includes("replicaSet"));
});

test("redacts credentials for logs", () => {
  assert.equal(redactMongoUri(SRV), "mongodb+srv://<credentials>@cluster0.ab12cd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0");
  assert.equal(redactMongoUri("mongodb://localhost:27017/x"), "mongodb://localhost:27017/x");
});

test("explains common MongoDB connection errors in plain words", async () => {
  const { explainMongoError } = await import("./connection-errors.ts");
  assert.match(explainMongoError("querySrv ECONNREFUSED _mongodb._tcp.cluster0.ab12cd.mongodb.net"), /address could not be looked up/);
  assert.match(explainMongoError("bad auth : authentication failed"), /username or password/);
  assert.match(explainMongoError("self-signed certificate in certificate chain"), /certificate/);
  assert.match(explainMongoError("Server selection timed out after 15000 ms"), /Network Access/);
  assert.match(explainMongoError("something else"), /Check MONGODB_URI/);
});
