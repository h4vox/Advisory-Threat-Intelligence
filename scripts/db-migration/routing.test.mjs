import { test } from "node:test";
import assert from "node:assert/strict";
import {
  APP_DB,
  DOC_TYPE_ROUTES,
  INTEL_DB,
  TABLES,
  appIdOf,
  docSha256,
  isoOf,
  mongoIdString,
  routeDocument,
  stripNul,
} from "./routing.mjs";

test("main collection is routed by docType", () => {
  assert.deepEqual(routeDocument("threat-intel", { docType: "report" }), { db: INTEL_DB, table: "reports" });
  assert.deepEqual(routeDocument("threat-intel", { docType: "agent_chat_message" }), { db: APP_DB, table: "agent_chat_messages" });
  assert.deepEqual(routeDocument("threat-intel", { docType: "marketplace_integration" }), { db: APP_DB, table: "integrations" });
  assert.deepEqual(routeDocument("threat-intel", { docType: "crawl_config" }), { db: APP_DB, table: "app_state" });
});

test("a renamed main collection (MONGODB_COLLECTION) is still routed by docType", () => {
  assert.deepEqual(routeDocument("intel-prod", { docType: "source" }, "intel-prod"), { db: INTEL_DB, table: "sources" });
});

test("dedicated collections", () => {
  assert.deepEqual(routeDocument("aie_users", {}), { db: APP_DB, table: "users" });
  assert.deepEqual(routeDocument("aie_sessions", {}), { db: APP_DB, table: "auth_sessions" });
  assert.deepEqual(routeDocument("aie_advisories", {}), { db: INTEL_DB, table: "advisories" });
});

test("unknown collections and docTypes are kept, never dropped", () => {
  assert.deepEqual(routeDocument("threat-intel", { docType: "something_new" }), { db: APP_DB, table: "unclassified_documents" });
  assert.deepEqual(routeDocument("threat-intel", {}), { db: APP_DB, table: "unclassified_documents" });
  assert.deepEqual(routeDocument("random_collection", { docType: "report" }), { db: APP_DB, table: "unclassified_documents" });
});

test("every route points at a table the schema creates", () => {
  for (const [db, table] of Object.values(DOC_TYPE_ROUTES)) assert.ok(TABLES[db].includes(table), `${db}.${table}`);
});

test("stripNul removes NUL from strings and keys, keeps everything else", () => {
  const { value, removed } = stripNul({ a: "x\u0000y", "k\u0000": [1, "\u0000\u0000", { b: true, c: null }], n: 2.5 });
  assert.deepEqual(value, { a: "xy", k: [1, "", { b: true, c: null }], n: 2.5 });
  assert.equal(removed, 4);
  const same = { a: "plain" };
  assert.equal(stripNul(same).removed, 0);
});

test("docSha256 ignores key order", () => {
  assert.equal(docSha256({ a: 1, b: { c: 2, d: [1, 2] } }), docSha256({ b: { d: [1, 2], c: 2 }, a: 1 }));
  assert.notEqual(docSha256({ a: 1 }), docSha256({ a: 2 }));
});

test("ids and dates from Extended JSON", () => {
  assert.equal(mongoIdString({ $oid: "65f0c0ffee" }), "65f0c0ffee");
  assert.equal(mongoIdString("cfg_default"), "cfg_default");
  assert.equal(appIdOf({ id: "rpt_1" }, "oid"), "rpt_1");
  assert.equal(appIdOf({}, "oid"), "oid");
  assert.equal(isoOf({ $date: "2026-10-26T00:00:00Z" }), "2026-10-26T00:00:00Z");
  assert.equal(isoOf({ $date: { $numberLong: "0" } }), "1970-01-01T00:00:00.000Z");
  assert.equal(isoOf("2026-10-26"), "2026-10-26");
  assert.equal(isoOf("not a date"), null);
});
