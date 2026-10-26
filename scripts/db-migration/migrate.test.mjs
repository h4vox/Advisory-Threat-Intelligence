import { test } from "node:test";
import assert from "node:assert/strict";
import { BSON } from "mongodb";
import { redact, toRow } from "./migrate.mjs";

const { Long, ObjectId, Binary, Decimal128 } = BSON;

test("toRow keeps BSON values exactly (large 64-bit integers included)", () => {
  const oid = new ObjectId("6adf3aa8d4c57a4c56ab0e52");
  const row = toRow("threat-intel", {
    _id: oid,
    docType: "report",
    id: "rpt_1",
    big: Long.fromString("9007199254740993"),
    small: Long.fromNumber(42),
    at: new Date("2026-01-03T04:05:06Z"),
    price: Decimal128.fromString("12.345"),
    blob: new Binary(Buffer.from("hello")),
    nested: [{ deep: Long.fromString("-9223372036854775808") }],
  });
  assert.equal(row.db, "aie_intel");
  assert.equal(row.table, "reports");
  assert.equal(row.mongoId, "6adf3aa8d4c57a4c56ab0e52");
  assert.equal(row.id, "rpt_1");
  assert.deepEqual(row.json.big, { $numberLong: "9007199254740993" });
  assert.equal(row.json.small, 42);
  assert.deepEqual(row.json.at, { $date: "2026-01-03T04:05:06Z" });
  assert.deepEqual(row.json.price, { $numberDecimal: "12.345" });
  assert.deepEqual(row.json.nested[0].deep, { $numberLong: "-9223372036854775808" });
  // Round trip: the stored JSON reads back as the same BSON values.
  const back = BSON.EJSON.deserialize(row.json, { relaxed: false });
  assert.equal(back.big.toString(), "9007199254740993");
  assert.equal(back.at.toISOString(), "2026-01-03T04:05:06.000Z");
});

test("toRow strips NUL and counts it; the checksum is stable", () => {
  const a = toRow("threat-intel", { _id: "x", docType: "report", t: "a\u0000b" });
  const b = toRow("threat-intel", { t: "a\u0000b", docType: "report", _id: "x" });
  assert.equal(a.json.t, "ab");
  assert.equal(a.nulRemoved, 1);
  assert.equal(a.sha, b.sha);
});

test("redact hides the password in connection strings", () => {
  assert.equal(redact("mongodb+srv://user:secret@host/db"), "mongodb+srv://user:***@host/db");
  assert.equal(redact("postgres://aie:p%40ss@127.0.0.1:5432/aie_app"), "postgres://aie:***@127.0.0.1:5432/aie_app");
  assert.equal(redact("mongodb://127.0.0.1:27017/"), "mongodb://127.0.0.1:27017/");
});
