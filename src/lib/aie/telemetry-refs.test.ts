import { test } from "node:test";
import assert from "node:assert/strict";
import { extractTelemetryRefs } from "./telemetry-refs.ts";

test("event IDs are read with their log and meaning, with the sentence that names them", () => {
  const t = extractTelemetryRefs(
    "Look for events with EventID 4624 where the logon type is 10. Script Block Logging (Event ID 4104) records the decoded script.\n" +
      "Sysmon Event ID 1 and Event ID 3 show the process and its connection. Event IDs 4698, 4702 cover the scheduled task.",
  );
  const byId = Object.fromEntries(t.events.map((e) => [e.id, e]));
  assert.equal(byId["4624"].log, "Windows Security");
  assert.equal(byId["4624"].meaning, "successful logon");
  assert.match(byId["4624"].quote, /^Look for events with EventID 4624 where the logon type is 10\.$/);
  assert.equal(byId["4104"].log, "PowerShell");
  assert.equal(byId["Sysmon 1"].meaning, "process created");
  assert.equal(byId["Sysmon 3"].meaning, "network connection");
  assert.equal(byId["4698"].meaning, "scheduled task created");
  assert.equal(byId["4702"].meaning, "scheduled task updated");
});

test("small numbers with no named log are not reported, and years are never event IDs", () => {
  const t = extractTelemetryRefs("The campaign ran in 2026. Event ID 7 was seen. Version 4688 of the tool was released.");
  assert.deepEqual(t.events, []);
});

test("log sources are named with a prose sentence rather than a bare code line", () => {
  const t = extractTelemetryRefs(
    "DeviceProcessEvents\n| where FileName == \"x.exe\"\n\nMicrosoft Defender XDR customers can run the following advanced hunting queries to find related activity.\n" +
      "Review AWS CloudTrail for CreateAccessKey calls by unusual principals. The actor cleared the Security event logs with wevtutil.\n" +
      "cp /etc/syslog.conf /tmp/x",
  );
  const names = t.sources.map((s) => s.name);
  assert.ok(names.includes("Microsoft Defender XDR advanced hunting"));
  assert.match(t.sources.find((s) => s.name === "Microsoft Defender XDR advanced hunting")!.quote, /customers can run the following advanced hunting queries/);
  assert.ok(names.includes("AWS CloudTrail"));
  assert.ok(names.includes("Windows Security event log"));
  assert.ok(!names.includes("Syslog"), "a config file path is not a log source");
});

test("published detection content is counted by kind", () => {
  const text = [
    "DeviceProcessEvents",
    "| where ProcessCommandLine has \"-enc\"",
    "SigninLogs | where ResultType == 0",
    "",
    "title: Suspicious shadow copy deletion",
    "logsource:",
    "  product: windows",
    "  category: process_creation",
    "detection:",
    "  selection:",
    "    Image|endswith: '\\\\vssadmin.exe'",
    "  condition: selection",
    "",
    "rule EXAMPLE_Loader : loader {",
    "  strings:",
    "    $a = \"example\"",
    "  condition:",
    "    $a",
    "}",
    "alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:\"example\"; sid:1;)",
    "index=windows sourcetype=WinEventLog EventCode=4688 | stats count by host",
  ].join("\n");
  const kinds = Object.fromEntries(extractTelemetryRefs(text).content.map((c) => [c.kind, c.count]));
  assert.equal(kinds.kql, 2);
  assert.equal(kinds.sigma, 1);
  assert.equal(kinds.yara, 1);
  assert.equal(kinds.suricata, 1);
  assert.equal(kinds.spl, 1);
});

test("prose about rules is not detection content", () => {
  assert.deepEqual(extractTelemetryRefs("We published Sigma rules and YARA rules. The condition: is simple; strings matter.").content, []);
});
