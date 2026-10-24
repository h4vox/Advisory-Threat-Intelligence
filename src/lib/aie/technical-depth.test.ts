import { test } from "node:test";
import assert from "node:assert/strict";
import { articleProse, assessTechnicalDepth, detectLanguage } from "./technical-depth.ts";
import { qualifyContent } from "./qualification.ts";
import {
  CAMPAIGN_SUMMARY,
  GOVERNMENT_ADVISORY,
  INDICATOR_APPENDIX,
  NEWS_REWRITE,
  NON_ENGLISH,
  PRODUCT_PAGE,
  STRATEGIC_ASSESSMENT,
} from "./__fixtures__/depth-samples.ts";

test("articleProse drops link-only lines (menus, footers, resource lists) and keeps text", () => {
  const prose = articleProse(PRODUCT_PAGE.text);
  assert.ok(!prose.includes("Threat Intel and Incident Response Services"), "footer link list is not content");
  assert.ok(!prose.includes("Request demo"), "a call-to-action link line is not content");
  assert.ok(prose.includes("Overprivileged users and applications"), "prose stays");
  // A link inside a sentence keeps its label.
  assert.equal(articleProse("Read the [full report](https://x.example/r) for details."), "Read the full report for details.");
});

test("the reported product page is rejected as marketing, despite 'lateral movement', 'ransomware' and ATT&CK", () => {
  const v = assessTechnicalDepth(PRODUCT_PAGE);
  assert.equal(v.pass, false);
  assert.equal(v.kind, "product_marketing");
  assert.match(v.reasons[0], /Product or marketing page/);
  // The crawler's qualifier used to approve it (72%, INTRUSION_REPORT from the footer).
  const q = qualifyContent(PRODUCT_PAGE.text, PRODUCT_PAGE.title, PRODUCT_PAGE.url);
  assert.equal(q.qualified, false);
  assert.match(q.rejectionReason ?? "", /Product or marketing page/);
});

test("strategic assessments and news rewrites are rejected with the reason", () => {
  const strategic = assessTechnicalDepth(STRATEGIC_ASSESSMENT);
  assert.equal(strategic.pass, false);
  assert.equal(strategic.kind, "strategic");

  const news = assessTechnicalDepth(NEWS_REWRITE);
  assert.equal(news.pass, false);
  assert.equal(news.kind, "news");
  assert.match(news.reasons[0], /News coverage without technical detail/);
});

test("a government advisory on an exploited CVE passes; the same facts in a news rewrite do not", () => {
  const advisory = assessTechnicalDepth(GOVERNMENT_ADVISORY);
  assert.equal(advisory.pass, true, advisory.reasons.join("; "));
  assert.ok(advisory.anchors.some((a) => /exploited CVE/.test(a)));
  assert.equal(assessTechnicalDepth(NEWS_REWRITE).pass, false);
});

test("described attacker activity by a named actor passes without indicators", () => {
  const v = assessTechnicalDepth(CAMPAIGN_SUMMARY);
  assert.equal(v.pass, true, v.reasons.join("; "));
  assert.deepEqual(v.stats.actors, ["UNC9999"]);
  assert.ok(v.stats.behaviours.length >= 5, v.stats.behaviours.join(", "));
});

test("indicators and technique IDs are hard evidence; defanged values count, private and version-like numbers do not", () => {
  const v = assessTechnicalDepth(INDICATOR_APPENDIX);
  assert.equal(v.pass, true);
  assert.equal(v.stats.techniques, 2);
  assert.equal(v.stats.indicators, 5, "2 hashes, 2 IPs (one defanged), 1 defanged domain");

  const noise = assessTechnicalDepth({
    title: "Release notes",
    url: "https://vendor.example/blog/release-notes-update",
    text: "Upgrade to version 10.2.3.4 today. The appliance listens on 192.168.1.10 and 10.0.0.5 by default. ".repeat(4),
  });
  assert.equal(noise.stats.indicators, 0);
  assert.equal(noise.pass, false);
});

test("a non-English page without hard evidence waits for translation instead of being judged", () => {
  const v = assessTechnicalDepth(NON_ENGLISH);
  assert.equal(v.pass, false);
  assert.equal(v.kind, "non_english");
  assert.equal(v.language, "pl");
});

test("detectLanguage: English by stopwords, others by script and common words", () => {
  assert.equal(detectLanguage(CAMPAIGN_SUMMARY.text).lang, "en");
  assert.equal(detectLanguage(NON_ENGLISH.text).lang, "pl");
  assert.equal(detectLanguage("Die Angreifer nutzen die Schwachstelle und werden nicht gestoppt, weil die Systeme mit alten Versionen und ohne Updates laufen. Die Betreiber werden aufgefordert, die Updates mit hoher Priorität einzuspielen und die Systeme nicht ungeschützt zu lassen, denn die Lücke wird mit hoher Wahrscheinlichkeit weiter ausgenutzt und die Folgen sind nicht absehbar.").lang, "de");
  assert.equal(detectLanguage("攻撃者は脆弱性を悪用して、システムに不正にアクセスしました。このキャンペーンは、複数の組織を標的にしています。").lang, "ja");
});

test("detectLanguage: an English page that is mostly an indicator table is never taken for another language", () => {
  const rows = Array.from({ length: 60 }, (_, i) => `| 203.0.113.${i} | per-host beacon | ${"ab".repeat(16)} | per day |`).join("\n");
  for (const text of [`Indicators of compromise\n\n${rows}`, `${"Requests per second per host per day were logged. ".repeat(15)}${rows}`]) {
    const d = detectLanguage(text, "en-US");
    assert.ok(d.english || d.lang === "und", d.lang);
  }
});

test("detectLanguage: Latin-script languages by several different function words", () => {
  const samples: Array<[string, string]> = [
    ["fr", "Les attaquants ont exploité une vulnérabilité dans le serveur pour obtenir un accès initial. Ils ont ensuite déployé des outils qui sont utilisés pour voler des identifiants, avec une persistance sur les machines. Cette campagne vise des organisations dans plusieurs pays et les opérateurs sont toujours actifs, car leur infrastructure n'est pas encore démantelée. Des correctifs sont disponibles pour ces produits et doivent être appliqués avec priorité."],
    ["es", "Los atacantes explotaron una vulnerabilidad en el servidor para obtener acceso inicial. Después desplegaron herramientas que son usadas para robar credenciales, con persistencia en los equipos. Esta campaña apunta a organizaciones de varios países y los operadores siguen activos, porque su infraestructura no fue desmantelada. Las actualizaciones para estos productos están disponibles y deben aplicarse con prioridad, como recomienda el fabricante en sus avisos."],
    ["nl", "De aanvallers hebben een kwetsbaarheid in de server misbruikt voor initiële toegang. Daarna werden hulpmiddelen ingezet die worden gebruikt voor het stelen van inloggegevens, met persistentie op de systemen. Deze campagne richt zich op organisaties in verschillende landen en de operators zijn nog actief, omdat hun infrastructuur niet is ontmanteld. Updates voor deze producten zijn beschikbaar en moeten met voorrang worden geïnstalleerd, zoals de leverancier ook adviseert bij de publicatie van het advies."],
    ["it", "Gli aggressori hanno sfruttato una vulnerabilità del server per ottenere l'accesso iniziale. Successivamente sono stati distribuiti strumenti che vengono usati per rubare le credenziali, con persistenza sulle macchine. Questa campagna colpisce organizzazioni di diversi paesi e gli operatori sono ancora attivi, perché la loro infrastruttura non è stata smantellata. Gli aggiornamenti per questi prodotti sono disponibili e devono essere applicati con priorità, come indicato anche nella comunicazione del produttore."],
    ["pt", "Os atacantes exploraram uma vulnerabilidade no servidor para obter acesso inicial. Depois foram implantadas ferramentas que são usadas para roubar credenciais, com persistência nas máquinas. Esta campanha visa organizações de vários países e os operadores continuam ativos, pois a infraestrutura não foi desmantelada. As atualizações para estes produtos estão disponíveis e devem ser aplicadas com prioridade, como também recomenda o fabricante nos seus avisos de segurança."],
  ];
  for (const [lang, text] of samples) assert.equal(detectLanguage(text).lang, lang, text.slice(0, 40));
});

const DETECTION_POST = {
  title: "Detecting LSASS memory access with Sigma",
  url: "https://example-research.org/blog/lsass-access-detection",
  text: [
    "This post explains how to detect credential dumping from LSASS on Windows endpoints.",
    "The rule below fires when a process opens LSASS with read access. It relies on Sysmon process access events.",
    "",
    "title: LSASS memory access by an unusual process",
    "status: experimental",
    "tags:",
    "  - attack.credential_access",
    "  - attack.t1003.001",
    "logsource:",
    "  product: windows",
    "  category: process_access",
    "detection:",
    "  selection:",
    "    TargetImage|endswith: '\\lsass.exe'",
    "    GrantedAccess: '0x1010'",
    "  condition: selection",
    "falsepositives:",
    "  - Backup and monitoring agents",
    "",
    "Tune the rule for your environment before enabling it in production. Expect a few false positives from monitoring agents.",
  ].join("\n"),
};

test("detection research with a published rule passes, and Sigma's lowercase tags count as technique IDs", () => {
  const v = assessTechnicalDepth(DETECTION_POST);
  assert.equal(v.pass, true, v.reasons.join("; "));
  assert.equal(v.stats.techniques, 1);
  assert.equal(v.stats.detectionRules, 1);
  assert.ok(v.anchors.some((a) => /detection rule/.test(a)), v.anchors.join("; "));
});

test("hunting queries count only when there are several real ones; talking about rules does not", () => {
  const twoQueries = assessTechnicalDepth({
    title: "Hunting for suspicious service creation",
    url: "https://example-research.org/blog/hunt-services",
    text: "Use these queries to hunt for new services installed from temporary folders.\nDeviceProcessEvents\n| where FileName =~ \"sc.exe\"\n| where ProcessCommandLine has \"create\"\n\nDeviceRegistryEvents\n| where RegistryKey has @\"SYSTEM\\CurrentControlSet\\Services\"\n| project Timestamp, DeviceName",
  });
  assert.equal(twoQueries.stats.detectionQueries, 2);
  assert.equal(twoQueries.pass, true, twoQueries.reasons.join("; "));
  const talk = assessTechnicalDepth({
    title: "Why detection engineering matters",
    url: "https://example-research.org/blog/why-detection",
    text: "Organizations should write Sigma rules and YARA rules. We recommend best practices for detection rules, governance and maturity. Security leaders should invest in detection engineering roadmaps. ".repeat(4),
  });
  assert.equal(talk.pass, false);
  assert.equal(talk.stats.detectionRules + talk.stats.detectionQueries, 0);
});
