/**
 * Test documents for the technical-depth check, in the shape the crawler's text extraction produces
 * (headings, bullets, `[label](url)` links). They mirror the cases seen in the library: a vendor
 * product page that was stored at 72% quality, a strategic assessment, a news rewrite of an
 * advisory, a government advisory on an exploited CVE, a campaign summary, an indicator appendix and
 * a non-English page. Synthetic text: indicators use documentation IP ranges and placeholder hashes.
 */

const FOOTER = [
  "Products and Services",
  "* [AI-Powered Network Security Platform](https://www.vendor.example/network-security)",
  "* [Advanced Threat Prevention](https://www.vendor.example/advanced-threat-prevention)",
  "* [Threat Intel and Incident Response Services](https://www.vendor.example/research)",
  "* [Respond to a Cyber Attack](https://www.vendor.example/research/respond)",
  "Company",
  "* [About Us](https://www.vendor.example/about-us)",
  "* [Contact Us](https://www.vendor.example/company/contact-sales)",
].join("\n");

export const PRODUCT_PAGE = {
  title: "Endpoint Privilege Manager",
  url: "https://www.vendor.example/identity/human/endpoint-privilege-manager",
  text: [
    "Endpoint Privilege Manager",
    "Overprivileged users and applications remain a critical gap in the endpoint security stack. Close the gap without adding a burden to your IT operations.",
    "* [Request demo](https://www.vendor.example/identity/human/endpoint-privilege-manager#contact-us)",
    "* [Learn more](https://www.vendor.example/resources/techbriefs/securing-endpoints)",
    "[Key Capabilities & Features](https://www.vendor.example/epm#key-capabilities)",
    "Challenges",
    "Identity is the primary vector in most breaches. Local admin rights invite attackers, and one compromised endpoint enables lateral movement.",
    "SOLUTIONS",
    "The platform replaces standing admin rights with just-in-time elevation while maintaining seamless business velocity, and it adapts to changing risks, including ransomware that relies on admin rights.",
    "KEY CAPABILITIES & FEATURES",
    "Application ringfencing blocks living off the land attacks and aligns with NIST and MITRE ATT&CK® guidance.",
    "* 274%",
    "average ROI over 3 years.",
    "Benefits & Values",
    "Real results from the identity security leader: a business value assessment shows customers achieve measurable cost savings.",
    "CUSTOMERS",
    "Trusted by global leaders to secure their most critical assets.",
    "Talk to an expert, and get started today.",
    "Resources",
    "DatasheetSolution BriefeBookWhitepaperWebinarBlog",
    "[Datasheet](https://www.vendor.example/resources/datasheets/epm)",
    "Why choose EPM over other products?",
    "Single management console and single agent, with out-of-the-box templates and policies. Repeatedly recognized by industry analysts as a leading solution.",
    FOOTER,
  ].join("\n"),
};

export const STRATEGIC_ASSESSMENT = {
  title: "Impact of AI on the cyber threat from now to 2027",
  url: "https://www.ncsc.gov.uk/report/impact-ai-cyber-threat-now-2027",
  text: [
    "Key judgements",
    "Artificial intelligence will almost certainly make elements of cyber intrusion operations more effective, increasing the frequency and intensity of threats by 2027.",
    "We assess that there will almost certainly be a divide between systems that keep pace with AI-enabled threats and systems that remain more vulnerable.",
    "It is highly likely that the threat landscape will keep shifting. There is a realistic possibility that critical systems become more exposed to capable actors by 2027.",
    "Over the next two years we expect criminals to use AI to improve reconnaissance and phishing, and we assess that current trends in vulnerability exploitation will continue.",
    "Context",
    "This assessment uses the probabilistic language of the intelligence assessment yardstick. Organisations should treat cyber security as a board-level risk and prioritise resilience.",
    "The outlook depends on how quickly defenders adopt AI. Survey data from respondents suggests that, on average, the percentage of incidents involving AI doubled.",
  ].join("\n"),
};

export const NEWS_REWRITE = {
  title: "Act now: cyber agency updates NetScaler critical alert to include brand-new vulnerability",
  url: "https://www.cyberdaily.au/security/14282-act-now-cyber-agency-updates-netscaler-critical-alert",
  text: [
    "The national cyber agency has updated its critical alert on NetScaler appliances to include a brand-new vulnerability, urging organisations to patch immediately.",
    "The flaw, tracked as CVE-2026-71234, affects NetScaler ADC and Gateway, and the vendor says it has been exploited in the wild.",
    "\"Organisations should apply the updates as soon as possible,\" an agency spokesperson said in a statement.",
    "The vendor said customers on affected builds should upgrade, and noted the issue only affects appliances configured as a gateway.",
    "The alert follows several high-profile incidents involving the same appliances over the past year, the agency said.",
  ].join("\n"),
};

export const GOVERNMENT_ADVISORY = {
  title: "Critical vulnerability in NetScaler ADC and Gateway actively exploited (CVE-2026-71234)",
  url: "https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/critical-netscaler-vulnerability",
  text: [
    "ASD's ACSC is aware of active exploitation of CVE-2026-71234, a critical vulnerability affecting NetScaler ADC and NetScaler Gateway appliances configured as a gateway.",
    "Threat actors have been exploiting the vulnerability against Australian organisations. Affected versions are listed in the vendor bulletin.",
    "Mitigation",
    "Upgrade to a fixed build immediately and review appliance logs for indicators of compromise. Report any compromise to ASD's ACSC.",
  ].join("\n"),
};

export const CAMPAIGN_SUMMARY = {
  title: "UNC9999 targets logistics firms with fake invoice lures",
  url: "https://research.vendor.example/blog/unc9999-logistics-campaign",
  text: [
    "Since June, we have tracked UNC9999, a financially motivated cluster, in a campaign against logistics companies in Europe.",
    "The campaign starts with phishing emails that carry invoice lures. Victims who open the attachment receive a loader that retrieves the group's backdoor.",
    "The backdoor maintains persistence through a scheduled task and communicates with command-and-control servers hosted on rented VPS infrastructure.",
    "After gaining access, the operators performed reconnaissance of the victim environment, harvested credentials and moved laterally before exfiltrating data to cloud storage.",
    "In two cases the intrusion ended with extortion demands. We share detection opportunities for each stage in the appendix.",
  ].join("\n"),
};

export const INDICATOR_APPENDIX = {
  title: "Appendix: indicators for the UNC9999 campaign",
  url: "https://research.vendor.example/blog/unc9999-indicators",
  text: [
    "Indicators of compromise",
    "| Type | Value |",
    "| SHA-256 | 0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0 |",
    "| SHA-256 | 1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809 |",
    "| IP | 198.51.100[.]23 |",
    "| IP | 203.0.113.77 |",
    "| Domain | invoice-portal[.]example |",
    "Technique mapping: T1566.001, T1053.005.",
  ].join("\n"),
};

export const NON_ENGLISH = {
  title: "Podatności w routerach aktywnie wykorzystywane",
  url: "https://cert.pl/posts/2026/09/podatnosci-w-routerach-aktywnie-wykorzystywane",
  text: [
    "Zespół CERT Polska otrzymał zgłoszenia dotyczące aktywnego wykorzystywania podatności w routerach.",
    "Atakujący wykorzystują błąd w panelu administracyjnym, aby przejąć kontrolę nad urządzeniem i zmienić jego konfigurację.",
    "Zalecamy niezwłoczną aktualizację oprogramowania do najnowszej wersji oraz zmianę haseł dostępowych.",
    "Prosimy o zgłaszanie incydentów za pośrednictwem formularza na naszej stronie. Właściciele urządzeń powinni sprawdzić, czy nie zostały one zmodyfikowane.",
    "Więcej informacji o podatności znajduje się w komunikacie producenta, który opublikował poprawki dla wszystkich wspieranych modeli.",
  ].join("\n"),
};
