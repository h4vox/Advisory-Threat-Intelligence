/**
 * Labelled candidate titles for the relevance pre-scorer (unit tests and the precision measurement).
 *
 * `intel` titles are real public report titles: the eval corpus, the seed reports, the curated
 * catalog and well-known vendor / government publications. `junk` titles are realistic examples
 * of what security-vendor feeds also publish (webinars, launches, awards, hiring, earnings,
 * event recaps, marketing). These are test fixtures only and are never stored as intelligence.
 */
export type LabelledTitle = { title: string; url?: string; summary?: string; label: "intel" | "junk" };

export const RELEVANCE_FIXTURES: LabelledTitle[] = [
  // --- eval corpus (scratchpad/eval/raw)
  { label: "intel", title: "Volt Typhoon targets US critical infrastructure with living-off-the-land techniques", url: "https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/" },
  { label: "intel", title: "Octo Tempest crosses boundaries to facilitate extortion, encryption, and destruction", url: "https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/" },
  { label: "intel", title: "Another BRICKSTORM: Stealthy Backdoor Enabling Espionage into Tech and Legal Sectors", url: "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign" },
  { label: "intel", title: "Financially Motivated Threat Actor BREEZE COMET Targets Brazil", url: "https://cloud.google.com/blog/topics/threat-intelligence/financially-motivated-threat-actor-breeze-comet-targets-brazil" },
  { label: "intel", title: "Defending Against UNC3944: Cybercrime Hardening Guidance from the Frontlines", url: "https://cloud.google.com/blog/topics/threat-intelligence/unc3944-proactive-hardening-recommendations" },
  // --- seed reports
  { label: "intel", title: "Lynx ransomware via a single valid RDP logon" },
  { label: "intel", title: "SEO-poisoned installer to Akira ransomware" },
  { label: "intel", title: "Ransomware TTPs: credentials and RDP still dominate" },
  { label: "intel", title: "Third-party IT provider compromise to domain-wide access" },
  // --- curated catalog / discovery pool
  { label: "intel", title: "From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira", url: "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/" },
  { label: "intel", title: "Apache ActiveMQ Exploit Leads to LockBit Ransomware", url: "https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/" },
  { label: "intel", title: "Bissa Scanner Exposed: AI-Assisted Mass Exploitation and Credential Harvesting" },
  { label: "intel", title: "Scattered Spider Multi-Cloud Intrusion and Identity Subversion Analysis" },
  { label: "intel", title: "Sandworm Disruptive ICS Substation Intrusion Campaign Writeup" },
  { label: "intel", title: "CTID Adversary Emulation Plan: LockBit 3.0 (Black)" },
  { label: "intel", title: "BYOVD Exploitation: Stealthy EDR Evasion and Kernel Callback Tampering" },
  { label: "intel", title: "AA26-088A: Volt Typhoon Living-off-the-Land Exploitation of Critical Infrastructure" },
  { label: "intel", title: "Purple Teaming Active Directory: Attack Path Analysis and Domain Tiering" },
  // --- well-known public reports
  { label: "intel", title: "APT44: Unearthing Sandworm", url: "https://cloud.google.com/blog/topics/threat-intelligence/apt44-unearthing-sandworm" },
  { label: "intel", title: "Midnight Blizzard: Guidance for responders on nation-state attack" },
  { label: "intel", title: "#StopRansomware: Black Basta", url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a" },
  { label: "intel", title: "IcedID Brings ScreenConnect and CSharp Streamer to ALPHV Ransomware Deployment" },
  { label: "intel", title: "Cutting Edge, Part 2: Investigating Ivanti Connect Secure VPN Zero-Day Exploitation" },
  { label: "intel", title: "Storm-0558 techniques for unauthorized email access" },
  { label: "intel", title: "PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure" },
  { label: "intel", title: "Threat Actors Exploit CVE-2023-34362 MOVEit Transfer Vulnerability" },
  { label: "intel", title: "Fake Browser Updates Lead to BOINC Volunteer Computing Software" },
  { label: "intel", title: "Analysis of a Lumma Stealer infection delivered through malvertising" },
  { label: "intel", title: "TA577 Hijacks Email Threads to Deliver Pikabot" },
  { label: "intel", title: "FIN7 Revisited: Inside the Threat Group's New Tooling" },
  { label: "intel", title: "Inside a ransomware intrusion: from initial access to domain admin in 48 hours" },
  { label: "intel", title: "Threat Brief: Ongoing Exploitation of a Critical Firewall Vulnerability" },
  { label: "intel", title: "Talos IR trends Q2 2025: Phishing attacks persist as actors leverage compromised valid accounts" },
  { label: "intel", title: "Hunting for persistence via scheduled tasks and WMI event subscriptions" },
  { label: "intel", title: "DEV-0537 criminal actor targeting organizations for data exfiltration and destruction" },
  { label: "intel", title: "Kimsuky deploys new backdoor against South Korean think tanks" },

  // --- realistic vendor-feed junk
  { label: "junk", title: "Webinar: Building a Modern SOC with AI-Driven Detection", url: "https://www.example-vendor.com/resources/webinars/modern-soc" },
  { label: "junk", title: "Join us at RSA Conference 2026 — Visit Booth 1234" },
  { label: "junk", title: "Introducing Falconry XDR 5.0: New Features for Faster Investigations" },
  { label: "junk", title: "Acme Security Named a Leader in the 2026 Gartner Magic Quadrant for Endpoint Protection" },
  { label: "junk", title: "We're Hiring: Senior Detection Engineer (Remote)", url: "https://www.example-vendor.com/careers/senior-detection-engineer" },
  { label: "junk", title: "Acme Security Reports Fourth Quarter and Fiscal Year 2026 Financial Results" },
  { label: "junk", title: "Acme Security Partners with Globex to Deliver Managed Detection in EMEA" },
  { label: "junk", title: "Podcast Episode 42: The Future of Zero Trust" },
  { label: "junk", title: "Black Hat USA 2026 Recap: Highlights from the Show Floor" },
  { label: "junk", title: "5 Tips for Choosing the Right Managed Security Provider" },
  { label: "junk", title: "Acme Security Wins 2026 Cybersecurity Excellence Award" },
  { label: "junk", title: "Now Available: Acme Cloud Posture Management for Google Cloud" },
  { label: "junk", title: "Customer Story: How Initech Cut Alert Fatigue by 60%" },
  { label: "junk", title: "Acme Raises $120M Series C Funding to Accelerate Growth" },
  { label: "junk", title: "Acme Appoints New Chief Revenue Officer" },
  { label: "junk", title: "Register Now: Cloud Security Summit 2026" },
  { label: "junk", title: "Meet the Team: A Day in the Life of Our Customer Success Group" },
  { label: "junk", title: "Release Notes: Platform Update 26.4" },
  { label: "junk", title: "Why You Need Exposure Management in 2026" },
  { label: "junk", title: "This Week in Security: Our Favorite Reads" },
  { label: "junk", title: "Acme Acquires Hooli to Expand Identity Security Portfolio" },
  { label: "junk", title: "On-Demand Webinar: Ransomware Readiness for Healthcare", url: "https://www.example-vendor.com/webinars/ransomware-readiness" },
  { label: "junk", title: "Celebrating Our Employees During the Holiday Season" },
  { label: "junk", title: "Book a Demo of the Acme Platform" },
  { label: "junk", title: "Press Release: Acme Launches Global Partner Program" },
];
