/** Samples for ./emulation-simulation tests: research write-ups an emulation or simulation team wants, and notices it does not. */

/** An infection-chain write-up (public research summary, ClickFix delivery platform). */
export const CLICKFIX_CHAIN = {
  title: "ROMULUS: A New Multi-Payload ClickFix Delivery Platform",
  text: `Researchers identified ROMULUS, a reusable ClickFix delivery platform across six IP addresses. It distributes different payloads through token-based PowerShell and installer routes.
Researchers analyzed two infection chains: Route A uses a trojanized MSI installer and DLL sideloading. Route B uses nested encrypted archives to deploy LegionLoader.
ROUTE A — TROJANIZED MSI AND DLL SIDELOADING
• PowerShell downloads IconEdit2Turb.msi through a decimal-IP URL.
• The installer lands in %TEMP%; Unblock-File removes its download restriction.
• msiexec.exe installs it silently using /qn and /norestart.
• An installer action launches legitimate Stardock DeElevate64.exe.
• It loads patched DeElevator64.dll, which introduces a dependency on malicious I++u.dll.
• This loader uses additional packaged components, including Build.dat and encrypted payload storage.
ROUTE B — ENCRYPTED ARCHIVES AND LEGIONLOADER
• PowerShell hides its console and downloads an encrypted archive from orbitflownetwork[.]lol.
• Legitimate 7zr.exe, downloaded from GitHub, extracts two nested password-protected archives.
• Extraction produces five .bin files and an executable padded to approximately 842 MiB, potentially exceeding scanner limits.
• The executable decrypts embedded shellcode using AES-256 and reverses the decrypted bytes.
• Shellcode repeats decryption and byte reversal, then manually maps LegionLoader into memory.
• LegionLoader contacts smashshape[.]com for tasking and reports results through RC4/Base64-protected messages.`,
};

/** A DLL side-loading procedure walk-through. */
export const SIDELOADING_PROCEDURE = {
  title: "BRONZE SANDCASTLE deploys modified Meterpreter shells",
  text: `Researchers investigated incidents attributed to BRONZE SANDCASTLE, a China-based threat group, in which the most distinctive technique was the consistent use of DLL sideloading.
1. The archive aez.zip contains the legitimate executable, malicious DLL, and encrypted payload. dllhost.exe reads the archive.
2. dllhost.exe wrote javaw.exe, jli.dll, and config.ini under C:\\ProgramData\\Microsoft\\AppV.
3. Once javaw.exe runs, it loads the attacker-controlled jli.dll placed beside it. This loading event is the actual DLL sideloading step.
4. The sideloaded DLL reads config.ini and decodes its contents at runtime. Despite its .ini extension, this file contains an encrypted executable payload.
5. A custom, position-independent PE loader within the decoded payload maps an embedded PE image into memory and transfers control to its entry point.
This progresses from reading encrypted data to executing the decoded backdoor in memory, reducing the need to write a separate decrypted executable to disk. The backdoor then beacons to its command-and-control server.`,
};

/** A vendor patch notice: CVE, CVSS, fixed versions, no attacker procedures. */
export const PATCH_NOTICE = {
  title: "Veeam Backup & Replication CVE-2026-108142 Patch",
  text: `Veeam has released security updates to address a critical vulnerability in Veeam Backup & Replication tracked as CVE-2026-108142 with a CVSS score of 9.9.
The flaw allows an authenticated domain user to achieve remote code execution on the backup server. Affected versions include 12.3.1.1139 and all earlier version 12 builds.
The vendor has released version 12.3.2.3617, which fixes the issue. Customers are urged to upgrade to version 12.3.2.3617 as soon as possible and apply the latest updates.
There is no evidence the vulnerability has been exploited in the wild. Workarounds are not available. Backup servers are attractive targets for ransomware operators, who have exploited earlier Veeam flaws.`,
};

/** The same notice with background on earlier attacks: passes the depth check, still nothing to replay. */
export const PATCH_NOTICE_WITH_BACKGROUND = {
  title: PATCH_NOTICE.title,
  text: `${PATCH_NOTICE.text}
Threat actors such as Akira have exploited earlier Veeam flaws for initial access through VPN appliances, followed by credential theft, lateral movement, data exfiltration and ransomware deployment. Phishing and brute-force attacks against exposed services remain common.`,
};

/** A news rewrite of a breach, no technical detail. */
export const BREACH_NEWS = {
  title: "Retailer confirms data breach after ransomware attack",
  text: `The retailer said on Tuesday that it had detected unauthorized activity on its network last month and engaged outside experts. The company said customer names and email addresses may have been accessed.
A ransomware group later claimed responsibility on its leak site. The company has notified law enforcement and says stores remain open. Analysts said the attack shows how retailers remain an attractive target.`,
};
