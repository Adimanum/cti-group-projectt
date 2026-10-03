# Week 1 — Cyber Threat Intelligence Fundamentals

**Group:** CS-2426 · Dilnaz Estaikyzy, Ademi Akmaganbet  
**Project topic:** Detection and analysis of threats distributed via AI-era phishing-as-a-service kits, using OSINT, MISP, YARA and Sigma  
**Case study:** Tycoon2FA, an Adversary-in-the-Middle (AiTM) Phishing-as-a-Service (PhaaS) platform (active since August 2023, still evolving in 2026)

**Syllabus tasks (§3.3, Week 1):** (1) create a glossary of key CTI terms; (2) classify different types of threats and their sources.

## 1. Why this case

Tycoon2FA is one of the most active and best-documented phishing platforms of 2025–2026.
At its peak it accounted for about 62% of the phishing attempts blocked by Microsoft and reached more than 500,000 organisations a month (Elastic Security Labs, 2026).
It is rented as a subscription service to low-skill attackers. It hides its JavaScript with invisible Unicode characters and bypasses MFA by relaying session cookies in real time.
Vendors have published indicators (eSentire) and a YARA rule (Trustwave) for it.
This makes it a good case for the full CTI cycle used in this course: **OSINT collection → processing and storage in MISP → detection rules (YARA / Sigma) → Kill Chain / ATT&CK mapping → hunting**.

## 2. Glossary of key terms

### 2.1 General CTI terms

| # | Term | Definition |
|---|---|---|
| 1 | **Cyber Threat Intelligence (CTI)** | Evidence-based knowledge about existing or emerging threats (context, mechanisms, indicators, implications) that helps defenders make decisions. |
| 2 | **Intelligence cycle** | The process that turns raw data into intelligence: *Direction → Collection → Processing → Analysis → Dissemination → Feedback*. Weeks 1–3 of this project follow its first steps. |
| 3 | **Strategic / Operational / Tactical / Technical intelligence** | Four levels of CTI: trends and risk for executives; campaigns and actors for security managers; TTPs for defenders; concrete IOCs for tools (SIEM, EDR, firewall). |
| 4 | **IOC (Indicator of Compromise)** | A technical artifact (IP, domain, URL, file hash, file name) that indicates a specific attack or tool. |
| 5 | **IOA (Indicator of Attack)** | An indicator of attacker *behaviour* (for example, a successful sign-in with a script User-Agent) rather than of a specific artifact. |
| 6 | **TTP (Tactics, Techniques and Procedures)** | *How* an adversary operates, described in MITRE ATT&CK (for example T1557 Adversary-in-the-Middle). |
| 7 | **Pyramid of Pain** | Model showing that hashes, IPs and domains are easy for attackers to change, while TTPs are hard to change. Detection should therefore also target behaviour. |
| 8 | **OSINT** | Open-Source Intelligence: intelligence collected from publicly available sources (vendor blogs, Shodan, WHOIS/RDAP, certificate logs). |
| 9 | **TLP (Traffic Light Protocol)** | Sharing labels (`TLP:CLEAR`, `GREEN`, `AMBER`, `AMBER+STRICT`, `RED`) that define who may receive information. |
| 10 | **Admiralty Code (NATO system)** | Rates a source's reliability (A–F) and the credibility of its information (1–6). |
| 11 | **MISP** | Open-source Threat Intelligence Platform for storing, correlating and sharing IOCs as *events* and *attributes*. |
| 12 | **STIX / TAXII** | Standard format (STIX) and transport protocol (TAXII) for exchanging threat intelligence between tools. |
| 13 | **YARA** | Pattern-matching language for identifying files (malware, phishing pages) by text or binary patterns. |
| 14 | **Sigma** | Generic, SIEM-independent format for writing detection rules over logs. It can be converted to Splunk, KQL, Elastic and other query languages. |
| 15 | **Threat Intelligence Feed** | A regularly updated stream of indicators or reports from vendors or communities (for example, eSentire IOC lists or MISP feeds). |
| 16 | **Defanging** | Making an indicator non-clickable (`evil[.]com`, `hxxps://`) so it can be shared safely. |

### 2.2 Case-specific terms (phishing / AiTM)

| # | Term | Definition |
|---|---|---|
| 17 | **PhaaS (Phishing-as-a-Service)** | A subscription-based criminal business model in which a ready-made phishing kit and infrastructure are rented to other attackers. |
| 18 | **AiTM (Adversary-in-the-Middle)** | A phishing technique in which the attacker's server sits between the victim and the real login page, relaying credentials and session tokens in real time. |
| 19 | **Reverse proxy** | A server that forwards requests to another server while appearing to be the destination itself. It is the core mechanism of AiTM kits. |
| 20 | **Session cookie hijacking** | Stealing an already-authenticated session token so the attacker no longer needs the password or MFA code. |
| 21 | **MFA bypass** | Any technique that defeats multi-factor authentication, for example by relaying the one-time code at the moment the victim enters it. |
| 22 | **Phishing-resistant MFA** | MFA bound to the real site's origin (FIDO2 / passkeys, certificate-based authentication). It cannot be relayed by an AiTM proxy. |
| 23 | **Obfuscation** | Deliberately transforming code (renaming, encoding, invisible characters) so that humans or static tools cannot easily read it. |
| 24 | **Anti-debugging / anti-analysis** | Code that detects inspection (developer tools, sandboxes, bots) and changes its behaviour or stops running. |
| 25 | **CAPTCHA / Turnstile gating** | Using a CAPTCHA (Cloudflare Turnstile or a custom canvas CAPTCHA) to keep security scanners away from the real phishing page. |
| 26 | **AI-generated phishing** | Phishing content (emails, landing pages, even code) produced or refined with generative AI to look more convincing. |

## 3. Classification of threat types and their sources

### 3.1 Types of cyber threats

| Threat type | Typical actor | Main goal | Example (2024–2026) |
|---|---|---|---|
| **Phishing / credential theft** (incl. AiTM, PhaaS) | Cybercriminals, PhaaS customers | Account takeover, BEC, resale of access | Tycoon2FA, EvilProxy |
| **Ransomware** | Organised cybercrime (RaaS affiliates) | Extortion | LockBit, Akira |
| **Info-stealer malware** | Cybercriminals | Theft of passwords, cookies, crypto wallets | Lumma Stealer |
| **APT / cyber-espionage** | State-sponsored groups | Long-term covert access, data theft | APT29, APT28 |
| **DDoS** | Hacktivists, criminals | Service disruption, extortion | Hacktivist campaigns against government sites |
| **Insider threat** | Employees, contractors | Data theft, sabotage | Leaking of customer databases |
| **Supply-chain attack** | APT groups, criminals | Mass compromise through a trusted vendor or package | Malicious npm / PyPI packages |
| **Hacktivism** | Politically motivated groups | Publicity, defacement, leaks | Defacements during geopolitical conflicts |

**Tycoon2FA classification (our case):**

| Parameter | Value |
|---|---|
| **Threat type** | Commoditised AiTM credential- and session-theft phishing kit (PhaaS) |
| **Actor** | Developer tracked by Microsoft as **Storm-1747**. The kit is sold to many unrelated criminal customers. |
| **Delivery vector** | Phishing email (payroll, bonus, document or DocuSign lures) with a link, QR code, PDF or SVG attachment |
| **Payload** | Obfuscated JavaScript and a reverse-proxy backend impersonating Microsoft 365 / Google login pages |
| **Target** | Any organisation using Microsoft 365 / Google Workspace (broad and opportunistic: education, healthcare, finance, government) |
| **Motivation** | Financial: credential and session resale, business email compromise |
| **CTI level of our work** | Technical (IOCs, Weeks 2–3) and tactical (TTPs, Weeks 4–6) |

### 3.2 Types of threat intelligence sources

| Source type | Examples | Pros | Cons |
|---|---|---|---|
| **Open source (OSINT)** | Vendor blogs, Shodan, RDAP/WHOIS, RIPEstat, crt.sh, urlscan.io | Free, fast, reproducible | Varying quality, noisy, often outdated |
| **Commercial / vendor** | Microsoft Threat Intelligence, Sekoia, Trustwave, eSentire TRU, Recorded Future | Analysed, high quality | Often paid; only part is public |
| **Community / ISAC** | MISP communities, abuse.ch (URLhaus, ThreatFox), RH-ISAC | Fast sharing between peers | Requires membership and trust |
| **Government / CERT** | CISA, ENISA, national CERTs (KZ-CERT) | Authoritative | Published with a delay |
| **Internal** | SIEM logs, EDR telemetry, email gateway, incident reports | Most relevant to the organisation | Needs tooling and analysts |
| **Closed / dark web** | Criminal forums, Telegram channels | Early warning (kits are sold there) | Legal and ethical risks, hard access |

### 3.3 Practical: rating the sources used in this project (Admiralty Code)

| Source used in the project | Type | Reliability | Credibility | Rating | Reason |
|---|---|---|---|---|---|
| Microsoft Threat Intelligence blog (2026) | Vendor | A – completely reliable | 1 – confirmed | **A1** | Direct telemetry; confirmed by the March 2026 takedown |
| Sekoia TDR report (2024) | Vendor | B – usually reliable | 2 – probably true | **B2** | Detailed technical analysis, but of an older kit version |
| Trustwave SpiderLabs (2025) | Vendor | B – usually reliable | 2 – probably true | **B2** | Technique shown with a public urlscan.io session |
| eSentire TRU IOC lists (2025–2026) | Vendor / feed | B – usually reliable | 3 – possibly true today | **B3** | Indicators are real, but they age quickly (see Week 2: re-registered domain) |
| Shodan InternetDB / RIPEstat / RDAP (queried by us) | OSINT | B – usually reliable | 2 – probably true | **B2** | Primary data, but it is a snapshot of one day |
| News sites (security news aggregators) | Media | C – fairly reliable | 3 – possibly true | **C3** | Second-hand; used only to find primary sources |

## Sources

- Sekoia TDR, "Tycoon 2FA: an in-depth analysis of the latest version of the AiTM phishing kit", 2024.
- Microsoft Security Blog, "Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale", March 2026.
- Trustwave SpiderLabs, "Tycoon2FA New Evasion Technique for 2025".
- Elastic Security Labs, "Detecting Tycoon 2FA AiTM attacks across Entra ID and Google Workspace", 2026.
- ENISA Threat Landscape; Recorded Future, *The Threat Intelligence Handbook*; MITRE ATT&CK.

Full links are in the main [README](README.md#references).
