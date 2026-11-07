# Week 10 — Learning APT Techniques (APT29)

**Group:** CS-2426 · Dilnaz Estaikyzy, Ademi Akmaganbet
**Case study:** Tycoon2FA AiTM Phishing-as-a-Service kit

**Syllabus tasks (§3.3, Week 10):** (1) analyze the TTPs of APT29 or APT41; (2) map the observed techniques to the MITRE ATT&CK framework.
Sources: FireEye/Mandiant reports, CrowdStrike Global Threat Report. Recommended reading: Mandiant APT1 Report, CrowdStrike Global Threat Report.

| What we produced | File |
|---|---|
| APT29 TTPs mapped to ATT&CK (one source of truth) | [`apt/apt29_ttps.json`](apt/apt29_ttps.json) |
| The TTP table (tactic → ATT&CK → APT29 use → overlap → our detection) | [`apt/apt29_ttps.csv`](apt/apt29_ttps.csv) |
| ATT&CK Navigator layer of APT29, coloured by overlap with our work | [`apt/apt29_layer.json`](apt/apt29_layer.json) |
| Overlap diagram (APT29 vs Tycoon2FA) | [`apt/apt29_overlap.png`](apt/apt29_overlap.png) |

## 1. Why we chose APT29

The task lets us pick **APT29 or APT41**. We chose **APT29** because it is the nation-state actor whose tradecraft most closely matches our case study. Tycoon2FA is an **identity-first, Microsoft 365 / cloud, MFA-bypass** attack — and that is exactly APT29's speciality. APT41, by contrast, is a China-nexus actor better known for software supply-chain and financially-motivated endpoint intrusions. Choosing APT29 lets us directly compare a **commodity PhaaS kit** with an **elite state actor** attacking the same surface.

**APT29** (aliases **Cozy Bear, Midnight Blizzard, Nobelium, UNC2452, The Dukes**) is attributed to the Russian Foreign Intelligence Service (**SVR**). It is behind the 2020 **SolarWinds** supply-chain compromise and the 2024 breach of **Microsoft's** corporate email.

## 2. APT29 TTPs mapped to ATT&CK

We analysed APT29's behaviour across the attack lifecycle and mapped each action to an ATT&CK technique. Full table in [`apt/apt29_ttps.csv`](apt/apt29_ttps.csv); 16 techniques:

| Tactic | ATT&CK | Technique | APT29 use (short) | Shared with Tycoon2FA? |
|---|---|---|---|---|
| Initial Access | T1566.002 | Spearphishing Link | Links / Teams / device-code lures | ✅ shared |
| Initial Access | T1566.001 | Spearphishing Attachment | Malicious LNK/ISO/doc | APT29-only |
| Initial Access | T1078.004 | Valid Accounts: Cloud | Login with stolen valid tokens | ✅ shared |
| Initial Access | T1195.002 | Software Supply Chain | SolarWinds Orion (2020) | APT29-only |
| Credential Access | T1621 | MFA Request Generation | MFA "push bombing" | ~ related (our T1111) |
| Credential Access | T1539 | Steal Web Session Cookie | Steal session cookies/tokens | ✅ shared |
| Credential Access | T1606.001 | Forge Web Credentials: Cookies | "Golden SAML" / forged OWA cookie | APT29-only |
| Defense Evasion | T1550.004 | Web Session Cookie (reuse) | Reuse stolen cookie | ✅ shared |
| Defense Evasion | T1550.001 | Application Access Token | Use OAuth app tokens | APT29-only |
| Persistence | T1098.005 | Device Registration | Enroll attacker device for mail sync | ✅ shared |
| Persistence | T1098.001 | Additional Cloud Credentials | Add secrets to OAuth apps | APT29-only |
| Persistence | T1098.002 | Additional Email Delegate Perms | Delegate mailbox access | APT29-only |
| Persistence | T1098.003 | Additional Cloud Roles | Grant admin roles to principals | APT29-only |
| Discovery | T1087.004 | Cloud Account Discovery | Enumerate Entra ID | ✅ shared |
| Collection | T1114.002 | Remote Email Collection | Read mailboxes in the tenant | ✅ shared |
| Exfiltration | T1048.002 | Exfil over Encrypted Non-C2 | Encrypted archives over HTTPS | ~ related (our T1567) |

## 3. The key finding — a shared identity-attack core

![APT29 vs Tycoon2FA](apt/apt29_overlap.png)

When we line APT29 up against our Tycoon2FA emulation plan (Week 8), **7 techniques are shared and 2 more are closely related**:

> T1566.002, T1078.004, T1539, T1550.004, T1098.005, T1087.004, T1114.002 — plus MFA attacks (APT29's T1621 bombing vs Tycoon2FA's T1111 interception) and exfiltration.

In other words, **Tycoon2FA's entire kill chain sits inside APT29's playbook.** A cheap rented phishing kit and a top-tier intelligence service use the *same* identity-attack core: phish → bypass MFA → steal the session token → register a device for persistence → enumerate the tenant → read the mail.

**What this means for our project:** the detections we built in Weeks 3/5/7/8 for a commodity kit **also catch part of a nation-state actor**. The same axios-UA Sigma rule, the device-registration hunt (H1), the Graph-recon hunt (H3) and the CAR concurrent-session analytic would all fire on the shared APT29 techniques. Good identity detections are **actor-agnostic**.

## 4. Where APT29 goes beyond a PhaaS kit (our gaps)

The **7 APT29-only techniques** are the capabilities a commodity kit does not have, and they are honest gaps in our coverage — a roadmap for future detection work:

- **T1606.001 Forge Web Credentials / "Golden SAML"** — forging tokens from a stolen AD FS signing key. Needs token-signing-certificate monitoring.
- **T1550.001 / T1098.001 Application Access Tokens & OAuth app credentials** — persistence through OAuth apps and service principals. Needs app-registration and service-principal auditing.
- **T1098.002 / T1098.003 Mailbox delegation & admin-role grants** — needs privileged-change auditing.
- **T1195.002 Software supply chain (SolarWinds)** — a nation-state capability beyond anything a PhaaS kit does.

## 5. Summary of the week

- We **analysed APT29** (Cozy Bear / Midnight Blizzard, SVR) and **mapped 16 of its TTPs to MITRE ATT&CK** across the full lifecycle, with a Navigator layer.
- We compared APT29 to our Tycoon2FA case: **7 shared + 2 related techniques** — Tycoon2FA's whole chain lives inside APT29's identity playbook.
- Therefore our existing detections already cover part of a nation-state actor; the **7 APT29-only techniques** (Golden SAML, OAuth-app persistence, supply chain) are clear, prioritised future work.

```bash
python3 apt/build_apt.py    # TTP table (CSV) + Navigator layer
python3 apt/plot_apt.py     # overlap diagram
```

## References

1. Mandiant, *APT29 / UNC2452* reporting and the *APT1* report (methodology). <https://www.mandiant.com/resources>
2. CrowdStrike, *Global Threat Report* (Cozy Bear / BEAR adversaries). <https://www.crowdstrike.com/global-threat-report/>
3. Microsoft Threat Intelligence, *Midnight Blizzard* (APT29) advisories, 2024. <https://www.microsoft.com/security/blog/>
4. CISA/FBI/NSA, *Russian SVR (APT29) cloud TTPs*, Advisory AA24-057A, 2024. <https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a>
5. MITRE ATT&CK, Group **G0016 (APT29)**. <https://attack.mitre.org/groups/G0016/>
