# Week 3 — Data Processing and Exploitation (MISP, filtering, YARA, Sigma)

**Group:** CS-2426 · Dilnaz Estaikyzy, Ademi Akmaganbet  
**Case study:** Tycoon2FA AiTM Phishing-as-a-Service kit

**Syllabus tasks (§3.3, Week 3):** (1) deploy MISP and import IOCs; (2) apply filtering and normalization techniques to the collected data.
Lecture topics: data enrichment, correlation; tools: MISP, Elastic Stack, Sigma rules.

| Step | What we did | Evidence in the repository |
|---|---|---|
| Processing | Parsed, cleaned, deduplicated and enriched 377 raw records into 667 indicators | `dataset/normalize_iocs.py`, `dataset/tycoon2fa_iocs.csv` |
| Filtering | Excluded stale and false-positive indicators from detection (`to_ids`) | Section 3.3, `FILTERED` rows in the CSV |
| Storage | Built a MISP event (indicators + tags + rules) for import | `dataset/misp_event_tycoon2fa.json` |
| Exploitation | Wrote and **tested** 2 YARA rules and 1 Sigma rule, and hunted through sign-in logs | `detection/` |

## 1. Deploying MISP (Docker)

```bash
git clone https://github.com/MISP/misp-docker
cd misp-docker
cp template.env .env          # set BASE_URL=https://localhost, admin e-mail and passwords
docker compose pull
docker compose up -d          # first start takes several minutes
```

Open `https://localhost` and log in with the admin account from `.env`. Then:

1. **Sync Actions → Feeds → Load default feed metadata**, and enable the *CIRCL OSINT* feed.
2. **Input Filters → Warninglists → Update**, and enable the lists for Cloudflare, CDN and public DNS ranges. They warn when an indicator belongs to shared, legitimate infrastructure.
3. **Taxonomies → Update**, and enable `tlp` and `type`. **Galaxies → Update** (MITRE ATT&CK).

## 2. Importing the IOCs

**Event Actions → Import from… → MISP JSON** → upload [`dataset/misp_event_tycoon2fa.json`](dataset/misp_event_tycoon2fa.json).

| Event field | Value |
|---|---|
| Info | Tycoon2FA AiTM PhaaS kit - phishing infrastructure & kit artifacts (OSINT) |
| Threat level / Analysis / Distribution | High / Ongoing / Your organisation only |
| Event tags | `tlp:clear`, `type:OSINT`, ATT&CK T1566.002, T1557, T1539 |
| Attributes | **669**: 229 `url`, 225 `hostname`, 131 `domain`, 76 `ip-src`, 1 `AS`, 2 `filename`, 1 `filename-pattern`, 2 `text`, **1 `yara`, 1 `sigma`** |
| Used for detection (`to_ids = true`) | 657 of the 667 indicators (the 2 rule attributes are stored with `to_ids = false`) |

After the import, the **Correlation** column shows which attributes also appear in other events or feeds.
Enabled warninglists put a warning on any value that belongs to shared infrastructure.

> **Screenshots for the defence:** event view, attribute list, correlation graph (*View graph*), and a warninglist hit. Save them in `dataset/` and add them to this report.

## 3. Filtering and normalization (practical)

All processing is done by [`dataset/normalize_iocs.py`](dataset/normalize_iocs.py), which uses only the Python standard library:

```bash
$ python3 dataset/normalize_iocs.py
Raw records parsed : 377
Duplicate raw rows : 71 (merged)
Unique indicators  : 667 (incl. derived hostnames/domains and kit patterns)
  url              229
  hostname         225
  domain           131
  ip-src           76
  filename         2
  text             2
  AS               1
  filename-pattern 1
Seen in >1 report  : 168
to_ids=True        : 657  (filtered out: 5)
Detection rules added to MISP event: 2
```

### 3.1 Normalization

| Technique | Example |
|---|---|
| Refang for processing | `vu[.]pdglkps[.]ru/2S9FJ90/` → `https://vu.pdglkps.ru/2S9FJ90/` |
| Lower-case hostnames, trim whitespace | Trailing spaces in the eSentire lists were removed |
| Split the URL into hostname and registered domain | `ooen.pnkptj.ru` → `pnkptj.ru` (handles `co.za`, `sa.com`, `it.com`) |
| Map to the MISP type, category and `to_ids` flag | IP → `ip-src` / *Network activity* / `to_ids=true` |
| Defang for publication | The CSV on GitHub uses `hxxps[://]` and `[.]`, so no link is clickable |

### 3.2 Deduplication and correlation

- **71 duplicate raw rows** were merged. The 2025-03-27 and 2025-04-10 lists overlap.
- **168 indicators appear in more than one report.** For each indicator we keep `first_seen_report`, `last_seen_report` and `report_count`. An indicator seen again weeks later is a stronger signal: the same `.ru` domains were reused for at least two weeks.
- **Aggregation:** 225 hostnames reduce to only **131 registered domains**, and 96 of them are `.ru`. Blocking at domain level covers many rotating sub-domains at once.

### 3.3 Filtering (what we exclude from detection, and why)

Based on the Week 2 enrichment:

| Indicator | Problem found | Filtering decision |
|---|---|---|
| alnaharegypt[.]com | Registered in **2009**: a compromised legitimate site | Domain and hostname `to_ids=false`. The exact malicious URL stays `to_ids=true` |
| fesxtmc[.]com | Expired and **re-registered 2026-09-11**, now parked | Domain, hostname and URL `to_ids=false` (stale) |
| 76 egress IPs | Several prefixes have **changed owner** since March 2026 | Kept for *hunting historical logs*. Not recommended for permanent firewall blocking |
| `text` / `AS` / CSS file names | Descriptive, or too generic to block on | `to_ids=false` |

Result: 657 of 667 indicators are marked for IDS/SIEM use; 10 are kept only as context.

![Dataset overview](dataset/dataset_overview.png)

## 4. Exploitation: detection rules built from the processed data

All files are in [`detection/`](detection/).

### 4.1 YARA (file / page detection), tested

[`detection/tycoon2fa.yar`](detection/tycoon2fa.yar) contains two rules written by the group:

| Rule | Detects | Logic |
|---|---|---|
| `Tycoon2FA_Landing_Page_Artifacts` | HTML landing page | `<html` and at least 2 of: `myscr[0-9]{6}.js`, `pages-godaddy.css`, `pages-okta.css`, `new WebSocket(` |
| `Tycoon2FA_Invisible_Unicode_JS` | Hidden JavaScript | A run of 64 or more Hangul Filler characters in UTF-8 (`E3 85 A4` / `EF BE A0`), plus `new Proxy(` |

We tested the rules with **YARA 4.5.2** on a synthetic, harmless test corpus generated by `detection/make_test_samples.py`. The corpus has 2 samples that imitate the kit's patterns and 4 benign look-alikes. Full log: [`detection/yara_test_results.txt`](detection/yara_test_results.txt).

```text
sample_neg_chat_app.html        expected: NO MATCH  got: NO MATCH                                  PASS
sample_neg_korean_text.html     expected: NO MATCH  got: NO MATCH                                  PASS
sample_neg_okta_docs.html       expected: NO MATCH  got: NO MATCH                                  PASS
sample_neg_proxy_library.js     expected: NO MATCH  got: NO MATCH                                  PASS
sample_pos_invisible_unicode.js expected: MATCH     got: MATCH (Tycoon2FA_Invisible_Unicode_JS)    PASS
sample_pos_landing_page.html    expected: MATCH     got: MATCH (Tycoon2FA_Landing_Page_Artifacts)  PASS
# result: 6/6 passed
```

What the negative tests prove:
- A normal chat app that opens a WebSocket does **not** trigger the rule.
- A page that only mentions `pages-okta.css` does **not** trigger it.
- Korean text with a few filler characters stays below the 64-character threshold.
- Ordinary use of JavaScript `Proxy` does not trigger it either.

Our first draft of the rule from the previous version of this report had two problems. It searched for the UTF-16 bytes `\xa0\xff`, but web pages are UTF-8. It also searched for the 2-byte string `"\x64\x31"` (the text `d1`), which occurs in almost any file. Both were fixed.

### 4.2 Sigma (log detection) and hunt

The eSentire data shows that Tycoon2FA replays stolen sessions from its egress IPs with User-Agent **`axios/1.13.x`**. A real user's browser never sends this.
[`detection/tycoon2fa_axios_signin.yml`](detection/tycoon2fa_axios_signin.yml) is a Sigma rule (logsource `azure / signinlogs`) that fires on a **successful sign-in with an `axios/` User-Agent**.
Equivalent Microsoft Sentinel KQL:

```kql
SigninLogs
| where UserAgent startswith "axios/" and ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress, UserAgent, AppId, AutonomousSystemNumber
```

`detection/hunt_signin_logs.py` applies the Sigma rule **and** IOC matching against our 76 egress IPs to 8 synthetic sign-in events ([`detection/hunt_results.txt`](detection/hunt_results.txt)):

| Case | Sigma | IOC | Verdict |
|---|---|---|---|
| axios UA from known egress IP (IPv4 and IPv6) | hit | hit | **ALERT, high confidence** (2 events) |
| axios UA from an IP **not** in our list | hit | – | **ALERT, behaviour only** (new infrastructure) |
| Known egress IP but browser UA | – | hit | REVIEW |
| Failed axios attempt | – | – | info (no session issued) |
| Normal browser / Outlook sign-ins | – | – | clean (3 events) |

**Conclusion:** IOC matching alone would miss the sign-in from new infrastructure, and the behavioural Sigma rule alone would miss the attacker who switches to a browser User-Agent. Using both follows the Pyramid of Pain: indicators give quick wins, and behaviour gives durable detection.

## 5. A note on dynamic analysis (CAPE Sandbox)

CAPE is designed for **Windows executables and documents**. A Tycoon2FA sample is a web page: submitted as a `.js` file, CAPE would run it with Windows Script Host, and the phishing logic, CAPTCHA and WebSocket relay would never execute.
Dynamic analysis of this kit therefore needs **browser detonation of the URL** in an isolated VM, for example urlscan.io or ANY.RUN.
Trustwave published such a urlscan.io session of a real Tycoon2FA page (see their 2025 report).
We use CAPE only for attachments delivered by the lures (for example malicious PDF or SVG files).

## 6. Summary of the week

- **Processing:** 377 raw records → 667 normalized, deduplicated, enriched indicators (CSV + MISP JSON).
- **Filtering:** 5 indicators excluded from blocking after enrichment (stale domain, compromised site). IPs are flagged as short-lived.
- **Storage:** a MISP event with 669 attributes, TLP and ATT&CK tags, and the detection rules attached.
- **Exploitation:** 2 YARA rules (6/6 tests passed) and 1 Sigma rule, used in a hunt that combines behaviour and IOCs.
- **Next week:** map the full attack to the Cyber Kill Chain and MITRE ATT&CK.
