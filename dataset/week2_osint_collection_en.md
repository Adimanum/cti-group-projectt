# Week 2 — Data Collection Process (OSINT)

**Group:** CS-2426 · Dilnaz Estaikyzy, Ademi Akmaganbet  
**Case study:** Tycoon2FA AiTM Phishing-as-a-Service kit

**Syllabus tasks (§3.3, Week 2):** (1) perform OSINT data collection using Shodan, VirusTotal and Maltego; (2) develop a data source mapping for analysis.

## 1. Collection plan

| Question (what we want to know) | Where we look | Output |
|---|---|---|
| Which technical artifacts identify the kit? | Vendor reports (Sekoia, Trustwave, Microsoft) | Kit patterns (section 2) |
| Which domains, URLs and IPs did the kit use? | eSentire TRU public IOC repository | Raw IOC files → `dataset/` |
| Who hosts the attacker's login infrastructure? | **Shodan InternetDB**, RIPEstat | `dataset/enrichment_ip.csv` |
| When and where were the phishing domains registered? | RDAP (WHOIS successor) | `dataset/enrichment_domain.csv` |
| Are the domains known as malicious? | **VirusTotal** API v3 | `dataset/enrichment_vt.csv` (script) |
| How are the entities connected? | **Maltego** (table import) and our own link graph | `dataset/maltego_import.csv`, `dataset/infra_graph.png` |

## 2. Kit-level artifacts from vendor reports

| Type | Value / pattern | Purpose | Source |
|---|---|---|---|
| JS file naming | `myscr[0-9]{6}.js` | Obfuscated JavaScript payload | Sekoia |
| CSS resource names | `pages-godaddy.css`, `pages-okta.css` | Styling reused across cloned login pages | Sekoia |
| CAPTCHA layer | Cloudflare Turnstile, later a custom HTML5-canvas CAPTCHA | Keeps scanners and bots away from the real page | Sekoia, Trustwave |
| Obfuscation marker | Invisible Unicode (U+FFA0 = 0, U+3164 = 1) decoded through a JS `Proxy` | Hides JavaScript from static analysis | Trustwave |
| Transport | WebSocket / backend relay of credentials and MFA codes | Real-time AiTM relay | Sekoia, Microsoft |
| Post-compromise | Sign-ins with User-Agent `axios/1.13.x` | Replay of stolen session material | eSentire (2026) |

> These patterns are publicly documented and used here only for detection and defensive research.

## 3. Raw data collected

We downloaded three public IOC lists from the eSentire Threat Response Unit (<https://github.com/eSentire/iocs/tree/main/Tycoon2FA>) and stored them unchanged in `dataset/`:

| File | Content | Lines |
|---|---|---|
| `esentire_tycoon2fa_2025-03-27.txt` | Phishing URLs, "check" URLs, 1 ASN | 125 |
| `esentire_tycoon2fa_2025-04-10.txt` | "Check" URLs | 140 |
| `esentire_tycoon2fa_2026-03-23.txt` | 80 login egress IPs (IP, User-Agent, App ID, ASN) and "check" URLs | 125 |

After processing in Week 3, this gives **667 unique indicators**: 229 URLs, 225 hostnames, 131 domains and 76 IPs.

## 4. Practical OSINT results (collected 2026-09-26)

### 4.1 Shodan: services running on the attacker's login IPs

We queried **Shodan InternetDB** (`https://internetdb.shodan.io/<ip>`, the free Shodan API) for all 14 IPv4 egress addresses.
We cross-checked the network owner with **RIPEstat** (`prefix-overview`).
Full results are in [`dataset/enrichment_ip.csv`](dataset/enrichment_ip.csv).

| IP | Owner today (RIPEstat) | Label in eSentire (March 2026) | Shodan ports | Shodan software |
|---|---|---|---|---|
| 142.252.171.135 | AS44559 IT Hostline | HOST TELECOM LTD | **1050, 24442** | Python 3.7, OpenSSH 9.2p1 Debian |
| 170.168.215.64 | AS204957 GreenFloid | GREEN FLOID LLC | **1050, 24442** | Python 3.7, OpenSSH 9.2p1 Debian |
| 142.252.86.104 | AS62240 Clouvider | Clouvider | **24442** | OpenSSH 9.2p1 Debian |
| 172.120.234.223 | AS44559 IT Hostline | HOST TELECOM LTD | **24442** | OpenSSH 9.2p1 Debian |
| 45.39.175.12 | AS44559 IT Hostline | HOST TELECOM LTD | **1050** | Python 3.7 |
| 50.118.198.26 | AS44559 IT Hostline | HOST TELECOM LTD | **1050** | Python 3.7 |
| 8 other IPs | AS44559, AS62240, AS204957, AS6079, AS3257 | — | not indexed | — |

**Findings:**

1. **A shared server fingerprint.** 6 of 14 IPs are indexed by Shodan, and all 6 expose the same unusual services: SSH on the non-standard port **24442** (OpenSSH 9.2p1, Debian 12) and/or a **Python 3.7 service on port 1050**. These servers sit with three *different* hosting providers. The same configuration everywhere suggests that one operator builds all of them from the same image. This gives a **pivot for hunting new infrastructure**. With a Shodan account, search `port:24442 "OpenSSH_9.2p1 Debian"` and `port:1050` inside the same ASNs. Confidence is **medium**, because Debian SSH on its own is common.
2. **Infrastructure drift.** For several IPs the network owner today differs from the eSentire label: 166.1.x now belongs to AS6079 RCN, and 166.88.219.45 to AS3257 GTT. Six months after the report, part of the space has changed hands. IP indicators therefore age fast and should not be used for permanent blocking (see the Week 3 filtering).
3. Shodan also lists about 30 CVEs for hosts with Python 3.7. These are *inferred from the version number* and not verified, so we do not treat them as findings.

### 4.2 RDAP (WHOIS): who registered the phishing domains

We queried the Verisign RDAP service for all six `.com` domains in the dataset.
The `.ru` domains have no public RDAP.
Results are in [`dataset/enrichment_domain.csv`](dataset/enrichment_domain.csv).

| Domain | Registrar | Created | DNS | Assessment |
|---|---|---|---|---|
| shoupeatai[.]com | Sav.com | 2026-03-04 | Cloudflare | Throw-away domain, registered about 3 weeks before the report |
| shailoyio[.]com | Sav.com | 2026-03-05 | Cloudflare | Same registrar, one day apart: likely registered in one batch |
| sistaidru[.]com | GMO Internet (Onamae) | 2026-02-12 | Cloudflare | Throw-away domain |
| yljdimage[.]com | Gname.com | 2025-11-06 | Cloudflare | Updated 2 days before the campaign |
| fesxtmc[.]com | Domain Science | **2026-09-11** | dns-redirect.com | **Stale.** The domain expired and was re-registered after the report; it is now parked |
| alnaharegypt[.]com | Name.com | **2009-12-23** | Cloudflare | **Compromised legitimate site.** Old domain; only the specific URL is malicious |

**Findings:** 5 of 6 domains sit behind **Cloudflare DNS**, which hides the real hosting (the Pyramid of Pain in practice). Four were registered only weeks before use. Two of them could cause false positives or waste analyst time if blocked blindly. This feeds the filtering step in Week 3.

### 4.3 VirusTotal

VirusTotal needs a free API key. Run `VT_API_KEY=<key> python3 dataset/osint_enrich.py`. The script requests `/api/v3/domains/<domain>` for every enriched domain and writes the detection ratio to `dataset/enrichment_vt.csv`. It waits 16 seconds between requests to respect the 4 requests/minute limit.
Manual alternative: search each domain on virustotal.com and record *Detections* and *Community* tags.

### 4.4 Maltego and the link graph

[`dataset/maltego_import.csv`](dataset/maltego_import.csv) contains 34 links (IP → ASN, IP → open port, domain → registrar, domain → name server).
To import it into Maltego CE: **Import → Import Graph from Table → select the CSV** → map *source_value* and *target_value* to the entity types in the columns.
From the domain entities you can then run the standard transforms `To DNS Name`, `To IP Address` and `To Netblock`.

The same relations, drawn with our script `dataset/plot_infra_graph.py`:

![Tycoon2FA infrastructure link graph](dataset/infra_graph.png)

## 5. Data source mapping

| Source | Access | Data type | What it gives our analysis | Used for | Reliability |
|---|---|---|---|---|---|
| Sekoia / Trustwave / Microsoft reports | Public web | Vendor CTI | TTPs, kit patterns, YARA ideas | Week 1, Week 3 YARA | High (A1–B2) |
| eSentire TRU IOC repository | GitHub | IOC feed | 377 raw indicators (URLs, IPs, ASN) | Week 3 dataset | High, but ages fast (B3) |
| Shodan InternetDB | Free API | Internet scan | Open ports and software on egress IPs | Pivot fingerprint | Medium–high (B2) |
| RIPEstat | Free API | Routing / ASN | Current network owner of each IP | Drift check, filtering | High (B2) |
| RDAP (Verisign) | Free API | Registration data | Registrar, creation date, name servers | Domain age, filtering | High (B2) |
| VirusTotal | Free API key | Reputation | Detection ratio, community tags | Validation | Medium–high |
| Maltego CE | Free account | Link analysis | Visual pivoting between entities | Infrastructure graph | Depends on transforms |
| MITRE ATT&CK | Public | TTP knowledge base | Technique IDs (T1566.002, T1557, T1539) | Weeks 4–6 | High |
| Entra ID sign-in logs (internal) | SIEM | Telemetry | Where the IOCs and Sigma rule are applied | Week 3 hunt, Week 5 | High (own data) |

Reproduce the collection: `python3 dataset/osint_enrich.py` (standard library only). The results change over time.

## 6. Summary of the week

- We collected **377 raw indicators** from a vendor feed plus the kit patterns from three vendor reports.
- We enriched **14 IPs** with Shodan and RIPEstat and **6 domains** with RDAP.
- We found a **shared SSH/Python fingerprint** on the attacker's login servers (a hunting pivot). We also found **two indicators that should not be blocked**: one stale domain and one compromised legitimate site.
- We built a data source map and a Maltego import file for link analysis.
