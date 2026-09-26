# Dataset — Tycoon2FA IOCs

![Dataset overview](../images/dataset_overview.png)

## Contents

| File | Description |
|---|---|
| `raw/esentire_tycoon2fa_2025-03-27.txt` | Raw public IOC list from eSentire TRU (phishing URLs, "check" URLs, ASN) |
| `raw/esentire_tycoon2fa_2025-04-10.txt` | Raw public IOC list from eSentire TRU ("check" URLs) |
| `raw/esentire_tycoon2fa_2026-03-23.txt` | Raw public IOC list from eSentire TRU (login egress IPs + "check" URLs) |
| `tycoon2fa_iocs.csv` | **Main dataset**: normalized, deduplicated and defanged (produced by `scripts/normalize_iocs.py`) |
| `misp_event_tycoon2fa.json` | The same indicators as a MISP event, refanged and ready to import |

Source of the raw data: eSentire Threat Response Unit, public IOC repository
<https://github.com/eSentire/iocs/tree/main/Tycoon2FA>. We only collected these files. We did not produce the indicators ourselves.
The kit-level patterns (JS/CSS names, Unicode obfuscation, WebSocket relay) come from the Week 2 OSINT sources (Sekoia, Trustwave, Microsoft).

## Processing steps (Week 3: filtering and normalization)

1. **Parse**: read each raw file section by section (URLs, IP table, ASN list).
2. **Clean**: trim whitespace, refang `[.]` → `.`, convert hostnames to lower case, drop malformed IP rows.
3. **Enrich**: extract the *hostname* and the *registered domain* from every URL. Keep the ASN and User-Agent for every IP.
4. **Deduplicate**: merge indicators that appear in several reports. For each one, keep the first and last report date and the number of reports.
5. **Classify**: assign a MISP type, category and `to_ids` flag. Descriptive `text` and `AS` attributes are not used for detection.
6. **Export**: write a defanged CSV (safe to publish) and a refanged MISP JSON (for import into MISP only).

Run it again with:

```bash
python3 scripts/normalize_iocs.py   # rebuilds CSV + MISP JSON
python3 scripts/plot_dataset.py     # rebuilds images/dataset_overview.png
```

## Result in numbers

| Metric | Value |
|---|---|
| Raw records parsed | 377 |
| Duplicate raw rows merged | 71 |
| Unique indicators in the dataset | 667 |
| URLs / hostnames / registered domains | 229 / 225 / 131 |
| Egress IP addresses (IPv4 + IPv6) | 76 |
| Indicators seen in more than one report | 168 |
| Top TLD | `.ru` (96 of 131 domains) |
| Top egress hosting provider | M247 Europe SRL (46 of 76 IPs) |

## Column description (`tycoon2fa_iocs.csv`)

| Column | Meaning |
|---|---|
| `id` | Row number |
| `misp_type` | MISP attribute type (`url`, `hostname`, `domain`, `ip-src`, `AS`, `filename`, `filename-pattern`, `text`) |
| `category` | MISP category |
| `value_defanged` | Indicator value, defanged (`[.]`, `hxxps[://]`) so it cannot be clicked |
| `to_ids` | `True` if the indicator should be used for detection (IDS/SIEM) |
| `comment` | Context: role of the URL, ASN and User-Agent of the IP, and so on |
| `first_seen_report` / `last_seen_report` | Earliest and latest report date in which the indicator appears |
| `report_count` | Number of raw reports that contain the indicator |
| `sources` | Raw file names (or vendor report) the indicator came from |

## Importing into MISP

**Event Actions → Import from… → MISP JSON** → upload `misp_event_tycoon2fa.json`.
The event is tagged `tlp:clear`, `type:OSINT` and with ATT&CK techniques T1566.002, T1557 and T1539.

## Safety note

All values are defanged in the CSV. The egress IPs belong to VPS/hosting providers and are short-lived. Use them for hunting historical sign-in logs, not for permanent blocking. Do not open the URLs outside an isolated sandbox.
