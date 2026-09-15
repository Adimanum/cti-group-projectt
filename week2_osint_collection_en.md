# Week 2 — Data Collection Process (OSINT)

**Case study:** Tycoon2FA AiTM Phishing-as-a-Service kit

## 1. Task

Perform OSINT data collection on Tycoon2FA infrastructure and artifacts using Shodan, VirusTotal, and Maltego, and build a data source mapping.

## 2. Known (published) artifacts and patterns - starting points for the search

| Type | Value / Pattern | Purpose |
|---|---|---|
| JS file naming pattern | `myscr[0-9]{6}.js` | Obfuscated JavaScript payload delivered to the victim's browser |
| CSS resource names | `pages-godaddy.css`, `pages-okta.css` | Styling resources reused across cloned login pages |
| CAPTCHA layer | Custom Cloudflare Turnstile implementation | Filters out scanners/bots before showing the real phishing page |
| Obfuscation marker | Invisible Unicode characters (Halfwidth Hangul Filler U+FFA0, Hangul Filler U+3164) used as binary encoding | Hides malicious JS from static analysis |
| Transport mechanism | WebSocket connection to relay credentials/MFA codes in real time | Confirms AiTM behavior vs. simple static phishing |

> These are publicly documented technical patterns (Sekoia, Trustwave, Microsoft) used strictly for detection and defensive research, not to reproduce or operate the kit.

## 3. OSINT collection process

### VirusTotal
- Search for file hashes or URL submissions matching the `myscr[0-9]{6}.js` naming pattern to find live or historical samples flagged by other analysts.
- Pivot on any identified phishing domain to see related URLs, downloaded files, and community comments/tags.

### Shodan
- Search for hosts serving the specific combination of CSS filenames (`pages-godaddy.css`, `pages-okta.css`) or the custom Turnstile challenge page — this can reveal currently-live Tycoon2FA front-end servers.
- Check TLS certificates on suspicious hosts for reuse across multiple phishing domains (certificate pivoting), a common trait of PhaaS infrastructure reused by many "customers" of the kit.

### Maltego
- Build a graph: domain -> hosting IP -> WHOIS registrant -> other domains sharing the same IP/registrar -> associated JS/CSS resource names.
- Transforms used: `Domain -> DNS -> IP`, `IP -> Shodan`, `URL -> VirusTotal report`.

## 4. Data Source Mapping

| Source | Data type | What it provides for the analysis | Confidence level |
|---|---|---|---|
| Sekoia / Trustwave / Microsoft reports | Vendor threat intelligence | Documented TTPs, obfuscation methods, published YARA rule | High |
| VirusTotal | File/URL reputation | Samples matching the JS naming pattern, community tags | High |
| Shodan | Internet scanning | Live front-end servers hosting the phishing kit's assets | Medium |
| Maltego (OSINT graph) | Entity relationships | Shared hosting/infrastructure across multiple kit deployments | Medium |
| MITRE ATT&CK | TTP knowledge base | Mapping AiTM/session-hijacking techniques to attack stages | High |

## 5. Summary of the week

An initial set of Tycoon2FA artifacts (JS naming pattern, CSS resource names, obfuscation markers, WebSocket behavior) has been collected, and a data source map has been built for further normalization, MISP storage, and dynamic/behavioral analysis in Week 3.
