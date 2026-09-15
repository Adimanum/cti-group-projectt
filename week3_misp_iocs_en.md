# Week 3 — Data Processing, Sandbox Analysis, and Detection Rule (MISP + CAPE + YARA)

**Case study:** Tycoon2FA AiTM Phishing-as-a-Service kit

## 1. Task

Store the Week 2 artifacts in MISP, submit a sample of the obfuscated JavaScript to CAPE Sandbox for dynamic/behavioral analysis, and write an original YARA rule to detect the kit's known patterns.

## 2. Deploying MISP (Docker)

```bash
git clone https://github.com/MISP/misp-docker
cd misp-docker
cp template.env .env
# edit .env: set BASE_URL, admin and DB passwords
docker compose up -d
```

Interface available at `https://localhost`, using the admin account configured in `.env`.

## 3. Creating an Event in MISP

1. **Events -> Add Event**
2. Fill in:
   - **Event info:** `Tycoon2FA AiTM PhaaS kit - obfuscation & session-relay TTPs`
   - **Threat Level:** High
   - **Analysis:** Ongoing
   - **Distribution:** Your Organisation Only (for a class project)

## 4. Importing the collected artifacts

| MISP attribute type | Value | Category |
|---|---|---|
| `pattern-in-file` | `myscr[0-9]{6}\.js` | Payload delivery |
| `filename` | `pages-godaddy.css`, `pages-okta.css` | Payload delivery |
| `text` | Invisible Unicode obfuscation (U+FFA0 / U+3164 binary encoding) | Other |
| `text` | WebSocket-based credential/MFA relay | Network activity |

## 5. Deploying CAPE Sandbox and submitting a sample

```bash
git clone https://github.com/kevoreilly/CAPEv2
cd CAPEv2
sudo ./installer/cape2.sh base
sudo ./installer/cape2.sh cape
```

After setup, CAPE exposes a web UI for submitting samples. Workflow for this case:

1. **Submit** a captured copy of the obfuscated `myscr*.js` file (or the full phishing HTML page) as a URL/file analysis job.
2. CAPE executes it in an isolated browser/VM environment and records:
   - Outbound network connections (the WebSocket relay to the attacker's backend)
   - Any dynamically decoded/`eval`'d JavaScript (the deobfuscated payload)
   - DOM/behavioral indicators (fake CAPTCHA rendering, anti-debugger triggers)
3. Review the **behavioral report** and **network (PCAP) tab** to confirm the AiTM relay pattern matches what was documented in Week 2's OSINT sources.

## 6. Writing an original YARA rule

Based on the publicly documented patterns (invisible-Unicode obfuscation technique, `myscr[0-9]{6}.js` naming, shared CSS resource names), here is an original detection rule combining these traits:

```yara
rule Suspected_Tycoon2FA_AiTM_Kit
{
    meta:
        description = "Detects JS/CSS artifacts consistent with Tycoon2FA-style AiTM phishing kits"
        author = "CS-2426 group project"
        reference = "Sekoia / Trustwave / Microsoft public reporting, 2025-2026"

    strings:
        $js_pattern   = /myscr[0-9]{6}\.js/ ascii wide
        $css_godaddy  = "pages-godaddy.css" ascii wide
        $css_okta     = "pages-okta.css" ascii wide
        $unicode_bit0 = "\xa0\xff" // Halfwidth Hangul Filler (U+FFA0)
        $unicode_bit1 = "\x64\x31" // Hangul Filler (U+3164)
        $ws_indicator = "new WebSocket(" ascii wide

    condition:
        (any of ($css_godaddy, $css_okta, $js_pattern)) and
        ($ws_indicator or (($unicode_bit0) and ($unicode_bit1)))
}
```

> This rule is written from scratch by the group based on publicly reported technical characteristics; it is a starting point for tuning against real samples, not a copy of any vendor's proprietary rule.

## 7. Filtering and normalization in MISP

- **Deduplication**: check via MISP search before adding new attributes.
- **Tagging (Taxonomies)**: `tlp:white` (built from public reports), `misp-galaxy:tool="Tycoon2FA"`, `kill-chain:command-and-control`.
- **Correlation**: enable MISP's Correlation Engine so future events sharing the same filename patterns or WebSocket indicator are automatically linked.

## 8. Summary of the week

The event now contains normalized artifacts, a CAPE-generated behavioral report confirming the AiTM relay mechanism, and an original YARA rule ready for tuning and future threat hunting.
