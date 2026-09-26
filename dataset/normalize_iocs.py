#!/usr/bin/env python3
"""
Week 3 - Data processing: filter and normalize raw Tycoon2FA IOCs.

Input : dataset/esentire_*.txt  (public eSentire TRU IOC lists, defanged)
Output: dataset/tycoon2fa_iocs.csv          - normalized, deduplicated dataset (defanged)
        dataset/misp_event_tycoon2fa.json   - MISP event ready for import (refanged)

Steps performed:
  1. Parse   - read each raw file section by section (URLs, IP table, ASNs)
  2. Clean   - strip whitespace, refang ("[.]" -> "."), lowercase hostnames
  3. Enrich  - extract hostname and registered domain from every URL,
               keep ASN / user-agent context for every IP
  4. Dedup   - merge identical indicators seen in several reports
               (keep earliest report date, count how many reports saw it)
  5. Classify- map each indicator to a MISP type/category and to_ids flag
  6. Export  - CSV (defanged, safe to publish) + MISP JSON (refanged)

Usage:  python3 dataset/normalize_iocs.py
Only the Python standard library is required.
"""
import csv
import ipaddress
import json
import re
import uuid
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent  # everything lives in dataset/
RAW = HERE
OUT_CSV = HERE / "tycoon2fa_iocs.csv"
OUT_MISP = HERE / "misp_event_tycoon2fa.json"

SOURCE_REF = "https://github.com/eSentire/iocs/tree/main/Tycoon2FA"
# Public suffixes with two labels that appear in this data set
TWO_LEVEL_SUFFIXES = {"co.za", "sa.com", "it.com"}

# Kit-level artifacts collected in Week 2 from vendor reports (not in eSentire files)
KIT_PATTERNS = [
    ("filename-pattern", "Payload delivery", r"myscr[0-9]{6}\.js",
     "Obfuscated JS payload naming pattern", "Sekoia / Trustwave public reporting", True),
    ("filename", "Payload delivery", "pages-godaddy.css",
     "CSS reused across cloned login pages", "Sekoia public reporting", False),
    ("filename", "Payload delivery", "pages-okta.css",
     "CSS reused across cloned login pages", "Sekoia public reporting", False),
    ("text", "Other", "Invisible Unicode obfuscation (U+FFA0 / U+3164 as binary)",
     "Hides JS from static analysis", "Trustwave SpiderLabs 2025", False),
    ("text", "Network activity", "WebSocket-based credential/MFA relay",
     "AiTM real-time relay behaviour", "Sekoia / Microsoft public reporting", False),
]

# Filtering: indicators that must NOT be used for blocking (warninglist-style exclusions),
# decided from the Week 2 RDAP enrichment (enrichment_domain.csv)
EXCLUDE_FROM_IDS = {
    "alnaharegypt.com": "FILTERED: domain registered in 2009 - likely a compromised legitimate site; "
                        "blocking it would cause false positives",
    "fesxtmc.com": "FILTERED: stale - domain was re-registered on 2026-09-11 and is now parked",
}

EVENT_TAGS = [
    "tlp:clear",
    'misp-galaxy:mitre-attack-pattern="Spearphishing Link - T1566.002"',
    'misp-galaxy:mitre-attack-pattern="Adversary-in-the-Middle - T1557"',
    'misp-galaxy:mitre-attack-pattern="Steal Web Session Cookie - T1539"',
    'type:OSINT',
]


def refang(s: str) -> str:
    return s.replace("[.]", ".").replace("hxxp", "http").strip()


def defang(s: str) -> str:
    return s.replace(".", "[.]") if not s.startswith("AS") else s


def registered_domain(host: str) -> str:
    labels = host.split(".")
    if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def report_date(path: Path) -> str:
    return re.search(r"(\d{4}-\d{2}-\d{2})", path.name).group(1)


def parse_file(path: Path):
    """Yield raw records: dict(type, value, context...)."""
    rdate = report_date(path)
    section = None
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        upper = line.upper()
        if "PHISHING URL" in upper:
            section = "url"; continue
        if "CHECK DOMAINS" in upper:
            section = "url_check"; continue
        if upper.startswith("ASNS"):
            section = "asn"; continue
        if "LOGIN INFRASTRUCTURE" in upper:
            section = "ip"; continue
        if upper.startswith("IP_ADDRESS"):
            continue  # table header

        if section in ("url", "url_check"):
            url = refang(line)
            host, _, path_part = url.partition("/")
            host = host.lower()
            yield dict(kind="url", value=f"https://{host}/{path_part}", host=host,
                       role="landing URL" if section == "url" else "'check' URL (pre-landing redirect)",
                       date=rdate, src=path.name)
        elif section == "ip":
            parts = re.split(r"\t+|\s{2,}", line)
            ip = parts[0]
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue  # filtering: drop malformed rows
            yield dict(kind="ip", value=ip, ua=parts[1] if len(parts) > 1 else "",
                       asn=parts[3] if len(parts) > 3 else "", date=rdate, src=path.name)
        elif section == "asn":
            m = re.match(r"(AS\d+)\s*-\s*(.+)", line)
            if m:
                yield dict(kind="asn", value=m.group(1), asn=m.group(2), date=rdate, src=path.name)


def main():
    raw_records = []
    for f in sorted(RAW.glob("esentire_*.txt")):
        raw_records.extend(parse_file(f))

    merged = {}  # (misp_type, value) -> row

    def add(mtype, category, value, to_ids, comment, rdate, src):
        key = (mtype, value)
        if key in merged:
            row = merged[key]
            row["first_seen_report"] = min(row["first_seen_report"], rdate)
            row["last_seen_report"] = max(row["last_seen_report"], rdate)
            row["_srcs"].add(src)
        else:
            merged[key] = dict(misp_type=mtype, category=category, value=value, to_ids=to_ids,
                               comment=comment, first_seen_report=rdate, last_seen_report=rdate,
                               _srcs={src})

    for r in raw_records:
        if r["kind"] == "url" and registered_domain(r["host"]) in EXCLUDE_FROM_IDS:
            note = EXCLUDE_FROM_IDS[registered_domain(r["host"])]
            # compromised legit site: the exact URL is still malicious, only the domain is excluded
            url_ids = "compromised" in note
            add("url", "Network activity", r["value"], url_ids,
                f"{r['role']}; " + ("compromised legitimate site - block this URL only, not the domain"
                                    if url_ids else note), r["date"], r["src"])
            add("hostname", "Network activity", r["host"], False, note, r["date"], r["src"])
            add("domain", "Network activity", registered_domain(r["host"]), False, note, r["date"], r["src"])
        elif r["kind"] == "url":
            add("url", "Network activity", r["value"], True, r["role"], r["date"], r["src"])
            add("hostname", "Network activity", r["host"], True, "Phishing hostname", r["date"], r["src"])
            add("domain", "Network activity", registered_domain(r["host"]), True,
                "Registered domain behind phishing hostnames", r["date"], r["src"])
        elif r["kind"] == "ip":
            ver = "IPv6" if ":" in r["value"] else "IPv4"
            add("ip-src", "Network activity", r["value"], True,
                f"AiTM login egress ({ver}); ASN: {r['asn']}; UA: {r['ua']}", r["date"], r["src"])
        elif r["kind"] == "asn":
            add("AS", "Network activity", r["value"], False, f"Hosting ASN: {r['asn']}", r["date"], r["src"])

    for mtype, cat, value, comment, src, to_ids in KIT_PATTERNS:
        add(mtype, cat, value, to_ids, comment, "2025-04" if "Trustwave" in src else "2024-03-25", src)

    rows = sorted(merged.values(), key=lambda r: (r["misp_type"], r["value"]))

    # Detection content written in Week 3 is stored in the same MISP event
    det = HERE.parent / "detection"
    rule_attrs = []
    for fname, mtype, comment in [("tycoon2fa.yar", "yara", "YARA rules (group-written, tested)"),
                                  ("tycoon2fa_axios_signin.yml", "sigma", "Sigma rule for Entra ID sign-in logs")]:
        if (det / fname).exists():
            rule_attrs.append({"type": mtype, "category": "Payload installation",
                               "value": (det / fname).read_text(encoding="utf-8"), "to_ids": False,
                               "comment": comment})

    # ---- CSV (defanged, safe to publish on GitHub) ----
    with OUT_CSV.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "misp_type", "category", "value_defanged", "to_ids", "comment",
                    "first_seen_report", "last_seen_report", "report_count", "sources"])
        for i, r in enumerate(rows, 1):
            val = r["value"]
            if r["misp_type"] in ("url", "hostname", "domain", "ip-src"):
                val = val.replace("https://", "hxxps://")
                val = defang(val) if r["misp_type"] != "ip-src" or ":" not in val else val
                if r["misp_type"] == "url":
                    val = val.replace("hxxps://", "hxxps[://]", 1)
            w.writerow([i, r["misp_type"], r["category"], val, r["to_ids"], r["comment"],
                        r["first_seen_report"], r["last_seen_report"], len(r["_srcs"]),
                        "; ".join(sorted(r["_srcs"]))])

    # ---- MISP event JSON (refanged, for import into MISP only) ----
    event = {"Event": {
        "info": "Tycoon2FA AiTM PhaaS kit - phishing infrastructure & kit artifacts (OSINT)",
        "date": date.today().isoformat(),
        "threat_level_id": "1", "analysis": "1", "distribution": "0",
        "Tag": [{"name": t} for t in EVENT_TAGS],
        "Attribute": [
            {"uuid": str(uuid.uuid4()), "type": r["misp_type"], "category": r["category"],
             "value": r["value"], "to_ids": r["to_ids"], "comment": r["comment"],
             "distribution": "5"}
            for r in rows
        ] + [dict(uuid=str(uuid.uuid4()), distribution="5", **a) for a in rule_attrs],
    }}
    OUT_MISP.write_text(json.dumps(event, indent=2, ensure_ascii=False), encoding="utf-8")

    # ---- Summary for the report ----
    from collections import Counter
    print(f"Raw records parsed : {len(raw_records)}")
    raw_keys = [(r["kind"], r["value"]) for r in raw_records]
    print(f"Duplicate raw rows : {len(raw_keys) - len(set(raw_keys))} (merged)")
    print(f"Unique indicators  : {len(rows)} (incl. derived hostnames/domains and kit patterns)")
    for t, n in Counter(r["misp_type"] for r in rows).most_common():
        print(f"  {t:<17}{n}")
    multi = [r for r in rows if len(r["_srcs"]) > 1]
    print(f"Seen in >1 report  : {len(multi)}")
    print(f"to_ids=True        : {sum(r['to_ids'] for r in rows)}  (filtered out: "
          f"{sum(1 for r in rows if 'FILTERED' in r['comment'])})")
    print(f"Detection rules added to MISP event: {len(rule_attrs)}")


if __name__ == "__main__":
    main()
