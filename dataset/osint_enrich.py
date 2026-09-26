#!/usr/bin/env python3
"""
Week 2 - OSINT enrichment of Tycoon2FA indicators with free public sources.

  * Shodan InternetDB  (https://internetdb.shodan.io/<ip>)      - open ports, CPEs, CVEs (no API key)
  * RIPEstat           (https://stat.ripe.net)                   - announcing prefix / ASN / holder
  * RDAP (Verisign)    (https://rdap.verisign.com/com/v1/domain) - registrar, creation date, nameservers
  * VirusTotal API v3  (optional, set VT_API_KEY)                - detection ratio for domains

Writes: enrichment_ip.csv, enrichment_domain.csv (and enrichment_vt.csv if VT_API_KEY is set)

The CSVs committed in this folder were collected on 2026-09-26 by querying these same
endpoints; run this script to refresh them (results change over time - IPs rotate,
domains expire and get re-registered).

Usage:
    python3 osint_enrich.py
    VT_API_KEY=xxxx python3 osint_enrich.py      # also query VirusTotal
Only the Python standard library is required.
"""
import csv
import json
import os
import time
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
TODAY = date.today().isoformat()

IPV4 = [
    "130.49.117.205", "138.249.139.6", "142.252.171.135", "142.252.86.104",
    "166.1.241.247", "166.1.255.233", "166.88.219.45", "170.168.215.64",
    "172.120.234.223", "172.120.57.92", "172.121.59.99", "193.228.131.161",
    "45.39.175.12", "50.118.198.26",
]
COM_DOMAINS = ["fesxtmc.com", "shoupeatai.com", "shailoyio.com",
               "sistaidru.com", "yljdimage.com", "alnaharegypt.com"]


def get_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "cti-student-project"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None           # InternetDB: "no information available"
        raise


def esentire_labels():
    labels = {}
    raw = HERE / "esentire_tycoon2fa_2026-03-23.txt"
    for line in raw.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and parts[0] in IPV4:
            labels[parts[0]] = parts[3]
    return labels


def enrich_ips():
    labels = esentire_labels()
    rows = []
    for ip in IPV4:
        ripe = get_json(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}")["data"]
        asn = ripe["asns"][0] if ripe.get("asns") else {"asn": "", "holder": ""}
        sh = get_json(f"https://internetdb.shodan.io/{ip}")
        cpes = ";".join(c.replace("cpe:/a:", "").replace("cpe:/o:", "").split(":", 1)[-1]
                        for c in (sh or {}).get("cpes", []))
        rows.append([ip, labels.get(ip, ""), ripe.get("resource", ""), f"AS{asn['asn']}", asn["holder"],
                     "yes" if sh else "no",
                     ";".join(map(str, (sh or {}).get("ports", []))), cpes,
                     len((sh or {}).get("vulns", [])) if sh else "", TODAY])
        time.sleep(1)
    with open(HERE / "enrichment_ip.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "esentire_asn_label_2026-03-23", "ripestat_prefix", "ripestat_origin_asn",
                    "ripestat_as_holder", "shodan_indexed", "shodan_ports", "shodan_cpes",
                    "shodan_vulns_count", "collected_utc"])
        w.writerows(rows)
    print(f"enrichment_ip.csv: {len(rows)} IPs, {sum(r[5] == 'yes' for r in rows)} indexed by Shodan")


def enrich_domains():
    rows = []
    for d in COM_DOMAINS:
        j = get_json(f"https://rdap.verisign.com/com/v1/domain/{d}")
        if not j:
            rows.append([d, "NOT FOUND", "", "", "", "", "", TODAY]); continue
        ev = {e["eventAction"]: e["eventDate"][:10] for e in j.get("events", [])}
        registrar = next((ent.get("vcardArray", [None, [[None, None, None, ""]]])[1][1][3]
                          for ent in j.get("entities", []) if "registrar" in ent.get("roles", [])), "")
        ns = "/".join(n["ldhName"].lower() for n in j.get("nameservers", []))
        rows.append([d, registrar, ev.get("registration", ""), ev.get("expiration", ""),
                     ev.get("last changed", ""), ns, "", TODAY])
        time.sleep(1)
    with open(HERE / "enrichment_domain.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "rdap_registrar", "created", "expires", "last_changed",
                    "nameservers", "assessment", "collected_utc"])
        w.writerows(rows)
    print(f"enrichment_domain.csv: {len(rows)} domains (fill in 'assessment' manually)")


def enrich_virustotal(key):
    rows = []
    for d in COM_DOMAINS:
        j = get_json(f"https://www.virustotal.com/api/v3/domains/{d}", {"x-apikey": key})
        st = j["data"]["attributes"]["last_analysis_stats"] if j else {}
        rows.append([d, st.get("malicious", ""), st.get("suspicious", ""), st.get("harmless", ""), TODAY])
        time.sleep(16)  # free API: 4 requests / minute
    with open(HERE / "enrichment_vt.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "vt_malicious", "vt_suspicious", "vt_harmless", "collected_utc"])
        w.writerows(rows)
    print(f"enrichment_vt.csv: {len(rows)} domains")


if __name__ == "__main__":
    enrich_ips()
    enrich_domains()
    if os.environ.get("VT_API_KEY"):
        enrich_virustotal(os.environ["VT_API_KEY"])
    else:
        print("VT_API_KEY not set - VirusTotal step skipped")
