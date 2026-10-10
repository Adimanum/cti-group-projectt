#!/usr/bin/env python3
"""
Week 5 - Execute the hypothesis-driven hunts.

The same hunt logic is written three times:
  * queries_esql.txt  - for Elastic (Kibana Discover -> ES|QL), index "tycoon2fa-hunt"
  * queries_spl.txt   - for Splunk (index=tycoon2fa)
  * below, as SQL     - executed here with Python's built-in SQLite, so the hunts can be run and
                        checked anywhere without a SIEM licence

Input : hunt_logs.ndjson (generate_logs.py), ../dataset/tycoon2fa_iocs.csv (our Week 3 IOC dataset)
Output: hunt_results.txt (findings + scoring against ground_truth.json)
"""
import csv
import json
import sqlite3
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOGS = HERE / "hunt_logs.ndjson"
IOCS = HERE.parent / "dataset" / "tycoon2fa_iocs.csv"
truth = json.loads((HERE / "ground_truth.json").read_text())
MAL = set(truth["malicious_users"])

db = sqlite3.connect(":memory:")
db.execute("""CREATE TABLE logs (ts TEXT, log_type TEXT, user TEXT, src_ip TEXT, asn INT, asn_name TEXT, country TEXT,
              user_agent TEXT, app_name TEXT, app_id TEXT, result TEXT, session_id TEXT, operation TEXT,
              details TEXT, request_uri TEXT, status INT)""")
rows = []
for line in LOGS.read_text(encoding="utf-8").splitlines():
    e = json.loads(line)
    rows.append((e["@timestamp"], e["log_type"], e["user"], e["src_ip"], e["asn"], e["asn_name"], e["country"],
                 e["user_agent"], e["app_name"], e["app_id"], e["result"], e["session_id"], e["operation"],
                 e["details"], e["request_uri"], e["status"]))
db.executemany("INSERT INTO logs VALUES (" + ",".join("?" * 16) + ")", rows)
db.execute("CREATE TABLE ioc_ip (ip TEXT PRIMARY KEY)")
with open(IOCS, encoding="utf-8") as f:
    db.executemany("INSERT OR IGNORE INTO ioc_ip VALUES (?)",
                   [(r["value_defanged"].replace("[.]", "."),) for r in csv.DictReader(f) if r["misp_type"] == "ip-src"])

NON_BROWSER = "(user_agent LIKE 'axios/%' OR user_agent LIKE 'node-fetch%' OR user_agent LIKE 'undici%' " \
              "OR user_agent = 'node' OR user_agent LIKE 'python-requests%')"
KNOWN_ASN = "(64500, 64501)"   # corporate network + the national home ISP used by employees

HUNTS = [
    ("H0", "Intel-driven IOC sweep: any sign-in from the 76 Tycoon2FA egress IPs (Week 3 dataset)", "T1078.004",
     """SELECT l.user, l.ts, l.src_ip, l.user_agent, l.result
        FROM logs l JOIN ioc_ip i ON l.src_ip = i.ip
        WHERE l.log_type = 'signin' ORDER BY l.ts"""),

    ("H1a", "Step 1 (broad): successful sign-ins with a non-browser User-Agent", "T1550.004",
     f"""SELECT user, COUNT(*) AS signins, GROUP_CONCAT(DISTINCT user_agent) AS user_agents,
               GROUP_CONCAT(DISTINCT src_ip) AS ips
        FROM logs WHERE log_type = 'signin' AND result = 'success' AND {NON_BROWSER}
        GROUP BY user ORDER BY user"""),

    ("H1", "Step 2 (correlated): non-browser sign-in followed within 60 min by a new MFA method or device registration", "T1098.005",
     f"""SELECT s.user, s.ts AS odd_signin, s.user_agent, s.src_ip, a.ts AS registered, a.operation, a.details,
               CAST(ROUND((julianday(a.ts) - julianday(s.ts)) * 1440) AS INT) AS minutes_after
        FROM logs s JOIN logs a ON a.user = s.user
        WHERE s.log_type = 'signin' AND s.result = 'success' AND {NON_BROWSER.replace('user_agent', 's.user_agent')}
          AND a.log_type = 'audit' AND a.operation IN ('User registered security info', 'Register device')
          AND julianday(a.ts) BETWEEN julianday(s.ts) AND julianday(s.ts) + 60.0/1440
        ORDER BY s.ts"""),

    ("H2", "New inbox rule that deletes / hides mail, created within 2 h after a sign-in from an unknown (hosting) ASN", "T1564.008",
     f"""SELECT r.user, s.ts AS risky_signin, s.src_ip, s.asn_name, r.ts AS rule_created, r.details,
               CAST(ROUND((julianday(r.ts) - julianday(s.ts)) * 1440) AS INT) AS minutes_after
        FROM logs r JOIN logs s ON s.user = r.user
        WHERE r.log_type = 'mailbox' AND r.operation = 'New-InboxRule'
          AND (r.details LIKE '%DeleteMessage=True%' OR r.details LIKE '%MarkAsRead=True%')
          AND s.log_type = 'signin' AND s.result = 'success' AND s.asn NOT IN {KNOWN_ASN}
          AND julianday(r.ts) BETWEEN julianday(s.ts) AND julianday(s.ts) + 120.0/1440
        GROUP BY r.user, r.ts ORDER BY r.ts"""),

    ("H3a", "Graph burst (raw): one session with >= 20 Graph calls inside 60 s", "T1087.004",
     """SELECT user, session_id, src_ip, app_name, COUNT(*) AS calls, COUNT(DISTINCT request_uri) AS endpoints,
               CAST(ROUND((julianday(MAX(ts)) - julianday(MIN(ts))) * 86400) AS INT) AS seconds
        FROM logs WHERE log_type = 'graph'
        GROUP BY session_id HAVING calls >= 20 AND seconds <= 60 ORDER BY MIN(ts)"""),

    ("H3", "Graph burst (tuned): same, but >= 8 DIFFERENT endpoints (reconnaissance, not bulk export)", "T1087.004",
     """SELECT user, session_id, src_ip, app_name, COUNT(*) AS calls, COUNT(DISTINCT request_uri) AS endpoints,
               CAST(ROUND((julianday(MAX(ts)) - julianday(MIN(ts))) * 86400) AS INT) AS seconds
        FROM logs WHERE log_type = 'graph'
        GROUP BY session_id HAVING calls >= 20 AND seconds <= 60 AND endpoints >= 8 ORDER BY MIN(ts)"""),
]

out = [f"# Tycoon2FA hunt results  (dataset: {len(rows)} events, {LOGS.name}; IOC list: "
       f"{db.execute('SELECT COUNT(*) FROM ioc_ip').fetchone()[0]} IPs)",
       f"# ground truth: {len(MAL)} compromised users = {', '.join(sorted(MAL))}", ""]
summary = []
for hid, title, technique, sql in HUNTS:
    cur = db.execute(sql)
    cols = [d[0] for d in cur.description]
    res = cur.fetchall()
    users = {r[0] for r in res}
    tp, fp, fn = users & MAL, users - MAL, MAL - users
    out.append(f"## {hid} [{technique}] {title}")
    out.append("   " + " | ".join(cols))
    for r in res:
        out.append("   " + " | ".join("" if v is None else str(v)[:70] for v in r))
    if not res:
        out.append("   (no results)")
    out.append(f"   => users flagged: {len(users)}  TP={len(tp)}  FP={len(fp)} {sorted(fp) if fp else ''}  not flagged={len(fn)}")
    out.append("")
    summary.append((hid, technique, len(users), len(tp), len(fp), len(fn)))

out.append("## Summary")
out.append("   hunt | technique | flagged users | true positives | false positives | compromised users not flagged")
for s in summary:
    out.append("   " + " | ".join(map(str, s)))
flagged_any = set()
for hid, title, technique, sql in HUNTS:
    if hid in ("H0", "H1", "H2", "H3"):
        flagged_any |= {r[0] for r in db.execute(sql).fetchall()}
out.append("")
out.append(f"# Combined (H0 + H1 + H2 + H3): {len(flagged_any & MAL)}/{len(MAL)} compromised users found, "
           f"{len(flagged_any - MAL)} false positives")
out.append("# Note: 'not flagged' counts compromised users the hunt did not flag. Not every victim performed every "
           "behaviour (only one created an inbox rule), so H2/H3 are expected to see only some of them.")
(HERE / "hunt_results.txt").write_text("\n".join(out) + "\n", encoding="utf-8")
print("\n".join(out))
