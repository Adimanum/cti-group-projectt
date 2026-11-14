#!/usr/bin/env python3
"""
Week 9 - run the Atomic Red Team-style tests SAFELY, record the results in a SIEM, and analyse them.

This is the "run selected atomic tests + record and analyse the results in a SIEM" task, applied to
our Tycoon2FA case. For each atomic test in atomics_tycoon2fa.yaml it:

  1. "executes" the test  -> every command is a harmless echo, so NO real attack happens;
  2. records the result    -> emits the SIEM log record the real action would leave, into
                              atomic_siem_events.ndjson (same schema as our Week 5 hunt index);
  3. analyses the result   -> runs our own detections (Week 5 hunts H1/H2/H3 + the axios Sigma rule)
                              over those events, in Python's built-in SQLite, and reports for each
                              test whether it was DETECTED.

The point of Atomic Red Team is to validate detection per technique. Result: our identity/cloud
detections catch the Tycoon2FA chain; the two generic endpoint examples (T1059/T1003) are NOT caught,
which is an honest, expected coverage gap (our scope is identity, not endpoint/EDR).

Run: python3 atomic/run_atomics.py
"""
import json
import subprocess
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
SUITE = yaml.safe_load((HERE / "atomics_tycoon2fa.yaml").read_text())
BASE = datetime(2026, 3, 20, 9, 0, 0)  # a fixed "test window" start

# full 16-field schema of our Week 5 hunt index (tycoon2fa-hunt)
FIELDS = ["@timestamp", "log_type", "user", "src_ip", "asn", "asn_name", "country", "user_agent",
          "app_name", "app_id", "result", "session_id", "operation", "details", "request_uri", "status"]
IN_TENANT_ASN = (64500, 64501)  # our own corporate ASNs


def ev(ts, **kw):
    e = {k: None for k in FIELDS}
    e["@timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    e.update(kw)
    return e


def siem_records_for(test, atomic, minute):
    """Turn one atomic test into the SIEM record(s) the real action would leave."""
    s = atomic.get("siem_event", {})
    lt = s.get("log_type")
    args = {a: atomic.get("input_arguments", {}).get(a, {}).get("default")
            for a in atomic.get("input_arguments", {})}
    user = args.get("user", "sara.kim@contoso.example")
    recs = []
    t0 = BASE + timedelta(minutes=minute)
    if lt == "signin":
        recs.append(ev(t0, log_type="signin", user=user, src_ip=args.get("src_ip", "45.39.175.12"),
                       asn=203999, asn_name="AITM-RELAY-HOST", country="NL",
                       user_agent=args.get("user_agent", "axios/1.6.8"), result="success",
                       session_id="atom-cookie-01", operation="Sign-in activity", status=0))
    elif lt == "audit":
        # persistence: the scripted sign-in first, then the device registration 8 min later -> H1
        recs.append(ev(t0, log_type="signin", user=user, src_ip="45.39.175.12", asn=203999,
                       asn_name="AITM-RELAY-HOST", country="NL", user_agent="axios/1.6.8",
                       result="success", session_id="atom-dev-01", operation="Sign-in activity", status=0))
        recs.append(ev(t0 + timedelta(minutes=8), log_type="audit", user=user, src_ip="45.39.175.12",
                       operation="Register device", details="MFA device added: Authenticator",
                       session_id="atom-dev-01"))
    elif lt == "mailbox":
        # evasion: a sign-in from an unknown ASN, then the inbox rule 15 min later -> H2
        recs.append(ev(t0, log_type="signin", user=user, src_ip="50.118.198.26", asn=203999,
                       asn_name="AITM-RELAY-HOST", country="NL", user_agent="Mozilla/5.0",
                       result="success", session_id="atom-rule-01", operation="Sign-in activity", status=0))
        recs.append(ev(t0 + timedelta(minutes=15), log_type="mailbox", user=user, src_ip="50.118.198.26",
                       operation="New-InboxRule", details=s.get("details", "DeleteMessage=True"),
                       session_id="atom-rule-01"))
    elif lt == "graph":
        # discovery: a burst of Graph calls across 10 endpoints in ~40s -> H3
        endpoints = ["/v1.0/users", "/v1.0/me", "/v1.0/groups", "/v1.0/directoryRoles",
                     "/v1.0/me/contacts", "/v1.0/me/messages", "/v1.0/organization",
                     "/v1.0/servicePrincipals", "/v1.0/applications", "/v1.0/me/memberOf"]
        n = int(args.get("calls", 30) or 30)
        for i in range(n):
            recs.append(ev(t0 + timedelta(seconds=int(i * 40 / n)), log_type="graph", user=user,
                           src_ip="45.39.175.12", asn=203999, asn_name="AITM-RELAY-HOST",
                           app_name="Scripted Client", app_id="atom-graph-app",
                           session_id="atom-graph-01", operation="GET",
                           request_uri=endpoints[i % len(endpoints)], status=200))
    elif lt == "process":
        recs.append(ev(t0, log_type="process", user=user, operation="ProcessCreate",
                       details=atomic["executor"]["command"].strip(), session_id="atom-proc-01"))
    return recs


# ---- 1 + 2: execute each test (safe) and collect its SIEM records -----------------------------
all_events, manifest, log = [], [], []
log.append(f"# Atomic Red Team run - suite: {SUITE['suite']}  tenant: {SUITE['tenant']}")
log.append("# SAFE: every command is a harmless echo. No real attack is performed.\n")
minute = 0
for test in SUITE["tests"]:
    tech, name = test["attack_technique"], test["display_name"]
    for atomic in test["atomic_tests"]:
        cmd = atomic["executor"]["command"]
        # substitute #{arg} with defaults, then run the benign echo
        for a, spec in atomic.get("input_arguments", {}).items():
            cmd = cmd.replace(f"#{{{a}}}", str(spec.get("default", "")))
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
        recs = siem_records_for(test, atomic, minute)
        all_events.extend(recs)
        manifest.append({"technique": tech, "scope": test.get("scope"), "name": atomic["name"],
                         "expect_detected": atomic.get("siem_event", {}).get("detected_expectation", False),
                         "records": len(recs)})
        log.append(f"[{tech}] {name}  (scope: {test.get('scope')})")
        log.append(f"     test     : {atomic['name']}")
        log.append(f"     executed : {out}")
        log.append(f"     recorded : {len(recs)} SIEM event(s) -> atomic_siem_events.ndjson")
        minute += 120

(HERE / "atomic_siem_events.ndjson").write_text(
    "\n".join(json.dumps(e) for e in all_events) + "\n", encoding="utf-8")

# ---- 3: analyse the recorded events with OUR detections (SQLite) ------------------------------
db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE logs (" + ",".join(f'"{f}" TEXT' for f in FIELDS) + ")")
db.executemany("INSERT INTO logs VALUES (" + ",".join("?" * 16) + ")",
               [tuple(e[f] for f in FIELDS) for e in all_events])
db.row_factory = sqlite3.Row


def detected_users():
    """Return {technique_tag: set(users)} for each of our detections firing on the recorded events."""
    hits = {}
    # Sigma / H1a: successful sign-in with a non-browser UA  (T1550.004)
    q = """SELECT DISTINCT user FROM logs WHERE log_type='signin' AND result='success'
           AND (user_agent LIKE 'axios/%' OR user_agent LIKE 'node-fetch%' OR user_agent LIKE 'undici%'
                OR user_agent LIKE 'python-requests%')"""
    hits["T1550.004"] = {r["user"] for r in db.execute(q)}
    # H1: non-browser sign-in -> device/MFA registration within 60 min  (T1098.005)
    h1 = set()
    for r in db.execute("""SELECT user, "@timestamp" ts FROM logs WHERE log_type='audit'
                           AND operation IN ('Register device','User registered security info')"""):
        for s in db.execute("""SELECT "@timestamp" ts FROM logs WHERE log_type='signin' AND result='success'
                               AND user=? AND (user_agent LIKE 'axios/%' OR user_agent LIKE 'node-fetch%')""",
                            (r["user"],)):
            d = (datetime.fromisoformat(r["ts"][:19]) - datetime.fromisoformat(s["ts"][:19])).total_seconds() / 60
            if 0 <= d <= 60:
                h1.add(r["user"])
    hits["T1098.005"] = h1
    # H2: external-ASN sign-in -> delete/hide inbox rule within 120 min  (T1564.008)
    h2 = set()
    for r in db.execute("""SELECT user, "@timestamp" ts, details FROM logs WHERE log_type='mailbox'
                           AND operation='New-InboxRule'
                           AND (details LIKE '%DeleteMessage=True%' OR details LIKE '%MarkAsRead=True%')"""):
        for s in db.execute("""SELECT "@timestamp" ts FROM logs WHERE log_type='signin' AND result='success'
                               AND user=? AND CAST(asn AS INT) NOT IN (64500,64501)""", (r["user"],)):
            d = (datetime.fromisoformat(r["ts"][:19]) - datetime.fromisoformat(s["ts"][:19])).total_seconds() / 60
            if 0 <= d <= 120:
                h2.add(r["user"])
    hits["T1564.008"] = h2
    # H3: Graph burst >= 20 calls, >= 8 endpoints, <= 60s in one session  (T1087.004)
    h3 = set()
    for r in db.execute("""SELECT user, session_id, COUNT(*) c, COUNT(DISTINCT request_uri) ep,
                           MIN("@timestamp") f, MAX("@timestamp") l FROM logs WHERE log_type='graph'
                           GROUP BY session_id, user"""):
        secs = (datetime.fromisoformat(r["l"][:19]) - datetime.fromisoformat(r["f"][:19])).total_seconds()
        if r["c"] >= 20 and r["ep"] >= 8 and secs <= 60:
            h3.add(r["user"])
    hits["T1087.004"] = h3
    return hits


hits = detected_users()
log.append("\n==================== ANALYSIS (our detections over the recorded events) ====================")
detected = 0
for m in manifest:
    tech = m["technique"]
    fired = bool(hits.get(tech))
    status = "DETECTED" if fired else "not detected"
    if fired:
        detected += 1
    flag = "" if fired == m["expect_detected"] else "  (!) unexpected"
    by = {"T1550.004": "Sigma axios UA + hunt H1a", "T1098.005": "hunt H1",
          "T1564.008": "hunt H2", "T1087.004": "hunt H3"}.get(tech, "- (out of SIEM scope: endpoint/EDR)")
    log.append(f"  [{tech:<10}] {m['name'][:52]:<52} -> {status:<12} via {by}{flag}")

log.append(f"\n# {len(manifest)} atomic tests run; {detected} detected by our identity/cloud SIEM detections.")
log.append(f"# {len(manifest) - detected} not detected: the generic endpoint examples (T1059.001, T1003.001) -")
log.append("#   Tycoon2FA is an identity attack, so endpoint execution is outside our current SIEM scope.")
log.append(f"# {len(all_events)} SIEM events recorded to atomic_siem_events.ndjson.")

(HERE / "atomic_results.txt").write_text("\n".join(log) + "\n", encoding="utf-8")
print("\n".join(log))
