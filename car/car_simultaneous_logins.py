#!/usr/bin/env python3
"""
Week 7 - implement MITRE CAR analytic CAR-2013-02-008 "Simultaneous Logins on a Host"
and adapt it to cloud identity logs (Entra ID / Microsoft 365 sign-ins).

Original CAR pseudocode (car.mitre.org/analytics/CAR-2013-02-008):
    users_list   = search UserSession:Login
    users_grouped = group users_list by hostname
    users_grouped = select min(time), max(time), count(user) by hostname
    multiple_logins = filter where (max-min <= 1 hour and user_count > 1)

The original flags one HOST with several USERS at once. In an AiTM attack there is instead one
ACCOUNT used from two places at once (the real victim and the attacker's relay). So we keep the
exact idea - "the same principal active from two places inside one hour" - but group by USER and
count distinct source networks (ASNs) instead of distinct users on a host. This is the cloud
analogue, close to an "impossible travel" / concurrent-session analytic.

Input : ../hunting/hunt_logs.ndjson  (the Week 5 synthetic Microsoft 365 dataset)
Output: car_results.txt  (findings + scoring against ../hunting/ground_truth.json)

Run: python3 car/car_simultaneous_logins.py
"""
import datetime as dt
import json
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOGS = HERE.parent / "hunting" / "hunt_logs.ndjson"
TRUTH = json.loads((HERE.parent / "hunting" / "ground_truth.json").read_text())["malicious_users"]
KNOWN_ASN = {64500, 64501}      # corporate network + the employees' home ISP = "normal" sources
WINDOW = 3600                   # one hour, exactly as in the CAR analytic


def t(x):
    return dt.datetime.strptime(x[:19], "%Y-%m-%dT%H:%M:%S")


signins = [json.loads(l) for l in LOGS.read_text().splitlines()
           if json.loads(l)["log_type"] == "signin" and json.loads(l)["result"] == "success"]
by_user = defaultdict(list)
for e in signins:
    by_user[e["user"]].append(e)

rows = []
for user, lst in by_user.items():
    lst.sort(key=lambda e: e["@timestamp"])
    hit = None
    for a in lst:
        for b in lst:
            if a is b:
                continue
            if abs((t(a["@timestamp"]) - t(b["@timestamp"])).total_seconds()) <= WINDOW \
               and a["asn"] != b["asn"] and (a["asn"] not in KNOWN_ASN or b["asn"] not in KNOWN_ASN):
                pair = sorted([a, b], key=lambda e: e["@timestamp"])
                hit = (pair[0]["@timestamp"], f"{pair[0]['asn_name']} ({pair[0]['src_ip']})",
                       pair[1]["@timestamp"], f"{pair[1]['asn_name']} ({pair[1]['src_ip']})")
                break
        if hit:
            break
    if hit:
        rows.append((user, *hit))

flagged = {r[0] for r in rows}
mal = set(TRUTH)
tp, fp, missed = flagged & mal, flagged - mal, mal - flagged

out = ["# CAR-2013-02-008 (Simultaneous Logins) adapted to cloud sign-ins",
       f"# dataset: {LOGS.name} ({len(signins)} successful sign-ins), window = 1 hour",
       f"# logic: same account active from 2+ distinct ASNs (>=1 external) within 1 hour", ""]
out.append(f"{'user':<34}{'first login (ASN)':<46}{'second login (ASN)'}")
for u, t1, a1, t2, a2 in sorted(rows):
    out.append(f"{u:<34}{t1[11:16]+'  '+a1:<46}{t2[11:16]+'  '+a2}")
out += ["",
        f"flagged users : {len(flagged)}   true positives : {len(tp)}   false positives : {len(fp)}",
        f"compromised users found : {len(tp)}/{len(mal)}   not flagged : {sorted(missed)}",
        "",
        "# Note: this analytic finds overlapping sessions. It catches victims whose real (KZ) session",
        "# and the attacker's external session overlap within the hour. A victim with no concurrent",
        "# legitimate session in the window is missed here - that case is caught by the Week 5 hunts",
        "# (H1 new-MFA, H3 Graph burst). One analytic is not full coverage; analytics complement each other."]
(HERE / "car_results.txt").write_text("\n".join(out) + "\n", encoding="utf-8")
print("\n".join(out))
