#!/usr/bin/env python3
"""
Week 5 - Build a SYNTHETIC hunting dataset for a fictional tenant (contoso.example).

Why synthetic: we have no access to a real company's Microsoft 365 logs. We therefore simulate
7 days of normal activity for 60 users and inject the Tycoon2FA post-compromise behaviour
described by Microsoft (2026), Elastic (2026) and eSentire (2026). The attacker IPs and
User-Agents come from our real dataset (dataset/tycoon2fa_iocs.csv), so the IOC sweep is
realistic. All users, benign IPs (RFC 5737 ranges) and benign apps are fictitious.

Output: hunt_logs.ndjson  - one JSON event per line, one index for Elastic / one sourcetype for Splunk
        ground_truth.json - which events/users are malicious (used only to score the hunts)

Fields (one flat schema for all log types):
  @timestamp, log_type (signin | audit | mailbox | graph), user, src_ip, asn, asn_name, country,
  user_agent, app_name, app_id, result, session_id, operation, details, request_uri, status
"""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
random.seed(2026)
START = datetime(2026, 3, 16, tzinfo=timezone.utc)   # Mon 16 Mar 2026, a week before the eSentire list
DAYS = 7
OFFICEHOME = "4765445b-32c6-49b0-83e6-1d93765276ca"
APPS = [("Microsoft Teams", "1fec8e78-bce4-4aaf-ab1b-5451cc387264"),
        ("Office 365 Exchange Online", "00000002-0000-0ff1-ce00-000000000000"),
        ("OfficeHome", OFFICEHOME),
        ("Microsoft Office", "d3590ed6-52b3-4102-aeff-aad2292ab01c")]
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17328)",
]
OFFICE_NET = [("192.0.2.%d" % i, 64500, "CONTOSO-CORP", "KZ") for i in range(10, 60)]
HOME_NET = [("198.51.100.%d" % i, 64501, "KAZAKHTELECOM-HOME", "KZ") for i in range(2, 200)]
FIRST = ["aliya", "daniyar", "madina", "nursultan", "aigerim", "timur", "dana", "arman", "zhanna", "erlan",
         "saule", "bekzat", "kamila", "ruslan", "asel", "yerlan", "dinara", "askar", "gulnara", "marat"]
LAST = ["sadykova", "omarov", "akhmetova", "seitkali", "nurlanova", "zhaksybek", "abenova", "karimov", "tulegen"]
USERS = sorted({f"{random.choice(FIRST)}.{random.choice(LAST)}@contoso.example" for _ in range(200)})[:60]

events, truth = [], {"malicious_users": {}, "false_positive_traps": {}}


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def add(dt, log_type, user, **kw):
    e = {"@timestamp": ts(dt), "log_type": log_type, "user": user, "src_ip": "", "asn": None, "asn_name": "",
         "country": "", "user_agent": "", "app_name": "", "app_id": "", "result": "", "session_id": "",
         "operation": "", "details": "", "request_uri": "", "status": None}
    e.update(kw)
    events.append(e)
    return e


def sid():
    return "%08x-%04x-%04x" % (random.getrandbits(32), random.getrandbits(16), random.getrandbits(16))


# ------------------------------------------------------------------ benign background
user_home = {u: random.choice(HOME_NET) for u in USERS}
user_ua = {u: random.choice(BROWSERS) for u in USERS}
for day in range(DAYS):
    d = START + timedelta(days=day)
    weekend = d.weekday() >= 5
    for u in USERS:
        n = random.randint(0, 2) if weekend else random.randint(3, 9)
        for _ in range(n):
            at_office = not weekend and random.random() < 0.7
            ip, asn, asn_name, cc = random.choice(OFFICE_NET) if at_office else user_home[u]
            t = d + timedelta(hours=random.uniform(7, 21))
            app = random.choice(APPS)
            ok = random.random() > 0.04
            add(t, "signin", u, src_ip=ip, asn=asn, asn_name=asn_name, country=cc, user_agent=user_ua[u],
                app_name=app[0], app_id=app[1], result="success" if ok else "failure", details="" if ok else random.choice(["error 50126: invalid password", "error 50074: MFA required"]),
                session_id=sid(), operation="Sign-in activity")
            # normal Graph usage by first-party apps: a few calls per session
            if ok and random.random() < 0.3:
                s = events[-1]["session_id"]
                for k in range(random.randint(1, 6)):
                    add(t + timedelta(seconds=random.randint(5, 900)), "graph", u, src_ip=ip, app_id=app[1],
                        app_name=app[0], session_id=s, operation="GET",
                        request_uri=random.choice(["/v1.0/me", "/v1.0/me/messages", "/v1.0/me/events",
                                                   "/v1.0/me/drive/recent", "/v1.0/me/photo/$value"]), status=200)

# benign security-info registrations (new phones) after normal browser sign-ins
for u in random.sample(USERS, 6):
    t = START + timedelta(days=random.randint(0, 4), hours=random.uniform(9, 17))
    ip, asn, asn_name, cc = random.choice(OFFICE_NET)
    add(t, "signin", u, src_ip=ip, asn=asn, asn_name=asn_name, country=cc, user_agent=user_ua[u],
        app_name="My Signins", app_id="19db86c3-b2b9-44cc-b339-36da233a3be2", result="success", session_id=sid(),
        operation="Sign-in activity")
    add(t + timedelta(minutes=random.randint(2, 15)), "audit", u, src_ip=ip, operation="User registered security info",
        details="Authenticator App (new phone)", result="success")

# benign inbox rules (newsletters, notifications)
for u in random.sample(USERS, 12):
    t = START + timedelta(days=random.randint(0, 6), hours=random.uniform(9, 18))
    ip, *_ = random.choice(OFFICE_NET)
    add(t, "mailbox", u, src_ip=ip, operation="New-InboxRule",
        details=random.choice(["Name=Newsletters; From=news@; MoveToFolder=Newsletters",
                               "Name=Jira; SubjectContains=[JIRA]; MoveToFolder=Jira",
                               "Name=Boss; From=ceo@contoso.example; MarkImportance=High"]), result="success")

# ------------------------------------------------------------------ false-positive traps (benign but look odd)
svc = "svc-reporting@contoso.example"
for day in range(DAYS):
    t = START + timedelta(days=day, hours=2)
    add(t, "signin", svc, src_ip="192.0.2.5", asn=64500, asn_name="CONTOSO-CORP", country="KZ",
        user_agent="python-requests/2.32.3", app_name="Reporting script", app_id="7a1e2c55-1111-4c0d-9b1e-2f6b3c4d5e6f",
        result="success", session_id=sid(), operation="Sign-in activity")
truth["false_positive_traps"][svc] = "internal reporting script: non-browser UA from the corporate network, no MFA change"

backup = "svc-backup@contoso.example"
for day in range(DAYS):
    s, t = sid(), START + timedelta(days=day, hours=1)
    for k in range(120):
        add(t + timedelta(seconds=k * 0.4), "graph", backup, src_ip="192.0.2.6", app_id="b4c1d5e6-2222-4f00-8a1b-backup0000001",
            app_name="Contoso Mail Backup", session_id=s, operation="GET",
            request_uri=random.choice(["/v1.0/users", "/v1.0/users/{id}/messages", "/v1.0/users/{id}/mailFolders"]), status=200)
truth["false_positive_traps"][backup] = "approved backup application: Graph burst every night from the corporate network"

helpdesk = USERS[5]
t = START + timedelta(days=2, hours=11)
add(t, "signin", helpdesk, src_ip="192.0.2.20", asn=64500, asn_name="CONTOSO-CORP", country="KZ",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134.0 Safari/537.36",
    app_name="Microsoft Teams", app_id=APPS[0][1], result="success", session_id=sid(), operation="Sign-in activity")
add(t + timedelta(minutes=20), "mailbox", helpdesk, src_ip="192.0.2.20", operation="New-InboxRule",
    details="Name=Auto-delete spam; From=promo@shop.example; DeleteMessage=True", result="success")
truth["false_positive_traps"][helpdesk] = "user deletes promo mail from the office network: delete rule, but no risky sign-in"

# ------------------------------------------------------------------ injected Tycoon2FA intrusions
GRAPH_RECON = ["/v1.0/me", "/v1.0/me/memberOf", "/v1.0/directoryRoles", "/v1.0/organization",
               "/v1.0/me/contactFolders/contacts?$top=1000", "/v1.0/users?$top=999", "/v1.0/me/mailboxSettings",
               "/v1.0/tenantRelationships/delegatedAdminCustomers", "/v1.0/me/messages?$top=50", "/v1.0/groups",
               "/v1.0/me/drive/root/children", "/v1.0/policies/conditionalAccessPolicies"]


def intrusion(user, t0, ip, asn, asn_name, cc, ua, steps, label):
    s = sid()
    # the victim's own browser sign-in through the AiTM proxy (relayed, looks normal)
    add(t0 - timedelta(minutes=3), "signin", user, src_ip=ip, asn=asn, asn_name=asn_name, country=cc,
        user_agent=user_ua[user], app_name="OfficeHome", app_id=OFFICEHOME, result="success", session_id=sid(),
        operation="Sign-in activity", details="interactive; MFA satisfied")
    # replay of the stolen session cookie from the relay server
    add(t0, "signin", user, src_ip=ip, asn=asn, asn_name=asn_name, country=cc, user_agent=ua,
        app_name="OfficeHome", app_id=OFFICEHOME, result="success", session_id=s, operation="Sign-in activity",
        details="non-interactive; token replay")
    if "mfa" in steps:
        add(t0 + timedelta(minutes=random.randint(4, 25)), "audit", user, src_ip=ip,
            operation="User registered security info", details="Authenticator App (attacker phone)", result="success")
    if "device" in steps:
        add(t0 + timedelta(minutes=random.randint(5, 30)), "audit", user, src_ip=ip,
            operation="Register device", details="DeviceName=DESKTOP-7F3K2Q; join type=Azure AD registered -> PRT",
            result="success")
    if "graph" in steps:
        g0 = t0 + timedelta(minutes=2)
        for k in range(42):
            add(g0 + timedelta(seconds=k * 0.9), "graph", user, src_ip=ip, app_id=OFFICEHOME, app_name="OfficeHome",
                session_id=s, operation="GET", request_uri=GRAPH_RECON[k % len(GRAPH_RECON)], status=200)
    if "rule" in steps:
        add(t0 + timedelta(minutes=random.randint(30, 90)), "mailbox", user, src_ip=ip, operation="New-InboxRule",
            details="Name=.; SubjectOrBodyContains=invoice,payroll,payment,bank; DeleteMessage=True; MarkAsRead=True",
            result="success")
    truth["malicious_users"][user] = label


v1, v2, v3 = USERS[12], USERS[27], USERS[41]
intrusion(v1, START + timedelta(days=3, hours=9, minutes=14), "142.252.171.135", 44559, "IT HOSTLINE LTD", "US",
          "axios/1.13.6", ["mfa", "graph", "rule"], "full chain: IOC IP + axios + new MFA + Graph recon + delete rule")
intrusion(v2, START + timedelta(days=4, hours=15, minutes=2), "2a0d:5600:8:94::f2cd:9d43", 9009, "M247 Europe SRL", "NL",
          "axios/1.13.2", ["mfa"], "IOC IPv6 + axios + new MFA method")
intrusion(v3, START + timedelta(days=5, hours=22, minutes=40), "203.0.113.77", 64496, "UNKNOWN-VPS-HOSTING", "DE",
          "node-fetch/1.0", ["device", "graph"], "NEW infrastructure (not in any IOC list) + node-fetch + device registration + Graph recon")

events.sort(key=lambda e: e["@timestamp"])
with open(HERE / "hunt_logs.ndjson", "w", encoding="utf-8") as f:
    for e in events:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")
(HERE / "ground_truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")

from collections import Counter
c = Counter(e["log_type"] for e in events)
print(f"events: {len(events)}  " + "  ".join(f"{k}={v}" for k, v in sorted(c.items())))
print(f"users : {len(USERS)} + 2 service accounts;  malicious: {len(truth['malicious_users'])};  FP traps: {len(truth['false_positive_traps'])}")
