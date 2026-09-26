#!/usr/bin/env python3
"""
Week 3 - Exploitation of the processed data: hunt through sign-in logs with
  (1) the Sigma rule tycoon2fa_axios_signin.yml  (behaviour: axios User-Agent + success)
  (2) IOC matching against ../dataset/tycoon2fa_iocs.csv (known Tycoon2FA egress IPs)

Input : sample_signin_logs.jsonl  - SYNTHETIC Entra ID sign-in events (Sentinel SigninLogs
        schema). Some events reuse real egress IPs from the dataset; users and other IPs are
        fictitious (RFC 5737 / example domains).
Output: hunt_results.txt

A tiny Sigma evaluator is included (supports field|startswith, field|contains, equality,
lists and "a and b" / "a or b" conditions) so the rule can be tested without a SIEM.
Requires PyYAML (pip install pyyaml).
"""
import csv
import json
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
RULE = HERE / "tycoon2fa_axios_signin.yml"
LOGS = HERE / "sample_signin_logs.jsonl"
IOCS = HERE.parent / "dataset" / "tycoon2fa_iocs.csv"
OUT = HERE / "hunt_results.txt"


def match_selection(event, selection):
    for key, expected in selection.items():
        field, _, mod = key.partition("|")
        value = str(event.get(field, ""))
        options = expected if isinstance(expected, list) else [expected]
        options = [str(o) for o in options]
        if mod == "startswith":
            ok = any(value.startswith(o) for o in options)
        elif mod == "contains":
            ok = any(o in value for o in options)
        else:
            ok = value in options
        if not ok:
            return False
    return True


def sigma_match(event, rule):
    det = rule["detection"]
    results = {name: match_selection(event, sel) for name, sel in det.items() if name != "condition"}
    expr = det["condition"]
    for name, val in results.items():
        expr = expr.replace(name, str(val))
    return eval(expr, {"__builtins__": {}}, {})  # expression contains only True/False/and/or/not


def load_ioc_ips():
    ips = {}
    with open(IOCS, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["misp_type"] == "ip-src":
                ips[row["value_defanged"].replace("[.]", ".")] = row["comment"]
    return ips


def main():
    rule = yaml.safe_load(RULE.read_text(encoding="utf-8"))
    ioc_ips = load_ioc_ips()
    events = [json.loads(l) for l in LOGS.read_text(encoding="utf-8").splitlines() if l.strip()]

    lines = [f"# Hunt: {rule['title']}",
             f"# Sigma rule : {RULE.name}  (level: {rule['level']})",
             f"# IOC list   : {len(ioc_ips)} Tycoon2FA egress IPs from dataset/tycoon2fa_iocs.csv",
             f"# Events     : {len(events)} synthetic sign-ins from {LOGS.name}", "",
             f"{'time':<21}{'user':<25}{'ip':<28}{'user-agent':<18}{'result':<8}{'SIGMA':<7}{'IOC':<5}VERDICT"]
    counts = {"both": 0, "sigma": 0, "ioc": 0, "clean": 0}
    for e in events:
        s = sigma_match(e, rule)
        i = e["IPAddress"] in ioc_ips
        verdict = ("ALERT - high confidence (behaviour + known IOC)" if s and i else
                   "ALERT - behaviour only (new infrastructure?)" if s else
                   "REVIEW - known IOC IP, but browser UA / not axios" if i else
                   "info - failed axios attempt (no session issued)" if e["UserAgent"].startswith("axios/") else "clean")
        counts["both" if s and i else "sigma" if s else "ioc" if i else "clean"] += 1  # info counts as clean
        lines.append(f"{e['TimeGenerated']:<21}{e['UserPrincipalName']:<25}{e['IPAddress']:<28}"
                     f"{e['UserAgent'][:16]:<18}{e['ResultType']:<8}{'hit' if s else '-':<7}"
                     f"{'hit' if i else '-':<5}{verdict}")
    lines += ["", "# Summary",
              f"#   behaviour + IOC      : {counts['both']}",
              f"#   behaviour only       : {counts['sigma']}",
              f"#   IOC only             : {counts['ioc']}",
              f"#   no alert             : {counts['clean']}",
              "# Conclusion: the Sigma rule also catches sign-ins from infrastructure that is NOT yet",
              "# in the IOC list (IP-based blocking alone would miss them), while IOC matching adds",
              "# confidence and finds cases where the attacker switched to a browser User-Agent."]
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
