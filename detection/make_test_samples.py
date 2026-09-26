#!/usr/bin/env python3
"""
Generate a SYNTHETIC, HARMLESS test corpus for tycoon2fa.yar.

No real phishing code is used. Positive samples only imitate the *patterns* the rules look
for (file names, WebSocket call, Hangul-filler encoding of the harmless string
"console.log('synthetic test')"). Hosts use the reserved .invalid TLD.
Negative samples are normal pages/scripts that share single features with the kit and
must NOT match (false-positive check).
"""
from pathlib import Path

OUT = Path(__file__).resolve().parent


BIT0, BIT1 = "ﾠ", "ㅤ"          # Halfwidth Hangul Filler = 0, Hangul Filler = 1


def invisible(text: str) -> str:
    return "".join(BIT1 if b == "1" else BIT0 for ch in text.encode() for b in f"{ch:08b}")


HIDDEN = invisible("console.log('synthetic test')")

samples = {
    # ---------- positives: should match ----------
    "pos_landing_page.html": """<!DOCTYPE html><html><head>
<link rel="stylesheet" href="/assets/pages-okta.css">
<script src="/js/myscr482913.js"></script></head><body>
<canvas id="captcha"></canvas>
<script>const s = new WebSocket("wss://relay.example.invalid/ws");</script>
</body></html>""",
    "pos_invisible_unicode.js": (
        "// synthetic sample: payload is only console.log('synthetic test')\n"
        "const store = { '" + HIDDEN + "': 1 };\n"
        "const view = new Proxy(store, { get(t, k) { return String(k).length; } });\n"
    ),
    # ---------- negatives: must NOT match ----------
    "neg_chat_app.html": """<!DOCTYPE html><html><head><link rel="stylesheet" href="/css/app.css"></head>
<body><div id="chat"></div>
<script>const ws = new WebSocket("wss://chat.example.invalid/socket");</script></body></html>""",
    "neg_okta_docs.html": """<!DOCTYPE html><html><body>
<p>Our SSO guide: we customise the pages-okta.css theme for the corporate login page.</p>
</body></html>""",
    "neg_korean_text.html": f"""<!DOCTYPE html><html><body>
<p>한글 채움 문자 예시: [{BIT1 * 3}] [{BIT0 * 2}]</p></body></html>""",
    "neg_proxy_library.js": """// ordinary use of JS Proxy for form validation
const handler = { set(o, k, v) { if (!v) throw new Error(k + ' required'); o[k] = v; return true; } };
const form = new Proxy({}, handler);
form.email = 'user@example.invalid';
""",
}

for name, content in samples.items():
    (OUT / f"sample_{name}").write_text(content, encoding="utf-8")
    print(f"wrote sample_{name} ({len(content.encode())} bytes)")
