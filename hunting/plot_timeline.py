#!/usr/bin/env python3
"""Draw the attack timeline of the 3 compromised users and which hunt catches each step -> hunt_timeline.png"""
import json
from datetime import datetime
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
truth = json.loads((HERE / "ground_truth.json").read_text())
events = [json.loads(l) for l in (HERE / "hunt_logs.ndjson").read_text().splitlines()]
victims = list(truth["malicious_users"])
IOC = {"142.252.171.135", "2a0d:5600:8:94::f2cd:9d43"}

SURF, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
HUNT = {"H0": ("#2a78d6", "H0 IOC sweep"), "H1": ("#eb6834", "H1 odd sign-in → MFA/device"),
        "H2": ("#1baf7a", "H2 hidden inbox rule"), "H3": ("#4a3aa7", "H3 Graph recon burst"),
        None: ("#b9b8b2", "not a hunt hit")}


def parse(t):
    return datetime.strptime(t, "%Y-%m-%dT%H:%M:%S.000Z")


fig, axes = plt.subplots(len(victims), 1, figsize=(15, 2.9 * len(victims) + 1), facecolor=SURF, sharex=True)
for ax, v in zip(axes, victims):
    ev = [e for e in events if e["user"] == v]
    replay = next(e for e in ev if e["log_type"] == "signin" and not e["user_agent"].startswith(("Mozilla", "Microsoft")))
    t0 = parse(replay["@timestamp"])
    pts, graph_done = [], False
    for e in ev:
        m = (parse(e["@timestamp"]) - t0).total_seconds() / 60
        if not -10 <= m <= 60:
            continue
        if e["log_type"] == "signin":
            odd = not e["user_agent"].startswith(("Mozilla", "Microsoft"))
            if not odd and "MFA satisfied" not in e["details"]:
                continue  # the victim's ordinary sign-ins are not part of the intrusion
            label = f"token replay\n{e['user_agent']}" if odd else "victim login\nvia AiTM proxy"
            hunt = "H1" if odd else ("H0" if e["src_ip"] in IOC else None)
            if odd and e["src_ip"] in IOC:
                label += "\n(+H0: IOC IP)"
            pts.append((m, label, hunt))
        elif e["log_type"] == "audit":
            pts.append((m, e["operation"].replace("User registered security info", "new MFA method"), "H1"))
        elif e["log_type"] == "mailbox":
            pts.append((m, "inbox rule\ndelete 'invoice,payroll'", "H2"))
        elif e["log_type"] == "graph" and not graph_done:
            pts.append((m, "Graph burst\n42 calls / 36 s", "H3"))
            graph_done = True
    ax.axhline(0, color=GRID, linewidth=2, zorder=1)
    for i, (m, label, hunt) in enumerate(sorted(pts)):
        col = HUNT[hunt][0]
        ax.scatter([m], [0], s=140, color=col, edgecolor=SURF, linewidth=2, zorder=3)
        up = [1, -1, 2, -2][i % 4]
        ax.annotate(label, (m, 0), xytext=(0, 22 * up if abs(up) == 1 else 30 * up), textcoords="offset points", ha="center",
                    va="bottom" if up > 0 else "top", fontsize=8.5, color=INK,
                    arrowprops=dict(arrowstyle="-", color=GRID, lw=1))
    ax.set_ylim(-1.6, 1.6); ax.set_yticks([]); ax.set_facecolor(SURF)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.set_title(f"{v.split('@')[0]}  -  {truth['malicious_users'][v]}", loc="left", fontsize=10, color=INK2)
axes[-1].set_xlabel("minutes after the stolen session token is replayed", color=INK2)
axes[-1].set_xlim(-8, 52)
axes[-1].tick_params(colors=INK2)
handles = [plt.Line2D([], [], marker="o", ls="", color=c, markersize=10, label=l) for k, (c, l) in HUNT.items()]
fig.legend(handles=handles, loc="lower center", ncol=5, frameon=False, fontsize=9.5, labelcolor=INK2)
fig.suptitle("Synthetic Tycoon2FA intrusions in the contoso.example tenant: which hunt catches which step",
             x=0.01, ha="left", fontsize=13, color=INK)
fig.tight_layout(rect=(0, 0.06, 1, 0.95))
fig.savefig(HERE / "hunt_timeline.png", dpi=140, facecolor=SURF)
print("saved hunt_timeline.png")
