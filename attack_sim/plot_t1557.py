#!/usr/bin/env python3
"""Draw the T1557 AiTM mechanism reproduced by the lab -> t1557_mechanism.png"""
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

HERE = Path(__file__).resolve().parent
SURF, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#c9c8c2"
BLUE, RED, GREEN = "#2a78d6", "#d03b3b", "#0ca30c"

fig, ax = plt.subplots(figsize=(14, 7.6), facecolor=SURF)
ax.set_xlim(0, 14); ax.set_ylim(0, 8.2); ax.axis("off"); ax.set_facecolor(SURF)
fig.suptitle("T1557 Adversary-in-the-Middle: the relay our localhost lab reproduces",
             x=0.01, ha="left", fontsize=15, color=INK)

# three actors
def box(x, title, sub, color):
    ax.add_patch(FancyBboxPatch((x, 3.4), 3.2, 1.5, boxstyle="round,pad=0.05,rounding_size=0.12",
                                facecolor=color, edgecolor="none"))
    ax.text(x + 1.6, 4.45, title, ha="center", va="center", color="white", fontsize=12, weight="bold")
    ax.text(x + 1.6, 3.85, sub, ha="center", va="center", color="white", fontsize=8.5)

box(0.4, "Victim", "browser, real person", BLUE)
box(5.4, "Attacker", "AiTM reverse proxy\n(Tycoon2FA kit)", RED)
box(10.4, "Real service", "ACME / Microsoft 365\nidentity server", GREEN)

# arrows with step numbers + ATT&CK ids
def arrow(x1, x2, y, text, tid, up=True, color=INK2):
    a = FancyArrowPatch((x1, y), (x2, y), arrowstyle="-|>", mutation_scale=16,
                        color=color, linewidth=1.6)
    ax.add_patch(a)
    yo = 0.33 if up else -0.5
    ax.text((x1 + x2) / 2, y + yo, text, ha="center", va="center", fontsize=8.7, color=INK)
    if tid:
        ax.text((x1 + x2) / 2, y + yo - 0.26, tid, ha="center", va="center", fontsize=8,
                color=RED, weight="bold")

arrow(3.6, 5.4, 7.2, "1. victim opens the lure link", "T1557", up=True)
arrow(3.6, 5.4, 6.1, "2-3. password + live MFA code", "T1557 / T1111", up=True, color=RED)
arrow(8.6, 10.4, 7.2, "4. relay login in real time", "T1557", up=True, color=RED)
arrow(10.4, 8.6, 6.1, "5. real server issues cookie", "", up=True, color=GREEN)
# steal + exfil inside attacker
ax.text(7.0, 2.7, "6. steal the session cookie  (T1539)\n7. exfiltrate to attacker channel  (T1567)",
        ha="center", va="top", fontsize=9, color=RED, weight="bold")
# replay
arrow(8.6, 10.4, 1.5, "8. replay stolen cookie - no password, no MFA", "T1550.004", up=True, color=RED)
ax.text(2.0, 1.5, "MFA is satisfied by the\nREAL user, but the attacker\nkeeps the session.",
        ha="center", va="center", fontsize=9, color=INK2, style="italic")

ax.text(0.1, 0.25, "Safe lab: all three parties run on 127.0.0.1 with dummy data (aitm_lab.py). "
        "7 attacker actions -> 5 ATT&CK techniques (attack_mapping.csv).",
        fontsize=9, color=INK2)
fig.tight_layout(rect=(0, 0, 1, 0.95))
fig.savefig(HERE / "t1557_mechanism.png", dpi=140, facecolor=SURF)
print("saved t1557_mechanism.png")
