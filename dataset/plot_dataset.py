#!/usr/bin/env python3
"""Draw a summary chart of dataset/tycoon2fa_iocs.csv -> dataset/dataset_overview.png"""
import csv, collections
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
rows = list(csv.DictReader(open(HERE / "tycoon2fa_iocs.csv", encoding="utf-8")))

types = collections.Counter(r["misp_type"] for r in rows if r["misp_type"] in ("url", "hostname", "domain", "ip-src"))
tld = collections.Counter("." + r["value_defanged"].split("[.]", 1)[1].replace("[.]", ".")
                          for r in rows if r["misp_type"] == "domain")
top_tld = tld.most_common(5); other = sum(tld.values()) - sum(n for _, n in top_tld)
top_tld.append(("other", other))
asn = collections.Counter(r["comment"].split("ASN: ")[1].split(";")[0].replace("GLOBAL CONNECTIVITY SOLUTIONS LLP", "Global Connectivity Sol.")
                          for r in rows if r["misp_type"] == "ip-src").most_common()

BLUE, SURF, INK, INK2 = "#2a78d6", "#fcfcfb", "#0b0b0b", "#52514e"
fig, axes = plt.subplots(1, 3, figsize=(15, 4.6), facecolor=SURF)
panels = [("Unique indicators by type", list(types.most_common())),
          ("Phishing domains by TLD", top_tld),
          ("Login egress IPs by provider", asn)]
for ax, (title, data) in zip(axes, panels):
    labels = [k for k, _ in data][::-1]; vals = [v for _, v in data][::-1]
    bars = ax.barh(labels, vals, color=BLUE, height=0.6)
    ax.set_facecolor(SURF); ax.set_title(title, loc="left", color=INK, fontsize=12, pad=10)
    for s in ("top", "right", "bottom"): ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#d6d5d0"); ax.tick_params(colors=INK2, length=0); ax.set_xticks([])
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + max(vals) * 0.02, b.get_y() + b.get_height() / 2, str(v),
                va="center", color=INK, fontsize=10)
    ax.set_xlim(0, max(vals) * 1.15)
fig.suptitle("Tycoon2FA IOC dataset (eSentire TRU public IOCs, 2025-2026) after normalization",
             x=0.01, ha="left", color=INK, fontsize=13)
fig.tight_layout(rect=(0, 0, 1, 0.93))
fig.savefig(HERE / "dataset_overview.png", dpi=150, facecolor=SURF)
print("saved dataset/dataset_overview.png")
