#!/usr/bin/env python3
"""Draw a Maltego-style link graph from enrichment_ip.csv and enrichment_domain.csv
-> infra_graph.png   (left: ASN -> IP -> Shodan fingerprint, right: domain -> registrar / DNS)"""
import csv
from collections import defaultdict
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
SURF, INK, INK2, EDGE = "#fcfcfb", "#0b0b0b", "#52514e", "#c9c8c2"

ips = list(csv.DictReader(open(HERE / "enrichment_ip.csv", encoding="utf-8")))
doms = list(csv.DictReader(open(HERE / "enrichment_domain.csv", encoding="utf-8")))

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8.5), facecolor=SURF,
                               gridspec_kw={"width_ratios": [1.35, 1]})


def column(ax, items, x, color, ha):
    pos = {}
    n = len(items)
    for i, (key, label) in enumerate(items):
        y = 1 - (i + 0.5) / n
        pos[key] = (x, y)
        ax.scatter([x], [y], s=110, color=color, edgecolor=SURF, linewidth=2, zorder=3)
        dx = -0.02 if ha == "right" else 0.02
        ax.text(x + dx, y, label, ha=ha, va="center", fontsize=9, color=INK, zorder=4)
    return pos


def edges(ax, pairs, pa, pb, start_off=0.0):
    """start_off: skip past the label of the source node so edges never cross text."""
    for a, b in pairs:
        (x1, y1), (x2, y2) = pa[a], pb[b]
        if start_off:
            ax.plot([x1, x1 + start_off], [y1, y1], color=EDGE, linewidth=1.2, zorder=1, alpha=0)
        ax.plot([x1 + start_off, x2], [y1, y2], color=EDGE, linewidth=1.2, zorder=1)


# ---- left panel: ASN -> IP -> Shodan fingerprint ----
asn_of = {r["ip"]: f'{r["ripestat_origin_asn"]} {r["ripestat_as_holder"].split(" - ")[0].split()[0]}' for r in ips}
asns = sorted(set(asn_of.values()), key=lambda a: -sum(v == a for v in asn_of.values()))
ip_order = sorted(ips, key=lambda r: (asns.index(asn_of[r["ip"]]), r["ip"]))
fp = defaultdict(list)
for r in ips:
    for p in filter(None, r["shodan_ports"].split(";")):
        fp[p].append(r["ip"])
fp_labels = {"24442": "tcp/24442  OpenSSH 9.2p1 (Debian)", "1050": "tcp/1050  Python 3.7 service"}
fps = [("none", "not indexed by Shodan")] + [(p, fp_labels.get(p, p)) for p in sorted(fp)]

pa = column(ax1, [(a, a) for a in asns], 0.18, BLUE, "right")
pi = column(ax1, [(r["ip"], r["ip"]) for r in ip_order], 0.50, ORANGE, "left")
pf = column(ax1, fps, 1.02, AQUA, "left")
edges(ax1, [(asn_of[r["ip"]], r["ip"]) for r in ips], pa, pi)
edges(ax1, [(ip, p) for p, lst in fp.items() for ip in lst], pi, pf, 0.23)
edges(ax1, [(r["ip"], "none") for r in ips if r["shodan_indexed"] == "no"], pi, pf, 0.23)
ax1.set_title("Login egress IPs: ASN (RIPEstat) → IP → Shodan InternetDB fingerprint",
              loc="left", color=INK, fontsize=12)

# ---- right panel: domain -> registrar, domain -> DNS provider ----
def ns_provider(ns):
    return "Cloudflare DNS" if "cloudflare" in ns else ns.split("/")[-1].split(".", 1)[-1]

reg = {d["domain"]: d["rdap_registrar"].replace(", LLC", "").replace(", Inc.", "").split(" (")[0].split(" Kutatasi")[0]
       for d in doms}
nsp = {d["domain"]: ns_provider(d["nameservers"]) for d in doms}
regs = sorted(set(reg.values()), key=lambda r: -list(reg.values()).count(r))
nss = sorted(set(nsp.values()), key=lambda r: -list(nsp.values()).count(r))
dom_labels = {d["domain"]: f'{d["domain"].replace(".", "[.]")}  (created {d["created"][:7]})' for d in doms}
dom_order = sorted(doms, key=lambda d: (regs.index(reg[d["domain"]]), d["domain"]))

pr = column(ax2, [(r, r) for r in regs], 0.12, BLUE, "right")
pd = column(ax2, [(d["domain"], dom_labels[d["domain"]]) for d in dom_order], 0.42, ORANGE, "left")
pn = column(ax2, [(n, n) for n in nss], 1.22, AQUA, "left")
edges(ax2, [(reg[d], d) for d in reg], pr, pd)
edges(ax2, [(d, nsp[d]) for d in nsp], pd, pn, 0.62)
ax2.set_title("Phishing .com domains: registrar ← domain → DNS (RDAP)", loc="left", color=INK, fontsize=12)

for ax in (ax1, ax2):
    ax.set_facecolor(SURF); ax.set_xlim(-0.2, 1.5); ax.set_ylim(-0.03, 1.03); ax.axis("off")
ax2.set_xlim(-0.3, 1.55)

handles = [plt.Line2D([], [], marker="o", ls="", color=c, markersize=9, label=l)
           for c, l in [(BLUE, "Infrastructure owner (ASN / registrar)"),
                        (ORANGE, "Indicator (IP / domain)"),
                        (AQUA, "Pivot attribute (service fingerprint / DNS)")]]
fig.legend(handles=handles, loc="lower center", ncol=3, frameon=False, fontsize=10, labelcolor=INK2)
fig.suptitle("Tycoon2FA infrastructure link analysis (OSINT collected 2026-09-26)",
             x=0.01, ha="left", color=INK, fontsize=14)
fig.tight_layout(rect=(0, 0.05, 1, 0.95))
fig.savefig(HERE / "infra_graph.png", dpi=150, facecolor=SURF)
print("saved infra_graph.png")
