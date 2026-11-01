"""Figures for the reports and paper, drawn only from committed result files in docs/results/.

  python scripts/make_figures.py            # writes docs/figures/*.png

Static figures for print: thin marks, a recessive grid, direct labels, one y-axis per panel, and at most
three colours from a palette validated for colour-vision deficiency (blue, orange, aqua; aqua is always
direct-labelled because its contrast on white is below 3:1).
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RES, OUT = ROOT / "docs/results", ROOT / "docs/figures"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
    "xtick.color": MUTED, "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "axes.titlesize": 10, "axes.titleweight": "bold", "axes.titlelocation": "left", "legend.frameon": False,
})


def load(name: str) -> dict:
    return json.loads((RES / name).read_text(encoding="utf-8"))


def save(fig, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / name, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("wrote", OUT / name)


def bar_labels(ax, bars, fmt="{:.0%}"):
    for b in bars:
        ax.annotate(fmt.format(b.get_height()), (b.get_x() + b.get_width() / 2, b.get_height()),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", color=INK, fontsize=8)


def transfer() -> None:
    runs = load("cross_dataset.json")["runs"]["all"]
    name = {"cicids2017": "2017", "csecicids2018": "2018"}
    labels = [f"{name[r['source']]} → {name[r['target']]}" for r in runs]
    recall = [r["classifier"]["recall"] for r in runs]
    fig, ax = plt.subplots(figsize=(4.6, 2.8))
    bars = ax.bar(labels, recall, color=[BLUE if r["source"] == r["target"] else ORANGE for r in runs],
                  width=0.6, edgecolor=SURFACE, linewidth=2)
    bar_labels(ax, bars)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Attack flows caught (recall)")
    ax.set_title("Near-perfect in-domain, collapses on another network")
    ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
    ax.set_xlabel("Train → test   (blue: same network · orange: another network)", color=MUTED)
    save(fig, "fig1_transfer.png")


def dose_response() -> None:
    res = load("service_aware_seeds.json")
    groups: dict[int, list] = {}
    for r in res["runs"]:
        if r.get("service_added") is not None:
            groups.setdefault(r["service_added"], []).append(r)
    added = sorted(groups)
    pooled = [sum(r["held_out_profile"]["false_alerts"] for r in groups[n]) /
              sum(r["held_out_profile"]["flows"] for r in groups[n]) for n in added]
    clean = [sum(r["held_out_profile"]["false_alerts"] == 0 for r in groups[n]) for n in added]
    det = [np.mean([r["target_test"]["macro_detection"] for r in groups[n]]) for n in added]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.6, 3.0), gridspec_kw={"width_ratios": [1.7, 1], "wspace": 0.35})
    a1.plot(added, pooled, color=BLUE, linewidth=2, marker="o", markersize=6)
    for x, y, c in zip(added, pooled, clean):
        if x in (0, 15):
            a1.annotate(f"{x} flows: {y:.1%}, {c}/10 seeds clean", (x, y), xytext=(8, 6 if x else -4),
                        textcoords="offset points", color=INK, fontsize=7.5)
    rest = [(x, c) for x, c in zip(added, clean) if x not in (0, 15)]
    a1.annotate(" and ".join(str(x) for x, _ in rest) + " flows:\n0 of 3,300, every seed clean",
                (rest[0][0], 0), xytext=(6, 52), textcoords="offset points", color=INK, fontsize=7.5,
                arrowprops={"arrowstyle": "-", "color": MUTED, "linewidth": 0.6})
    a1.set_xlabel("Benign local service flows added")
    a1.set_ylabel("False alerts on unseen services")
    a1.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
    a1.set_ylim(-0.03, 0.46)
    a1.set_title("False alerts on legitimate services")
    a2.plot(added, det, color=BLUE, linewidth=2, marker="o", markersize=6)
    a2.set_ylim(0.95, 1.0)
    a2.set_xlabel("Flows added")
    a2.set_ylabel("Attack detection")
    a2.set_title("Detection")
    fig.suptitle("About one benign flow per service removes the regression, at no detection cost (10 seeds)",
                 x=0.06, y=1.02, ha="left", fontsize=10, fontweight="bold", color=INK)
    save(fig, "fig2_dose_response.png")


def per_block(name: str = "real_network_portable.json", out: str = "fig3_real_network_blocks.png") -> None:
    res = load(name)
    series = {"few-shot": ("Few-shot adapted", ORANGE),
              "few-shot + 30 triaged local flows + exemplar envelope": ("+ triage repair + local envelope", BLUE)}
    fig, ax = plt.subplots(figsize=(6.4, 2.9))
    x = np.arange(1, 13)
    for cfg, (label, colour) in series.items():
        rates = np.mean([r["real_network"]["block_rates"] for r in res["runs"] if r["config"] == cfg], axis=0)
        ax.plot(x[:len(rates)], rates, color=colour, linewidth=2, marker="o", markersize=5, label=label)
        ax.annotate(label, (len(rates), rates[-1]), xytext=(6, 0), textcoords="offset points",
                    color=INK, fontsize=7.5, va="center")
    ax.set_xticks(x)
    ax.set_xlim(0.6, 15.8)
    ax.set_xlabel("Capture block (5 min each, one evening, previous day used for repair)")
    ax.set_ylabel("Alerts on normal traffic")
    ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))
    ax.set_title("Real home network: lower in every one of 12 blocks")
    ax.set_ylim(0, None)
    ax.legend(loc="upper center", fontsize=7.5, ncol=2)
    save(fig, out)


def offload() -> None:
    res = load("offload_counterfactual_12us.json")
    o = {k: sum(s["original"][k] for s in res["sessions"]) for k in ("classifier_alerts", "anomaly_only_alerts")}
    r = {k: sum(s["resegmented"][k] for s in res["sessions"]) for k in o}
    fig, ax = plt.subplots(figsize=(4.6, 2.8))
    idx, w = np.arange(2), 0.36
    b1 = ax.bar(idx - w / 2 - 0.01, [o["classifier_alerts"], o["anomaly_only_alerts"]], w, color=BLUE,
                label="As captured (offload on)", edgecolor=SURFACE, linewidth=2)
    b2 = ax.bar(idx + w / 2 + 0.01, [r["classifier_alerts"], r["anomaly_only_alerts"]], w, color=ORANGE,
                label="Offload undone, same traffic", edgecolor=SURFACE, linewidth=2)
    bar_labels(ax, list(b1) + list(b2), "{:.0f}")
    ax.set_xticks(idx, ["Classifier (attack class)", "Anomaly detector only"])
    ax.set_ylabel("Alerts on 13 captures")
    ax.set_ylim(0, max(r.values()) * 1.2)
    ax.set_title("Sensor position shifts verdicts both ways")
    ax.legend(loc="upper left", fontsize=7.5)
    save(fig, "fig4_offload.png")


def envelope() -> None:
    res = load("envelope_audit_study.json")
    a, q = res["anomaly_only"]["feature_rates"], res["quiet"]["feature_rates"]
    top = sorted(a, key=lambda k: q.get(k, 0) - a[k])[:8][::-1]
    fig, ax = plt.subplots(figsize=(6.0, 3.2))
    y, h = np.arange(len(top)), 0.38
    ax.barh(y + h / 2, [a[k] for k in top], h, color=ORANGE, label=f"Anomaly-only alerts (n={res['anomaly_only']['flows']})")
    ax.barh(y - h / 2, [q.get(k, 0) for k in top], h, color=BLUE, label=f"Flows with no alert (n={res['quiet']['flows']:,})")
    ax.set_yticks(y, top)
    ax.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))
    ax.set_xlabel("Share of flows outside the benchmark's benign range")
    ax.set_title("Alerts on ordinary transfers: bigger than anything in the benchmark")
    ax.legend(loc="upper center", bbox_to_anchor=(0.45, -0.17), ncol=2, fontsize=7.5)
    ax.grid(axis="y", visible=False)
    save(fig, "fig5_envelope.png")


def baselines() -> None:
    path = RES / "real_network_baselines.json"
    if not path.exists():
        print("skip fig6: real_network_baselines.json not present yet")
        return
    res = load("real_network_baselines.json")
    order = [("few-shot", "Few-shot adapted"),
             ("few-shot + 30 uncertain local flows", "+ 30 uncertain flows"),
             ("few-shot + 30 triaged local flows", "+ 30 triaged flows"),
             ("few-shot + 30 triaged local flows + local refit anomaly", "+ triaged + local refit"),
             ("few-shot + 30 uncertain local flows + exemplar envelope", "+ uncertain + local envelope"),
             ("few-shot + 30 triaged local flows + exemplar envelope", "+ triaged + local envelope")]
    rates, dets = [], []
    for cfg, _ in order:
        rows = [r for r in res["runs"] if r["config"] == cfg]
        rates.append(np.mean([r["real_network"]["rate"] for r in rows]))
        dets.append(np.mean([r["target_test"]["macro_detection"] for r in rows]))
    fig, ax = plt.subplots(figsize=(6.2, 3.0))
    y = np.arange(len(order))[::-1]
    bars = ax.barh(y, rates, 0.6, color=[BLUE if "envelope" in c else ORANGE for c, _ in order])
    for b, d in zip(bars, dets):
        ax.annotate(f"{b.get_width():.1%}  (detection {d:.3f})", (b.get_width(), b.get_y() + b.get_height() / 2),
                    xytext=(4, 0), textcoords="offset points", va="center", color=INK, fontsize=7.5)
    ax.set_yticks(y, [label for _, label in order])
    ax.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))
    ax.set_xlim(0, max(rates) * 1.55)
    ax.set_xlabel("Alerts on normal traffic, real network (mean of 5 seeds)")
    ax.set_title("Which repair: chosen flows and local normal model")
    ax.grid(axis="y", visible=False)
    save(fig, "fig6_baselines.png")


if __name__ == "__main__":
    transfer(); dose_response(); per_block(); offload(); envelope(); baselines()
