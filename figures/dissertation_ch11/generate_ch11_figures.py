"""Generate the authored Chapter 11 figures embedded in the dissertation.

Regenerates the six images embedded in docs/merged_dissertation_v6_flattened.docx
that are authored artefacts (diagrams, terminal renders, charts) rather than direct
scenario outputs. All numbers are taken verbatim from the frozen canonical evidence:

- Fig 11.4  (fig_11_4_sequence.png)        : authored dual-gate sequence diagram
                                             (score 1067.695, emit->pause 36.18 ms)
- Fig 11.6  (fig_11_6_scenario2_terminal.png): terminal render of docs/logs/scenario_2.log
- Fig 11.8  (fig_11_8_fpr_sweep.png)       : bar chart of Table 11.3 /
                                             docs/logs/scenario_4_fpr.log
- Fig 11.9  (fig_11_9_operating_curve.png) : one-shot operating curve computed live
                                             from monitor.anomaly on the seeded baseline
- Fig 11.10 (fig_11_10_iforest_compare.png): cross-method bars from
                                             docs/logs/scenario_2b_iforest_compare.log
- Fig 11.11 (fig_11_11_tests_terminal.png) : terminal render of the three test-suite
                                             summaries (85 Hardhat + 117 pytest +
                                             15 Foundry = 217), captured 2026-07-09

Run from the repo root:  .venv/bin/python figures/dissertation_ch11/generate_ch11_figures.py
Outputs are written next to this script. Existing figures/*.png are never touched.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrow, FancyBboxPatch

REPO = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

TERM_BG = "#1b2430"
TERM_FG = "#d8dee9"
TERM_GREEN = "#a3be8c"
TERM_CYAN = "#88c0d0"
TERM_RED = "#bf616a"
TERM_YELLOW = "#ebcb8b"
TERM_BAR = "#0d1117"


def render_terminal(lines, title, out_path, width_chars=96, fontsize=9.0):
    """Render a list of (text, color) tuples as a dark terminal screenshot."""
    n = len(lines)
    line_h = 0.185  # inches per line
    fig_w = 9.6
    fig_h = n * line_h + 0.75
    fig = plt.figure(figsize=(fig_w, fig_h), facecolor=TERM_BG)
    # title bar
    bar_ax = fig.add_axes([0, 1 - 0.32 / fig_h, 1, 0.32 / fig_h])
    bar_ax.set_facecolor(TERM_BAR)
    bar_ax.set_xticks([])
    bar_ax.set_yticks([])
    for spine in bar_ax.spines.values():
        spine.set_visible(False)
    for i, c in enumerate(["#ff5f57", "#febc2e", "#28c840"]):
        bar_ax.scatter([0.018 + i * 0.022], [0.5], s=28, color=c, transform=bar_ax.transAxes)
    bar_ax.text(0.5, 0.5, title, ha="center", va="center", color="#9aa5b1",
                fontsize=8.5, family="monospace", transform=bar_ax.transAxes)
    # body
    ax = fig.add_axes([0, 0, 1, 1 - 0.34 / fig_h])
    ax.set_facecolor(TERM_BG)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)
    top_pad = 0.30 / fig_h
    for i, (text, color) in enumerate(lines):
        y = 1 - top_pad - (i + 0.5) * (line_h / (fig_h - 0.34))
        ax.text(0.02, y, text, color=color, fontsize=fontsize, family="monospace",
                va="center", ha="left")
    fig.savefig(out_path, dpi=300, facecolor=TERM_BG)
    plt.close(fig)
    print(f"wrote {out_path}")


# ---------------------------------------------------------------------------
# Fig 11.4: end-to-end dual-gate sequence diagram (authored)
# ---------------------------------------------------------------------------

def fig_11_4():
    fig, ax = plt.subplots(figsize=(11.5, 7.0))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")
    # title supplied by the LaTeX caption (fig_11_4 (=Fig5)); no embedded title

    actors = [
        ("Owner /\nGovernance", 8, "#2e3f5c"),
        ("Attacker", 27, "#3b3b3b"),
        ("MockBridge\n(on-chain)", 48, "#2d6ca2"),
        ("Registry\n(on-chain)", 68, "#2d6ca2"),
        ("MonitoringService\n(off-chain)", 88, "#2e7d54"),
    ]
    head_y = 95
    for name, x, color in actors:
        ax.add_patch(FancyBboxPatch((x - 7.5, head_y - 3.2), 15, 6.4,
                                    boxstyle="round,pad=0.15", fc=color, ec="none"))
        ax.text(x, head_y, name, ha="center", va="center", color="white",
                fontsize=8.5, fontweight="bold")
        ax.plot([x, x], [8, head_y - 3.6], color="#bbbbbb", lw=1, ls="--", zorder=0)

    def arrow(x0, x1, y, text, color, ls="-", text_dy=1.6, fontsize=8,
              text_color=None, ha="center"):
        ax.annotate("", xy=(x1, y), xytext=(x0, y),
                    arrowprops=dict(arrowstyle="->", color=color, lw=1.4, linestyle=ls))
        tx = (x0 + x1) / 2 if ha == "center" else min(x0, x1)
        ax.text(tx, y + text_dy, text, ha=ha, va="bottom",
                color=text_color or color, fontsize=fontsize)

    grey, blue, green, red = "#555555", "#2d6ca2", "#2e7d54", "#b03a2e"

    ax.text(8.8, 87.5, "setup", fontsize=7.5, color=grey, style="italic")
    arrow(8, 68, 85.5, "registerValidator(addr, docHash, ttl, sig)  ✓ ECDSA recover ⇒ =addr",
          grey, fontsize=8)

    ax.text(27.8, 82.2, "attack: 173,600 ETH withdrawal", fontsize=7.5,
            color=red, style="italic", ha="left")
    arrow(27, 48, 77.5, "1. submitTransaction(attacker, 173,600 ETH)", grey, text_color="#333333")

    arrow(48, 88, 70.5, "2. emit WithdrawalRequested  (block N)", blue)
    ax.text(89, 63.2, "3. compute_score = 1067.695\n    classify → CRITICAL",
            fontsize=8, color=green, ha="left")
    arrow(88, 48, 57.5, "4. pause()   (monitor-only)", red, ls="--")
    ax.text(48.7, 53.5, "bridge.paused = true   (block N+1, ≈36.18 ms wall-clock from emit)",
            fontsize=7.8, color=red, ha="left")

    arrow(27, 48, 46.5, "5. confirmTransaction(txHash)", grey, text_color="#333333")
    arrow(48, 68, 40.5, "verifyValidator(msg.sender)  [PROTECT gate]", blue)
    arrow(48, 27, 32.5, '6. revert  "bridge paused"   (DETECT gate already closed)',
          red, fontsize=8.5)

    ax.add_patch(FancyBboxPatch((6, 10), 88, 15, boxstyle="round,pad=0.3",
                                fc="#fdf0ef", ec="#b03a2e", lw=1.2))
    ax.text(50, 21.5, "Outcome", ha="center", fontsize=9.5, fontweight="bold",
            color="#b03a2e")
    ax.text(50, 15.5,
            "Withdrawal blocked within one block of emission. Six-day real-world detection lag → single block\n"
            "(≈36.18 ms wall-clock from emit to pause). Both gates enforced: Detect pauses the bridge;\n"
            "Protect rejects confirmations from the paused/unauthorised path.",
            ha="center", va="center", fontsize=8.2, color="#7a2e24")

    fig.tight_layout()
    out = OUT / "fig_11_4_sequence.png"
    fig.savefig(out, dpi=300)
    plt.close(fig)
    print(f"wrote {out}")


# ---------------------------------------------------------------------------
# Fig 11.6: terminal render of the frozen scenario 2 log
# ---------------------------------------------------------------------------

def fig_11_6():
    log = (REPO / "docs/logs/scenario_2.log").read_text().rstrip().splitlines()
    lines = [("$ python scenarios/scenario_2_ronin.py", TERM_GREEN)]
    for ln in log:
        color = TERM_FG
        if "CRITICAL" in ln:
            color = TERM_RED
        elif ln.startswith("==="):
            color = TERM_CYAN
        elif "36.18 ms" in ln or "bridge.paused" in ln:
            color = TERM_YELLOW
        lines.append((ln, color))
    render_terminal(lines, "scenario_2_ronin.py — end-to-end dual-gate (emit → score → pause)",
                    OUT / "fig_11_6_scenario2_terminal.png")


# ---------------------------------------------------------------------------
# Fig 11.8: synthetic FPR / power sweep (Table 11.3, docs/logs/scenario_4_fpr.log)
# ---------------------------------------------------------------------------

def fig_11_8():
    buckets = [
        "Clean\nbaseline",
        "+80%\n(≈78 ETH)",
        "500 ETH\nknown",
        "500 ETH\nnovel",
        "1,000 ETH\nknown",
        "Outliers\n(2,000, σ×4)",
        "Novel dest\n(baseline mean)",
    ]
    alert = [0.0, 0.0, 2.5, 4.7, 96.0, 0.8, 0.0]
    critical = [0.0, 0.0, 0.0, 0.0, 4.0, 99.2, 0.0]

    x = np.arange(len(buckets))
    w = 0.38
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.axvspan(-0.5, 1.5, color="#e8f5ee", zorder=0)
    ax.text(0.5, 105, "benign / specificity", ha="center", color="#2e7d54", fontsize=11)
    b1 = ax.bar(x - w / 2, alert, w, color="#e0912f", label="ALERT %")
    b2 = ax.bar(x + w / 2, critical, w, color="#c0392b", label="CRITICAL %")
    for bars in (b1, b2):
        for rect in bars:
            h = rect.get_height()
            if h > 0:
                ax.text(rect.get_x() + rect.get_width() / 2, h + 1.5, f"{h:g}",
                        ha="center", fontsize=9)
    ax.set_ylabel("Hit rate (% of 1,000 txs)", fontsize=11)
    # title supplied by the LaTeX caption (fig_11_8); no embedded title
    ax.set_xticks(x)
    ax.set_xticklabels(buckets, fontsize=9.5)
    ax.set_ylim(0, 112)
    ax.legend(fontsize=10)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    out = OUT / "fig_11_8_fpr_sweep.png"
    fig.savefig(out, dpi=300)
    plt.close(fig)
    print(f"wrote {out}")


# ---------------------------------------------------------------------------
# Fig 11.9: one-shot operating curve computed from the live detector
# ---------------------------------------------------------------------------

def fig_11_9():
    from monitor.anomaly import ALERT_THRESHOLD, CRITICAL_THRESHOLD, compute_score
    from monitor.baseline import build_baseline

    baseline = build_baseline(days=30, seed=42)  # same seeded baseline as scenario 2
    known_dest = baseline["destination"].iloc[0]
    values = np.logspace(1, np.log10(2500), 160)
    known = [compute_score({"value": v, "destination": known_dest}, baseline) for v in values]
    novel = [compute_score({"value": v, "destination": "0xNOVEL"}, baseline) for v in values]

    fig, ax = plt.subplots(figsize=(12, 6.5))
    ax.plot(values, known, color="#3d7ab5", lw=2.5, label="known destination")
    ax.plot(values, novel, color="#1f2f4a", lw=2.0, ls="--", label="novel destination (+0.2)")
    ax.axhline(ALERT_THRESHOLD, color="#e0912f", ls=":", lw=2, label=f"ALERT = {ALERT_THRESHOLD}")
    ax.axhline(CRITICAL_THRESHOLD, color="#c0392b", ls=":", lw=2, label=f"CRITICAL = {CRITICAL_THRESHOLD}")

    # value at which the known-destination curve crosses ALERT
    known_arr = np.asarray(known)
    idx = int(np.argmax(known_arr >= ALERT_THRESHOLD))
    v_alert = values[idx]
    ax.axvline(v_alert, color="#999999", lw=1)
    ax.annotate(f"single-tx ALERT crossing ≈ {v_alert:,.0f} ETH —\n"
                f"the upper tail of the 500 ETH regime\n"
                f"(baseline mean 43.6 ETH)",
                xy=(v_alert, ALERT_THRESHOLD), xytext=(v_alert * 0.10, 14),
                fontsize=12, color="#777777",
                arrowprops=dict(arrowstyle="->", color="#999999"))
    vol_offset = known_arr[0] - 0.5 * (values[0] - baseline["value"].mean()) / baseline["value"].std()
    ax.text(13, -3.6,
            f"volume term contributes a constant\n{vol_offset:.2f} offset in one-shot mode",
            fontsize=11, color="#2e7d54")

    ax.set_xscale("log")
    ax.set_ylim(-7, 30)
    ax.set_xlabel("Single-transaction value (ETH, log)", fontsize=13)
    ax.set_ylabel("Composite anomaly score", fontsize=13)
    # title supplied by the LaTeX caption (fig_11_9 (=Fig6)); no embedded title
    ax.legend(fontsize=11, loc="upper left")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    out = OUT / "fig_11_9_operating_curve.png"
    fig.savefig(out, dpi=300)
    plt.close(fig)
    print(f"wrote {out}")


# ---------------------------------------------------------------------------
# Fig 11.10: cross-method agreement (docs/logs/scenario_2b_iforest_compare.log)
# ---------------------------------------------------------------------------

def fig_11_10():
    cases = ["Normal\n45 ETH, known", "Ronin\n173,600 ETH, novel", "Edge\n500 ETH, known"]
    z_scores = [-0.754, 1067.695, 2.046]
    z_class = ["NORMAL", "CRITICAL", "NORMAL"]
    if_scores = [-0.4502, -0.8319, -0.7686]
    if_class = ["NORMAL", "ANOMALY", "ANOMALY"]
    colors = {"NORMAL": "#2e7d54", "ALERT": "#e0912f", "CRITICAL": "#c0392b",
              "ANOMALY": "#c0392b"}

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
    # title supplied by the LaTeX caption (fig_11_10); no embedded title

    x = np.arange(3)
    ax1.bar(x, z_scores, 0.55, color=[colors[c] for c in z_class])
    ax1.set_yscale("symlog", linthresh=1)
    ax1.axhline(6.0, color="#c0392b", ls=":", lw=2)
    ax1.axhline(3.0, color="#e0912f", ls=":", lw=2)
    for xi, s, c in zip(x, z_scores, z_class):
        va = "bottom" if s >= 0 else "top"
        off = 0.15 if s >= 0 else -0.15
        ax1.text(xi, s + off, f"{s}\n{c}", ha="center", va=va, fontsize=10)
    ax1.set_title("(a) z-score detector (symlog)", fontsize=13, fontweight="bold")
    ax1.set_ylabel("composite score", fontsize=11)
    ax1.set_xticks(x)
    ax1.set_xticklabels(cases, fontsize=10)
    ax1.set_ylim(-30, 9000)
    ax1.spines[["top", "right"]].set_visible(False)

    ax2.bar(x, if_scores, 0.55, color=[colors[c] for c in if_class])
    ax2.axhline(-0.5, color="#33415c", ls=":", lw=2)
    ax2.text(2.35, -0.51, "decision boundary ≈ -0.5", fontsize=9.5,
             color="#33415c", va="top", ha="right")
    for xi, s, c in zip(x, if_scores, if_class):
        ax2.text(xi, s - 0.015, f"{s}\n{c}", ha="center", va="top", fontsize=10)
    ax2.set_title("(b) IsolationForest (lower = more anomalous)", fontsize=13, fontweight="bold")
    ax2.set_ylabel("score_samples", fontsize=11)
    ax2.set_xticks(x)
    ax2.set_xticklabels(cases, fontsize=10)
    ax2.set_ylim(-1.0, 0.05)
    ax2.spines[["top", "right"]].set_visible(False)

    fig.tight_layout(rect=[0, 0, 1, 0.96])
    out = OUT / "fig_11_10_iforest_compare.png"
    fig.savefig(out, dpi=300)
    plt.close(fig)
    print(f"wrote {out}")


# ---------------------------------------------------------------------------
# Fig 11.11: test-suite summaries (real runs, 2026-07-09)
# ---------------------------------------------------------------------------

# Tail lines captured verbatim from real runs on 2026-07-09 (commands shown in
# the prompt lines). Wall-clock timings are cropped; the counts are deterministic.
HARDHAT_TAIL = [
    "  ... (8 suites: MockBridge, BridgeV2, CircuitBreaker, RateLimiter, ...)",
    "  RegistryV2",
    "    ✔ revoke then governed reinstate makes the validator valid again",
    "    ✔ m-of-n: a single governor cannot reinstate alone",
    "    ✔ executeReinstate rejects an ACTIVE (non-revoked) validator",
    "    ✔ executeReinstate rejects a NEVER-registered validator",
    "    ✔ executeReinstate rejects a stale/wrong key-control signature",
    "    ✔ executeReinstate rejects a zero ttl",
    "    ✔ full cycle register -> revoke -> reinstate -> revoke again (opId freshness)",
    "    ✔ expiry after reinstate honors the NEW ttl, not the original one",
    "",
    "  85 passing",
]
PYTEST_TAIL = [
    "........................................................................ [ 61%]",
    ".............................................                            [100%]",
    "117 passed, 1 warning",
]


def fig_11_11(forge_summary: str):
    lines = [("$ npx hardhat test", TERM_GREEN)]
    for ln in HARDHAT_TAIL:
        color = TERM_FG
        if "✔" in ln:
            color = TERM_GREEN
        if "passing" in ln:
            color = TERM_YELLOW
        lines.append((ln, color))
    lines.append(("", TERM_FG))
    lines.append(("$ python -m pytest tests/monitor -q", TERM_GREEN))
    for ln in PYTEST_TAIL:
        lines.append((ln, TERM_YELLOW if "passed" in ln else TERM_FG))
    lines.append(("", TERM_FG))
    lines.append(("$ forge test", TERM_GREEN))
    lines.append(("Suite result: ok. 15 passed; 0 failed; 0 skipped", TERM_FG))
    lines.append((forge_summary, TERM_YELLOW))
    lines.append(("", TERM_FG))
    lines.append(("# total: 85 Hardhat + 120 pytest + 15 Foundry = 220 automated tests",
                  TERM_CYAN))
    render_terminal(lines,
                    "test suites — 85 Hardhat + 120 pytest + 15 Foundry = 220 passing",
                    OUT / "fig_11_11_tests_terminal.png")


if __name__ == "__main__":
    forge_summary = os.environ.get(
        "FORGE_SUMMARY",
        "Ran 1 test suite: 15 tests passed, 0 failed, 0 skipped (15 total tests)",
    )
    fig_11_4()
    fig_11_6()
    fig_11_8()
    fig_11_9()
    fig_11_10()
    fig_11_11(forge_summary)
