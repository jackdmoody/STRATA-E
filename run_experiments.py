"""
STRATA-E Experiment Runner
============================
Executes all five hypothesis tests and saves results to CSV and PNG.
Supports synthetic data (fast, no data needed) and real datasets.

Usage
-----
# Quick run on synthetic data (no dataset download needed):
    python run_experiments.py --synthetic --output results/

# Run on DARPA CADETS:
    python run_experiments.py --dataset darpa --data-dir data/darpa/cadets/ --output results/

# Run on your own Sysmon CSV:
    python run_experiments.py --dataset sysmon --data-path data/sysmon.csv --output results/

# Run a single hypothesis:
    python run_experiments.py --synthetic --hypothesis H1

Hypotheses tested
-----------------
H1: Dirichlet shrinkage reduces JSD variance vs MLE under sparse windows
H2: Peer-role baselines improve Top-K recall vs global baseline
H3: Bootstrap-calibrated p-values are uniform under benign data (KS test)
H4: Multi-channel fusion improves Top-K recall vs any single channel
H5: Corroboration gating reduces FPR without degrading Top-K recall

Outputs (all in --output directory)
------------------------------------
  h1_variance_reduction.csv     — JSD variance by window size, with/without shrinkage
  h2_role_vs_global_recall.csv  — Top-K recall by K, with/without role baselining
  h3_pvalue_uniformity.csv      — KS test results per role
  h4_channel_comparison.csv     — Precision/Recall per channel and fused
  h5_gating_fpr_recall.csv      — FPR and recall with/without corroboration gate
  results_summary.csv           — One-row-per-hypothesis summary for the paper
  *.png                         — Figures for the paper
"""
from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from scipy.stats import kstest

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("strata.experiments")


# ---------------------------------------------------------------------------
# Imports (local)
# ---------------------------------------------------------------------------

from sysmon_pipeline.config import StrataConfig, AblationConfig
from sysmon_pipeline.pipeline import StrataPipeline
from sysmon_pipeline.loaders import load_darpa_tc, load_sysmon_csv, split_time_windows


# ---------------------------------------------------------------------------
# Synthetic data generator (scaled up from test_pipeline.py)
# ---------------------------------------------------------------------------

def make_synthetic(
    n_hosts: int = 50,
    n_events_per_host: int = 300,
    n_attack_hosts: int = 10,
    attack_strength: float = 1.0,
    seed: int = 42,
    n_roles: int = 3,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Generate synthetic Sysmon-like data with injected attack sequences.

    Returns (events_df, labels_df) matching the canonical STRATA schema.

    Attack injection: encodes PowerShell + LOLBin + CreateRemoteThread chain,
    modeled on a typical commodity RAT post-exploitation sequence.

    attack_strength: 0.0 = no attack signal, 1.0 = full injection
    n_roles: number of distinct host behavioral roles (workstation/server/DC)
    """
    rng = np.random.default_rng(seed)

    # Role definitions: different event type distributions per role
    role_profiles = {
        "workstation": {
            "event_ids":  [1, 3, 5, 7, 11, 22, 4624, 4688],
            "weights":    [0.30, 0.15, 0.10, 0.10, 0.10, 0.10, 0.10, 0.05],
            "images":     ["explorer.exe", "chrome.exe", "winword.exe",
                           "powershell.exe", "cmd.exe", "svchost.exe"],
        },
        "server": {
            "event_ids":  [1, 3, 5, 11, 4624, 4688, 7045, 4769],
            "weights":    [0.20, 0.25, 0.10, 0.15, 0.10, 0.10, 0.05, 0.05],
            "images":     ["svchost.exe", "iis.exe", "sqlservr.exe",
                           "powershell.exe", "cmd.exe", "w3wp.exe"],
        },
        "dc": {
            "event_ids":  [4624, 4634, 4648, 4672, 4768, 4769, 4776, 1109],
            "weights":    [0.20, 0.15, 0.10, 0.15, 0.15, 0.10, 0.10, 0.05],
            "images":     ["lsass.exe", "svchost.exe", "ntds.exe",
                           "powershell.exe", "cmd.exe", "explorer.exe"],
        },
    }
    role_names = list(role_profiles.keys())

    # Assign roles to hosts
    host_roles = {}
    for i in range(n_hosts):
        role = role_names[i % min(n_roles, len(role_names))]
        host_roles[f"HOST{i:02d}"] = role

    attack_hosts = set(list(host_roles.keys())[:n_attack_hosts])

    rows = []
    base_time = pd.Timestamp("2026-01-01", tz="UTC")

    for host, role in host_roles.items():
        profile = role_profiles[role]
        is_attacker = host in attack_hosts

        for j in range(n_events_per_host):
            # Temporal spacing: mostly short inter-event gaps with occasional long pauses
            if j == 0:
                t = base_time + pd.Timedelta(seconds=rng.integers(0, 3600))
            else:
                gap = rng.exponential(30) if rng.random() < 0.8 else rng.exponential(3600)
                t = rows[-1]["ts"] + pd.Timedelta(seconds=gap)

            # Normal event
            eid = rng.choice(profile["event_ids"], p=profile["weights"])
            img = rng.choice(profile["images"])
            parent = rng.choice(profile["images"])
            cmdline = f"{img} /normal"
            user = f"DOMAIN\\user{rng.integers(1, 5)}"

            # Attack injection: replace some events in attack hosts
            if is_attacker and attack_strength > 0:
                attack_prob = attack_strength * 0.25  # ~25% of events are attack at full strength
                if rng.random() < attack_prob:
                    # Inject attack sequence event
                    attack_events = [
                        # Encoded PowerShell
                        (4104, "powershell.exe", "winword.exe",
                         "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
                         "HIGH"),
                        # LOLBin execution
                        (1, "rundll32.exe", "powershell.exe",
                         "rundll32.exe javascript:..\\..\\mshtml,RunHTMLApplication",
                         "HIGH"),
                        # LSASS access
                        (10, "lsass.exe", "rundll32.exe",
                         "",
                         "SYSTEM"),
                        # CreateRemoteThread
                        (8, "svchost.exe", "lsass.exe",
                         "",
                         "SYSTEM"),
                        # Lateral movement: network connection to internal host
                        (3, "cmd.exe", "powershell.exe",
                         "cmd.exe /c net use \\\\192.168.1.50\\admin$",
                         "HIGH"),
                    ]
                    eid, img, parent, cmdline, user = attack_events[j % len(attack_events)]

            rows.append({
                "ts":              t,
                "host":            host,
                "event_id":        eid,
                "image":           f"C:\\Windows\\System32\\{img}",
                "parent_image":    f"C:\\Windows\\System32\\{parent}",
                "cmdline":         cmdline,
                "user":            user,
                "integrity_level": user.split("\\")[-1].upper() if "\\" in user else "MEDIUM",
                "signed":          img not in ["rundll32.exe", "mshta.exe"],
            })

    df = pd.DataFrame(rows).sort_values("ts").reset_index(drop=True)

    labels = pd.DataFrame({
        "host":           list(host_roles.keys()),
        "role":           list(host_roles.values()),
        "is_compromised": [h in attack_hosts for h in host_roles.keys()],
    })

    logger.info(
        "Synthetic data: %d events, %d hosts (%d attack), %d roles",
        len(df), n_hosts, n_attack_hosts, n_roles,
    )
    return df, labels


# ---------------------------------------------------------------------------
# Evaluation utilities
# ---------------------------------------------------------------------------

def top_k_recall(
    triage: pd.DataFrame,
    labels: pd.DataFrame,
    k_values: List[int] = [1, 3, 5, 10, 20],
) -> pd.DataFrame:
    """
    Compute Top-K recall: fraction of attack hosts in the top-K triage results.

    Sorts by triage_rank (ascending) if available, otherwise by score (descending).
    Returns DataFrame with columns: K, recall, n_attack, n_found
    """
    if "triage_rank" in triage.columns:
        triage = triage.sort_values("triage_rank", ascending=True).reset_index(drop=True)
    else:
        triage = triage.sort_values("score", ascending=False).reset_index(drop=True)
    attack_hosts = set(labels.loc[labels["is_compromised"], "host"])
    n_attack = len(attack_hosts)

    rows = []
    for k in k_values:
        top_k_hosts = set(triage.head(k)["host"])
        found = len(top_k_hosts & attack_hosts)
        recall = found / n_attack if n_attack > 0 else 0.0
        rows.append({"K": k, "recall": recall, "n_attack": n_attack, "n_found": found})

    return pd.DataFrame(rows)


def false_positive_rate(
    triage: pd.DataFrame,
    labels: pd.DataFrame,
    threshold: float = 0.5,
) -> float:
    """
    FPR = false alerts / total clean hosts above threshold.
    """
    attack_hosts = set(labels.loc[labels["is_compromised"], "host"])
    alerted = set(triage.loc[triage["score"] >= threshold, "host"])
    clean_alerted = alerted - attack_hosts
    total_clean = len(set(triage["host"]) - attack_hosts)
    return len(clean_alerted) / total_clean if total_clean > 0 else 0.0


# ---------------------------------------------------------------------------
# H1: Shrinkage reduces JSD variance under sparse windows
# ---------------------------------------------------------------------------

def run_h1(df: pd.DataFrame, labels: pd.DataFrame, output_dir: Path) -> pd.DataFrame:
    """
    Compare JSD variance with and without Dirichlet shrinkage
    across multiple window sizes.
    """
    logger.info("=== H1: Shrinkage variance reduction ===")
    window_sizes_hours = [0.25, 0.5, 1, 3, 6, 12, 24]
    results = []

    for with_shrinkage in [True, False]:
        label = "shrinkage" if with_shrinkage else "mle"
        ablation = AblationConfig.full_pipeline() if with_shrinkage else AblationConfig.no_shrinkage()
        cfg = StrataConfig(ablation=ablation)
        pipe = StrataPipeline(cfg)

        # Fit on full data
        fitted = pipe.fit(df)

        for hours in window_sizes_hours:
            # Sample a random window of `hours` hours from the data
            window_jsds = []
            t_max = df["ts"].max() if pd.api.types.is_datetime64_any_dtype(df["ts"]) \
                else pd.to_datetime(df["ts"], utc=True).max()

            for trial in range(10):  # 10 random windows per size
                rng = np.random.default_rng(trial)
                # Pick a random start time within the first 80% of the data
                t_start_offset = pd.Timedelta(hours=rng.uniform(0, max(1, (t_max - df["ts"].min()).total_seconds() / 3600 * 0.8)))
                t_start = df["ts"].min() + t_start_offset
                t_end = t_start + pd.Timedelta(hours=hours)

                window_df = df[(df["ts"] >= t_start) & (df["ts"] < t_end)]
                if len(window_df) < 10:
                    continue

                art = pipe.score(window_df, fitted)
                if art.seq_scores is not None and not art.seq_scores.empty:
                    window_jsds.extend(art.seq_scores["S_seq"].tolist())

            if window_jsds:
                results.append({
                    "window_hours":  hours,
                    "condition":     label,
                    "jsd_mean":      np.mean(window_jsds),
                    "jsd_variance":  np.var(window_jsds),
                    "jsd_std":       np.std(window_jsds),
                    "n_samples":     len(window_jsds),
                })

    h1_df = pd.DataFrame(results)
    h1_df.to_csv(output_dir / "h1_variance_reduction.csv", index=False)

    # Compute variance reduction ratio
    if not h1_df.empty:
        shrink = h1_df[h1_df["condition"] == "shrinkage"]["jsd_variance"].mean()
        mle = h1_df[h1_df["condition"] == "mle"]["jsd_variance"].mean()
        reduction_pct = (1 - shrink / mle) * 100 if mle > 0 else 0
        logger.info("H1 result: Shrinkage reduces JSD variance by %.1f%%", reduction_pct)

    _plot_h1(h1_df, output_dir)
    return h1_df


# ---------------------------------------------------------------------------
# H2: Role baselining improves Top-K recall
# ---------------------------------------------------------------------------

def run_h2(
    df: pd.DataFrame, labels: pd.DataFrame, output_dir: Path,
    baseline_df: Optional[pd.DataFrame] = None,
    score_df: Optional[pd.DataFrame] = None,
) -> pd.DataFrame:
    """Compare Top-K recall with role baselining vs global baseline."""
    logger.info("=== H2: Role baselining vs global baseline ===")

    if baseline_df is None or score_df is None:
        baseline_df, score_df = split_time_windows(df)

    results = []
    conditions = {
        "role_baselines":  AblationConfig.full_pipeline(),
        "global_baseline": AblationConfig.no_role_baselining(),
    }

    for condition, ablation in conditions.items():
        cfg = StrataConfig(ablation=ablation)
        pipe = StrataPipeline(cfg)
        fitted = pipe.fit(baseline_df)
        art = pipe.score(score_df, fitted, prior_window_df=baseline_df)

        if art.triage is not None:
            recall_df = top_k_recall(art.triage, labels)
            recall_df["condition"] = condition
            results.append(recall_df)

    h2_df = pd.concat(results, ignore_index=True) if results else pd.DataFrame()
    h2_df.to_csv(output_dir / "h2_role_vs_global_recall.csv", index=False)
    _plot_h2(h2_df, output_dir)
    return h2_df


# ---------------------------------------------------------------------------
# H3: Bootstrap p-values are uniform under benign data
# ---------------------------------------------------------------------------

def run_h3(df: pd.DataFrame, labels: pd.DataFrame, output_dir: Path) -> pd.DataFrame:
    """KS test for p-value uniformity on benign hosts only."""
    logger.info("=== H3: P-value calibration uniformity ===")

    # Use only clean hosts for calibration test
    clean_hosts = set(labels.loc[~labels["is_compromised"], "host"])
    benign_df = df[df["host"].isin(clean_hosts)]

    if benign_df.empty:
        logger.warning("H3: No benign hosts found — skipping")
        return pd.DataFrame()

    cfg = StrataConfig(ablation=AblationConfig.full_pipeline())
    pipe = StrataPipeline(cfg)
    fitted = pipe.fit(benign_df)
    art = pipe.score(benign_df, fitted)

    results = []
    if art.seq_scores is not None and "S_seq_pvalue" in art.seq_scores.columns:
        pvals = art.seq_scores["S_seq_pvalue"].dropna().to_numpy()
        stat, p = kstest(pvals, "uniform")
        results.append({
            "n_hosts":         len(pvals),
            "ks_statistic":    round(stat, 4),
            "ks_pvalue":       round(p, 4),
            "calibration_ok":  p > 0.05,
            "mean_pvalue":     round(pvals.mean(), 4),
            "interpretation":  "PASS — p-values approximately uniform" if p > 0.05
                               else "FAIL — non-uniform, recalibrate null distribution",
        })
        logger.info(
            "H3 result: KS stat=%.4f, p=%.4f (%s)",
            stat, p, "PASS" if p > 0.05 else "FAIL"
        )

    h3_df = pd.DataFrame(results)
    h3_df.to_csv(output_dir / "h3_pvalue_uniformity.csv", index=False)
    _plot_h3(art.seq_scores, output_dir)
    return h3_df


# ---------------------------------------------------------------------------
# H4: Multi-channel fusion improves Top-K recall
# ---------------------------------------------------------------------------

def run_h4(
    df: pd.DataFrame, labels: pd.DataFrame, output_dir: Path,
    baseline_df: Optional[pd.DataFrame] = None,
    score_df: Optional[pd.DataFrame] = None,
) -> pd.DataFrame:
    """Compare Top-K recall per channel individually vs fused."""
    logger.info("=== H4: Multi-channel fusion vs individual channels ===")

    if baseline_df is None or score_df is None:
        baseline_df, score_df = split_time_windows(df)

    cfg = StrataConfig(ablation=AblationConfig.full_pipeline())
    pipe = StrataPipeline(cfg)
    fitted = pipe.fit(baseline_df)
    art = pipe.score(score_df, fitted, prior_window_df=baseline_df)

    if art.triage is None:
        return pd.DataFrame()

    attack_hosts = set(labels.loc[labels["is_compromised"], "host"])
    results = []
    k_values = [1, 3, 5, 10, 15, 20]

    # Score each channel independently
    channel_cols = {
        "sequence":  "S_seq",
        "frequency": "S_freq",
        "context":   "S_ctx",
        "drift":     "S_drift",
        "fused":     "score",
    }

    # Build a unified scores DataFrame
    # Drop channel cols already in triage before merging to avoid suffix collisions
    triage_drop = [c for c in ["S_seq", "S_freq", "S_ctx", "S_drift"]
                   if c in art.triage.columns]
    scores_df = art.triage.drop(columns=triage_drop).copy()
    if art.seq_scores is not None:
        scores_df = scores_df.merge(
            art.seq_scores[["host", "S_seq"]], on="host", how="left"
        )
    if art.freq_scores is not None:
        scores_df = scores_df.merge(
            art.freq_scores[["host", "S_freq"]], on="host", how="left"
        )
    if art.ctx_scores is not None:
        scores_df = scores_df.merge(
            art.ctx_scores[["host", "S_ctx"]], on="host", how="left"
        )
    if art.drift_scores is not None:
        scores_df = scores_df.merge(
            art.drift_scores[["host", "S_drift"]], on="host", how="left"
        )

    # Diagnostic: check each channel has real variance before fusion
    logger.info("H4 channel score diagnostics:")
    for col in ["S_seq", "S_freq", "S_ctx", "S_drift", "score"]:
        if col in scores_df.columns:
            s = scores_df[col].dropna()
            logger.info("  %s: min=%.4f  max=%.4f  std=%.4f  nonzero=%d/%d",
                        col, s.min(), s.max(), s.std(), (s != 0).sum(), len(s))
        else:
            logger.warning("  %s: MISSING from scores_df", col)

    for channel, col in channel_cols.items():
        score_col = col if col in scores_df.columns else col.replace("S_", "")
        if score_col not in scores_df.columns:
            continue

        ranked = scores_df.sort_values(score_col, ascending=False).reset_index(drop=True)
        for k in k_values:
            top_k = set(ranked.head(k)["host"])
            found = len(top_k & attack_hosts)
            n_attack = len(attack_hosts)
            results.append({
                "channel": channel,
                "K":       k,
                "recall":  found / n_attack if n_attack > 0 else 0.0,
                "n_found": found,
                "n_attack": n_attack,
            })

    h4_df = pd.DataFrame(results)
    h4_df.to_csv(output_dir / "h4_channel_comparison.csv", index=False)
    _plot_h4(h4_df, output_dir)
    return h4_df


# ---------------------------------------------------------------------------
# H5: Corroboration gating reduces FPR without degrading recall
# ---------------------------------------------------------------------------

def run_h5(
    df: pd.DataFrame, labels: pd.DataFrame, output_dir: Path,
    baseline_df: Optional[pd.DataFrame] = None,
    score_df: Optional[pd.DataFrame] = None,
) -> pd.DataFrame:
    """Compare FPR and recall with vs without corroboration gate."""
    logger.info("=== H5: Corroboration gating FPR vs recall ===")

    if baseline_df is None or score_df is None:
        baseline_df, score_df = split_time_windows(df)

    results = []

    for use_gate in [True, False]:
        ablation = AblationConfig.full_pipeline()
        ablation.use_corroboration_gate = use_gate
        cfg = StrataConfig(ablation=ablation)
        pipe = StrataPipeline(cfg)
        fitted = pipe.fit(baseline_df)
        art = pipe.score(score_df, fitted, prior_window_df=baseline_df)

        if art.triage is None:
            continue

        label = "with_gate" if use_gate else "no_gate"
        recall_df = top_k_recall(art.triage, labels)
        fpr = false_positive_rate(art.triage, labels, threshold=0.5)

        for _, row in recall_df.iterrows():
            results.append({
                "condition": label,
                "K":         row["K"],
                "recall":    row["recall"],
                "fpr":       fpr,
                "n_found":   row["n_found"],
                "n_attack":  row["n_attack"],
            })

    h5_df = pd.DataFrame(results)
    h5_df.to_csv(output_dir / "h5_gating_fpr_recall.csv", index=False)
    _plot_h5(h5_df, output_dir)
    return h5_df


# ---------------------------------------------------------------------------
# Plotting (minimal — outputs clean PNGs for the paper)
# ---------------------------------------------------------------------------

def _plot_h1(df: pd.DataFrame, out: Path) -> None:
    try:
        import matplotlib.pyplot as plt
        if df.empty:
            return
        fig, ax = plt.subplots(figsize=(7, 4))
        for cond, grp in df.groupby("condition"):
            ax.plot(grp["window_hours"], grp["jsd_variance"],
                    marker="o", label=cond)
        ax.set_xlabel("Window Size (hours)")
        ax.set_ylabel("JSD Variance")
        ax.set_title("H1: JSD Variance by Window Size")
        ax.legend()
        ax.set_xscale("log")
        plt.tight_layout()
        plt.savefig(out / "h1_variance.png", dpi=150)
        plt.close()
    except Exception as e:
        logger.warning("H1 plot failed: %s", e)


def _plot_h2(df: pd.DataFrame, out: Path) -> None:
    try:
        import matplotlib.pyplot as plt
        if df.empty:
            return
        fig, ax = plt.subplots(figsize=(7, 4))
        for cond, grp in df.groupby("condition"):
            ax.plot(grp["K"], grp["recall"], marker="o", label=cond)
        ax.set_xlabel("K")
        ax.set_ylabel("Top-K Recall")
        ax.set_title("H2: Role Baselines vs Global Baseline")
        ax.legend()
        plt.tight_layout()
        plt.savefig(out / "h2_recall.png", dpi=150)
        plt.close()
    except Exception as e:
        logger.warning("H2 plot failed: %s", e)


def _plot_h3(seq_scores: Optional[pd.DataFrame], out: Path) -> None:
    try:
        import matplotlib.pyplot as plt
        if seq_scores is None or "S_seq_pvalue" not in seq_scores.columns:
            return
        pvals = seq_scores["S_seq_pvalue"].dropna()
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.hist(pvals, bins=20, edgecolor="black", density=True)
        ax.axhline(1.0, color="red", linestyle="--", label="Uniform density")
        ax.set_xlabel("Calibrated p-value")
        ax.set_ylabel("Density")
        ax.set_title("H3: P-value Distribution Under Benign Data")
        ax.legend()
        plt.tight_layout()
        plt.savefig(out / "h3_pvalue_hist.png", dpi=150)
        plt.close()
    except Exception as e:
        logger.warning("H3 plot failed: %s", e)


def _plot_h4(df: pd.DataFrame, out: Path) -> None:
    try:
        import matplotlib.pyplot as plt
        if df.empty:
            return
        fig, ax = plt.subplots(figsize=(7, 4))
        styles = {"fused": {"linewidth": 2.5, "linestyle": "-"},
                  "sequence": {"linestyle": "--"},
                  "frequency": {"linestyle": "-."},
                  "context": {"linestyle": ":"},
                  "drift": {"linestyle": (0, (3, 5, 1, 5))}}
        for channel, grp in df.groupby("channel"):
            style = styles.get(channel, {})
            ax.plot(grp["K"], grp["recall"], marker="o", label=channel, **style)
        ax.set_xlabel("K")
        ax.set_ylabel("Top-K Recall")
        ax.set_title("H4: Channel Comparison — Recall at Top-K")
        ax.legend()
        plt.tight_layout()
        plt.savefig(out / "h4_channel_recall.png", dpi=150)
        plt.close()
    except Exception as e:
        logger.warning("H4 plot failed: %s", e)


def _plot_h5(df: pd.DataFrame, out: Path) -> None:
    try:
        import matplotlib.pyplot as plt
        if df.empty:
            return
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        for cond, grp in df.groupby("condition"):
            ax1.plot(grp["K"], grp["recall"], marker="o", label=cond)
        ax1.set_xlabel("K")
        ax1.set_ylabel("Top-K Recall")
        ax1.set_title("H5: Recall (with/without gate)")
        ax1.legend()

        fpr_by_cond = df.groupby("condition")["fpr"].first()
        ax2.bar(fpr_by_cond.index, fpr_by_cond.values)
        ax2.set_ylabel("False Positive Rate")
        ax2.set_title("H5: FPR (with/without gate)")
        plt.tight_layout()
        plt.savefig(out / "h5_gating.png", dpi=150)
        plt.close()
    except Exception as e:
        logger.warning("H5 plot failed: %s", e)


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def build_summary(
    h1: pd.DataFrame, h2: pd.DataFrame, h3: pd.DataFrame,
    h4: pd.DataFrame, h5: pd.DataFrame,
) -> pd.DataFrame:
    """One-row-per-hypothesis summary for copy-pasting into the paper."""
    rows = []

    # H1
    if not h1.empty:
        shrink_var = h1[h1["condition"] == "shrinkage"]["jsd_variance"].mean()
        mle_var    = h1[h1["condition"] == "mle"]["jsd_variance"].mean()
        rows.append({
            "hypothesis": "H1",
            "claim":      "Shrinkage reduces JSD variance vs MLE",
            "metric":     f"Variance reduction: {(1-shrink_var/mle_var)*100:.1f}%",
            "result":     "SUPPORTED" if shrink_var < mle_var else "NOT SUPPORTED",
        })

    # H2
    if not h2.empty:
        at_5 = h2[h2["K"] == 5].pivot(index="K", columns="condition", values="recall")
        if "role_baselines" in at_5.columns and "global_baseline" in at_5.columns:
            role_r = at_5["role_baselines"].iloc[0]
            glob_r = at_5["global_baseline"].iloc[0]
            rows.append({
                "hypothesis": "H2",
                "claim":      "Role baselining improves Top-5 recall",
                "metric":     f"Role: {role_r:.2f}, Global: {glob_r:.2f}",
                "result":     "SUPPORTED" if role_r > glob_r else "NOT SUPPORTED",
            })

    # H3
    if not h3.empty:
        ok = h3["calibration_ok"].all()
        rows.append({
            "hypothesis": "H3",
            "claim":      "Calibrated p-values are uniform (KS test)",
            "metric":     f"KS p={h3['ks_pvalue'].iloc[0]:.4f}",
            "result":     "SUPPORTED" if ok else "NOT SUPPORTED",
        })

    # H4
    if not h4.empty:
        at_5 = h4[h4["K"] == 5].set_index("channel")["recall"]
        if "fused" in at_5.index:
            fused_r = at_5["fused"]
            best_single = at_5.drop("fused").max()
            rows.append({
                "hypothesis": "H4",
                "claim":      "Fusion improves Top-5 recall vs best single channel",
                "metric":     f"Fused: {fused_r:.2f}, Best single: {best_single:.2f}",
                "result":     "SUPPORTED" if fused_r >= best_single else "NOT SUPPORTED",
            })

    # H5
    if not h5.empty:
        gate    = h5[h5["condition"] == "with_gate"]
        no_gate = h5[h5["condition"] == "no_gate"]
        if not gate.empty and not no_gate.empty:
            gate_fpr = gate["fpr"].iloc[0]
            no_gate_fpr = no_gate["fpr"].iloc[0]
            gate_r5 = gate[gate["K"] == 5]["recall"].iloc[0] if (gate["K"] == 5).any() else 0
            no_gate_r5 = no_gate[no_gate["K"] == 5]["recall"].iloc[0] if (no_gate["K"] == 5).any() else 0
            rows.append({
                "hypothesis": "H5",
                "claim":      "Gating reduces FPR without degrading recall",
                "metric":     f"FPR: {gate_fpr:.3f} vs {no_gate_fpr:.3f} | Recall@5: {gate_r5:.2f} vs {no_gate_r5:.2f}",
                "result":     "SUPPORTED" if gate_fpr < no_gate_fpr else "NOT SUPPORTED",
            })

    summary = pd.DataFrame(rows)
    return summary


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="STRATA-E Experiment Runner")
    parser.add_argument("--synthetic",   action="store_true",
                        help="Use synthetic data (no dataset needed)")
    parser.add_argument("--dataset",     choices=["darpa", "sysmon"], default="darpa")
    parser.add_argument("--data-dir",    default="data/darpa/cadets/",
                        help="DARPA TC dataset directory")
    parser.add_argument("--darpa-name",  default="cadets",
                        choices=["cadets", "theia", "fivedirections", "trace"])
    parser.add_argument("--data-path",   default="data/sysmon.csv",
                        help="Path to Sysmon CSV (if --dataset sysmon)")
    parser.add_argument("--output",      default="results/",
                        help="Output directory for CSVs and figures")
    parser.add_argument("--hypothesis",  default="all",
                        choices=["all", "H1", "H2", "H3", "H4", "H5"])
    parser.add_argument("--n-hosts",     type=int, default=50,
                        help="Number of hosts for synthetic data")
    parser.add_argument("--n-events",    type=int, default=300,
                        help="Events per host for synthetic data")
    parser.add_argument("--n-attack",    type=int, default=10,
                        help="Number of attack hosts for synthetic data")
    parser.add_argument("--max-records", type=int, default=None,
                        help="Cap records loaded (for testing)")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # --- Load data ---
    t0 = time.time()
    if args.synthetic:
        logger.info("Generating synthetic data (%d hosts, %d events/host, %d attack hosts)",
                    args.n_hosts, args.n_events, args.n_attack)
        df, labels = make_synthetic(
            n_hosts=args.n_hosts,
            n_events_per_host=args.n_events,
            n_attack_hosts=args.n_attack,
        )
    elif args.dataset == "darpa":
        df, labels = load_darpa_tc(
            data_dir=args.data_dir,
            dataset=args.darpa_name,
            max_records=args.max_records,
        )
    else:
        df = load_sysmon_csv(args.data_path, max_rows=args.max_records)
        # For real Sysmon data without ground truth, create empty labels
        # Replace with your actual labels if available
        logger.warning(
            "No ground truth labels for Sysmon CSV. "
            "Create a labels CSV with columns [host, is_compromised] "
            "and pass it separately."
        )
        labels = pd.DataFrame({
            "host": df["host"].unique() if "host" in df.columns else [],
            "is_compromised": False,
        })

    logger.info("Data loaded in %.1fs", time.time() - t0)

    # Schema normalization for splitting (needs ts column)
    from sysmon_pipeline.schema import normalize_schema
    from sysmon_pipeline.config import StrataConfig
    cfg_norm = StrataConfig()
    df_norm = normalize_schema(df, cfg_norm)

    # Split into baseline and scoring windows
    try:
        baseline_df, score_df = split_time_windows(df_norm, ts_col="ts")
    except ValueError as e:
        logger.warning("Time split failed (%s) — using 80/20 row split", e)
        split_idx = int(len(df_norm) * 0.8)
        baseline_df = df_norm.iloc[:split_idx].copy()
        score_df    = df_norm.iloc[split_idx:].copy()

    # --- Run hypotheses ---
    run_all = args.hypothesis == "all"
    results = {}

    if run_all or args.hypothesis == "H1":
        results["H1"] = run_h1(df_norm, labels, output_dir)

    if run_all or args.hypothesis == "H2":
        results["H2"] = run_h2(df_norm, labels, output_dir, baseline_df, score_df)

    if run_all or args.hypothesis == "H3":
        results["H3"] = run_h3(baseline_df, labels, output_dir)

    if run_all or args.hypothesis == "H4":
        results["H4"] = run_h4(df_norm, labels, output_dir, baseline_df, score_df)

    if run_all or args.hypothesis == "H5":
        results["H5"] = run_h5(df_norm, labels, output_dir, baseline_df, score_df)

    # --- Summary ---
    if run_all:
        summary = build_summary(
            results.get("H1", pd.DataFrame()),
            results.get("H2", pd.DataFrame()),
            results.get("H3", pd.DataFrame()),
            results.get("H4", pd.DataFrame()),
            results.get("H5", pd.DataFrame()),
        )
        summary.to_csv(output_dir / "results_summary.csv", index=False)
        print("\n" + "="*60)
        print("RESULTS SUMMARY")
        print("="*60)
        print(summary.to_string(index=False))
        print(f"\nAll results written to: {output_dir.resolve()}")

    logger.info("Total runtime: %.1fs", time.time() - t0)


if __name__ == "__main__":
    main()