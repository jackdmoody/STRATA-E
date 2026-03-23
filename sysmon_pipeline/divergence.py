"""
Divergence functions, Bayesian peer baselines, and JSD calibration.
=====================================================================
Best of:
  - v12_modular divergence.py:    clean kl/js matrix functions
  - pipeline_updated divergence.py: fit_peer_baselines, score_sequence_divergence

Adds:
  - Fix 2: seq/drift covariance meta-feature
  - Fix 5: shrinkage weight tracking as evasion signal
  - JSD null distribution calibration via bootstrap (from README)
  - Hierarchical Dirichlet shrinkage (from README spec)
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple
import numpy as np
import pandas as pd
from scipy.stats import kstest

from .config import StrataConfig


# ---------------------------------------------------------------------------
# Core divergence functions (from v12_modular - cleanest implementation)
# ---------------------------------------------------------------------------

def kl_divergence(p: np.ndarray, q: np.ndarray, eps: float = 1e-12) -> float:
    p = np.clip(p, eps, 1.0); p = p / p.sum()
    q = np.clip(q, eps, 1.0); q = q / q.sum()
    return float(np.sum(p * np.log(p / q)))


def js_divergence(p: np.ndarray, q: np.ndarray, eps: float = 1e-12) -> float:
    p = np.clip(p, eps, 1.0); p = p / p.sum()
    q = np.clip(q, eps, 1.0); q = q / q.sum()
    m = 0.5 * (p + q)
    return 0.5 * kl_divergence(p, m, eps) + 0.5 * kl_divergence(q, m, eps)


# ---------------------------------------------------------------------------
# Hierarchical Dirichlet peer baselines (README spec + pipeline_updated)
# ---------------------------------------------------------------------------

def fit_role_prior_concentration(
    role_baseline: pd.DataFrame,
    alpha: float = 0.5,
) -> float:
    """
    Estimate the Dirichlet concentration α₀ for the role-level prior (paper Eq. 5:
    θ_r ~ Dirichlet(α₀)) via moment matching on the role transition distribution.

    In practice we treat the Laplace-smoothed role baseline as a point estimate of
    θ̂_r (the posterior mean under a symmetric Dirichlet prior), and back out the
    implied concentration from the empirical variance of p_baseline across outgoing
    transitions.  This bridges the notation gap between Eq. 5 (full Bayesian model)
    and the implemented estimator (Eq. 7 posterior mean).

    Returns α₀ (scalar); used only for documentation / calibration reporting.
    If estimation is degenerate, returns the configured laplace_alpha as a fallback.
    """
    if role_baseline.empty or "p_baseline" not in role_baseline.columns:
        return alpha

    per_state_var = (
        role_baseline
        .groupby("state")["p_baseline"]
        .var(ddof=1)
        .dropna()
    )
    if per_state_var.empty or per_state_var.mean() == 0:
        return alpha

    # Moment-matching: for Dir(α₀ * p̄), Var(p_k) ≈ p̄_k(1-p̄_k)/(α₀+1)
    # => α₀ ≈ p̄_k(1-p̄_k)/Var(p_k) - 1
    per_state_mean = role_baseline.groupby("state")["p_baseline"].mean()
    p_bar = per_state_mean.mean()
    v_bar = per_state_var.mean()
    alpha0 = max(alpha, p_bar * (1.0 - p_bar) / (v_bar + 1e-12) - 1.0)
    return float(alpha0)


def fit_peer_baselines(
    trans: pd.DataFrame,
    host_roles: pd.DataFrame,
    cfg: StrataConfig,
) -> Dict[str, pd.DataFrame]:
    """
    Fit role-level transition distributions with Dirichlet smoothing.

    Returns {role_id -> DataFrame[state, next_state, dt_bucket, p_baseline, alpha0]}

    Relationship to paper Eqs. 5–7:
      - Eq. 5 (θ_r ~ Dir(α₀)): α₀ is estimated via moment matching on the role
        distribution using fit_role_prior_concentration(). The returned p_baseline
        is the posterior mean θ̂_r under this prior.
      - Eq. 6 (θ_h | θ_r ~ Dir(κ_r θ_r)): applied per-host in score_sequence_divergence()
        via _get_host_posterior(), using the stored p_baseline as θ̂_r.
      - Eq. 7 (θ̂_h = (N_h + κ θ̂_r)/(n_h + κ)): the closed-form posterior mean,
        implemented directly in _get_host_posterior().

    The Laplace-smoothed empirical counts serve as a point estimate for θ̂_r
    (equivalent to Eq. 7 with N_role replacing N_h and the role's total as n_role).
    """
    t = trans.merge(host_roles[["host", "role_id"]], on="host", how="left")
    baselines: Dict[str, pd.DataFrame] = {}
    alpha = cfg.baseline.laplace_alpha

    for role_id, g in t.groupby("role_id"):
        agg = (
            g.groupby(["state", "next_state", "dt_bucket"])["count"]
            .sum()
            .reset_index()
        )
        agg["total"] = agg.groupby("state")["count"].transform("sum")
        k = agg.groupby("state")["count"].transform("count")
        agg["p_baseline"] = (agg["count"] + alpha) / (agg["total"] + alpha * k)

        # Estimate α₀ (paper Eq. 5) for calibration reporting
        alpha0 = fit_role_prior_concentration(agg, alpha=alpha)
        agg["alpha0"] = alpha0

        baselines[str(role_id)] = agg[[
            "state", "next_state", "dt_bucket", "p_baseline", "alpha0"
        ]].copy()

    return baselines


def _get_host_posterior(
    host_trans: pd.DataFrame,
    role_baseline: pd.DataFrame,
    kappa: float,
    alpha: float,
) -> pd.DataFrame:
    """
    Compute host-level posterior distribution using Dirichlet shrinkage:
      θ̂_h = (N_h + κ θ̂_r) / (n_h + κ)

    Returns merged DataFrame with p_host (posterior) and p_baseline columns.
    """
    # Host empirical probs
    n_h = host_trans["count"].sum()
    host_emp = host_trans.copy()
    host_emp["p_host_empirical"] = host_emp["count"] / (n_h + 1e-9)

    # Merge with role baseline
    merged = host_emp.merge(
        role_baseline, on=["state", "next_state", "dt_bucket"], how="outer"
    ).fillna(0.0)

    # Posterior (Dirichlet shrinkage)
    merged["p_host"] = (
        (merged["count"] + kappa * merged["p_baseline"])
        / (n_h + kappa)
    )
    return merged


# ---------------------------------------------------------------------------
# Sequence channel scoring
# ---------------------------------------------------------------------------

def score_sequence_divergence(
    trans: pd.DataFrame,
    host_roles: pd.DataFrame,
    baselines: Dict[str, pd.DataFrame],
    cfg: StrataConfig,
) -> pd.DataFrame:
    """
    Per-host sequence anomaly score using JS divergence between:
      P_host(next, dt | state)  vs  P_peer(next, dt | state)

    Applies Dirichlet shrinkage if cfg.ablation.use_dirichlet_shrinkage.

    Returns: host, role_id, S_seq, rare_transition_hits, n_events
    """
    t = trans.merge(host_roles[["host", "role_id"]], on="host", how="left")
    kappa = cfg.baseline.dirichlet_kappa if cfg.ablation.use_dirichlet_shrinkage else 0.0
    rows = []

    for (host, role_id), g in t.groupby(["host", "role_id"]):
        base = baselines.get(str(role_id))
        n_h = int(g["count"].sum())

        if base is None or base.empty:
            rows.append((host, role_id, 0.0, 0, n_h))
            continue

        divs, sev_weights, rare_hits = [], [], 0
        for state, hs in g.groupby("state"):
            if cfg.ablation.use_dirichlet_shrinkage:
                merged = _get_host_posterior(hs, base[base["state"] == state], kappa, cfg.baseline.laplace_alpha)
                p = merged["p_host"].to_numpy()
                q = merged["p_baseline"].to_numpy()
            else:
                hb = hs.copy()
                hb["p_host"] = hb["count"] / hb["count"].sum()
                pb = base[base["state"] == state].copy()
                if pb.empty:
                    continue
                hb["key"] = hb["next_state"].astype(str) + "|" + hb["dt_bucket"].astype(str)
                pb["key"] = pb["next_state"].astype(str) + "|" + pb["dt_bucket"].astype(str)
                all_keys = sorted(set(hb["key"]).union(set(pb["key"])))
                p = np.array([hb.loc[hb["key"] == k, "p_host"].sum() for k in all_keys])
                q = np.array([pb.loc[pb["key"] == k, "p_baseline"].sum() for k in all_keys])

            if q.sum() == 0:
                continue

            jsd = js_divergence(p, q)
            rare_hits += int((q[q > 0].min() if (q > 0).any() else 1.0) < 1e-4)

            # Severity-weighted JSD: weight each state's contribution by mean
            # severity of events observed from that state. A structurally anomalous
            # transition involving high-severity events (LSASS access, CreateRemoteThread)
            # contributes more than the same deviation in low-severity process chains.
            state_sev = float(hs["severity_score"].mean()) if "severity_score" in hs.columns else 0.5
            if np.isnan(state_sev):
                state_sev = 0.5

            divs.append(jsd * state_sev)
            sev_weights.append(state_sev)

        # Severity-weighted mean: sum(jsd_i * w_i) / sum(w_i)
        S_seq = float(np.sum(divs) / (np.sum(sev_weights) + 1e-9)) if divs else 0.0
        rows.append((host, role_id, S_seq, rare_hits, n_h))

    return pd.DataFrame(rows, columns=["host", "role_id", "S_seq", "rare_transition_hits", "n_events"])


# ---------------------------------------------------------------------------
# Drift channel scoring
# ---------------------------------------------------------------------------

def score_drift(
    current_trans: pd.DataFrame,
    prior_trans: Optional[pd.DataFrame],
    host_roles: pd.DataFrame,
    cfg: StrataConfig,
) -> pd.DataFrame:
    """
    Per-host drift score: JS divergence between current and prior window distributions.
    Uses Dirichlet smoothing for stability on sparse windows.

    Returns: host, S_drift
    """
    hosts = pd.Index(current_trans["host"].unique())
    if prior_trans is None or prior_trans.empty or not cfg.ablation.use_drift_channel:
        return pd.DataFrame({"host": hosts.values, "S_drift": 0.0})

    alpha = cfg.baseline.laplace_alpha
    rows = []

    for host in hosts:
        cur = current_trans[current_trans["host"] == host]
        pri = prior_trans[prior_trans["host"] == host]

        if cur.empty or pri.empty:
            rows.append({"host": host, "S_drift": 0.0})
            continue

        cur_agg = cur.groupby(["state", "next_state", "dt_bucket"])["count"].sum().reset_index()
        pri_agg = pri.groupby(["state", "next_state", "dt_bucket"])["count"].sum().reset_index()

        merged = cur_agg.merge(pri_agg, on=["state", "next_state", "dt_bucket"],
                                how="outer", suffixes=("_cur", "_pri")).fillna(0.0)
        n_cur = merged["count_cur"].sum()
        n_pri = merged["count_pri"].sum()

        p = (merged["count_cur"] + alpha) / (n_cur + alpha)
        q = (merged["count_pri"] + alpha) / (n_pri + alpha)

        rows.append({"host": host, "S_drift": js_divergence(p.to_numpy(), q.to_numpy())})

    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Fix 2: Seq/Drift covariance meta-feature
# ---------------------------------------------------------------------------

def compute_seq_drift_covariance(scores: pd.DataFrame) -> pd.Series:
    """
    The product of z-scored seq and drift scores is a 5th detection signal.
    High positive value = both channels firing together = sustained behavioral change.
    Catches slow lateral movement that gradually shifts a host's profile.
    """
    seq_z = (scores["S_seq"] - scores["S_seq"].mean()) / (scores["S_seq"].std() + 1e-9)
    drft_z = (scores["S_drift"] - scores["S_drift"].mean()) / (scores["S_drift"].std() + 1e-9)
    return (seq_z * drft_z).rename("S_seq_drift_cov")


def check_channel_correlation(scores: pd.DataFrame) -> dict:
    """
    Report Pearson correlation between seq and drift channels.
    High correlation (>0.75) warns of single-source signal amplification.
    """
    r = scores["S_seq"].corr(scores["S_drift"])
    return {
        "seq_drift_correlation": round(float(r), 4),
        "high_correlation_warning": abs(r) > 0.75,
    }


# ---------------------------------------------------------------------------
# Fix 5: Shrinkage anomaly tracking (evasion detection)
# ---------------------------------------------------------------------------

def compute_shrinkage_weights(
    host_event_counts: Dict[str, int],
    kappa: float,
) -> pd.DataFrame:
    """
    For each host, compute how much its estimate is pulled toward the role baseline.
    Shrinkage weight = κ / (n_h + κ).

    High shrinkage in a previously active host = sudden event suppression.
    """
    rows = []
    for host, n_h in host_event_counts.items():
        sw = kappa / (n_h + kappa)
        rows.append({
            "host": host,
            "event_count": n_h,
            "shrinkage_weight": sw,
            "data_dominated": sw < 0.2,
            "prior_dominated": sw > 0.8,
        })
    return pd.DataFrame(rows)


def detect_shrinkage_anomalies(
    current_shrinkage: pd.DataFrame,
    historical_shrinkage: pd.DataFrame,
    delta_threshold: float = 0.3,
) -> pd.DataFrame:
    """
    Flag hosts where shrinkage weight jumped significantly since last window.
    This signals a host that normally has lots of events has gone quiet —
    a potential log suppression or very quiet attacker evasion pattern.
    """
    merged = current_shrinkage.merge(
        historical_shrinkage[["host", "shrinkage_weight"]].rename(
            columns={"shrinkage_weight": "hist_shrinkage_weight"}
        ),
        on="host", how="left",
    )
    merged["shrinkage_delta"] = (
        merged["shrinkage_weight"] - merged["hist_shrinkage_weight"].fillna(0)
    )
    merged["evasion_signal"] = merged["shrinkage_delta"] > delta_threshold
    return merged


# ---------------------------------------------------------------------------
# JSD calibration (Fix 5 / README)
# ---------------------------------------------------------------------------

def calibrate_jsd_null_distribution(
    role_baseline: pd.DataFrame,
    n_h: int,
    cfg: StrataConfig,
    rng: Optional[np.random.Generator] = None,
) -> Tuple[float, float]:
    """
    Bootstrap the null distribution of JSD under the role baseline for a host with n_h events.
    Returns (mean_null, std_null) for computing z-score and percentile rank.

    Algorithm:
      1. Sample n_h events from the role baseline distribution
      2. Compute JSD between sample and baseline
      3. Repeat bootstrap_samples times
    """
    if not cfg.ablation.use_jsd_calibration:
        return 0.0, 1.0

    rng = rng or np.random.default_rng(cfg.scoring.random_seed)
    alpha = cfg.baseline.laplace_alpha
    agg = role_baseline.groupby("state")

    # Pre-compute per-state event share from p_baseline weights (no "count" col in baseline)
    # n_state for each state is proportional to that state's total probability mass
    state_groups = list(agg)
    n_states = len(state_groups)
    if n_states == 0:
        return 0.0, 1.0

    # Fraction of total events going through each state (uniform fallback if only 1 state)
    state_weights = np.array([g["p_baseline"].sum() for _, g in state_groups])
    state_weights = state_weights / (state_weights.sum() + 1e-12)

    bootstrap_jsds = []
    for _ in range(cfg.baseline.bootstrap_samples):
        # For each outgoing state, sample n_state transitions proportional to state weight
        jsd_vals = []
        for (state, g), sw in zip(state_groups, state_weights):
            n_state = max(2, int(n_h * sw))  # at least 2 so multinomial has variance
            p_baseline = (g["p_baseline"] + alpha).to_numpy().copy()
            p_baseline /= p_baseline.sum()
            sample_counts = rng.multinomial(n_state, p_baseline)
            p_sample = (sample_counts + alpha) / (sample_counts.sum() + alpha)
            jsd_vals.append(js_divergence(p_sample, p_baseline))
        if jsd_vals:
            # Use simple mean to match score_sequence_divergence (severity weights
            # are not available in the null; uniform weighting is the correct null)
            bootstrap_jsds.append(float(np.mean(jsd_vals)))

    if not bootstrap_jsds:
        return 0.0, 1.0
    return float(np.mean(bootstrap_jsds)), float(np.std(bootstrap_jsds) + 1e-9)


def test_pvalue_uniformity(pvalues: np.ndarray, alpha: float = 0.05) -> dict:
    """
    KS test: are calibrated p-values uniform under benign data?
    Uniform = calibration is valid. Use this in your evaluation framework.
    """
    stat, p = kstest(pvalues, "uniform")
    return {
        "ks_statistic": round(float(stat), 4),
        "ks_pvalue": round(float(p), 4),
        "calibration_valid": bool(p > alpha),
        "interpretation": "Calibration OK" if p > alpha else "Non-uniform p-values — recalibrate null distribution",
    }