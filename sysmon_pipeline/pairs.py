"""
Per-host rate features, role inference, and critical event pair correlation.
=============================================================================
Merges:
  - pipeline_updated pairs.py: rate feature computation, role feature matrix
  - v12_modular pairs.py:      critical event pair correlation, IsolationForest on pair stats

The two files served different purposes and are genuinely complementary:
  pipeline_updated.pairs -> feeds frequency channel + role clustering
  v12_modular.pairs      -> feeds context channel (temporal co-occurrence of critical events)
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .config import StrataConfig


# ---------------------------------------------------------------------------
# Rate features (pipeline_updated - for frequency channel + role inference)
# ---------------------------------------------------------------------------

def compute_rate_features(df: pd.DataFrame, cfg: StrataConfig) -> pd.DataFrame:
    """
    Compute per-host volumetric rate features.

    These feed two places:
      1. Frequency channel (IsolationForest on rates)
      2. Role inference (clustering on behavioral rates to assign peer groups)

    Produces (per host):
      proc_rate_total, script_rate, office_rate, lolbin_rate,
      has_encoded_rate, has_download_cradle_rate,
      unique_users, unique_parents, event_count, hours
    """
    host_span = df.groupby("host")["ts"].agg(["min", "max"])
    host_span["hours"] = (host_span["max"] - host_span["min"]).dt.total_seconds() / 3600.0
    host_span["hours"] = host_span["hours"].clip(lower=1e-6)

    counts = df.groupby("host").size().rename("event_count").to_frame()
    feats = counts.join(host_span["hours"])
    feats["proc_rate_total"] = feats["event_count"] / feats["hours"]

    for feat_name, token in [
        ("script_rate", "SCRIPT"),
        ("office_rate", "OFFICE"),
        ("lolbin_rate", "LOLBIN"),
        ("browser_rate", "BROWSER"),
    ]:
        c = df[df["token_coarse"] == token].groupby("host").size().rename(feat_name)
        feats = feats.join(c, how="left")
        feats[feat_name] = feats[feat_name].fillna(0.0) / feats["hours"]

    for flag in ["has_encoded", "has_download_cradle", "has_bypass"]:
        feat_name = f"{flag}_rate"
        if flag in df.columns:
            c = df[df[flag] == True].groupby("host").size().rename(feat_name)
            feats = feats.join(c, how="left")
            feats[feat_name] = feats[feat_name].fillna(0.0) / feats["hours"]
        else:
            feats[feat_name] = 0.0

    feats["unique_users"] = df.groupby("host")["user"].nunique(dropna=True)
    feats["unique_parents"] = df.groupby("host")["parent_image"].nunique(dropna=True)

    return feats.reset_index()


def build_role_features(df_rates: pd.DataFrame, cfg: StrataConfig) -> pd.DataFrame:
    """Extract the feature columns used for role inference/clustering."""
    cols = ["host"] + [c for c in cfg.role.role_feature_cols if c in df_rates.columns]
    return df_rates[cols].copy()


# ---------------------------------------------------------------------------
# Role inference (pipeline_updated pipeline.py infer_roles)
# ---------------------------------------------------------------------------

def infer_roles(role_features: pd.DataFrame, cfg: StrataConfig) -> pd.DataFrame:
    """
    Assign role_id per host.

    Priority order (matches paper Section IV-E):
      1. Asset inventory join — most accurate; wire in by replacing this function.
      2. KMeans clustering on behavioral rate features — data-driven fallback.
      3. Single 'default' role — only when insufficient hosts to cluster.

    The clustering approach uses the same rate features that feed the frequency
    channel (proc_rate_total, script_rate, lolbin_rate, etc.), which naturally
    separate workstations, servers, and privileged hosts without labels.
    """
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler

    feature_cols = [c for c in cfg.role.role_feature_cols if c in role_features.columns]
    n_hosts = len(role_features)
    min_hosts = cfg.role.min_hosts_per_role * 2

    # Fall back to single role if too few hosts or no features
    if n_hosts < min_hosts or not feature_cols:
        out = role_features[["host"]].copy()
        out["role_id"] = "default"
        return out

    X = role_features[feature_cols].fillna(0.0).to_numpy()
    X_scaled = StandardScaler().fit_transform(X)

    # Number of clusters: at least 2, at most n_hosts // min_hosts_per_role
    n_clusters = max(2, min(n_hosts // cfg.role.min_hosts_per_role, 8))

    labels = KMeans(
        n_clusters=n_clusters,
        random_state=42,
        n_init=10,
    ).fit_predict(X_scaled)

    out = role_features[["host"]].copy()
    out["role_id"] = [f"role_{l}" for l in labels]
    return out


# ---------------------------------------------------------------------------
# Semantically meaningful event pair definitions
# ---------------------------------------------------------------------------
# Each tuple (src, dst) represents a known adversarial transition pattern.
# These are grouped by MITRE ATT&CK tactic for readability and auditability.
# Weights reflect how unambiguous the pair is as an attack indicator:
#   1.00 = near-certain malicious (e.g. CreateRemoteThread -> LSASS access)
#   0.75 = strong indicator, possible benign explanation
#   0.50 = meaningful but common enough to require corroboration
#
# The pair list is consulted during scoring; only hits against known pairs
# contribute to S_ctx. Generic co-occurrence of high-severity events is NOT
# scored — that prevents noisy environments from inflating context scores.
# ---------------------------------------------------------------------------

DEFAULT_INTERESTING_PAIRS: List[Tuple[int, int]] = [
    # ---- Credential Access / LSASS / Sysmon chains ----
    (10, 1),   # ProcessAccess (LSASS) -> Process Create
    (1, 10),   # Process Create -> ProcessAccess (LSASS)
    (10, 3),   # LSASS access -> Network Connection (exfil/C2)
    (11, 10),  # File dropped -> LSASS access (tool written then executed)
    (7, 10),   # DLL Load -> LSASS access (reflective injection)
    (8, 10),   # CreateRemoteThread -> LSASS access (Mimikatz chain)

    # ---- Kerberos / Auth behavior ----
    (4768, 4769),  # TGT request -> Service Ticket (Kerberoasting)
    (4624, 4648),  # Successful logon -> explicit credential logon
    (4672, 4688),  # Special privileges assigned -> process creation
    (4769, 4688),  # Service ticket request -> process creation
    (4624, 10),    # Successful logon -> LSASS access

    # ---- Lateral Movement ----
    (4624, 7045),  # Logon -> service installed (remote service creation)
    (4688, 3),     # Process creation -> network connection
    (4648, 3),     # Explicit credential logon -> network connection
    (1, 3),        # Process Create -> Network Connection
    (4104, 3),     # PowerShell script block -> network

    # ---- Execution chains ----
    (1, 11),   # Process Create -> File Create (payload write)
    (11, 1),   # File dropped -> Process Create (payload execute)
    (22, 1),   # DNS Query -> Process Create (download-and-execute)
    (1, 6),    # Process Create -> Driver Loaded
    (1, 7),    # Process Create -> DLL Load
    (1, 8),    # Process Create -> CreateRemoteThread (injection)
    (3, 1),    # Network Connection -> Process Create
    (4104, 1), # PowerShell script block -> process

    # ---- Persistence ----
    (12, 1),   # Registry object -> Process Create
    (13, 1),   # Registry value set -> Process Create
    (7045, 1), # Service installed -> process
    (11, 12),  # File dropped -> Registry object (install artifact)
    (11, 13),  # File dropped -> Registry value set
    (1, 7045), # Process -> service install

    # ---- C2 / Beaconing ----
    (1, 22),   # Process -> DNS (unusual process resolving external name)
    (22, 3),   # DNS -> Network Connection (resolve then connect)
    (8, 3),    # Injection -> Network Connection (injected process calling out)
    (4104, 3), # PowerShell script block -> network

    # ---- Defense Evasion / Privilege Escalation ----
    (1, 4624),    # Process -> Logon event (token manipulation)
    (4688, 4672), # Process creation -> Special privileges assigned
    (7045, 10),   # Service installed -> LSASS access

    # ---- Reconnaissance ----
    (1, 4798),    # Process -> Local group enumeration
    (11, 4798),   # File dropped -> Local group enumeration
]

# Per-pair weights: maps (src, dst) -> float in [0,1]
# Pairs not in this dict get the default weight (0.50)
PAIR_WEIGHTS: Dict[Tuple[int, int], float] = {
    (8, 10):   1.00,  # CreateRemoteThread -> LSASS: Mimikatz, near certain
    (11, 10):  0.95,  # File dropped -> LSASS: credential dumper written to disk
    (7, 10):   0.90,  # DLL load -> LSASS: reflective injection then dump
    (10, 3):   0.90,  # LSASS access -> network: credential exfil
    (4768, 4769): 0.85,  # Kerberoasting chain
    (7045, 10):   0.85,  # Service install -> LSASS
    (4624, 7045): 0.80,  # Remote logon -> service install (lateral movement)
    (4624, 10):   0.80,  # Logon -> LSASS
    (4688, 4672): 0.75,  # Process -> special privileges (privesc)
    (4104, 3):    0.75,  # PS script block -> network (staged download)
    (22, 1):      0.70,  # DNS -> process (download-and-execute)
    (1, 8):       0.70,  # Process -> CreateRemoteThread
    (8, 3):       0.70,  # Injection -> network
}
_DEFAULT_PAIR_WEIGHT = 0.50

# Build a fast lookup set for O(1) pair membership testing
_PAIR_SET: set = set(DEFAULT_INTERESTING_PAIRS)


# ---------------------------------------------------------------------------
# Semantic pair correlation (replaces generic co-occurrence)
# ---------------------------------------------------------------------------

def correlate_critical_events_single_host(
    host_df: pd.DataFrame,
    *,
    cfg: StrataConfig,
    interesting_pairs: Optional[List[Tuple[int, int]]] = None,
) -> pd.DataFrame:
    """
    Detect occurrences of semantically meaningful event pairs within
    window_seconds on a single host.

    Unlike generic co-occurrence counting, this function ONLY scores hits
    against the known-pair list (DEFAULT_INTERESTING_PAIRS or a custom list).
    Each hit is weighted by PAIR_WEIGHTS — pairs like (8, 10) that are
    near-certain attack indicators contribute more than generic pairs.

    Returns DataFrame with columns:
        src_event, dst_event, pair, count, weight, weighted_score, tactic
    """
    df = host_df.sort_values("ts").copy()
    df = df.dropna(subset=["ts", "event_id"])
    if df.empty:
        return pd.DataFrame(columns=[
            "src_event", "dst_event", "pair",
            "count", "weight", "weighted_score", "tactic",
        ])

    pair_set = set(interesting_pairs) if interesting_pairs else _PAIR_SET
    times = (df["ts"].astype("int64") // 10**9).to_numpy()
    evs   = df["event_id"].fillna(0).astype(int).to_numpy()
    window = cfg.scoring.window_seconds

    counts: Dict[Tuple[int, int], int] = {}
    for i in range(len(df)):
        j = i + 1
        while j < len(df) and (times[j] - times[i]) <= window:
            key = (int(evs[i]), int(evs[j]))
            if key in pair_set:
                counts[key] = counts.get(key, 0) + 1
            j += 1

    if not counts:
        return pd.DataFrame(columns=[
            "src_event", "dst_event", "pair",
            "count", "weight", "weighted_score", "tactic",
        ])

    rows = []
    for (a, b), c in counts.items():
        w = PAIR_WEIGHTS.get((a, b), _DEFAULT_PAIR_WEIGHT)
        rows.append({
            "src_event":     a,
            "dst_event":     b,
            "pair":          f"{a}->{b}",
            "count":         c,
            "weight":        w,
            "weighted_score": c * w,   # count × severity weight
            "tactic":        _pair_tactic(a, b),
        })

    return (
        pd.DataFrame(rows)
        .sort_values("weighted_score", ascending=False)
        .reset_index(drop=True)
    )


def _pair_tactic(src: int, dst: int) -> str:
    """Return a MITRE tactic label for a known pair, for explainability output."""
    cred_access = {(10,1),(1,10),(10,3),(11,10),(7,10),(8,10),(4768,4769),(4624,10)}
    lateral     = {(4624,7045),(4688,3),(4648,3),(4769,4688)}
    execution   = {(1,11),(11,1),(22,1),(1,6),(1,7),(1,8),(3,1),(4104,1)}
    persistence = {(12,1),(13,1),(7045,1),(11,12),(11,13),(1,7045)}
    c2          = {(1,22),(22,3),(8,3),(4104,3)}
    evasion     = {(1,4624),(4688,4672),(7045,10)}
    recon       = {(1,4798),(11,4798)}

    pair = (src, dst)
    if pair in cred_access: return "credential_access"
    if pair in lateral:     return "lateral_movement"
    if pair in execution:   return "execution"
    if pair in persistence: return "persistence"
    if pair in c2:          return "c2"
    if pair in evasion:     return "defense_evasion"
    if pair in recon:       return "reconnaissance"
    return "unknown"


def correlate_critical_events_by_host(
    df: pd.DataFrame,
    cfg: StrataConfig,
    interesting_pairs: Optional[List[Tuple[int, int]]] = None,
) -> pd.DataFrame:
    """Run semantic pair correlation across all hosts."""
    all_rows = []
    for host, g in df.groupby("host", dropna=False):
        pairs = correlate_critical_events_single_host(
            g, cfg=cfg, interesting_pairs=interesting_pairs
        )
        if not pairs.empty:
            pairs.insert(0, "host", str(host))
            all_rows.append(pairs)

    if not all_rows:
        return pd.DataFrame(columns=[
            "host", "src_event", "dst_event", "pair",
            "count", "weight", "weighted_score", "tactic",
        ])
    return pd.concat(all_rows, ignore_index=True)


def compute_pair_stats(pairs_df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate per-host pair statistics for the context channel.

    Key output columns:
      n_pairs          — number of distinct known pairs observed
      weighted_score_sum — sum of count × pair_weight (primary signal)
      max_pair_weight  — weight of the highest-confidence pair seen
      n_tactics        — number of distinct MITRE tactics represented
      top_tactic       — most frequently represented tactic (for triage output)
    """
    if pairs_df.empty:
        return pd.DataFrame(columns=[
            "host", "n_pairs", "weighted_score_sum",
            "max_pair_weight", "n_tactics", "top_tactic",
        ])

    stats = pairs_df.groupby("host").agg(
        n_pairs=("pair", "nunique"),
        weighted_score_sum=("weighted_score", "sum"),
        max_pair_weight=("weight", "max"),
        n_tactics=("tactic", "nunique"),
    ).reset_index()

    # Top tactic: which MITRE tactic had the highest total weighted score
    top_tactic = (
        pairs_df.groupby(["host", "tactic"])["weighted_score"]
        .sum()
        .reset_index()
        .sort_values("weighted_score", ascending=False)
        .groupby("host")
        .first()["tactic"]
        .reset_index()
        .rename(columns={"tactic": "top_tactic"})
    )
    stats = stats.merge(top_tactic, on="host", how="left")
    stats["top_tactic"] = stats["top_tactic"].fillna("none")
    return stats
