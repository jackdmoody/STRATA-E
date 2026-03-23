# STRATA-(E)
### Structural and Temporal Role-Aware Threat Analytics for Endpoint Telemetry

> A hierarchical, statistically calibrated behavioral anomaly detection framework for Windows Sysmon and Windows Event telemetry. Reduces thousands of endpoint events to a ranked, explainable triage list by combining time-aware sequence modeling, Bayesian peer-role baselines, multi-channel anomaly scoring, and a corroboration gate — answering: **which hosts are behaving abnormally, why, and based on what evidence?**

---

## The Problem

Enterprise endpoint anomaly detection faces four recurring challenges. **Temporal abstraction ambiguity**: coarse time bucketing loses kill-chain velocity signatures while fine-grained bucketing creates unmanageable state spaces. **Transition sparsity**: sparse host windows produce unreliable divergence estimates that inflate false positive rates. **Baseline contamination**: in compromised-by-default environments, global baselines absorb attacker behavior as "normal." **Structural vs. volumetric mismatch**: a host running encoded PowerShell at normal volume looks fine to rate-based detectors; a host running `svchost.exe` at high volume looks anomalous to sequence-based detectors.

STRATA-(E) addresses all four by modeling behavior per-host, per-role, with time-aware transitions, Dirichlet-stabilized baselines, and four independent detection channels that must corroborate before surfacing an alert.

---

## Architectural Overview

<img width="1102" height="1118" alt="strata_layout" src="https://github.com/user-attachments/assets/d21b21ad-4056-4318-bbf0-999a962ac7ef" />


*Time-aware, role-aware, multi-channel Sysmon behavioral analytic architecture with Bayesian peer baselines and calibrated sequence divergence. Dirichlet shrinkage stabilizes transition estimation; bootstrap calibration yields statistical significance for JSD-based sequence anomalies. A parallel validation framework supports attack injection, ablation, calibration checks, and stability analysis.*

---

## How It Works

Each stage builds on the previous, and the four scoring channels answer independent questions about host behavior:

```
Raw Sysmon / Windows Event Telemetry (CSV or JSON)
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  Stage 1 — Ingest & Preprocessing                               │
│  Flexible column detection (Sysmon, Splunk, Elastic, DARPA TC)  │
│  Canonical schema: ts, host, event_id, image, cmdline, user     │
│  Multi-resolution tokenization (coarse / medium / fine)         │
│  Sessionization with adaptive τ_gap per role                    │
│  Inter-event Δt discretization into time buckets                │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  Stage 2 — Feature Construction                                  │
│  Time-aware transitions: P(z', β | z)                           │
│  Per-host rate features (proc/script/office/lolbin rates)       │
│  Critical event pair correlation (MITRE ATT&CK-aligned)         │
│  Context flags: encoded cmds, download cradles, LOLBin usage    │
│  Event-level MITRE ATT&CK technique mapping                     │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  Stage 3 — Bayesian Peer-Role Baselines                          │
│  Host role inference (workstation / server / DC)                │
│  Hierarchical Dirichlet model: θ_r ~ Dir(α₀), θ_h|θ_r ~ Dir(κθ_r) │
│  Shrinkage toward role baseline stabilizes sparse windows       │
│  Smoothed peer role baselines: P̂_r(z', β | z)                  │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼  4 independent channels — each answers a different question
┌─────────────────────────────────────────────────────────────────┐
│  Stage 4 — Calibrated Multi-Channel Scoring                      │
│                                                                  │
│  Sequence channel (structural anomalies):                        │
│    S_seq = JS(P̂_h ‖ P̂_r(h)), Dirichlet-smoothed                │
│    Bootstrap calibration → z-score, p-value, percentile          │
│                                                                  │
│  Frequency channel (volumetric anomalies):                       │
│    S_freq = IsolationForest(rate features)                       │
│                                                                  │
│  Context channel (fine-grained signals):                         │
│    S_ctx = f(encoded cmds, LOLBins, pair correlation, TF-IDF)    │
│                                                                  │
│  Drift channel (behavioral change over time):                    │
│    S_drift = JS(P̂_h^cur ‖ P̂_h^hist)                             │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼  Question: Is the anomaly corroborated across channels?
┌─────────────────────────────────────────────────────────────────┐
│  Stage 5 — Evidence Fusion & Gating                              │
│  Borda rank aggregation or weighted linear fusion                │
│  Corroboration gate: requires ≥ 2 channels above threshold      │
│  Extreme-channel bypass for single-channel extreme scores        │
│  Result: dramatically reduces false positives                    │
│  (H5 finding: FPR 1.0 → 0.0 on APT29 data, recall maintained)  │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
  Ranked Host Triage — explainable per-host scores with
  top anomalous transitions, channel breakdowns, calibrated
  percentiles, MITRE ATT&CK technique annotations, and
  suggested next steps
```

### Why this architecture

| Component | Technique | What it answers | Why the alternatives fail |
|---|---|---|---|
| Multi-resolution tokens | Coarse/medium/fine abstraction | What granularity captures the signal? | Fixed-granularity tokens either lose semantic fidelity (too coarse) or create intractable state spaces (too fine). Backoff mixing uses both. |
| Dirichlet shrinkage | Hierarchical Bayesian prior | How do you score a host with 25 events? | MLE on sparse windows produces unstable divergence scores. Shrinkage toward the role baseline stabilizes estimates while preserving genuine deviations. |
| Bootstrap calibration | Multinomial null simulation | Is this divergence score significant or just noise? | Raw JSD depends on window size — a host with 500 events always has higher JSD than one with 50, even if both are normal. Calibration normalizes for this. |
| Peer-role baselines | Behavioral clustering | What's "normal" for this type of host? | Global baselines absorb server behavior into the workstation norm (and vice versa). Role conditioning makes "abnormal" mean "abnormal for your peer group." |
| Corroboration gate | Multi-channel consensus | Is this really suspicious or just one noisy signal? | Single-channel detectors produce lists dominated by false positives. Requiring independent agreement across structural, volumetric, and contextual channels filters coincidental anomalies. |

---

## Installation

```bash
# Clone and create a virtual environment
git clone https://github.com/jackdmoody/Sysmon_Behavioral_Analytic.git
cd Sysmon_Behavioral_Analytic/strata_repo
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (Linux/Mac)
source .venv/bin/activate

# Install in editable mode
pip install -e .
```

### Dependencies

Python ≥ 3.10. Core: `pandas`, `numpy`, `scikit-learn`, `scipy`, `networkx`, `matplotlib`, `plotly`, `ipywidgets`.

---

## Usage

### CLI

```bash
# Run on a Sysmon CSV export
strata --input data/sysmon_export.csv --output results

# Run with HTML report (opens in browser)
strata --input data/sysmon_export.csv --output results --report --browser

# Run a specific ablation condition
strata --input data/sysmon_export.csv --output results --ablation sequence_only

# Run on DARPA TC JSON data
strata --input data/darpa/cadets/ --output results

# Suppress matplotlib visualizations (headless)
strata --input data/sysmon_export.csv --output results --report --no-plots
```

### Run from Python

```python
from sysmon_pipeline import StrataPipeline, StrataConfig
from sysmon_pipeline.loaders import load_sysmon_csv

cfg = StrataConfig()
df  = load_sysmon_csv("data/sysmon_export.csv")

pipe   = StrataPipeline(cfg)
fitted = pipe.fit(df)
art    = pipe.score(df, fitted)
print(art.triage.head(20))
```

### Run with HTML report from Python

```python
from sysmon_pipeline import StrataPipeline, StrataConfig
from sysmon_pipeline.report import ReportContext
from sysmon_pipeline.loaders import load_sysmon_csv

cfg = StrataConfig()
df  = load_sysmon_csv("data/sysmon_export.csv")

with ReportContext(output_dir="results", open_browser=True) as report:
    pipe   = StrataPipeline(cfg)
    fitted = pipe.fit(df)
    art    = pipe.score(df, fitted)
    report.finalise(art)
```

### One-liner convenience

```python
from sysmon_pipeline.report import run_with_report
run_with_report("data/sysmon_export.csv", output_dir="results", open_browser=True)
```

### Separate baseline and scoring windows

```python
from sysmon_pipeline import StrataPipeline, StrataConfig
from sysmon_pipeline.loaders import load_sysmon_csv, split_time_windows

cfg = StrataConfig()
df  = load_sysmon_csv("data/sysmon_30days.csv")

baseline_df, scoring_df = split_time_windows(df, baseline_days=7, score_days=1)

pipe   = StrataPipeline(cfg)
fitted = pipe.fit(baseline_df)
art    = pipe.score(scoring_df, fitted, prior_window_df=baseline_df)
```

### DARPA Transparent Computing datasets

```python
from sysmon_pipeline.loaders import load_darpa_tc

df, labels = load_darpa_tc(
    data_dir="data/darpa/cadets",
    dataset="cadets",
)
```

---

## Data Ingestion

STRATA-(E) accepts data from three sources:

**Generic Sysmon CSV** — Any CSV export from Sysmon, Splunk, Elastic, or a SIEM. Column names are auto-detected via ordered candidate lists:

| Field | Candidates (first match wins) |
|---|---|
| Timestamp | `_timestamp`, `UtcTime`, `ts`, `timestamp`, `TimeCreated` |
| Host | `host.fqdn`, `Computer`, `Host`, `Hostname`, `host` |
| Event ID | `winlog.event_id`, `EventID`, `EventId`, `event_id` |
| Image | `Image`, `ProcessImage`, `process_image`, `ProcessName` |
| Parent image | `ParentImage`, `ParentProcessName`, `parent_image` |
| Command line | `CommandLine`, `CmdLine`, `cmdline`, `command_line` |
| User | `User`, `UserName`, `SubjectUserName`, `user` |
| Integrity level | `IntegrityLevel`, `integrity_level` |
| Signed | `Signed`, `signed` |

Only timestamp, host, and event ID are required. All other columns degrade gracefully if absent.

**DARPA Transparent Computing** — JSON lines from the CADETS, THEIA, FIVEDIRECTIONS, and TRACE datasets. Linux syscall event types are mapped to approximate Sysmon event IDs via `_DARPA_EVENT_MAP`.

**Synthetic data** — Built-in generator for testing and ablation without real data. Use `run_experiments.py --synthetic`.

---

## HTML Report

The `--report` flag generates an interactive, self-contained HTML dashboard with:

- Summary metric cards: events processed, hosts scored, corroborated hosts, critical findings
- Pipeline flow visualization showing stage-by-stage counts
- **Interactive host selector** with severity indicators — click any host to investigate
- Per-host **channel score cards** with bootstrap calibration detail (z-score, p-value, percentile)
- **Event timeline strip** — color-coded by process category (SCRIPT, LOLBIN, OFFICE, PROC), height by severity level. Hover for event detail including MITRE T-code
- **Top transition bars** — the actual event-to-event sequences behind the sequence channel score
- **Channel radar chart** (Chart.js) — selected host vs. fleet median across all 4 channels
- **MITRE ATT&CK technique summary** — per-host technique frequency with clickable links to attack.mitre.org, showing technique ID, name, and tactic
- **Suspicious command log** — encoded/obfuscated command lines with timestamps
- **Evasion signal alerts** when shrinkage anomaly detects sudden telemetry drops
- CSV download buttons for all artifact tables
- Diagnostic plot gallery (captured matplotlib figures) with click-to-zoom
- Run metadata table

---

## Scoring Channels

STRATA-(E) scores each host independently across four channels. The corroboration gate requires signal from ≥ 2 channels before surfacing a host as a triage lead.

| Channel | Technique | What it detects | Key output |
|---|---|---|---|
| **Sequence** | Jensen-Shannon divergence from Dirichlet-shrunk peer-role baseline, bootstrap-calibrated | Structural anomalies — novel process chains, unusual transition patterns relative to peer role | `S_seq`, z-score, p-value, percentile, rare transition hits |
| **Frequency** | Isolation Forest on per-host rate features | Volumetric anomalies — unusual event volume, rate spikes, abnormal process mix | `S_freq` |
| **Context** | Weighted flag aggregation + TF-IDF command novelty + critical event pair correlation | Fine-grained behavioral indicators — encoded commands, LOLBin usage, suspicious parent-child chains | `S_ctx`, cmdline novelty score |
| **Drift** | JSD between current and prior-window transition distributions | Behavioral change over time — sustained shifts in host behavior vs. its own history | `S_drift` |

---

 
## Event Severity Grading
 
Each Sysmon/Windows event ID is assigned a severity score in [0, 1] based on threat-hunting signal value:
 
| Score | Label | Example events |
|---|---|---|
| 0.95–1.00 | Critical | Event 10 (ProcessAccess/LSASS), Event 8 (CreateRemoteThread), Event 4104 (PS Script Block) |
| 0.80–0.90 | High | Event 3 (Network Connection), Event 7 (Image Load), Event 11 (File Create), Event 22 (DNS Query), Event 7045 (Service Installed) |
| 0.60–0.75 | Medium | Event 1 (Process Create), Event 12/13 (Registry), Event 17 (Named Pipe), Event 4624 (Logon) |
| 0.20–0.40 | Low | Event 5 (Process Terminate), Event 7036 (Service Start/Stop), App crashes |
 
---
 
## MITRE ATT&CK Coverage
 
STRATA-(E) maps each event to the most specific applicable ATT&CK technique using event ID, process image, and behavioral context flags. The mapping is evidence-based — no external threat intelligence feeds required. Coverage is organized by tactic below.
 
### Execution
 
| T-code | Technique | How STRATA-E addresses it |
|---|---|---|
| T1059.001 | PowerShell | Explicit `SCRIPT:POWERSHELL` token; encoded command flag (`-enc`, `-encodedcommand`) detection in Context Channel |
| T1059.003 | Windows Command Shell | `SCRIPT:CMD` token class; parent-child chain modeling in transition sequences |
| T1059.005 | Visual Basic (WScript/CScript) | `SCRIPT:WSCRIPT` and `SCRIPT:CSCRIPT` tokens; script interpreter execution tracking |
| T1059 (general) | Command and Scripting Interpreter | `SCRIPT` coarse token class; sequence anomaly scoring detects novel script-to-process transitions |
| T1047 | Windows Management Instrumentation | `wmic.exe` classified as LOLBin; WMI-initiated process chains tracked via transition modeling |
| T1106 | Native API | Covered indirectly via Event 8 (CreateRemoteThread) and Event 7 (Image Load) — API-level execution surfaces as observable Sysmon events |
 
### Defense Evasion
 
| T-code | Technique | How STRATA-E addresses it |
|---|---|---|
| T1027 | Obfuscated Files or Information | Encoded command flags (`has_encoded`, `has_bypass`, `has_reflection`) are named Context Channel signals; TF-IDF command novelty scoring detects obfuscated command lines |
| T1218.011 | System Binary Proxy Execution: Rundll32 | Explicit `LOLBIN:RUNDLL32` token; LOLBin usage is a weighted context flag |
| T1218.010 | System Binary Proxy Execution: Regsvr32 | Explicit `LOLBIN:REGSVR32` token; parent-child transitions from script → LOLBin are scored |
| T1218.005 | System Binary Proxy Execution: Mshta | `LOLBIN:MSHTA` token; mshta.exe classified in LOLBin set |
| T1218.003 | System Binary Proxy Execution: CMSTP | `LOLBIN:CMSTP` token; cmstp.exe classified in LOLBin set |
| T1140 | Deobfuscate/Decode Files or Information | `certutil.exe` LOLBin classification; certutil-to-process transitions flagged |
| T1036 | Masquerading | Integrity level mismatch detection; unsigned execution flagging (`signed=False` context flag); anomalous process-in-role deviations via Sequence Channel |
| T1055 | Process Injection | Event 8 (CreateRemoteThread) mapped directly; parent-child integrity mismatch and suspicious parent-child relationship scoring in Context Channel |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Event 6 (Driver Loaded) mapped directly; novel driver load transitions detected by Sequence Channel |
 
### Credential Access
 
| T-code | Technique | How STRATA-E addresses it |
|---|---|---|
| T1003 | OS Credential Dumping | Event 10 (ProcessAccess / LSASS) mapped directly at severity 1.0 (highest); pair correlation weights Event 8→10 at 1.0 (near-certain Mimikatz chain) |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Event 4768 (Kerberos TGT request) mapped; pair correlation for 4768→4769 (TGT→Service Ticket) weighted at 0.85 |
 
### Persistence
 
| T-code | Technique | How STRATA-E addresses it |
|---|---|---|
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Event 12/13 (Registry Object Added/Value Set) mapped; registry→process transitions are explicit pair correlation targets |
| T1543.003 | Create or Modify System Process: Windows Service | Event 7045 (Service Installed) mapped at severity 0.90; service install→LSASS and service install→process pairs weighted 0.80–0.85 |
| T1053 | Scheduled Task/Job | Covered via persistence-category synthetic attack injection; process chains involving task scheduler binaries tracked in transition sequences |
 
### Lateral Movement
 
| T-code | Technique | How STRATA-E addresses it |
|---|---|---|
| T1021 | Remote Services | Network attributes (dest_ip, dest_port, protocol) are canonical schema fields; Event 4624 (Logon)→Event 7045 (Service Install) pair correlation weighted at 0.80 targets remote service creation |
| T1570 | Lateral Tool Transfer | Event 4688→Event 3 (Process Creation→Network Connection) and Event 4648→Event 3 (Explicit Credential Logon→Network) are explicit pair correlation targets for lateral movement |
 
### Command and Control
 
| T-code | Technique | How STRATA-E addresses it |
|---|---|---|
| T1071 | Application Layer Protocol | Event 22 (DNS Query) mapped directly; Event 1→22 (Process→DNS) and Event 22→3 (DNS→Network Connection) are pair correlation targets for C2 beaconing patterns |
 
### Privilege Escalation
 
| T-code | Technique | How STRATA-E addresses it |
|---|---|---|
| T1134 | Access Token Manipulation | Event 4672 (Special Privileges Assigned) mapped at severity 0.90; Event 4688→4672 (Process Creation→Special Privileges) pair weighted at 0.75 |
 
### Discovery
 
| T-code | Technique | How STRATA-E addresses it |
|---|---|---|
| T1087 | Account Discovery | Event 4798 (Group Membership Enumeration) mapped directly; Event 1→4798 (Process→Enumeration) pair targets automated reconnaissance |
| T1082 / T1083 | System / File Discovery | Process behavior baseline deviations detected via Sequence Channel — novel enumeration tool execution surfaces as structural anomaly relative to peer-role baseline |
 
### Pair-level tactic mapping
 
In addition to event-level technique mapping, STRATA-(E) performs **pair-level tactic annotation** on critical event co-occurrences within a configurable time window. Each pair is weighted by specificity:
 
| Weight | Example pair | Tactic | Significance |
|---|---|---|---|
| 1.00 | Event 8 → Event 10 (CreateRemoteThread → LSASS) | Credential Access | Near-certain Mimikatz / credential dumper chain |
| 0.95 | Event 11 → Event 10 (File Drop → LSASS) | Credential Access | Tool written to disk then used for credential access |
| 0.85 | Event 4768 → Event 4769 (TGT → Service Ticket) | Credential Access | Kerberoasting chain |
| 0.80 | Event 4624 → Event 7045 (Logon → Service Install) | Lateral Movement | Remote service creation |
| 0.75 | Event 4104 → Event 3 (PS Script Block → Network) | C2 | PowerShell staged download |
| 0.70 | Event 22 → Event 1 (DNS → Process Create) | Execution | Download-and-execute pattern |
| 0.50 | Default | Various | Meaningful but requires corroboration |

---

## Ablation Conditions

STRATA-(E) supports structured ablation studies via `AblationConfig` presets. All conditions use the same `StrataPipeline.run()` code path:

| Condition | What it disables | Purpose |
|---|---|---|
| `full_pipeline` | Nothing | Full system — all components active |
| `sequence_only` | Context, drift, covariance channels | Isolate structural sequence modeling contribution |
| `no_shrinkage` | Dirichlet shrinkage | Test MLE vs. Bayesian estimation |
| `no_role_baselining` | Role-conditioned baselines | Test role-aware vs. global baseline |
| `no_calibration` | Bootstrap JSD calibration | Test raw vs. calibrated divergence |
| `no_drift` | Drift channel + seq-drift covariance | Test with/without temporal change detection |

```python
from sysmon_pipeline import StrataConfig, AblationConfig, StrataPipeline

for condition in [AblationConfig.full_pipeline(),
                  AblationConfig.sequence_only(),
                  AblationConfig.no_shrinkage()]:
    cfg = StrataConfig(ablation=condition)
    pipe = StrataPipeline(cfg)
    fitted = pipe.fit(df_baseline)
    art = pipe.score(df_scoring, fitted)
    evaluate(art.triage, labels, condition=condition)
```

---

## Module Reference

| Module | Stage | Description |
|---|---|---|
| `config.py` | — | Typed dataclass configuration. Sub-configs: `IOConfig`, `TimeBucketingConfig`, `BaselineConfig`, `RoleConfig`, `ScoringConfig`, `AblationConfig`. JSON serialization. |
| `schema.py` | 1 | Flexible multi-candidate column detection. Canonical schema normalization. Type coercion. |
| `loaders.py` | 1 | CSV and DARPA TC JSON ingestion. `load_sysmon_csv()`, `load_darpa_tc()`, `split_time_windows()`. |
| `mapping.py` | 2 | Multi-resolution token abstraction (coarse/medium/fine). Context flags. Event severity grading. MITRE ATT&CK event-level technique mapping. |
| `sequence.py` | 2 | Sessionization with adaptive τ_gap. Inter-event Δt bucketing. Transition count extraction. |
| `pairs.py` | 2 | Semantic critical event pair correlation. MITRE tactic-labeled pair weights. Per-host pair statistics. |
| `divergence.py` | 3–4 | Hierarchical Dirichlet peer baselines. JSD scoring. Bootstrap calibration. Drift computation. Shrinkage anomaly detection. |
| `scoring.py` | 4–5 | Isolation Forest frequency channel. Context channel (flag aggregation + TF-IDF). Borda/weighted fusion. Corroboration gate. Ranked triage builder. |
| `pipeline.py` | — | `StrataPipeline` orchestrator. `fit()` / `score()` / `fit_score()`. CLI entry point with `--report`, `--ablation`, `--browser`. |
| `report.py` | — | Self-contained HTML report generator. Interactive host investigation dashboard. Chart.js radar. Event timeline. MITRE technique summary. CSV downloads. |
| `visuals.py` | — | Static matplotlib plots (score histogram, top hosts, channel breakdown) and interactive Plotly visualizations (Sankey, heatmap, timeline). |
| `graph.py` | — | NetworkX graph utilities for transition visualization. |

---

## Hypotheses Tested

The STRATA-(E) validation framework tests five hypotheses:

| Hypothesis | Claim | Metric | Result (synthetic) |
|---|---|---|---|
| **H1** | Dirichlet shrinkage reduces JSD variance vs. MLE under sparse windows | JSD variance by window size | Variance reduction 2.5× at n=25 events |
| **H2** | Peer-role baselines improve Top-K recall vs. global baseline | Top-K recall by K | Null on synthetic (mechanistically explained — roles identical in generator) |
| **H3** | Bootstrap-calibrated p-values are uniform under benign data | KS test per role | Marginal (KS p=0.064) |
| **H4** | Multi-channel fusion improves Top-K recall vs. any single channel | Precision/Recall per channel | Publication-ready |
| **H5** | Corroboration gating reduces FPR without degrading Top-K recall | FPR and recall with/without gate | **Strongest result**: FPR 1.0 → 0.0, recall maintained (APT29 data) |

---

## Limitations

- **Batch-oriented** — not streaming-native. Each run processes a fixed time window.
- **Assumes reliable host role assignment** — role inference depends on sufficient behavioral diversity in the baseline window.
- **Dependent on Sysmon configuration quality** — events not collected by Sysmon cannot be scored.
- **Unsupervised** — no attribution modeling. STRATA identifies anomalous hosts, not specific threat actors.
- **Calibration assumes multinomial null** — the bootstrap null distribution is an approximation.
- **H2 null result on synthetic data** — peer-role baselining was not further validated by tuning synthetic data to prove the hypothesis (explicitly rejected as methodologically unsound). Real-world datasets with genuine role diversity are needed.
- **Synthetic-only validation** — real-world performance depends on Sysmon configuration, threat mix, and environmental diversity.

---

## License

MIT
