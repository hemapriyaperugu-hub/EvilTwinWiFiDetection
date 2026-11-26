# Detection Logic & History Architecture — Evil Twin Wi-Fi Attack Detection System

## 1. End-to-End Detection Pipeline

When a Wi-Fi scan runs (via Flask `/api/scan`, CLI `main.py`, or Tkinter `gui.py`), every visible access point goes through the following pipeline:

1. **Passive Windows Scan (`src/scanner.py`)**
   - Executes `netsh wlan show networks mode=bssid` without modifying adapter state or collecting passwords.
   - `parse_netsh_output()` extracts `SSID`, `BSSID` (normalized lowercase colon-separated), `Signal` (%), `Channel`, `Band`, `Authentication` (`Security`), `Encryption` (`CCMP`, `GCMP`, `TKIP`, `None`), and `Radio`.
   - Any missing field is preserved as `None` / `"Unavailable"`—never fabricated as `Channel=1` or `Signal=0`.
   - Scanner errors (`wlansvc` stopped, disabled adapter, timeout) return `success=False` with the actual error so a failed scan is never treated as a safe empty environment.

2. **Feature & Diagnostic Extraction (`src/features.py`)**
   - Extracts the 7 standardized ML features (`Signal`, `Channel`, `Security`, `SameSSIDCount`, `BSSIDKnown`, `ChannelMatch`, `SecurityMatch`) with `np.nan` for unavailable values (handled by `SimpleImputer` in both ML pipelines).
   - Computes 18 diagnostic inspection attributes including `OUI` (first 3 MAC octets), `SignalDelta` (change vs last scan), `MissingFeatures`, `BSSIDOtherSSIDs` (detects if a MAC previously broadcast a different SSID), `BaselineFingerprint` vs `CurrentFingerprint`, and saved Windows profile security comparison (`netsh wlan show profile`).
   - Excludes `<Hidden Network>` from `SameSSIDCount` duplicate grouping so unrelated hidden routers are not treated as Evil Twin clones.
   - Identifies legitimate dual-band pairs (`is_dual_band_pair`: matching OUI, consecutive MAC within `<= 16` in last octet, complementary 2.4/5 GHz bands, compatible security tier) and consistent same-OUI / Enterprise multi-AP deployments.

3. **Three-Layer Machine Learning Analysis (`src/train.py`, `src/predict.py`)**
   - **Random Forest (Primary Supervised Classifier):** `SimpleImputer(strategy="median") -> RandomForestClassifier(n_estimators=100, max_depth=5, min_samples_split=4, class_weight="balanced", random_state=42)`. Classifies APs as `Legitimate` or `Evil Twin`.
   - **K-Nearest Neighbors (KNN Comparison Classifier):** `SimpleImputer(strategy="median") -> StandardScaler -> KNeighborsClassifier(n_neighbors=5, weights="distance")`. Compares each AP against its nearest neighbors in feature space as a second supervised check against Random Forest.
   - **Isolation Forest (Unsupervised Anomaly Detection):** `SimpleImputer(strategy="median") -> StandardScaler -> IsolationForest(n_estimators=150, contamination=0.02, random_state=42)`, trained strictly on `Legitimate` (`y == 0`) networks to flag previously unseen anomalous Wi-Fi patterns (`Normal` vs `Anomaly` + `decision_function` score).
   - **Strict Rule Priority:** ML is **supporting evidence only**. `RF=Legitimate`, `KNN=Legitimate`, and `IsoForest=Normal` can never override rule-based security downgrades, BSSID conflicts, or unencrypted networks. If `KNN != RF`, the AP is forced into verification (`UNVERIFIED NETWORK AND UNSAFE`).

4. **Non-Overlapping Risk Scoring (`src/predict.py`)**
   - Computes a `0–100` score (capped at 100) across independent dimensions to avoid double-counting:
     - **Security** (mutually exclusive): Critical Security Downgrade (`+40`), Moderate Security Shift (`+25`), Open/WEP (`+20`). Missing security adds `0` points and communicates uncertainty.
     - **BSSID Identity** (mutually exclusive): Concurrent Duplicate BSSID Collision (`+30`), BSSID SSID-Switch (`+25`), Unfamiliar BSSID for Known/Verified SSID (`+25`), Unverified Dual-Band Partner (`+10`).
     - **Concurrent Duplicate SSID** (non-dual-band, non-consistent multi-AP): `+10`.
     - **Channel Consistency**: Unexpected channel shift (`+10`).
     - **Signal Shift**: Sudden shift `>= 30%` vs previous scan (`+10`).
     - **Supervised ML Consensus (RF + KNN)**: Both predict Evil Twin (`+20`), RF/KNN disagree (`+15`), Both predict Legitimate (`+0`).
     - **Unsupervised ML Anomaly (Isolation Forest)**: Anomalous pattern (`-1`, `+10`), Normal (`+1`, `+0`).

---

## 2. Four-State Classification Rules

- **`UNSAFE`**  
  Triggered when `RiskScore >= high_risk_threshold` (default `60`) **AND** at least `2` independent warning indicators exist. A single indicator alone (e.g., new BSSID alone, duplicate SSID alone, channel shift alone, or an Isolation Forest outlier alone) never triggers `UNSAFE`.

- **`UNVERIFIED NETWORK AND UNSAFE`**  
  Triggered when not `UNSAFE`, and any of: `RiskScore >= suspicious_threshold` (default `25`), security downgrade/mismatch, unfamiliar BSSID on a known SSID, duplicate BSSID collision or BSSID SSID-switch, ML disagreement (`RF != KNN`) or dual supervised attack consensus, unencrypted (`Open`/`WEP`) security, or unavailable security attribute.

- **`UNVERIFIED NETWORK BUT SAFE`**  
  Triggered when no suspicious indicators fired (`RiskScore < suspicious_threshold`), and the AP either lacks an explicitly established `TRUSTED_BASELINE` (including passively observed `OBSERVED_UNVERIFIED` APs seen multiple times!) or is missing non-security scan attributes (`Signal`, `Channel`).

- **`SAFE`**  
  Triggered **only** when the AP matches an explicitly verified `TRUSTED_BASELINE` (`Verified = Yes`), its security/encryption matches baseline, all critical attributes are present, `RiskScore < suspicious_threshold`, there are no active suspicious indicators, and both supervised ML models (`RF` and `KNN`) predict `Legitimate`. Note: even `SAFE` does not guarantee absolute safety.

---

## 3. Anti-Poisoning Network History Design (`src/history.py` & `src/db_manager.py`)

- **Observation Count Is Not Trust:** Passive scans initialize new APs as `OBSERVED_UNVERIFIED` (`Observation Count = 1`). Repeated scans increment `Observation Count` and update `Last Seen` / `Last Signal` / `Last Channel` / `Last Security`, but **never** promote `OBSERVED_UNVERIFIED` or `FLAGGED_SUSPICIOUS` to `TRUSTED_BASELINE`.
- **Immutable Baselines:** Baseline `Security`, `Encryption`, `Channel`, and `Fingerprint` are preserved when suspicious changes occur so a downgrade on Scan 1 remains detectable on Scan 2, Scan 3, and beyond.
- **Persistent Alerts & History:** SQLite (`database/eviltwin.db`) stores timestamped `scans`, per-AP `scan_results`, real `alerts`, and `settings` across application restarts, while `dataset/network_history.csv` keeps AP baseline fingerprints synchronized across CLI, GUI, and Web interfaces.
- **Poisoned Record Defense:** Even if a history row erroneously marks a rogue AP as `TRUSTED_BASELINE`, `assess_network_risk()` still cross-checks sibling history records for that SSID, saved Windows profile security settings, concurrent scan duplicates, and ML predictions on every scan.
