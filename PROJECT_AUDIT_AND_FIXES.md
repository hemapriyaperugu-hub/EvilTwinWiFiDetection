# PROJECT AUDIT AND FIXES — Evil Twin Wi-Fi Attack Detection System

**Project Directory:** `E:\Vardhaman\3-1 sem\MINI PROJECT\EvilTwinDetection`  
**Original Pre-Audit Backup:** `E:\Vardhaman\3-1 sem\MINI PROJECT\EvilTwinDetection_backup_before_audit`  
**Original Model Backups:** `models/knn_model_v1_orig.pkl`, `models/random_forest_model_v1_orig.pkl`  

---

## A. Problems Identified (Audit Report)

| File Name | Existing Function & Purpose | Problem Identified | Risk Associated | Proposed & Implemented Correction |
|---|---|---|---|---|
| `src/predict.py` | `assess_network_risk` — Determines final risk classification from rules, history, and ML | **Auto-trust via history**: Once any BSSID was stored in `network_history.csv` (`bssid_known == 1`) with matching security, `assess_network_risk` returned `LOWER RISK` / `LIKELY LEGITIMATE` even when `ml_both_attack` or `is_concurrent_broadcast` existed. New WPA2 networks also defaulted to `LOWER RISK`. | **Critical False Negatives**: An Evil Twin or suspicious AP scanned twice became trusted (`LIKELY LEGITIMATE`) simply by persisting across two scans. | Replaced with 4 explicit classifications (`KNOWN / CONSISTENT`, `NEW / UNVERIFIED`, `SUSPICIOUS / VERIFY`, `HIGH RISK / POSSIBLE EVIL TWIN`). Only `TRUSTED_BASELINE` + clean fingerprint + ML Legitimate consensus + complete features can reach `KNOWN / CONSISTENT`. |
| `src/predict.py` | `assess_network_risk` — Saved Windows profile handling | **SSID-only profile trust**: `is_saved_profile` trusted any AP whose SSID name matched a saved Windows profile (`bssid_known == 0` ignored) before checking `ml_both_attack` or `is_concurrent_broadcast`. | An attacker broadcasting a saved SSID with WPA2-Personal from a rogue BSSID bypassed detection and was labeled `USER_VERIFIED` / `LOWER RISK`. | Removed blind SSID-only promotion. Saved profile security (`get_profile_security_details`) is compared as a security baseline, while unfamiliar BSSIDs remain unverified/suspicious. |
| `src/history.py` | `update_history` — Updates `network_history.csv` after scans | **History self-poisoning**: Unconditionally merged any changed `Channel` into `Channel` and **overwrote** baseline `Security` with new values; stored no `Trust Status`, `Previous Classification`, `Fingerprint`, `Signal`, `Suspicious Indicators`, or `Changes`. | If an AP downgraded (`WPA2 -> Open`) or hopped channels on Scan 1, Scan 2 compared against the overwritten rogue values and treated the attacker as consistent. | Added `Trust Status` (`TRUSTED_BASELINE`, `OBSERVED_UNVERIFIED`, `FLAGGED_SUSPICIOUS`), `Fingerprint`, `Last Signal`/`Last Channel`/`Last Security`, `Previous Classification`, `Suspicious Indicators`, and `Changes`. Baseline fields are never overwritten by anomalies, and flagged/unverified APs are never auto-promoted. |
| `src/history.py` | `is_bssid_known` — Checks if a BSSID was seen before | Checked globally (`bssid_clean in history_df["BSSID"]`) if `(SSID, BSSID)` did not match. | A known router MAC repurposed to impersonate a different SSID was treated as `BSSIDKnown = 1`. | Restricted `is_bssid_known` to exact `(SSID, BSSID)` matching and added `get_bssid_other_ssids()` to detect BSSID SSID-switching anomalies. |
| `src/features.py` | `parse_signal`, `parse_channel`, `parse_security_binary`, `get_security_tier` | **Silent feature fabrication**: Missing `Signal` defaulted to `0`, missing `Channel` defaulted to `1`, `None` security defaulted to `Open`, and `"Unknown"` security defaulted to tier `3` (`WPA2-Personal`). | Missing scan attributes were silently treated as real RF measurements or assumed safe (`WPA2-Personal`). | Represented missing/unavailable `Signal`, `Channel`, and `Security` as `np.nan` / `None`, explicitly tracked `MissingFeatures`, and flagged unavailable security in risk scoring. |
| `src/features.py` | `extract_features`, `check_security_match` | `get_profile_security_details` was imported in `features.py` and `predict.py` but never called. `check_security_match` compared against `min(known_tiers)` and grouped `<Hidden Network>` SSIDs together in `SameSSIDCount`. | Saved profile security downgrades were missed; poisoned history rows lowered `min(known_tiers)`; multiple distinct hidden routers inflated `SameSSIDCount`. | Integrated saved Windows profile security details into baseline checks, compared against `max(known_tiers)` + cipher tier, and excluded `<Hidden Network>` from duplicate-SSID counting. |
| `src/dataset.py` | `seed_baseline_dataset` — Generates controlled training observations | 1) `rogue_enterprise_downgrade` omitted `"Signal": sig`, producing `Signal = 0` in `training_dataset.csv`. 2) Attack rows lacked concurrent legitimate APs at the same `Timestamp`, so `SameSSIDCount = 1` for all attacks. 3) 100% of attacks had `ChannelMatch = 0` and 100% of benign samples had `ChannelMatch = 1`. | Models learned an unrealistic `ChannelMatch == 0` shortcut (50.08% RF importance) and failed to learn same-channel Evil Twins or concurrent duplicate SSID patterns. | Fixed missing `Signal` in `rogue_enterprise_downgrade`, paired concurrent legitimate APs at attack timestamps, added legitimate auto-channel shift scenarios and same-channel downgrade attacks, and preserved real unlabelled rows (`Label=Unknown`). |
| `src/train.py` | `train_models` — Trains KNN and Random Forest | No `SimpleImputer` in KNN/RF pipelines (crashes on `np.nan`), small single `GroupShuffleSplit` with only 5 test attack samples yielding artificial 100% test metrics, and no overfitting check. | Missing features during inference could crash `predict()`; evaluation masked model weaknesses. | Added `SimpleImputer(strategy="median")` to both KNN and RF pipelines, used `StratifiedGroupKFold` (4-fold group CV + holdout), reported train-vs-test gap, and backed up original `*_v1_orig.pkl` models before saving retrained models. |
| `src/scanner.py` | `scan_wifi`, `parse_netsh_output` | 1) Initialized `"Signal": 0` and `"Channel": 1` before parsing. 2) Returned `[]` identically for both failed scans and empty environments. 3) Used `errors="ignore"` on UTF-8 decode, dropping non-ASCII SSID characters. 4) Only split BSSID on `:` in dual-band checks. | Failed `netsh` scans looked identical to an empty safe environment; missing fields became fake `0%`/`Ch 1`; non-UTF8 characters were silently dropped. | Added `scan_wifi_detailed()` returning `{"success", "networks", "error"}`, `parse_netsh_output()` initializing missing fields as `None`, clean encoding fallback decoding, and hyphen/colon MAC normalization. |
| `gui.py` | `_scan_worker`, `_set_active_connection_info`, `_display_network_details` | Ignored `is_portal`/`portal_msg` in `_set_active_connection_info`; treated failed scans as empty scan info dialogs; lacked risk score display and manual baseline verification option. | Captive portal warnings were invisible in the GUI pill, and failed scans showed misleading "No Networks Visible" messages. | Updated `gui.py` to surface scanner errors explicitly, display captive portal status, render the 4 classifications + Risk Score + factor breakdown, pass assessments to `update_history()`, and add an explicit "Verify & Trust Selected AP" button. |
| `src/train.py.txt` | Unused legacy draft | Duplicate older draft file left in `src/` (not imported anywhere). | Minor clutter (no runtime risk). | Left untouched in place per non-deletion safety policy and documented here. |
| `EvilTwinWiFiDetection/` | Nested duplicate repository clone | Untracked nested clone inside `EvilTwinDetection/` containing older code and 2026-10-24 scan CSVs. | Confusion over which directory is active. | Left untouched per non-deletion safety policy; all fixes applied cleanly in the root `EvilTwinDetection/` project. |

---

## B. Files Modified

1. **`src/scanner.py`**: Added `normalize_bssid()`, `infer_band_from_channel()`, `parse_netsh_output()`, and `scan_wifi_detailed()` with proper error propagation, encoding handling, and `None` representation for unavailable fields. Kept `scan_wifi()` backward-compatible.
2. **`src/system_profiles.py`**: Improved encoding handling (`_decode_bytes`), added `User Profile` matching alongside `All User Profile`, normalized BSSID hyphens to colons, and changed unavailable interface `Signal`/`Channel` defaults from `0` to `None`.
3. **`src/history.py`**: Expanded `HISTORY_COLUMNS` to 19 columns including `Fingerprint`, `Trust Status`, `Previous Classification`, `Last Signal`, `Last Channel`, `Last Security`, `OUI`, `Suspicious Indicators`, and `Changes`. Prevented baseline overwriting and automatic trust promotion; restricted `is_bssid_known()` to `(SSID, BSSID)` pairs; added `get_bssid_other_ssids()` and explicit `mark_ap_trusted()`.
4. **`src/features.py`**: Updated parsers to return `np.nan`/`None` for unavailable attributes; added `get_encryption_tier()`, `estimate_dbm_from_percent()`, `is_locally_administered_mac()`, and `extract_ap_diagnostics()`; integrated saved Windows profile security checks; excluded `<Hidden Network>` from duplicate-SSID grouping; enforced exact security-tier compatibility in `is_dual_band_pair()`.
5. **`src/dataset.py`**: Fixed missing `Signal` in `rogue_enterprise_downgrade`, added concurrent legitimate APs alongside attacks, added legitimate auto-channel shifts and same-channel Evil Twin scenarios, preserved real `Label=Unknown` scan rows in `dataset/wifi_observations.csv`, and preserved non-seeded user records in `dataset/network_history.csv`.
6. **`src/train.py`**: Wrapped both KNN and Random Forest in `SimpleImputer(strategy="median")` pipelines, preserved original v1 models (`*_v1_orig.pkl`), implemented `StratifiedGroupKFold` holdout + 4-fold group cross-validation, and added train-vs-test overfitting checks.
7. **`src/predict.py`**: Implemented the 4-state classification system (`KNOWN / CONSISTENT`, `NEW / UNVERIFIED`, `SUSPICIOUS / VERIFY`, `HIGH RISK / POSSIBLE EVIL TWIN`), added the explainable 0–100 `RISK_WEIGHTS` scoring engine without double-counting, prevented ML from overriding security/fingerprint anomalies, forced verification on ML disagreement or missing attributes, and added sibling/profile cross-checks to resist history poisoning.
8. **`main.py`**: Switched to `scan_wifi_detailed()` error handling, updated CLI output format to show Classification, Reasons, ML Results, Final Decision, Risk Score + factor breakdown, and passed `assessments=results` to `update_history()`.
9. **`gui.py`**: Updated to use `scan_wifi_detailed()`, display the 4 classifications and Risk Score breakdown, display captive portal alerts in the active connection pill, pass `assessments=results` to `update_history()`, and add a manual `"Verify & Trust Selected AP"` button.
10. **`tests/test_scenarios.py`**: Rewrote/expanded deterministic unit tests to 16 cases covering all 12 required scenarios plus `netsh` parsing, scanner failures, history corruption, missing models, and saved-profile BSSID protection.
11. **`dataset/network_history.csv`, `dataset/wifi_observations.csv`, `dataset/training_dataset.csv`, `models/knn_model.pkl`, `models/random_forest_model.pkl`**: Migrated/updated with preserved original records and newly verified models.

---

## C. Files Added

- `PROJECT_AUDIT_AND_FIXES.md` (this audit and documentation report)
- `models/knn_model_v1_orig.pkl` and `models/random_forest_model_v1_orig.pkl` (preserved copies of the original serialized models before retraining)
- `../EvilTwinDetection_backup_before_audit/` (full pre-audit backup directory outside the repo edits)

---

## D. Corrected Detection Logic

Every scanned access point is evaluated independently on every scan (even if seen 10+ times previously):

1. **Feature Extraction & Availability Check**: Parses `SSID`, `BSSID`, `OUI`, `Security`, `Encryption`, `Channel`, `Band`, and `Signal` without fabricating missing values. Tracks `MissingFeatures` explicitly.
2. **Baseline & Profile Comparison**: Compares current attributes against:
   - The AP's immutable baseline record in `network_history.csv` (`Security`, `Encryption`, `Channel`, `Signal`, `Trust Status`, prior `Suspicious Indicators`),
   - Sibling historical records sharing the same `SSID` (catching poisoned individual records),
   - Saved Windows Wi-Fi profile security settings (`netsh wlan show profile`),
   - Whether this `BSSID` previously advertised a *different* `SSID`.
3. **Multi-AP Relationship Analysis**: Distinguishes correlated dual-band routers (matching OUI, consecutive MACs `<= 4`, complementary bands, identical security tier) and consistent Enterprise multi-AP deployments from unexplained duplicate-SSID clones.
4. **Supporting ML Consensus**: Runs KNN and Random Forest on identical `FEATURE_COLUMNS` through identical preprocessing pipelines (`SimpleImputer` -> `StandardScaler` for KNN).
5. **Final Classification Rules**:
   - **`HIGH RISK / POSSIBLE EVIL TWIN`**: `RiskScore >= 60` **AND** at least 2 independent warning indicators. Never triggered by a single weak indicator.
   - **`SUSPICIOUS / VERIFY`**: `RiskScore >= 25`, OR security mismatch/downgrade, OR unfamiliar BSSID for a known SSID, OR BSSID collision/SSID-switch, OR prior `FLAGGED_SUSPICIOUS` history, OR ML model disagreement (`KNN != RF`), OR both ML models predicting Evil Twin, OR open/WEP unencrypted network.
   - **`NEW / UNVERIFIED`**: No suspicious triggers above, AND either not an explicitly verified `TRUSTED_BASELINE` (including passively observed networks with `Observation Count >= 1`!) OR missing critical attributes (`SSID`, `BSSID`, `Signal`, `Channel`, `Security`).
   - **`KNOWN / CONSISTENT — No suspicious indicators detected during this scan.`**: Triggered **only** when the AP matches an established trusted baseline with consistent `BSSID`, consistent `Security`/`Encryption`, no prior suspicious flags, complete critical features, `RiskScore < 25`, and both ML models predicting Legitimate.

---

## E. Risk Scoring System

Scores are computed on a **0–100 scale** (capped at 100) by summing **non-overlapping** dimensions so correlated attributes are not double-counted:

| Dimension | Factor | Weight | Selection Rationale |
|---|---|---|---|
| **Security** *(mutually exclusive)* | Security Mismatch / Downgrade | `+40` | Strongest single indicator of an Evil Twin or rogue downgrade (e.g., WPA2 -> Open, Enterprise -> Personal). |
| | Unencrypted / Weak Encryption (Open/WEP) | `+20` | Traffic is exposed to eavesdropping/interception; prevents `KNOWN / CONSISTENT`. |
| | Security Unavailable | `+15` | Uncertainty penalty so missing security is never treated as safe. |
| **BSSID Identity** *(mutually exclusive)* | Duplicate BSSID Collision in Same Scan | `+30` | Two APs sharing the exact same MAC concurrently indicates spoofing or misconfiguration. |
| | BSSID Previously Seen Under Different SSID | `+25` | Indicates an AP hardware identity changed its advertised network name. |
| | Unfamiliar BSSID for Known SSID | `+25` | Unexpected MAC on a familiar SSID triggers `SUSPICIOUS / VERIFY` without claiming Evil Twin alone. |
| | Unverified Dual-Band Partner | `+10` | Mild verification note for an unseen secondary radio matching OUI/band/security. |
| **SSID Multiplicity** | Concurrent Duplicate SSID (non-dual-band, non-Enterprise) | `+15` | Multiple competing APs sharing an SSID raises suspicion when unexplained by hardware/Enterprise layout. |
| **Channel / Band** | Channel Deviation from Baseline | `+15` | Channel shifts can occur legitimately (auto-channel), so weighted modestly. |
| | Channel Unavailable | `+5` | Uncertainty penalty for missing channel telemetry. |
| **Signal Strength** | Abrupt Signal Jump (`>= 30%` vs last scan) | `+10` | Supporting proximity-change clue; signal fluctuates naturally with movement, so kept low. |
| | Signal Unavailable | `+5` | Uncertainty penalty for missing signal telemetry. |
| **History Memory** | Prior Suspicious Flag in History | `+20` | Prevents previously suspicious APs from fading into trust over repeated scans. |
| **ML Evidence** *(mutually exclusive)* | Both KNN & RF Predict Evil Twin | `+20` | Supporting non-linear anomaly signal; cannot trigger High Risk alone. |
| | KNN & RF Disagree | `+15` | Forces uncertainty verification rather than defaulting to Legitimate. |

**Thresholds & Limitations**:
- `0–24`: Low / informational (`KNOWN / CONSISTENT` if established baseline & complete & ML Legitimate; otherwise `NEW / UNVERIFIED`).
- `25–59`: Moderate / uncertain (`SUSPICIOUS / VERIFY`).
- `60–100` (with `>= 2` independent warnings): `HIGH RISK / POSSIBLE EVIL TWIN`.
- **Limitation**: These weights are heuristic engineering values calibrated for clarity and false-negative prevention; they are not empirically derived probabilities from a large-scale field capture.

---

## F. ML Modifications & Controlled Dataset Evaluation

### Modifications
- **Preprocessing & Missing Values**: Wrapped both `KNeighborsClassifier(n_neighbors=5, weights="distance")` (with `StandardScaler`) and `RandomForestClassifier(n_estimators=100, max_depth=5, min_samples_split=4, class_weight="balanced", random_state=42)` in `sklearn.pipeline.make_pipeline` starting with `SimpleImputer(strategy="median")`.
- **Feature Ordering**: Strictly enforced `FEATURE_COLUMNS = ["Signal", "Channel", "Security", "SameSSIDCount", "BSSIDKnown", "ChannelMatch", "SecurityMatch"]` at both training and inference.
- **Controlled Dataset (`dataset/training_dataset.csv`)**: 206 labelled controlled samples (`173` Legitimate, `33` Evil Twin) + `20` preserved unlabelled real scan rows in `dataset/wifi_observations.csv`.

### Controlled Dataset Evaluation Results (`python -m src.train`)
*(Important: These metrics measure performance on the **controlled synthetic/experimental dataset** using `StratifiedGroupKFold` so no AP group overlaps train/test. They do NOT represent live-world accuracy across arbitrary public Wi-Fi environments.)*

- **Holdout Split**: 155 train samples (`24` Evil Twin) / 51 test samples (`9` Evil Twin)
  - **KNN (Holdout Test)**: Accuracy = **98.04%**, Precision = **90.00%**, Recall = **100.00%**, F1 = **94.74%**, FPR = **2.38%**, FNR = **0.00%**  
    Confusion Matrix: `TN=41, FP=1, FN=0, TP=9` (Train Accuracy = 100.00%)
  - **Random Forest (Holdout Test)**: Accuracy = **94.12%**, Precision = **100.00%**, Recall = **66.67%**, F1 = **80.00%**, FPR = **0.00%**, FNR = **33.33%**  
    Confusion Matrix: `TN=42, FP=0, FN=3, TP=6` (Train Accuracy = 100.00%)
- **4-Fold Group Cross-Validation (Unseen AP Groups)**:
  - **KNN**: Mean Accuracy = **99.51% (±0.85%)**, Mean Recall = **100.00%**, Mean FNR = **0.00%**
  - **Random Forest**: Mean Accuracy = **98.53% (±2.55%)**, Mean Recall = **91.67%**, Mean FNR = **8.33%**
- **Random Forest Feature Importances**: `ChannelMatch` (32.99%), `SecurityMatch` (17.50%), `BSSIDKnown` (15.40%), `SameSSIDCount` (13.52%), `Security` (10.51%), `Signal` (5.57%), `Channel` (4.51%).
- Notice why the rule engine is essential: on unseen holdout attack groups, Random Forest exhibited a 33.33% FNR (`FN=3`), confirming that ML alone cannot be trusted to prevent false negatives.

---

## G. Testing Results

Executed `python -m unittest -v tests/test_scenarios.py` after final code edits (**16/16 PASSED in 3.091s**):

| Test ID | Scenario | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| `test_01` | Known legitimate network | `KNOWN / CONSISTENT` | `KNOWN / CONSISTENT`, added to `safer` | **PASS** |
| `test_02` | New network | `NEW / UNVERIFIED` | `NEW / UNVERIFIED`, not in `safer` | **PASS** |
| `test_03` | Same SSID, new BSSID | `SUSPICIOUS / VERIFY` (not auto Evil Twin) | `SUSPICIOUS / VERIFY` | **PASS** |
| `test_04` | Same SSID, weaker security | Elevated risk + security mismatch warning | `HIGH RISK / POSSIBLE EVIL TWIN` (score >= 60, downgrade warning) | **PASS** |
| `test_05` | Repeated suspicious network (5 scans) | Never promoted to `KNOWN / CONSISTENT`; stays `FLAGGED_SUSPICIOUS` | Remained `SUSPICIOUS / VERIFY` across all 5 scans, `Trust Status = FLAGGED_SUSPICIOUS` | **PASS** |
| `test_06` | Known BSSID with altered security | Configuration anomaly warning; baseline preserved across scans | Flagged on Scan 1 & Scan 2; baseline `Security` stayed `WPA2-Personal` | **PASS** |
| `test_07` | ML model disagreement | `SUSPICIOUS / VERIFY` + verification advice | `SUSPICIOUS / VERIFY` | **PASS** |
| `test_08` | ML predicts legitimate, strong suspicious evidence exists | Rules override ML (`HIGH RISK / POSSIBLE EVIL TWIN`) | `HIGH RISK / POSSIBLE EVIL TWIN` with override explanation | **PASS** |
| `test_09` | Multiple legitimate APs with same SSID (Enterprise + Dual-Band) | Not falsely flagged as malicious | Enterprise -> `KNOWN / CONSISTENT`; New Dual-Band -> `NEW / UNVERIFIED` | **PASS** |
| `test_10` | Missing information (`None` Signal/Channel/Security) | Unverified/uncertain; no fabricated defaults | `NEW / UNVERIFIED` / `SUSPICIOUS / VERIFY`; `Unavailable` preserved | **PASS** |
| `test_11` | First scan vs second scan of unverified AP | Must remain `NEW / UNVERIFIED` on second scan | Remained `NEW / UNVERIFIED` on Scan 1 and Scan 2 | **PASS** |
| `test_12` | History poisoning (`TRUSTED_BASELINE` on rogue `Open` AP) | Still re-evaluated and flagged via current/sibling evidence | Flagged `SUSPICIOUS / VERIFY` / `HIGH RISK`, not trusted | **PASS** |
| `test_13` | `parse_netsh_output` Unicode, hyphen MACs, multi-BSSID, missing fields | Preserves Unicode & multiple BSSIDs; missing fields stay `None` | Parsed 3 APs cleanly, missing Signal/Channel remained `None` | **PASS** |
| `test_14` | Scanner failure (`wlansvc` stopped / `returncode != 0`) | `success=False` with explicit error (not empty safe list) | `success=False` with service error message | **PASS** |
| `test_15` | Corrupted/empty history CSV & missing model pickles | Graceful recovery & descriptive `FileNotFoundError` | Recovered cleanly with 19-column schema; raised `FileNotFoundError` | **PASS** |
| `test_16` | Saved Windows profile with unfamiliar BSSID & security downgrade | Must not blindly trust SSID-only saved profile | Flagged `HIGH RISK / POSSIBLE EVIL TWIN` | **PASS** |

### Live Hardware Verification Status
- **Live Windows `netsh wlan show networks mode=bssid` execution**: **NOT TESTED against physical Wi-Fi APs** in this session because this Windows host returned `The following command was not found: wlan show networks mode=bssid.` (no active WLAN interface / WLAN service available in this environment).
- **`main.py` CLI Execution**: Verified direct execution (`python main.py` reports scanner failure cleanly without pretending the environment is safe) AND verified full end-to-end report formatting with a simulated `scan_wifi_detailed()` payload.
- **`gui.py` Import & Syntax**: Verified `py_compile` and `import gui` succeed cleanly (interactive Tkinter window launch was not visually clicked through in this headless session).

---

## H. Remaining Limitations

1. **No Raw 802.11 Frame Inspection**: Windows `netsh` uses NDIS station scanning and cannot observe beacon intervals, Information Elements (IEs), deauthentication/disassociation floods, or probe responses.
2. **Same-BSSID + Same-Channel + Same-Security Spoofing**: If a sophisticated attacker clones the *exact* BSSID, SSID, channel, and security mode (e.g., WPA2-Personal PSK Evil Twin or Karma/Mana attack with identical MAC and no simultaneous legitimate beacon visible), passive `netsh` scanning alone cannot distinguish the clone from the real router.
3. **Windows Signal Percentage vs True RSSI (dBm)**: `netsh` reports 0–100% quality rather than calibrated dBm; displayed dBm values are linear approximations (`(pct / 2) - 100`).
4. **Controlled Dataset Scope**: The ML models are trained on 206 controlled/synthetic observations rather than large-scale labeled packet captures from live Evil Twin attacks.
5. **Post-Connection Risks**: Captive portals, DNS hijacking, and ARP spoofing are only checked when already connected via `src/system_profiles.py`, not prior to association.
