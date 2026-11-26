# FALSE POSITIVE AUDIT AND FIX REPORT — Evil Twin Wi-Fi Detection System

**Project Directory:** `E:\Vardhaman\3-1 sem\MINI PROJECT\EvilTwinDetection`  
**Pre-Fix Backup:** `E:\Vardhaman\3-1 sem\MINI PROJECT\EvilTwinDetection_backup_before_fp_fix`  

---

## 1. Exact Root Cause of the `SHIVA` False Positive (Verified from `database/eviltwin.db` & `dataset/network_history.csv`)

During the real scans recorded on `2026-11-26 14:09:01`, `14:09:15`, and `14:09:20` (`scan_id` 1, 2, 3 in `database/eviltwin.db`), `SHIVA` (`16:32:51:69:ea:63`, Channel `44`, Signal `100%`, Security `WPA2-Personal`, Encryption `CCMP`) was misclassified through a **two-step cascading bug**:

1. **Scan #1 (`id=1`, `2026-11-26 14:09:01` — `Risk Score: 40/100`, `SUSPICIOUS / VERIFY`):**
   - `SHIVA` existed in `dataset/network_history.csv` as `OBSERVED_UNVERIFIED` with `Security = WPA2-Personal`.
   - However, `SHIVA` was also a saved Windows Wi-Fi profile where `netsh wlan show profile name="SHIVA"` returned `Authentication : WPA3-Personal` (captured in `reasons_json`: `"SSID matches a saved Windows Wi-Fi profile ('SHIVA', configured security: WPA3-Personal)."`).
   - `get_profile_security_details()` in `src/system_profiles.py` only kept `auths[0]` (discarding secondary authentication lines on mixed profiles), and `assess_network_risk()` in `src/predict.py` treated an **unverified** saved Windows profile as an authoritative baseline.
   - Comparing `WPA3-Personal` (tier 4, from the saved profile) against `WPA2-Personal / CCMP` (tier 3, from `netsh wlan show networks`) triggered `security_match = 0.0` (`+40` points: `CRITICAL: Security mismatch/downgrade detected (observed: WPA2-Personal / CCMP)`), even though both KNN (`100.0%`) and Random Forest (`60.0%`) predicted `Legitimate`.
   - Additionally, `is_saved_profile and bssid_known == 1` falsely labeled `SHIVA` as `ESTABLISHED_BASELINE` despite `Trust Status == OBSERVED_UNVERIFIED`.

2. **Scans #2 & #3 (`id=2` & `id=4`, `2026-11-26 14:09:15` & `14:09:20` — `Risk Score: 60/100`, `HIGH RISK / POSSIBLE EVIL TWIN`):**
   - Scan #1 saved `SHIVA` in `dataset/network_history.csv` with `Trust Status = FLAGGED_SUSPICIOUS` and `Suspicious Indicators = CRITICAL: Security mismatch/downgrade...`.
   - On Scan #2 (14 seconds later, **zero new anomalies**), `assess_network_risk()` counted **both** the exact same `Security Mismatch / Downgrade` (`+40`) **and** `Prior Suspicious Flag in History` (`+20`, plus `independent_warnings += 1`).
   - Double-counting the prior alert produced `40 + 20 = 60/100` with `2` warnings, crossing `THRESHOLD_HIGH_RISK = 60` and triggering **`HIGH RISK / POSSIBLE EVIL TWIN`** on a normal home WPA2-Personal / CCMP router.

---

## 2. Files Modified

1. **`src/system_profiles.py`**: Updated `get_profile_security_details()` to preserve all `Authentication` and `Cipher` lines (`Authentications`, `Ciphers`) and represent dual `WPA2`+`WPA3` profiles as `WPA2/WPA3-Personal` rather than discarding secondary entries.
2. **`src/features.py`**:
   - Added `get_compatible_security_tiers()`, `normalize_security_label()`, and `classify_security_comparison()` to normalize formatting variants (`WPA2-Personal` vs `WPA2-Personal / CCMP` vs `WPA2PSK`), support `WPA2/WPA3` mixed/transition modes, and distinguish genuine downgrades (`DOWNGRADE_CRITICAL`) from non-critical shifts (`SHIFT_MODERATE`).
   - Updated `extract_features()` and `generate_feature_explanations()` so missing `Channel` / `Security` remain `np.nan` without fabricating mismatches or raising `ValueError` on `int(np.nan)`.
   - Broadened `is_dual_band_pair()` MAC distance from `<= 4` to `<= 16` in the last octet (still requiring identical OUI, complementary bands, and compatible security).
   - Updated `extract_ap_diagnostics()` to compare normalized security labels when logging fingerprint changes.
3. **`src/history.py`**:
   - Added explicit verification columns (`Verified`, `Verified At`, `Verified Fingerprint`) to `HISTORY_COLUMNS`.
   - Added reversible `unverify_ap()` alongside `mark_ap_trusted()` and `get_verified_records_for_ssid()`.
   - Migrated `dataset/network_history.csv` and cleared the false-positive `FLAGGED_SUSPICIOUS` artifact on `SHIVA` (`16:32:51:69:ea:63`), setting it cleanly to `OBSERVED_UNVERIFIED` / `Verified=No`.
4. **`src/predict.py`**:
   - Removed the self-amplifying `+20` `prior_suspicious_history` score penalty and removed risk-point penalties for missing `Signal`/`Channel`/`Security`.
   - Separated verified baseline security checks from unverified observed history and saved Windows profiles (saved profiles now only flag genuine `DOWNGRADE_CRITICAL`, never `WPA3` profile vs `WPA2-Personal / CCMP` beacon).
   - Separated manual verification (`TRUSTED_BASELINE`) from `is_saved_profile` so saved SSIDs are never treated as `MANUALLY_VERIFIED` baselines.
   - Added `_detect_consistent_multiap()` (covering Enterprise and same-OUI secured multi-AP deployments) and reduced uncorroborated `concurrent_duplicate_ssid` weight to `+10` so legitimate mesh/repeater/campus APs are not escalated to `UNSAFE`.
   - Integrated `IsolationForest` unsupervised anomaly detection (`load_isolation_forest()`, `+10` supporting weight when `-1`) alongside Random Forest (Primary) and KNN (Comparison), calibrated `channel_deviation=10` so normal weak-signal home routers undergoing auto-channel shifts stay `UNVERIFIED NETWORK BUT SAFE`, and adopted the 4-state verdict names (`SAFE`, `UNVERIFIED NETWORK BUT SAFE`, `UNVERIFIED NETWORK AND UNSAFE`, `UNSAFE`).
   - Added `severity` and `source` fields to every `ScoreBreakdown` entry.
5. **`app.py`, `EvilTwinDetector.pyw`, `src/db_manager.py`, `static/js/app.js`, `templates/*.html`, `main.py`, `gui.py`**: Added `POST /api/network/untrust`, reversible `Verify & Trust Baseline` / `Revoke Verification` buttons, explicit `Manual Verification` status, 4-state UI badges/charts, `Random Forest (Primary)` / `KNN (Comparison)` / `Isolation Forest (Anomaly)` reporting + SQLite columns, and standalone desktop launcher/shortcut/PyInstaller `.spec`.
6. **`tests/test_scenarios.py`**: Expanded automated test suite to 29 deterministic unit and Flask integration tests (including `test_25_isolation_forest_and_gopu_home_weak_signal_no_false_positive` and `test_web_04_unverified_network_labels_and_desktop_software_launcher`).

---

## 3. Detection Logic & Risk Scoring Changes (Before vs After)

| Aspect | Before Fix | After Fix |
|---|---|---|
| **Saved Profile Security (`WPA3` profile vs `WPA2/CCMP` scan)** | Treated as `+40` `CRITICAL: Security mismatch/downgrade`. | Treated as normal WPA2/WPA3 transition context (`0` pts); saved profiles only flag critical downgrades (`Open`/`WEP`/`WPA1` or `Enterprise -> Personal`). |
| **Prior `FLAGGED_SUSPICIOUS` in History** | Added `+20` pts + `1` extra independent warning (`40 + 20 = 60` `HIGH RISK` on Scan #2). | Adds `0` risk points. Cannot auto-promote to `SAFE`, while current scan evidence is re-evaluated cleanly on every scan. |
| **Missing `Security` / `Channel` / `Signal`** | Added `15 + 5 + 5 = +25` pts (`SUSPICIOUS / VERIFY`). | Adds `0` risk points; missing `Security` routes safely to `UNVERIFIED NETWORK AND UNSAFE`, while missing `Signal`/`Channel` alone with standard encryption stays `UNVERIFIED NETWORK BUT SAFE`. |
| **Unfamiliar BSSID on Verified SSID** | `+25` + `+15` duplicate -> `40`, easily escalated to `60` (`HIGH RISK`) by history/ML. | `+25` + `+10` duplicate = `35` (`UNVERIFIED NETWORK AND UNSAFE`, never `UNSAFE` without additional strong indicators). |
| **Manual Verification** | Mixed `is_saved_profile` with `TRUSTED_BASELINE`; irreversible in UI. | Strictly requires explicit `TRUSTED_BASELINE` (`Verified=Yes`, `Verified At`, `Verified Fingerprint`); reversible via `unverify_ap()` / `Revoke Verification`. |
| **Same-OUI Multi-AP & Dual-Band** | Only `Enterprise` exempt; dual-band MAC offset capped at `<= 4`. | Both `Enterprise` and same-OUI `>= WPA2` multi-AP deployments recognized; dual-band MAC offset `<= 16`. |

---

## 4. Security Comparison & History/Trust Corrections

- **Normalized Equivalence:** `"WPA2-Personal"`, `"WPA2-Personal / CCMP"`, `"WPA2PSK"`, and `"RSN"` normalize to `WPA2-Personal`. `"WPA2/WPA3-Personal"` matches both `WPA2-Personal` and `WPA3-Personal`.
- **Reliable Baseline Requirement:** Security downgrades are strictly evaluated against `TRUSTED_BASELINE` records first; unverified observed history and saved profiles only trigger on genuine critical downgrades (`Secured -> Open/WEP/WPA1`, `Enterprise -> Personal`, `CCMP/GCMP -> TKIP/WEP/None`).
- **Observation Count Is Not Trust:** Repeated scans increment `Observation Count` and update `Last Seen`, but never promote `OBSERVED_UNVERIFIED` or `FLAGGED_SUSPICIOUS` to `SAFE`.

---

## 5. ML Integration Notes

- Three complementary ML layers work strictly as supporting evidence alongside rules and verified fingerprints:
  - **Random Forest (Primary Supervised Classifier):** `SimpleImputer -> RandomForestClassifier` classifies APs (`Legitimate` / `Evil Twin`).
  - **KNN (Comparison Supervised Classifier):** `SimpleImputer -> StandardScaler -> KNeighborsClassifier` compares nearest neighbors as a second supervised check (`+20` when both predict Evil Twin; `+15` and `UNVERIFIED NETWORK AND UNSAFE` when RF and KNN disagree).
  - **Isolation Forest (Unsupervised Anomaly Detection):** `SimpleImputer -> StandardScaler -> IsolationForest` trained strictly on `Legitimate` (`y == 0`) APs flags unusual/unseen patterns (`-1` adds `+10` supporting risk points; cannot trigger `UNSAFE` alone).
- Neither ML agreement on `Legitimate`, ML disagreement, nor an Isolation Forest anomaly alone can produce `UNSAFE` or override validated rule-based security downgrades.
- No accuracy claims are extrapolated beyond the 206-sample controlled dataset (`src/train.py`).

---

## 6. Automated Tests & Results

Executed `python -m py_compile ...` and `python -m unittest -v tests/test_scenarios.py` after final edits: **29 / 29 PASSED**.

- **Core, False-Positive & Isolation Forest Regression Tests (`test_01`–`test_25`):**
  - Known legitimate home network (`SAFE`), `SHIVA` (`WPA2-Personal / CCMP`, Ch 44, 100%, with saved `WPA3-Personal` profile across repeated scans -> `UNVERIFIED NETWORK BUT SAFE`, `0` pts), mobile hotspot (`100%` signal -> `UNVERIFIED NETWORK BUT SAFE`, `0` pts), new network, unfamiliar BSSID on known/verified SSID (`UNVERIFIED NETWORK AND UNSAFE`, not `UNSAFE`), college Wi-Fi, mesh network, repeater, consecutive & non-consecutive dual-band routers, security text variations & mixed mode, actual security downgrade against verified baseline, missing security/channel (`0` pts, uncertainty), ML overrides, ML disagreement (`UNVERIFIED NETWORK AND UNSAFE`), suspicious AP scanned 5 times (never promoted), history poisoning, manual verification + fingerprint change detection + revocation, mislabelled suspicious AP in history re-evaluated cleanly (`UNVERIFIED NETWORK BUT SAFE`), and Isolation Forest + weak-signal home router (`GOPU HOME` at 10% signal + channel `1->6` -> `UNVERIFIED NETWORK BUT SAFE`).
- **Web App, Database & Software Launcher Tests (`test_web_01`–`test_web_04`):**
  - Empty dashboard, all Flask GET routes, full `/api/scan` -> SQLite -> network details -> alert acknowledge -> cross-restart DB persistence -> CSV/HTML report exports -> settings update -> failed scan handling -> manual trust & untrust endpoints -> new 4-state label verification & desktop launcher/icon helpers.
- **Not Tested in This Sandbox Environment:** Live hardware execution of `netsh wlan show networks mode=bssid` against physical APs (`netsh wlan` is unavailable inside this sandboxed session).

---

## 7. How to Manually Verify Your Home Wi-Fi (`SHIVA`)

1. Launch the desktop software via `Launch_Software.bat` (or `EvilTwinDetector.pyw` / `run.bat`) and open `/scanner`.
2. Click **Start Scan** and observe `SHIVA` (`16:32:51:69:ea:63`) — it will now classify as `UNVERIFIED NETWORK BUT SAFE` (`Risk Score: 0/100`) instead of `UNSAFE`.
3. Click **View Details** on `SHIVA`, verify the BSSID (`16:32:51:69:ea:63`), Channel (`44`), and Security (`WPA2-Personal / CCMP`) match your router label/admin page, then click **Verify & Trust Baseline**.
4. Re-run **Start Scan**: `SHIVA` will now show `SAFE` while continuing to monitor for genuine security downgrades or unexpected BSSIDs. You can reverse verification anytime via **Revoke Verification**.

---

## 8. Remaining Limitations & Uncertain Situations

- Windows `netsh` cannot capture raw 802.11 management frames (deauthentication floods, beacon timing anomalies, or vendor Information Elements).
- Windows reports signal quality as a `0–100%` indicator rather than calibrated hardware dBm.
- An Evil Twin that clones the exact BSSID, SSID, channel, and security mode (`WPA2-Personal / CCMP`) while suppressing the real AP cannot be distinguished passively using `netsh` alone.
- When multiple APs share an SSID with identical strong security (e.g., an added repeater vs a legitimate-looking WPA2 rogue clone), the system flags `UNVERIFIED NETWORK AND UNSAFE` for human verification because passive `netsh` telemetry alone cannot prove hardware ownership.
