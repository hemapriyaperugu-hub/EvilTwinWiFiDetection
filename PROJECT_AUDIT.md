# PROJECT AUDIT — Evil Twin Wi-Fi Attack Detection System

**Audit Scope:** Full inspection of `E:\Vardhaman\3-1 sem\MINI PROJECT\EvilTwinDetection` prior to web application integration and final detection enhancements.  
**Backups Preserved:**
- Original pre-audit snapshot: `../EvilTwinDetection_backup_before_audit`
- Pre-web integration snapshot: `../EvilTwinDetection_backup_pre_web`
- Original serialized models: `models/knn_model_v1_orig.pkl`, `models/random_forest_model_v1_orig.pkl`

---

## 1. Existing Architecture

The project is organized around a modular `src/` package plus two local entry points:
- `src/scanner.py`: Invokes Windows `netsh wlan show networks mode=bssid`, parses SSID/BSSID/Signal/Channel/Security/Encryption/Band/Radio, and logs raw observations to `dataset/wifi_observations.csv`.
- `src/system_profiles.py`: Queries Windows saved profiles (`netsh wlan show profiles`), active interface (`netsh wlan show interfaces`), gateway ARP MAC (`ipconfig /all` + `arp -a`), and captive portal checks.
- `src/history.py`: Manages persistent AP baseline history (`dataset/network_history.csv`) with explicit trust states (`TRUSTED_BASELINE`, `OBSERVED_UNVERIFIED`, `FLAGGED_SUSPICIOUS`), immutable baseline fields, and change tracking.
- `src/features.py`: Extracts the 7 ML features (`Signal`, `Channel`, `Security`, `SameSSIDCount`, `BSSIDKnown`, `ChannelMatch`, `SecurityMatch`) and 18 diagnostic attributes, plus dual-band router correlation (`is_dual_band_pair`).
- `src/dataset.py` & `src/train.py`: Generates controlled labelled scenarios (`dataset/training_dataset.csv`), preserves unlabelled real observations, and trains `KNeighborsClassifier` and `RandomForestClassifier` pipelines using `SimpleImputer(strategy="median")` and `StratifiedGroupKFold`.
- `src/predict.py`: Loads serialized models and executes `assess_network_risk()` combining rules, fingerprint comparison, saved Windows profile validation, heuristic risk scoring (`0–100`), and supporting ML consensus.
- `main.py` & `gui.py`: CLI and Tkinter desktop entry points.
- `tests/test_scenarios.py`: 16 deterministic unit tests covering detection, history poisoning, ML overrides, scanner parsing, and failure handling.

---

## 2. Existing Features & Working Components

- Native Windows `netsh` scanning with explicit error reporting (`scan_wifi_detailed`).
- Missing-value preservation (`None` / `np.nan` / `"Unavailable"`) without fabricating fake `Channel=1` or `Signal=0` values.
- 4-state classification (`KNOWN / CONSISTENT`, `NEW / UNVERIFIED`, `SUSPICIOUS / VERIFY`, `HIGH RISK / POSSIBLE EVIL TWIN`).
- Non-double-counting `0–100` heuristic risk score with per-factor explanations.
- Protection against automatic trust promotion on repeated scans and against history poisoning.
- Dual-band router correlation and Enterprise multi-AP handling.
- Leakage-free ML training (`StratifiedGroupKFold`) with preserved original models.

---

## 3. Identified Gaps & Remaining Improvements Needed for Web Software Delivery

### A. Architecture & User Interface Gaps
- **No Web Application / Browser Interface**: Currently only CLI (`main.py`) and desktop Tkinter (`gui.py`) exist. There is no Flask backend, dark cybersecurity monitoring dashboard, or browser-accessible workflow (`http://127.0.0.1:5000`).
- **No Scan Session History & Alert Persistence**: `network_history.csv` only stores per-AP summary rows; it does not store individual timestamped scan sessions, per-scan network snapshots, alert records, or user-configurable settings.
- **No Report Export**: There is no built-in CSV or printable HTML report export for actual scan sessions.
- **No `run.bat` Startup Script**: Users must invoke Python commands manually.

### B. Detection, ML & Output Refinement Gaps
- **ML Probability / Confidence Display**: `src/predict.py` currently calls `model.predict()` but does not extract `predict_proba()` confidence values when supported by `KNN` and `Random Forest`.
- **Configurable Risk Thresholds**: `THRESHOLD_SUSPICIOUS` (`25`) and `THRESHOLD_HIGH_RISK` (`60`) in `src/predict.py` are hardcoded constants rather than accepting configurable settings from the Settings page (`settings` table in SQLite).
- **Signal Percentage vs Estimated dBm Clarity**: `SignalDisplay` shows `(approx. -XX dBm)`. To strictly honor honest Windows `netsh` reporting, signal quality should be displayed primarily as Windows `%` and any dBm conversion must never be presented as hardware-measured dBm.

### C. Previously Audited & Fixed Weaknesses (Retained for Traceability)
- **False-Negative Risks (Fixed)**: Previously auto-trusted any `bssid_known == 1` AP, blindly trusted SSID-only saved Windows profiles, overwrote baseline security/channels in history, and allowed `ChannelMatch=0` training bias.
- **False-Positive Risks (Fixed)**: Previously grouped `<Hidden Network>` APs as duplicate SSIDs and treated missing security as `Open`.
- **ML & Dataset Limitations**: Training data consists of 206 controlled/synthetic observations (plus 20 unlabelled real scan rows); RF showed 33.33% FNR on an unseen holdout attack group, confirming ML must remain supporting evidence only.
- **Windows Scanning Limitations**: `netsh` cannot capture raw 802.11 management frames (deauth floods, beacon timing, vendor IEs), and reports signal quality as percentage rather than calibrated dBm.

---

## 4. Recommended Changes (Execution Plan)

1. Expose real `predict_proba()` confidence values (only when `hasattr(model, "predict_proba")`) and configurable risk thresholds in `src/predict.py`, and clarify Windows signal percentage display.
2. Implement `src/db_manager.py` using SQLite (`database/eviltwin.db`) to persistently store scan sessions, per-scan AP observations, threat alerts, AP baseline history (synced with `src/history.py`), and application settings—without duplicating detection or scanner logic.
3. Build `app.py` (Flask) and 7 dark cybersecurity UI pages (`Dashboard`, `Wi-Fi Scanner`, `Network Details`, `Alerts`, `Scan History`, `Reports`, `Settings`) using local HTML5/CSS3/vanilla JS (including offline Canvas charts—no CDN/internet requirement).
4. Add CSV and printable HTML report generation stored/served cleanly from `Reports/` and downloadable via browser.
5. Add `run.bat`, `DETECTION_LOGIC.md`, updated `README.md`, and comprehensive web + database + detection + scanner tests in `tests/`.
