# Evil Twin Wi-Fi Attack Detection System

A local, defensive Windows cybersecurity web application (with CLI and Tkinter GUI support) that inspects nearby Wi-Fi access points using Windows `netsh` scanning, persistent AP fingerprint history, rule-based risk scoring, and three-layer machine learning analysis (**Random Forest** primary + **KNN** comparison + **Isolation Forest** anomaly detection).

---

## Objectives

- Scan nearby Wi-Fi networks passively using the built-in Windows Wi-Fi adapter (without connecting or collecting passwords).
- Detect potential Evil Twin and rogue AP indicators by combining historical fingerprint comparison, security downgrade checks, BSSID/OUI analysis, and ML predictions.
- Prevent false negatives caused by blindly trusting repeatedly scanned or unverified networks.
- Present clear, explainable classifications, risk scores, threat alerts, scan history, and exportable reports via a local Flask web dashboard (`http://127.0.0.1:5000`).

---

## Technology Stack

- **Backend:** Python, Flask
- **Frontend:** HTML5, CSS3, Vanilla JavaScript (dark cybersecurity UI + offline Canvas charts)
- **Machine Learning:** Scikit-learn (`RandomForestClassifier` with `SimpleImputer`, `KNeighborsClassifier` with `StandardScaler` + `SimpleImputer`, `IsolationForest` unsupervised anomaly detector trained on legitimate APs), `joblib`, `pandas`, `numpy`
- **Storage:** SQLite (`database/eviltwin.db`) for scan sessions, per-AP snapshots, alerts, and settings; CSV (`dataset/network_history.csv`, `dataset/wifi_observations.csv`, `dataset/training_dataset.csv`) for AP baselines and ML data
- **Wi-Fi Scanner:** Native Windows `netsh wlan show networks mode=bssid`, `netsh wlan show interfaces`, `netsh wlan show profiles`

---

## Folder Structure

```text
EvilTwinDetection/
├── app.py                     # Flask web application & API routes
├── main.py                    # Terminal / CLI scanner & report
├── gui.py                     # Optional Tkinter desktop GUI
├── run.bat                    # Windows one-click startup script
├── requirements.txt           # Python dependencies
├── PROJECT_AUDIT.md           # Initial project audit & architecture review
├── PROJECT_AUDIT_AND_FIXES.md # Detailed audit log & fix verification
├── DETECTION_LOGIC.md         # Detection rules, scoring, and anti-poisoning history
├── README.md                  # Project documentation
├── src/
│   ├── scanner.py             # Windows netsh WLAN scanning & parser
│   ├── system_profiles.py     # Saved Windows profiles, gateway & captive portal probe
│   ├── features.py            # Feature extraction, dual-band & OUI diagnostics
│   ├── history.py             # Persistent AP fingerprint & trust-state engine
│   ├── predict.py             # Risk scoring engine, 4-state classifier & ML inference
│   ├── db_manager.py          # SQLite persistence (scans, scan_results, alerts, settings)
│   ├── dataset.py             # Controlled training dataset builder
│   └── train.py               # Leakage-free Group CV training & evaluation
├── templates/                 # Flask Jinja2 templates (7 pages + printable report)
├── static/                    # Dark theme CSS & offline JS charts/interactions
├── dataset/                   # CSV baselines, observations, and training dataset
├── models/                    # Serialized RF, KNN & Isolation Forest models (+ v1 backups)
├── database/                  # SQLite database (eviltwin.db created on run)
├── Reports/                   # Generated CSV and printable HTML reports
└── tests/
    └── test_scenarios.py      # Automated scanner, detection, DB & Flask web tests
```

---

## Quick Launch as Standalone Desktop Software (Windows 11 / 10)

### 1. Double-Click Desktop App Mode
Double-click **[`Launch_Software.bat`](Launch_Software.bat)** (or [`EvilTwinDetector.pyw`](EvilTwinDetector.pyw)) to launch with **zero terminal window**:
- Starts the local Flask + SQLite + 3-model ML engine (`Random Forest + KNN + Isolation Forest`)
- Opens the cybersecurity dashboard in **Dedicated App Window Mode** (`msedge --app=` / `chrome --app=`)
- Displays the **Software Control Center** with one-click Dashboard, Scanner, Alerts, Native Tkinter GUI, Reports, and **Create Desktop Shortcut** (`Create_Desktop_Shortcut.bat`).

### 2. Build Standalone `.exe` (Optional)
Run `build_exe.bat` (requires `pyinstaller`) to generate `dist\EvilTwinDetector\EvilTwinDetector.exe`.

### 3. Browser-Only Launch (`run.bat`)
Double-click `run.bat` to open `http://127.0.0.1:5000` in your default browser.

### Manual Setup & Run
```powershell
pip install -r requirements.txt
python app.py
```
Then open `http://127.0.0.1:5000` in your browser.

### Optional CLI / Desktop GUI / Model Retraining
```powershell
python main.py               # CLI scan & report
python gui.py                # Desktop Tkinter GUI
python -m src.dataset        # Rebuild controlled training dataset
python -m src.train          # Train & evaluate RF + KNN + Isolation Forest
```

---

## Web Application Pages

1. **Dashboard (`/`)**: Real statistics from stored scans, classification & risk distributions, scan timeline, recent scans, recent alerts, and suspicious AP summary.
2. **Wi-Fi Scanner (`/scanner`)**: Triggers live Windows `netsh` scan via `POST /api/scan`, shows loading status/errors, and displays searchable/sortable AP results.
3. **Network Details (`/network/<id>`)**: Full AP info, current vs baseline fingerprint comparison, changed attributes, Random Forest (Primary), KNN (Comparison), and Isolation Forest (Anomaly Detection) predictions + scores, risk score breakdown, and manual `Verify & Trust Baseline` confirmation.
4. **Threat Alerts (`/alerts`)**: Severity-filtered alerts generated from actual `UNVERIFIED NETWORK AND UNSAFE` and `UNSAFE` detections with acknowledge/reopen controls.
5. **Scan & AP History (`/history`)**: Past timestamped scan sessions (clickable to inspect captured APs) and persistent AP fingerprints from `dataset/network_history.csv`.
6. **Reports (`/reports`)**: Export any stored scan to CSV or printable HTML/PDF (saved to `Reports/`).
7. **Settings (`/settings`)**: Configure scan timeout, suspicious/high-risk score thresholds, CSV logging, captive portal probe, and clear unverified history or stored scan sessions.

---

## Classification System & Risk Scoring

- **SAFE**: Matches an explicitly verified `TRUSTED_BASELINE`, consistent BSSID & security, complete critical features, `RiskScore < 25`, and both supervised ML models (`RF` & `KNN`) predict `Legitimate`. *(Does not guarantee absolute safety.)*
- **UNVERIFIED NETWORK BUT SAFE**: Not registered/verified yet (`OBSERVED_UNVERIFIED`) without warning triggers, or missing non-security attributes (`Signal`, `Channel`) with standard encryption. Repeated passive scans never auto-promote to `SAFE`.
- **UNVERIFIED NETWORK AND UNSAFE**: `RiskScore >= 25`, security mismatch/downgrade, unfamiliar BSSID on a known SSID, duplicate BSSID collision, open/WEP network, unavailable security attribute, or supervised ML disagreement/attack consensus.
- **UNSAFE**: `RiskScore >= 60` **and** at least 2 independent warning indicators.

See [DETECTION_LOGIC.md](DETECTION_LOGIC.md) for full weights, thresholds, and anti-poisoning guarantees.

---

## Testing

```powershell
python -m unittest -v tests/test_scenarios.py
```

---

## Honest Limitations

- Windows `netsh` operates via NDIS station scanning and **cannot** capture raw 802.11 management frames (deauthentication floods, beacon interval anomalies, probe requests, or vendor Information Elements).
- Windows reports signal quality as a **percentage (`0–100%`)**, not hardware-measured dBm.
- A sophisticated Evil Twin that clones the exact BSSID, SSID, channel, and encryption mode while suppressing or replacing the legitimate AP may not be distinguishable using passive `netsh` scanning alone.
- ML models are trained on a controlled dataset (`206` labelled samples) and serve strictly as supporting evidence alongside rule-based and fingerprint checks.
