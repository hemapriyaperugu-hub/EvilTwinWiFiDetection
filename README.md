# Wi-Fi Evil Twin & Rogue AP Detection System

An evidence-based, client-side Wi-Fi Evil Twin and Rogue Access Point detection system for Windows. Built with Python, combining machine learning consensus (K-Nearest Neighbors + Random Forest), physical RF telemetry, cryptographic validation, and operating system network baselines.

---

## 🌟 Key Highlights

- **Evidence-Based Risk Assessment**: Distinguishes between unfamiliar networks and genuine attacks using 3 user-facing risk categories:
  - 🟢 **LOWER RISK — NO SIGNIFICANT WARNING INDICATORS DETECTED**
  - 🟡 **UNCERTAIN — VERIFY BEFORE CONNECTING**
  - 🔴 **HIGH RISK — DO NOT CONNECT**
- **Dual-Model ML Consensus**: Uses both K-Nearest Neighbors (KNN) and Random Forest (RF) trained on realistic Wi-Fi RF telemetry (signal, channel, multi-AP relationships, cryptographic suites).
- **Dual-Band AP Correlation**: Recognizes modern 2.4 GHz + 5 GHz dual-band routers (consecutive MAC addresses with matching hardware OUIs), preventing false positives on home and mesh routers.
- **Windows Profile Integration**: Queries local Windows Wi-Fi profiles (`netsh`) to establish user-verified trust baselines.
- **Active Gateway & Captive Portal Probing**: Validates default gateway ARP/MAC alignment and performs HTTP 204 connectivity probes to detect MITM/captive portal interception.
- **Minimal & Zero GUI Dependencies**: Built using standard library `tkinter` and `ttk`. No heavy UI frameworks required—clones and runs instantly on any standard Python installation.

---

## 📸 Interface Preview

The application features a sleek split-panel layout:
- **Left Panel**: Discovered Wi-Fi access points with SSID, BSSID, Signal, Channel, Security Suite, and Real-Time Classification.
- **Right Panel**: Deep analysis breakdown including prominent status banner, RF characteristics, dual-ML outputs, historical baseline, observed evidence bullet points, and actionable connection advice.

---

## 📁 Project Structure

```text
EvilTwinDetection/
├── dataset/
│   ├── training_dataset.csv     # Model training dataset
│   ├── network_history.csv      # Local AP observation baseline
│   └── wifi_observations.csv    # Raw scan telemetry
├── models/
│   ├── knn_model.pkl            # Trained K-Nearest Neighbors model
│   └── random_forest_model.pkl  # Trained Random Forest model
├── src/
│   ├── dataset.py               # Dataset generation and synthesis
│   ├── features.py              # RF feature extraction & dual-band analysis
│   ├── history.py               # Multi-channel tracking & trust state engine
│   ├── predict.py               # Evidence-based risk assessment & ML inference
│   ├── scanner.py               # Native Windows WLAN scanning via netsh
│   ├── system_profiles.py       # Windows profile query & gateway diagnostics
│   └── train.py                 # Leakage-free GroupShuffleSplit ML training
├── tests/
│   └── test_scenarios.py        # 15 research-grade validation unit tests
├── gui.py                       # Graphical User Interface (Tkinter)
├── main.py                      # Terminal / CLI Scanner
├── requirements.txt             # Minimal dependencies
└── README.md                    # Project documentation
```

---

## 🚀 Getting Started

### 1. Prerequisites
- **Operating System**: Windows 10 or Windows 11 (requires built-in Wi-Fi adapter).
- **Python Version**: Python 3.8 to 3.14+
- **Wi-Fi**: Ensure Wi-Fi is turned ON in Windows Settings.

### 2. Clone the Repository
```bash
git clone https://github.com/hemapriyaperugu-hub/EvilTwinWiFiDetection.git
cd EvilTwinWiFiDetection
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

*(Note: The GUI uses Python's standard `tkinter` library, so no extra GUI packages like PyQt or PySide are required.)*

---

## 💻 How to Run

### Graphical User Interface (GUI)
Launch the modern minimal interface:
```bash
python gui.py
```
Click **"🔍 SCAN WI-FI"** to initiate a scan of all nearby access points. Selecting any network in the left table immediately displays its comprehensive risk breakdown on the right.

### Terminal / CLI Mode
Run in standard console mode:
```bash
python main.py
```

### Run Unit & Research Validation Tests
Execute the automated test suite covering all 15 operational scenarios (dual-band APs, saved profile trust, missing attributes, model disagreements, evil twin attacks, and captive portal probes):
```bash
python -m unittest -v tests/test_scenarios.py
```

### Retrain Machine Learning Models
```bash
python -m src.train
```

---

## 🔬 Detection Methodology

| Pillar | Detection Factor | Evaluation Purpose |
|---|---|---|
| **Cryptographic Suite** | WPA2/WPA3 (CCMP) vs Open/WEP | Detects security downgrades from familiar baselines. |
| **Physical RF Telemetry** | Channel, Band, Signal | Detects channel hops and anomalous proximity spikes. |
| **MAC & OUI Correlation** | Vendor OUI & Sub-allocations | Distinguishes legitimate dual-band hardware from rogue clones. |
| **Machine Learning** | KNN & Random Forest Consensus | Flags non-linear anomalies in multi-access-point environments. |
| **Host Network Health** | Default Gateway MAC & HTTP 204 | Detects post-connection ARP spoofing and captive portal redirection. |

---

## 📜 Academic Disclaimer
This project was developed for academic, educational, and defense-oriented research purposes. Passive client-side scanning provides risk-informed assessments but cannot offer an absolute mathematical guarantee of network safety. Always exercise caution when connecting to public wireless networks.
