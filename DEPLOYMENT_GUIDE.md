# Software Packaging & Deployment Guide — Evil Twin Wi-Fi Detection System

## 1. Standalone Windows Software (`EvilTwinDetector.exe`)

After building with PyInstaller, the complete standalone software lives inside:

- **`dist\EvilTwinDetector\EvilTwinDetector.exe`**

It bundles Python, Flask, Scikit-learn (`Random Forest` + `KNN` + `Isolation Forest`), HTML/CSS/JS assets, and initial datasets cleanly—**no Python installation required** on target Windows 10/11 laptops.

---

## 2. Deployment Options

### Option A — One-Click Install on Your Windows Laptop (Recommended)
Run **`Install_Local_Software.bat`**.
- Copies the standalone application to `%LOCALAPPDATA%\Programs\EvilTwinDetector\` (no admin rights required).
- Creates **Desktop** and **Start Menu** shortcuts named **`Evil Twin Wi-Fi Detector`**.
- Stores scan logs, SQLite history (`database\eviltwin.db`), baselines (`dataset\network_history.csv`), and reports (`Reports\`) inside the application directory.

### Option B — Portable Deployment (USB / College Demo / Another PC)
1. Use the generated portable archive **`dist\EvilTwinDetector_Portable.zip`** (or zip `dist\EvilTwinDetector\`).
2. Copy the zip to any **Windows 10 / Windows 11** laptop with a Wi-Fi adapter.
3. Extract anywhere (e.g., Desktop or `D:\Tools\EvilTwinDetector`) and double-click **`EvilTwinDetector.exe`**.

### Option C — Rebuild `.exe` After Any Code Changes
Run **`build_exe.bat`** (uses `EvilTwinDetector.spec`).

### Option D — Run Directly From Source Without `.exe`
Double-click **`Launch_Software.bat`** (runs `EvilTwinDetector.pyw` cleanly via `pythonw.exe` with no terminal window) or run **`Create_Desktop_Shortcut.bat`**.

### Option E — Automated GitHub Deployment (GitHub Actions & Releases)
- Every push to `main` triggers **`.github/workflows/build-and-release.yml`** on `windows-latest`, running all 29 tests and uploading `EvilTwinDetector-Windows-x64` (`EvilTwinDetector_Portable.zip`) under the **Actions** tab.
- Pushing a version tag (e.g. `v1.0.0`) automatically publishes a **GitHub Release** with `EvilTwinDetector_Portable.zip` attached for direct download.
- *Why not cloud web hosting (Render/GitHub Pages)?* Live passive Wi-Fi scanning relies on Windows `netsh wlan show networks mode=bssid`, which must execute locally against a physical Windows Wi-Fi adapter rather than a remote Linux container.

---

## 3. Windows Security & First-Run Notes

- **Windows Defender SmartScreen:** Because the local `.exe` is unsigned (academic project build), clicking **More info → Run anyway** once on another PC allows it to launch normally.
- **Port `5000`:** Ensure no older `run.bat` or `python app.py` terminal instance is already holding port `5000` (if one is already running, `EvilTwinDetector.exe` attaches to it safely).
- **Wi-Fi Scanning:** Uses Windows native `netsh wlan show networks mode=bssid`, requiring the laptop's Wi-Fi adapter (`WLAN AutoConfig` / `wlansvc`) to be enabled.
