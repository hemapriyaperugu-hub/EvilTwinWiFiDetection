"""
Evil Twin Wi-Fi Attack Detection System — Complete Desktop Software Launcher
=============================================================================
Runs cleanly with zero console window via pythonw.exe (or packaged .exe):
  1. Initializes local SQLite database, AP history, and 3-layer ML models
     (Random Forest + KNN + Isolation Forest).
  2. Starts the local Flask engine on http://127.0.0.1:5000 (or attaches safely
     if already running).
  3. Launches the web dashboard in Dedicated App Window mode (--app=) so it
     behaves like a standalone Windows cybersecurity desktop application.
  4. Provides a Control Center window for scanning, alerts, native GUI scanner,
     desktop shortcut creation, and clean server shutdown.
"""

import os
import shutil
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
import zlib
import tkinter as tk
from tkinter import messagebox

# Ensure project root / frozen bundle root is importable
if getattr(sys, "frozen", False):
    BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.executable)))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app
from src.paths import get_data_dir, get_resource_dir
from werkzeug.serving import make_server


APP_HOST = "127.0.0.1"
APP_PORT = 5000
APP_URL = f"http://{APP_HOST}:{APP_PORT}"


def _png_chunk(tag, data):
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def ensure_app_icon(icon_path=None):
    """Creates a crisp 64x64 Wi-Fi shield PNG-in-ICO icon using only stdlib."""
    target = icon_path or os.path.join(get_resource_dir(), "static", "app_icon.ico")
    if os.path.exists(target) and os.path.getsize(target) > 100:
        return target

    size = 64
    rows = []
    cx = (size - 1) / 2.0
    cy = 44.0

    for y in range(size):
        row = bytearray([0])  # filter byte
        for x in range(size):
            # Rounded dark-navy shield badge with cyan Wi-Fi arcs
            nx = abs(x - cx) / 29.0
            ny = (y - 6) / 52.0
            inside_shield = (
                y >= 6
                and y <= 58
                and nx <= (1.0 - 0.55 * max(0.0, (ny - 0.45) / 0.55) ** 1.35)
                and not (y < 12 and nx > 0.88)
            )
            if not inside_shield:
                row.extend((0, 0, 0, 0))
                continue

            border = nx >= (0.90 - 0.50 * max(0.0, (ny - 0.45) / 0.55) ** 1.35) or y <= 8
            dx = x - cx
            dy = y - cy
            dist = (dx * dx + dy * dy) ** 0.5
            in_cone = dy <= 3 and abs(dx) <= max(2.0, (-dy + 4.0) * 1.15)
            arc1 = in_cone and (7.5 <= dist <= 11.0)
            arc2 = in_cone and (14.5 <= dist <= 18.0)
            arc3 = in_cone and (21.5 <= dist <= 25.0)
            dot = dist <= 3.6

            if dot or arc1 or arc2 or arc3:
                row.extend((56, 189, 248, 255))   # Cyan #38bdf8
            elif border:
                row.extend((14, 165, 233, 255))   # Rim #0ea5e9
            else:
                row.extend((11, 17, 32, 255))     # Navy #0b1120
        rows.append(bytes(row))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(b"".join(rows), 9)
    png_bytes = (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
    )

    ico_header = struct.pack("<HHH", 0, 1, 1)
    ico_entry = struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32, len(png_bytes), 22)
    os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
    with open(target, "wb") as f:
        f.write(ico_header + ico_entry + png_bytes)
    return target


def bootstrap_frozen_data():
    """When running as a frozen .exe, seed writable dataset & Reports folders if missing."""
    data_dir = get_data_dir()
    res_dir = get_resource_dir()
    for sub in ("database", "dataset", "Reports", "models"):
        os.makedirs(os.path.join(data_dir, sub), exist_ok=True)

    if getattr(sys, "frozen", False):
        for rel in (
            os.path.join("dataset", "network_history.csv"),
            os.path.join("dataset", "training_dataset.csv"),
            os.path.join("models", "knn_model.pkl"),
            os.path.join("models", "random_forest_model.pkl"),
            os.path.join("models", "isolation_forest_model.pkl"),
        ):
            src_file = os.path.join(res_dir, rel)
            dst_file = os.path.join(data_dir, rel)
            if os.path.exists(src_file) and not os.path.exists(dst_file):
                shutil.copy2(src_file, dst_file)


def find_app_browser():
    """Finds Microsoft Edge or Google Chrome on Windows for frameless --app= mode."""
    candidates = [
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(os.environ.get("LocalAppData", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(os.environ.get("LocalAppData", ""), "Google", "Chrome", "Application", "chrome.exe"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def open_app_window(url=APP_URL):
    """Opens URL as a dedicated desktop app window (--app=), or falls back to default browser."""
    browser = find_app_browser()
    if browser:
        try:
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.Popen(
                [browser, f"--app={url}", "--window-size=1320,840"],
                creationflags=creation_flags,
            )
            return "app"
        except Exception:
            pass
    webbrowser.open(url)
    return "browser"


def is_server_alive(url=f"{APP_URL}/api/dashboard", timeout=1.2):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def create_windows_desktop_shortcut(create_start_menu=False):
    """Creates a clean Windows Desktop shortcut (.lnk) using Shell SpecialFolders (handles OneDrive Desktop)."""
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    desk_res = subprocess.run(
        ["powershell", "-NoProfile", "-Command", "[Environment]::GetFolderPath('Desktop')"],
        capture_output=True,
        text=True,
        creationflags=creation_flags,
        timeout=10,
    )
    desktop = desk_res.stdout.strip() if desk_res.returncode == 0 and desk_res.stdout.strip() else os.path.join(os.path.expanduser("~"), "Desktop")
    if not os.path.isdir(desktop):
        desktop = os.environ.get("USERPROFILE", os.path.expanduser("~"))

    data_dir = get_data_dir()
    icon_path = ensure_app_icon()
    built_exe = os.path.join(data_dir, "dist", "EvilTwinDetector", "EvilTwinDetector.exe")

    if getattr(sys, "frozen", False):
        target_path = sys.executable
        arguments = ""
        work_dir = os.path.dirname(sys.executable)
    elif os.path.isfile(built_exe):
        target_path = built_exe
        arguments = ""
        work_dir = os.path.dirname(built_exe)
    else:
        py_dir = os.path.dirname(sys.executable)
        pythonw = os.path.join(py_dir, "pythonw.exe")
        target_path = pythonw if os.path.exists(pythonw) else sys.executable
        script_path = os.path.abspath(__file__)
        arguments = f'"{script_path}"'
        work_dir = data_dir

    shortcuts = [os.path.join(desktop, "Evil Twin Wi-Fi Detector.lnk")]
    if create_start_menu:
        start_menu = os.path.join(
            os.environ.get("APPDATA", ""),
            "Microsoft", "Windows", "Start Menu", "Programs"
        )
        if os.path.isdir(start_menu):
            shortcuts.append(os.path.join(start_menu, "Evil Twin Wi-Fi Detector.lnk"))

    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    for sc_path in shortcuts:
        ps_script = (
            '$ws = New-Object -ComObject WScript.Shell; '
            f'$sc = $ws.CreateShortcut("{sc_path}"); '
            f'$sc.TargetPath = "{target_path}"; '
            f'$sc.Arguments = \'{arguments}\'; '
            f'$sc.WorkingDirectory = "{work_dir}"; '
            f'$sc.IconLocation = "{icon_path},0"; '
            '$sc.Description = "Evil Twin Wi-Fi Attack Detection System"; '
            '$sc.Save()'
        )
        res = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            creationflags=creation_flags,
            timeout=15,
        )
        if res.returncode != 0:
            raise RuntimeError(res.stderr.strip() or f"Failed to create shortcut: {sc_path}")
    return shortcuts[0]


class EvilTwinSoftwareShell(tk.Tk):
    """Dark cybersecurity desktop control center wrapping the local Evil Twin engine."""

    def __init__(self, owns_server=False, server=None):
        super().__init__()
        self.owns_server = owns_server
        self.server = server

        self.title("Evil Twin Wi-Fi Attack Detection Software")
        self.geometry("620x520")
        self.resizable(False, False)
        self.configure(bg="#0b1120")

        try:
            ico = ensure_app_icon()
            if os.path.exists(ico):
                self.iconbitmap(ico)
        except Exception:
            pass

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_exit)

    def _build_ui(self):
        header = tk.Frame(self, bg="#111a2e", padx=20, pady=16)
        header.pack(fill="x")

        tk.Label(
            header,
            text="Evil Twin Wi-Fi Attack Detection Software",
            bg="#111a2e",
            fg="#f8fafc",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w")
        tk.Label(
            header,
            text="Random Forest (Primary) + KNN (Comparison) + Isolation Forest (Anomaly)",
            bg="#111a2e",
            fg="#38bdf8",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(3, 0))

        body = tk.Frame(self, bg="#0b1120", padx=20, pady=14)
        body.pack(fill="both", expand=True)

        status_card = tk.Frame(body, bg="#162238", highlightbackground="#263248", highlightthickness=1, padx=14, pady=12)
        status_card.pack(fill="x", pady=(0, 14))

        mode_txt = "Active (Managed Local Engine)" if self.owns_server else "Active (Attached to Existing Local Engine)"
        for key, val, color in (
            ("Engine Status:", mode_txt, "#10b981"),
            ("Dashboard Address:", APP_URL, "#f1f5f9"),
            ("Classification Modes:", "SAFE | UNVERIFIED NETWORK BUT SAFE | UNVERIFIED NETWORK AND UNSAFE | UNSAFE", "#94a3b8"),
            ("Data Folder:", get_data_dir(), "#94a3b8"),
        ):
            row = tk.Frame(status_card, bg="#162238")
            row.pack(fill="x", pady=2)
            tk.Label(row, text=key, width=19, anchor="w", bg="#162238", fg="#94a3b8", font=("Segoe UI", 9, "bold")).pack(side="left")
            tk.Label(row, text=val, anchor="w", bg="#162238", fg=color, font=("Segoe UI", 9)).pack(side="left", fill="x")

        btn_opts = {
            "font": ("Segoe UI", 10, "bold"),
            "relief": "flat",
            "cursor": "hand2",
            "pady": 8,
            "padx": 14,
        }

        tk.Button(
            body,
            text="Open Cybersecurity Dashboard (App Window)",
            bg="#0284c7",
            fg="#ffffff",
            activebackground="#0369a1",
            activeforeground="#ffffff",
            command=lambda: open_app_window(APP_URL),
            **btn_opts,
        ).pack(fill="x", pady=(0, 8))

        grid_row1 = tk.Frame(body, bg="#0b1120")
        grid_row1.pack(fill="x", pady=(0, 8))

        tk.Button(
            grid_row1,
            text="Open Live Wi-Fi Scanner",
            bg="#0f766e",
            fg="#ffffff",
            activebackground="#115e59",
            activeforeground="#ffffff",
            command=lambda: open_app_window(f"{APP_URL}/scanner"),
            **btn_opts,
        ).pack(side="left", fill="x", expand=True, padx=(0, 5))

        tk.Button(
            grid_row1,
            text="View Threat Alerts",
            bg="#1e293b",
            fg="#f1f5f9",
            activebackground="#334155",
            activeforeground="#ffffff",
            command=lambda: open_app_window(f"{APP_URL}/alerts"),
            **btn_opts,
        ).pack(side="right", fill="x", expand=True, padx=(5, 0))

        grid_row2 = tk.Frame(body, bg="#0b1120")
        grid_row2.pack(fill="x", pady=(0, 8))

        tk.Button(
            grid_row2,
            text="Native Desktop Scanner (Tkinter)",
            bg="#1e293b",
            fg="#f1f5f9",
            activebackground="#334155",
            activeforeground="#ffffff",
            command=self._launch_native_gui,
            **btn_opts,
        ).pack(side="left", fill="x", expand=True, padx=(0, 5))

        tk.Button(
            grid_row2,
            text="Open Reports Folder",
            bg="#1e293b",
            fg="#f1f5f9",
            activebackground="#334155",
            activeforeground="#ffffff",
            command=self._open_reports_folder,
            **btn_opts,
        ).pack(side="right", fill="x", expand=True, padx=(5, 0))

        tk.Button(
            body,
            text="Create Desktop Shortcut (One-Click Launch)",
            bg="#1e293b",
            fg="#38bdf8",
            activebackground="#334155",
            activeforeground="#38bdf8",
            command=self._create_shortcut,
            **btn_opts,
        ).pack(fill="x", pady=(0, 12))

        tk.Button(
            body,
            text="Stop Engine & Exit Software" if self.owns_server else "Close Control Center",
            bg="#991b1b",
            fg="#ffffff",
            activebackground="#7f1d1d",
            activeforeground="#ffffff",
            command=self._on_exit,
            **btn_opts,
        ).pack(fill="x")

        self.status_lbl = tk.Label(
            self,
            text="Ready. All local scans run passively via Windows netsh without capturing passwords.",
            bg="#080d1a",
            fg="#64748b",
            font=("Segoe UI", 8),
            anchor="w",
            padx=16,
            pady=6,
        )
        self.status_lbl.pack(fill="x", side="bottom")

    def _launch_native_gui(self):
        try:
            if getattr(sys, "frozen", False):
                subprocess.Popen([sys.executable, "--gui"], cwd=get_data_dir())
            else:
                gui_script = os.path.join(BASE_DIR, "gui.py")
                py_dir = os.path.dirname(sys.executable)
                py_gui = os.path.join(py_dir, "pythonw.exe")
                exe = py_gui if os.path.exists(py_gui) else sys.executable
                subprocess.Popen([exe, gui_script], cwd=get_data_dir())
            self.status_lbl.config(text="Launched native Tkinter Wi-Fi scanner window.")
        except Exception as exc:
            messagebox.showerror("Launch Error", f"Could not open Tkinter GUI:\n{exc}")

    def _open_reports_folder(self):
        reports_dir = os.path.join(get_data_dir(), "Reports")
        os.makedirs(reports_dir, exist_ok=True)
        try:
            os.startfile(reports_dir)
        except Exception as exc:
            messagebox.showinfo("Reports Folder", f"Reports folder path:\n{reports_dir}\n\n({exc})")

    def _create_shortcut(self):
        try:
            lnk = create_windows_desktop_shortcut()
            self.status_lbl.config(text=f"Desktop shortcut created: {lnk}")
            messagebox.showinfo("Shortcut Created", f"Desktop shortcut created:\n{lnk}")
        except Exception as exc:
            messagebox.showerror("Shortcut Error", str(exc))

    def _on_exit(self):
        if self.owns_server and self.server is not None:
            if not messagebox.askyesno(
                "Stop & Exit",
                "Stop the local Evil Twin Detection server and exit the software?"
            ):
                return
            try:
                self.server.shutdown()
            except Exception:
                pass
        self.destroy()


def launch_desktop_software():
    ensure_app_icon()
    bootstrap_frozen_data()

    owns_server = False
    server = None
    if not is_server_alive():
        flask_app = create_app()
        server = make_server(APP_HOST, APP_PORT, flask_app, threaded=True)
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()
        owns_server = True

        # Wait briefly until HTTP socket answers
        for _ in range(25):
            if is_server_alive(timeout=0.5):
                break
            time.sleep(0.15)

    # Launch dedicated frameless desktop web-app window automatically on startup
    open_app_window(APP_URL)

    shell = EvilTwinSoftwareShell(owns_server=owns_server, server=server)
    shell.mainloop()


def verify_software_bundle():
    """Headless self-check for frozen/standalone software validation."""
    ensure_app_icon()
    bootstrap_frozen_data()
    flask_app = create_app()
    client = flask_app.test_client()
    for route in ("/", "/scanner", "/alerts", "/history", "/reports", "/settings"):
        resp = client.get(route)
        if resp.status_code != 200:
            raise RuntimeError(f"Route {route} returned HTTP {resp.status_code}")
    from src.predict import load_isolation_forest, load_models
    load_models()
    if load_isolation_forest() is None:
        raise RuntimeError("Isolation Forest model missing")
    print("BUNDLE_OK")


if __name__ == "__main__":
    if "--verify-bundle" in sys.argv[1:]:
        verify_software_bundle()
    elif "--gui" in sys.argv[1:]:
        bootstrap_frozen_data()
        from gui import EvilTwinGUI
        EvilTwinGUI().mainloop()
    else:
        launch_desktop_software()
