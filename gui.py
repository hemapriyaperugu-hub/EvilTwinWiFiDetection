"""
Wi-Fi Evil Twin Detection System - Graphical User Interface (GUI)
==================================================================
Dual-ML Classification (KNN + Random Forest) with Local Baseline
& Multi-Dimensional Evidence-Based Risk Assessment.

Built with Python standard library Tkinter + ttk (zero external GUI bloat).
Fully compatible with Windows Wi-Fi scanning via native netsh.
"""

import os
import sys
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.scanner import scan_wifi, save_observations_to_csv
from src.history import load_history, update_history, get_ap_record
from src.predict import (
    load_models,
    analyze_scanned_networks,
    RISK_LOWER,
    RISK_UNCERTAIN,
    RISK_HIGH,
    STATUS_LEGITIMATE,
    STATUS_NEW,
    STATUS_SUSPICIOUS,
    STATUS_EVIL_TWIN
)
from src.system_profiles import (
    get_active_wifi_interface,
    get_default_gateway_and_ip,
    check_captive_portal
)
from src.dataset import seed_baseline_dataset, build_training_dataset
from src.train import train_models


# =====================================================================
# THEME & COLOR PALETTE (Clean, Modern Slate & Navy)
# =====================================================================

CLR_HEADER_BG = "#0B132B"       # Deep Slate Navy
CLR_HEADER_FG = "#FFFFFF"       # Crisp White
CLR_SUBTITLE  = "#94A3B8"       # Muted Slate Blue
CLR_APP_BG    = "#F1F5F9"       # Soft Light Gray / Slate 100
CLR_CARD_BG   = "#FFFFFF"       # Pure White Cards
CLR_BORDER    = "#CBD5E1"       # Subtle Slate Border
CLR_TEXT_MAIN = "#0F172A"       # Slate 900
CLR_TEXT_MUTED= "#475569"       # Slate 600

# Action & Status Accents
CLR_BTN_PRIMARY  = "#1D68BD"    # Deep Blue
CLR_BTN_HOVER    = "#18549A"
CLR_TAG_SAFE     = "#16A34A"    # Vibrant Green
CLR_TAG_EVIL     = "#DC2626"    # Danger Red
CLR_TAG_SUSP     = "#D97706"    # Amber
CLR_TAG_NEW      = "#2563EB"    # Slate / Blue

# Banner Colors
CLR_BANNER_SAFE  = "#15803D"
CLR_BANNER_EVIL  = "#B91C1C"
CLR_BANNER_SUSP  = "#D97706"
CLR_BANNER_NEW   = "#1D4ED8"


# =====================================================================
# MAIN APPLICATION WINDOW
# =====================================================================

class EvilTwinGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Wi-Fi Evil Twin Detection System (ML)")
        self.geometry("1220x760")
        self.minsize(1050, 680)
        self.configure(bg=CLR_APP_BG)

        # State storage
        self.scanned_results = []
        self.safer_candidates = []
        self.scan_in_progress = False
        self.tree_iid_map = {}
        self.history_df = None
        self.msg_queue = queue.Queue()

        self._init_models_if_needed()
        self._configure_styles()
        self._build_header()
        self._build_control_bar()
        self._build_main_split()
        self._build_footer_status()

        # Start periodic queue polling for thread-safe UI updates
        self._poll_queue()

        # Check active connection on launch
        self._update_active_connection_pill()

    def _poll_queue(self):
        """Polls the message queue from the main thread for thread-safe UI updates."""
        try:
            while True:
                msg_type, payload = self.msg_queue.get_nowait()
                if msg_type == "SUCCESS":
                    self._scan_completed(*payload)
                elif msg_type == "FAILED":
                    self._scan_failed(payload)
                elif msg_type == "IFACE":
                    self._set_active_connection_info(*payload)
        except queue.Empty:
            pass
        finally:
            self.after(100, self._poll_queue)

    def _init_models_if_needed(self):
        """Ensures KNN & Random Forest models exist before scanning."""
        try:
            load_models()
        except Exception:
            try:
                seed_baseline_dataset(overwrite_if_exists=False)
                build_training_dataset()
                train_models()
            except Exception as err:
                print(f"[GUI Init Warning] Failed to initialize baseline models: {err}")

    def _configure_styles(self):
        """Sets up ttk fonts, colors, and table heights."""
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        # Global backgrounds
        self.style.configure(".", background=CLR_APP_BG, font=("Segoe UI", 9))
        self.style.configure("TFrame", background=CLR_APP_BG)
        self.style.configure("Card.TFrame", background=CLR_CARD_BG, relief="solid", borderwidth=1)
        self.style.configure("Header.TFrame", background=CLR_HEADER_BG)

        # Treeview styling
        self.style.configure(
            "Treeview",
            background=CLR_CARD_BG,
            foreground=CLR_TEXT_MAIN,
            fieldbackground=CLR_CARD_BG,
            font=("Segoe UI", 9),
            rowheight=26,
            borderwidth=1,
            relief="solid"
        )
        self.style.configure(
            "Treeview.Heading",
            background="#E2E8F0",
            foreground=CLR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"),
            padding=(6, 4)
        )
        self.style.map("Treeview.Heading", background=[("active", "#CBD5E1")])
        self.style.map("Treeview", background=[("selected", "#0284C7")], foreground=[("selected", "#FFFFFF")])

        # Group LabelFrames
        self.style.configure(
            "TLabelframe",
            background=CLR_APP_BG,
            foreground=CLR_TEXT_MAIN,
            borderwidth=1,
            relief="solid"
        )
        self.style.configure(
            "TLabelframe.Label",
            background=CLR_APP_BG,
            foreground=CLR_TEXT_MAIN,
            font=("Segoe UI", 10, "bold")
        )

    # -----------------------------------------------------------------
    # UI CONSTRUCTION
    # -----------------------------------------------------------------

    def _build_header(self):
        """Top dark banner with application title and subtitle."""
        header_frame = tk.Frame(self, bg=CLR_HEADER_BG, height=72)
        header_frame.pack(fill="x", side="top")
        header_frame.pack_propagate(False)

        title_lbl = tk.Label(
            header_frame,
            text="WI-FI EVIL TWIN DETECTION SYSTEM",
            bg=CLR_HEADER_BG,
            fg=CLR_HEADER_FG,
            font=("Segoe UI", 15, "bold")
        )
        title_lbl.pack(pady=(12, 2))

        sub_lbl = tk.Label(
            header_frame,
            text="Dual-ML Classification (KNN + Random Forest) with Local Network Baseline",
            bg=CLR_HEADER_BG,
            fg=CLR_SUBTITLE,
            font=("Segoe UI", 9)
        )
        sub_lbl.pack(pady=(0, 10))

    def _build_control_bar(self):
        """Control bar with Scan button, status text, and active interface badge."""
        bar = tk.Frame(self, bg=CLR_APP_BG, pady=8, padx=16)
        bar.pack(fill="x", side="top")

        # Scan Button
        self.scan_btn = tk.Button(
            bar,
            text="🔍  SCAN WI-FI",
            bg=CLR_BTN_PRIMARY,
            fg="#FFFFFF",
            activebackground=CLR_BTN_HOVER,
            activeforeground="#FFFFFF",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=16,
            pady=6,
            cursor="hand2",
            command=self.start_scan
        )
        self.scan_btn.pack(side="left")

        # Status text
        self.status_var = tk.StringVar(value="Status: Ready. Click 'SCAN WI-FI' to analyze nearby access points.")
        self.status_lbl = tk.Label(
            bar,
            textvariable=self.status_var,
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MUTED,
            font=("Segoe UI", 9, "italic")
        )
        self.status_lbl.pack(side="left", padx=16)

        # Active interface pill on right
        self.active_iface_var = tk.StringVar(value="● Checking Wi-Fi Interface...")
        self.active_iface_lbl = tk.Label(
            bar,
            textvariable=self.active_iface_var,
            bg="#E2E8F0",
            fg="#334155",
            font=("Segoe UI", 9),
            padx=10,
            pady=4,
            relief="solid",
            borderwidth=1
        )
        self.active_iface_lbl.pack(side="right")

    def _build_main_split(self):
        """Split view: Left = Table of nearby networks, Right = Detailed analysis."""
        split_frame = tk.Frame(self, bg=CLR_APP_BG)
        split_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        # LEFT PANE: Nearby Networks Table (55% width)
        left_box = tk.LabelFrame(
            split_frame,
            text=" Nearby Wi-Fi Networks ",
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MAIN,
            font=("Segoe UI", 10, "bold"),
            padx=6,
            pady=6
        )
        left_box.pack(side="left", fill="both", expand=True, padx=(0, 8))

        cols = ("ssid", "bssid", "signal", "channel", "security", "classification")
        self.tree = ttk.Treeview(
            left_box,
            columns=cols,
            show="headings",
            selectmode="browse"
        )

        self.tree.heading("ssid", text="SSID", anchor="w")
        self.tree.heading("bssid", text="BSSID (MAC)", anchor="center")
        self.tree.heading("signal", text="Signal", anchor="center")
        self.tree.heading("channel", text="Ch", anchor="center")
        self.tree.heading("security", text="Security", anchor="w")
        self.tree.heading("classification", text="Final Classification", anchor="w")

        self.tree.column("ssid", width=140, minwidth=100, stretch=True)
        self.tree.column("bssid", width=135, minwidth=110, stretch=False, anchor="center")
        self.tree.column("signal", width=65, minwidth=50, stretch=False, anchor="center")
        self.tree.column("channel", width=45, minwidth=40, stretch=False, anchor="center")
        self.tree.column("security", width=110, minwidth=90, stretch=False)
        self.tree.column("classification", width=175, minwidth=140, stretch=True)

        # Tag configurations for color-coded status in table
        self.tree.tag_configure("tag_legitimate", foreground=CLR_TAG_SAFE)
        self.tree.tag_configure("tag_evil", foreground=CLR_TAG_EVIL, font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("tag_suspicious", foreground=CLR_TAG_SUSP, font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("tag_new", foreground=CLR_TAG_NEW)

        v_scroll = ttk.Scrollbar(left_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        v_scroll.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # RIGHT PANE: Network Analysis & Detection Details (45% width)
        self.right_box = tk.LabelFrame(
            split_frame,
            text=" Network Analysis & Detection Details ",
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MAIN,
            font=("Segoe UI", 10, "bold"),
            padx=10,
            pady=8
        )
        self.right_box.pack(side="right", fill="both", expand=True, padx=(8, 0))

        self._build_details_pane(self.right_box)

    def _build_details_pane(self, parent):
        """Constructs the details card on the right."""
        # Top Prominent Status Banner
        self.banner_frame = tk.Frame(parent, bg="#475569", height=38)
        self.banner_frame.pack(fill="x", pady=(0, 10))
        self.banner_frame.pack_propagate(False)

        self.banner_lbl = tk.Label(
            self.banner_frame,
            text="SELECT A NETWORK TO VIEW ANALYSIS",
            bg="#475569",
            fg="#FFFFFF",
            font=("Segoe UI", 11, "bold")
        )
        self.banner_lbl.pack(expand=True)

        # Scrollable container for detail sections
        canvas = tk.Canvas(parent, bg=CLR_APP_BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        self.detail_content = tk.Frame(canvas, bg=CLR_APP_BG)

        self.detail_content.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=self.detail_content, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 1. Access Point Information Group
        ap_group = tk.LabelFrame(
            self.detail_content,
            text=" Access Point Information ",
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=6
        )
        ap_group.pack(fill="x", pady=(0, 8))

        self.lbl_det_ssid = self._make_key_value(ap_group, "SSID:", "--", row=0)
        self.lbl_det_bssid = self._make_key_value(ap_group, "BSSID (MAC):", "--", row=1)
        self.lbl_det_signal = self._make_key_value(ap_group, "Signal Strength:", "--", row=2)
        self.lbl_det_channel = self._make_key_value(ap_group, "Channel:", "--", row=3)
        self.lbl_det_security = self._make_key_value(ap_group, "Security:", "--", row=4)
        self.lbl_det_radio = self._make_key_value(ap_group, "Physical Radio:", "--", row=5)

        # 2. Machine Learning Models Group
        ml_group = tk.LabelFrame(
            self.detail_content,
            text=" Machine Learning Models ",
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=6
        )
        ml_group.pack(fill="x", pady=(0, 8))

        self.lbl_det_knn = self._make_key_value(ml_group, "KNN Prediction:", "--", row=0)
        self.lbl_det_rf = self._make_key_value(ml_group, "Random Forest:", "--", row=1)

        # 3. Network History Baseline Group
        hist_group = tk.LabelFrame(
            self.detail_content,
            text=" Network History Baseline ",
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=6
        )
        hist_group.pack(fill="x", pady=(0, 8))

        self.lbl_det_trust = self._make_key_value(hist_group, "Trust Baseline:", "--", row=0)
        self.lbl_det_first = self._make_key_value(hist_group, "First Seen:", "--", row=1)
        self.lbl_det_last = self._make_key_value(hist_group, "Last Seen:", "--", row=2)
        self.lbl_det_obs = self._make_key_value(hist_group, "Observations:", "--", row=3)

        # 4. Evidence & Observations Group
        ev_group = tk.LabelFrame(
            self.detail_content,
            text=" Evidence & Observations ",
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=6
        )
        ev_group.pack(fill="x", pady=(0, 8))

        self.txt_evidence = tk.Text(
            ev_group,
            height=6,
            wrap="word",
            bg="#FFFFFF",
            fg=CLR_TEXT_MAIN,
            font=("Segoe UI", 8),
            relief="solid",
            borderwidth=1,
            padx=6,
            pady=6
        )
        self.txt_evidence.pack(fill="both", expand=True)
        self.txt_evidence.insert("1.0", "Select an access point from the table on the left.")
        self.txt_evidence.configure(state="disabled")

        # 5. Connection Recommendation / Action Advice
        rec_group = tk.LabelFrame(
            self.detail_content,
            text=" Connection Assessment & Advice ",
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=6
        )
        rec_group.pack(fill="x", pady=(0, 4))

        self.lbl_det_verdict = tk.Label(
            rec_group,
            text="--",
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"),
            anchor="w",
            justify="left"
        )
        self.lbl_det_verdict.pack(fill="x", pady=(0, 4))

        self.lbl_det_advice = tk.Label(
            rec_group,
            text="--",
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MUTED,
            font=("Segoe UI", 8),
            wraplength=420,
            justify="left",
            anchor="w"
        )
        self.lbl_det_advice.pack(fill="x")

    def _make_key_value(self, parent, key_text, val_text, row):
        """Helper to create crisp two-column key-value rows."""
        k = tk.Label(
            parent,
            text=key_text,
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"),
            anchor="w",
            width=18
        )
        k.grid(row=row, column=0, sticky="w", pady=2)

        v = tk.Label(
            parent,
            text=val_text,
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MUTED,
            font=("Segoe UI", 9),
            anchor="w"
        )
        v.grid(row=row, column=1, sticky="w", pady=2)
        return v

    def _build_footer_status(self):
        """Clean minimal footer with project attribution."""
        footer = tk.Frame(self, bg="#E2E8F0", height=24)
        footer.pack(fill="x", side="bottom")

        lbl = tk.Label(
            footer,
            text="Wi-Fi Evil Twin & Rogue AP Detection System | B.Tech Mini Project | Windows Client Security",
            bg="#E2E8F0",
            fg="#64748B",
            font=("Segoe UI", 8)
        )
        lbl.pack(side="left", padx=16)

    # -----------------------------------------------------------------
    # SCANNING & BACKGROUND WORKER
    # -----------------------------------------------------------------

    def start_scan(self):
        """Triggers the Wi-Fi scan on a separate daemon thread to keep UI fluid."""
        if self.scan_in_progress:
            return

        self.scan_in_progress = True
        self.scan_btn.configure(state="disabled", text="⏳  SCANNING...")
        self.status_var.set("Status: Scanning nearby Wi-Fi networks using Windows built-in adapter...")

        worker = threading.Thread(target=self._scan_worker, daemon=True)
        worker.start()

    def _scan_worker(self):
        """Background thread worker doing passive scanning and multi-dimensional ML analysis."""
        try:
            # 1. Scan Wi-Fi via netsh
            scanned = scan_wifi()
            save_observations_to_csv(scanned)

            # 2. Load history before update
            hist = load_history()

            # 3. Analyze networks
            results, safer = analyze_scanned_networks(scanned, history_df=hist)

            # 4. Update history after analysis
            update_history(scanned)

            # 5. Query active interface & gateway info
            active_iface = get_active_wifi_interface()
            is_portal, portal_msg = check_captive_portal()

            self.msg_queue.put(("SUCCESS", (results, safer, hist, active_iface, is_portal, portal_msg)))
        except Exception as exc:
            err_msg = str(exc)
            self.msg_queue.put(("FAILED", err_msg))

    def _scan_failed(self, err_msg):
        self.scan_in_progress = False
        self.scan_btn.configure(state="normal", text="🔍  SCAN WI-FI")
        self.status_var.set(f"Status: Scan error encountered ({err_msg}).")
        messagebox.showerror("Scan Error", f"Failed to complete Wi-Fi scan:\n{err_msg}")

    def _scan_completed(self, results, safer, hist, active_iface, is_portal, portal_msg):
        self.scan_in_progress = False
        self.scan_btn.configure(state="normal", text="🔍  SCAN WI-FI")
        self.scanned_results = results
        self.safer_candidates = safer
        self.history_df = hist

        # Update status bar
        count = len(results)
        self.status_var.set(f"Status: Scan completed successfully. Found {count} Access Point(s).")

        # Update active interface pill
        self._set_active_connection_info(active_iface, is_portal, portal_msg)

        # Clear and repopulate table
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.tree_iid_map = {}

        if not results:
            messagebox.showinfo(
                "No Networks Visible",
                "No Wi-Fi access points were detected.\n"
                "Please verify that Wi-Fi is turned ON in Windows Settings."
            )
            return

        for idx, res in enumerate(results):
            status = res.get("AcademicStatus", res.get("FinalResult", "NEW / UNVERIFIED"))
            risk = res.get("RiskCategory", "")

            # Tag determination
            if status == STATUS_EVIL_TWIN or risk == RISK_HIGH:
                tag = "tag_evil"
            elif status == STATUS_LEGITIMATE or risk == RISK_LOWER:
                tag = "tag_legitimate"
            elif status == STATUS_SUSPICIOUS:
                tag = "tag_suspicious"
            else:
                tag = "tag_new"

            iid = self.tree.insert(
                "",
                "end",
                values=(
                    res.get("SSID", "<Hidden>"),
                    res.get("BSSID", "--"),
                    f"{res.get('Signal', 0)}%",
                    res.get("Channel", "--"),
                    res.get("Security", "Open"),
                    status
                ),
                tags=(tag,)
            )
            self.tree_iid_map[iid] = idx

        # Auto-select first item
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])
            self.tree.focus(children[0])
            self._display_network_details(results[0])

    # -----------------------------------------------------------------
    # SELECTION & DETAILS RENDERING
    # -----------------------------------------------------------------

    def _on_tree_select(self, event):
        """Called when user clicks on a network row in the Treeview."""
        selected = self.tree.selection()
        if not selected:
            return
        iid = selected[0]
        idx = self.tree_iid_map.get(iid)
        if idx is not None and idx < len(self.scanned_results):
            self._display_network_details(self.scanned_results[idx])

    def _display_network_details(self, res):
        """Renders full technical evidence, ML outputs, and risk banner."""
        ssid = res.get("SSID", "")
        bssid = res.get("BSSID", "")
        status = res.get("AcademicStatus", res.get("FinalResult", "NEW / UNVERIFIED"))
        risk = res.get("RiskCategory", "")

        # 1. Update Prominent Banner
        if status == STATUS_EVIL_TWIN or risk == RISK_HIGH:
            banner_bg = CLR_BANNER_EVIL
            banner_text = f"[ EVIL TWIN ]  {status}"
        elif status == STATUS_LEGITIMATE or risk == RISK_LOWER:
            banner_bg = CLR_BANNER_SAFE
            banner_text = f"[ LOWER RISK ]  {status}"
        elif status == STATUS_SUSPICIOUS:
            banner_bg = CLR_BANNER_SUSP
            banner_text = f"[ SUSPICIOUS ]  {status}"
        else:
            banner_bg = CLR_BANNER_NEW
            banner_text = f"[ UNCERTAIN ]  {status}"

        self.banner_frame.configure(bg=banner_bg)
        self.banner_lbl.configure(bg=banner_bg, text=banner_text)

        # 2. Access Point Information
        band_info = res.get("Band", "")
        ch_text = f"{res.get('Channel', '--')} ({band_info})" if band_info else str(res.get("Channel", "--"))
        sec_text = res.get("Security", "Unknown")
        enc = res.get("Encryption", "")
        if enc and enc != "Unknown" and enc not in sec_text:
            sec_text = f"{sec_text} ({enc})"

        self.lbl_det_ssid.configure(text=ssid or "<Hidden Network>")
        self.lbl_det_bssid.configure(text=bssid)
        self.lbl_det_signal.configure(text=f"{res.get('Signal', 0)}%")
        self.lbl_det_channel.configure(text=ch_text)
        self.lbl_det_security.configure(text=sec_text)
        self.lbl_det_radio.configure(text=res.get("Radio", "802.11 Standard"))

        # 3. Machine Learning Models
        knn = res.get("KNN_Pred", "Unknown")
        rf = res.get("RF_Pred", "Unknown")
        self.lbl_det_knn.configure(
            text=knn,
            fg=CLR_TAG_SAFE if knn == "Legitimate" else CLR_TAG_EVIL
        )
        self.lbl_det_rf.configure(
            text=rf,
            fg=CLR_TAG_SAFE if rf == "Legitimate" else CLR_TAG_EVIL
        )

        # 4. History Baseline
        trust = res.get("TrustState", "UNFAMILIAR")
        self.lbl_det_trust.configure(text=trust)

        ap_rec = None
        if self.history_df is not None:
            ap_rec = get_ap_record(self.history_df, ssid, bssid)

        if ap_rec is not None:
            first_seen = ap_rec.get("First Seen", "Recorded in history")
            last_seen = ap_rec.get("Last Seen", "Recorded in history")
            obs_cnt = ap_rec.get("Observation Count", 1)
            self.lbl_det_first.configure(text=str(first_seen))
            self.lbl_det_last.configure(text=str(last_seen))
            self.lbl_det_obs.configure(text=f"{obs_cnt} prior scan(s)")
        else:
            self.lbl_det_first.configure(text="First observation in this scan")
            self.lbl_det_last.configure(text="Active observation now")
            self.lbl_det_obs.configure(text="0 prior scans (New network)")

        # 5. Evidence & Observations Bullet List
        evidence_lines = []
        for ev in res.get("ObservedEvidence", []):
            evidence_lines.append(f"• {ev}")
        for warn in res.get("WarningIndicators", []):
            evidence_lines.append(f"• [WARNING] {warn}")
        for reason in res.get("Reasons", []):
            if reason not in evidence_lines and f"• {reason}" not in evidence_lines:
                evidence_lines.append(f"• {reason}")

        if not evidence_lines:
            evidence_lines.append("• Standard physical RF broadcast observed. No anomalies detected.")

        self.txt_evidence.configure(state="normal")
        self.txt_evidence.delete("1.0", "end")
        self.txt_evidence.insert("1.0", "\n".join(evidence_lines))
        self.txt_evidence.configure(state="disabled")

        # 6. Verdict & Connection Advice
        badge = res.get("RiskBadge", "")
        self.lbl_det_verdict.configure(
            text=f"{badge} {res.get('RiskCategory', risk)}",
            fg=CLR_TAG_SAFE if risk == RISK_LOWER else (CLR_TAG_EVIL if risk == RISK_HIGH else CLR_TAG_SUSP)
        )
        self.lbl_det_advice.configure(text=res.get("SummaryAdvice", ""))

    # -----------------------------------------------------------------
    # ACTIVE INTERFACE & GATEWAY STATUS
    # -----------------------------------------------------------------

    def _update_active_connection_pill(self):
        """Asynchronously checks active Windows Wi-Fi connection for the status pill."""
        def _check():
            iface = get_active_wifi_interface()
            is_portal, portal_msg = check_captive_portal()
            self.msg_queue.put(("IFACE", (iface, is_portal, portal_msg)))
        threading.Thread(target=_check, daemon=True).start()

    def _set_active_connection_info(self, iface, is_portal, portal_msg):
        if iface.get("State") == "connected":
            ssid = iface.get("SSID", "Connected")
            band = iface.get("Band", "")
            ch = iface.get("Channel", "")
            pill_text = f"● Connected: {ssid} ({band}, Ch {ch})"
            self.active_iface_lbl.configure(
                text=pill_text,
                bg="#DCFCE7",
                fg="#166534"
            )
        else:
            self.active_iface_lbl.configure(
                text="● Wi-Fi: Disconnected / Scanning Only",
                bg="#F1F5F9",
                fg="#64748B"
            )


# =====================================================================
# APPLICATION ENTRYPOINT
# =====================================================================

def main():
    app = EvilTwinGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
