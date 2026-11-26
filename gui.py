"""
Wi-Fi Evil Twin Detection System - Graphical User Interface (GUI)
==================================================================
Dual-ML Classification (KNN + Random Forest) with Local Baseline
& Multi-Dimensional Evidence-Based Risk Assessment.

Built with Python standard library Tkinter + ttk (zero external GUI bloat).
Fully compatible with Windows Wi-Fi scanning via native netsh.
"""

import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.dataset import build_training_dataset, seed_baseline_dataset
from src.history import get_ap_record, load_history, mark_ap_trusted, update_history
from src.paths import get_resource_dir
from src.predict import (
    STATUS_HIGH_RISK,
    STATUS_KNOWN_CONSISTENT,
    STATUS_NEW_UNVERIFIED,
    STATUS_SUSPICIOUS,
    analyze_scanned_networks,
    load_models
)
from src.scanner import save_observations_to_csv, scan_wifi_detailed
from src.system_profiles import check_captive_portal, get_active_wifi_interface
from src.train import train_models


# =====================================================================
# THEME & COLOR PALETTE (Clean, Modern Slate & Navy)
# =====================================================================

CLR_HEADER_BG = "#0B132B"
CLR_HEADER_FG = "#FFFFFF"
CLR_SUBTITLE  = "#94A3B8"
CLR_APP_BG    = "#F1F5F9"
CLR_CARD_BG   = "#FFFFFF"
CLR_TEXT_MAIN = "#0F172A"
CLR_TEXT_MUTED= "#475569"

CLR_BTN_PRIMARY  = "#1D68BD"
CLR_BTN_HOVER    = "#18549A"
CLR_TAG_SAFE     = "#16A34A"
CLR_TAG_EVIL     = "#DC2626"
CLR_TAG_SUSP     = "#D97706"
CLR_TAG_NEW      = "#2563EB"

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
        self.title("Wi-Fi Evil Twin Detection System (ML + Rule Engine)")
        self.geometry("1240x780")
        self.minsize(1060, 680)
        self.configure(bg=CLR_APP_BG)
        try:
            ico_path = os.path.join(get_resource_dir(), "static", "app_icon.ico")
            if os.path.exists(ico_path):
                self.iconbitmap(ico_path)
        except Exception:
            pass

        self.scanned_results = []
        self.safer_candidates = []
        self.scan_in_progress = False
        self.tree_iid_map = {}
        self.history_df = None
        self.selected_result = None
        self.msg_queue = queue.Queue()

        self._init_models_if_needed()
        self._configure_styles()
        self._build_header()
        self._build_control_bar()
        self._build_main_split()
        self._build_footer_status()

        self._poll_queue()
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

        self.style.configure(".", background=CLR_APP_BG, font=("Segoe UI", 9))
        self.style.configure("TFrame", background=CLR_APP_BG)
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

    # -----------------------------------------------------------------
    # UI CONSTRUCTION
    # -----------------------------------------------------------------

    def _build_header(self):
        header_frame = tk.Frame(self, bg=CLR_HEADER_BG, height=72)
        header_frame.pack(fill="x", side="top")
        header_frame.pack_propagate(False)

        tk.Label(
            header_frame,
            text="WI-FI EVIL TWIN DETECTION SYSTEM",
            bg=CLR_HEADER_BG,
            fg=CLR_HEADER_FG,
            font=("Segoe UI", 15, "bold")
        ).pack(pady=(12, 2))

        tk.Label(
            header_frame,
            text="Rule-Based Risk Scoring + Fingerprint History + Dual-ML Consensus (KNN & Random Forest)",
            bg=CLR_HEADER_BG,
            fg=CLR_SUBTITLE,
            font=("Segoe UI", 9)
        ).pack(pady=(0, 10))

    def _build_control_bar(self):
        bar = tk.Frame(self, bg=CLR_APP_BG, pady=8, padx=16)
        bar.pack(fill="x", side="top")

        self.scan_btn = tk.Button(
            bar,
            text="SCAN WI-FI",
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

        self.trust_btn = tk.Button(
            bar,
            text="Verify & Trust Selected AP",
            bg="#0F766E",
            fg="#FFFFFF",
            activebackground="#115E59",
            activeforeground="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=6,
            cursor="hand2",
            state="disabled",
            command=self._trust_selected_ap
        )
        self.trust_btn.pack(side="left", padx=(8, 0))

        self.status_var = tk.StringVar(value="Status: Ready. Click 'SCAN WI-FI' to analyze nearby access points.")
        tk.Label(
            bar,
            textvariable=self.status_var,
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MUTED,
            font=("Segoe UI", 9, "italic")
        ).pack(side="left", padx=16)

        self.active_iface_var = tk.StringVar(value="Checking Wi-Fi Interface...")
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
        split_frame = tk.Frame(self, bg=CLR_APP_BG)
        split_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))

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

        cols = ("ssid", "bssid", "signal", "channel", "security", "score", "classification")
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
        self.tree.heading("score", text="Risk", anchor="center")
        self.tree.heading("classification", text="Classification", anchor="w")

        self.tree.column("ssid", width=135, minwidth=95, stretch=True)
        self.tree.column("bssid", width=130, minwidth=110, stretch=False, anchor="center")
        self.tree.column("signal", width=65, minwidth=55, stretch=False, anchor="center")
        self.tree.column("channel", width=50, minwidth=40, stretch=False, anchor="center")
        self.tree.column("security", width=105, minwidth=85, stretch=False)
        self.tree.column("score", width=55, minwidth=45, stretch=False, anchor="center")
        self.tree.column("classification", width=225, minwidth=195, stretch=True)

        self.tree.tag_configure("tag_known", foreground=CLR_TAG_SAFE)
        self.tree.tag_configure("tag_high_risk", foreground=CLR_TAG_EVIL, font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("tag_suspicious", foreground=CLR_TAG_SUSP, font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("tag_new", foreground=CLR_TAG_NEW)

        v_scroll = ttk.Scrollbar(left_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        v_scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

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
        self.lbl_det_bssid = self._make_key_value(ap_group, "BSSID (MAC / OUI):", "--", row=1)
        self.lbl_det_signal = self._make_key_value(ap_group, "Signal Strength:", "--", row=2)
        self.lbl_det_channel = self._make_key_value(ap_group, "Channel / Band:", "--", row=3)
        self.lbl_det_security = self._make_key_value(ap_group, "Security:", "--", row=4)
        self.lbl_det_radio = self._make_key_value(ap_group, "Physical Radio:", "--", row=5)

        ml_group = tk.LabelFrame(
            self.detail_content,
            text=" Machine Learning & Risk Score ",
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=6
        )
        ml_group.pack(fill="x", pady=(0, 8))

        self.lbl_det_rf = self._make_key_value(ml_group, "Random Forest (Primary):", "--", row=0)
        self.lbl_det_knn = self._make_key_value(ml_group, "KNN (Comparison):", "--", row=1)
        self.lbl_det_iso = self._make_key_value(ml_group, "Isolation Forest (Anomaly):", "--", row=2)
        self.lbl_det_score = self._make_key_value(ml_group, "Risk Score:", "--", row=3)

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

        ev_group = tk.LabelFrame(
            self.detail_content,
            text=" Reasons, Score Breakdown & Warnings ",
            bg=CLR_APP_BG,
            fg=CLR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=6
        )
        ev_group.pack(fill="x", pady=(0, 8))

        self.txt_evidence = tk.Text(
            ev_group,
            height=8,
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

        rec_group = tk.LabelFrame(
            self.detail_content,
            text=" Final Decision & Advice ",
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
            wraplength=440,
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
            wraplength=440,
            justify="left",
            anchor="w"
        )
        self.lbl_det_advice.pack(fill="x")

    def _make_key_value(self, parent, key_text, val_text, row):
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
        footer = tk.Frame(self, bg="#E2E8F0", height=24)
        footer.pack(fill="x", side="bottom")

        tk.Label(
            footer,
            text="Wi-Fi Evil Twin Detection System | B.Tech Mini Project | Defensive Client Assessment",
            bg="#E2E8F0",
            fg="#64748B",
            font=("Segoe UI", 8)
        ).pack(side="left", padx=16)

    # -----------------------------------------------------------------
    # SCANNING & BACKGROUND WORKER
    # -----------------------------------------------------------------

    def start_scan(self):
        if self.scan_in_progress:
            return

        self.scan_in_progress = True
        self.scan_btn.configure(state="disabled", text="SCANNING...")
        self.trust_btn.configure(state="disabled")
        self.status_var.set("Status: Scanning nearby Wi-Fi networks using Windows built-in adapter...")

        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            scan_res = scan_wifi_detailed()
            if not scan_res["success"]:
                self.msg_queue.put(("FAILED", scan_res["error"] or "Unknown scanner error."))
                return

            scanned = scan_res["networks"]
            save_observations_to_csv(scanned)
            hist = load_history()
            results, safer = analyze_scanned_networks(scanned, history_df=hist)
            update_history(scanned, assessments=results)

            active_iface = get_active_wifi_interface()
            is_portal, portal_msg = check_captive_portal()

            self.msg_queue.put(("SUCCESS", (results, safer, hist, active_iface, is_portal, portal_msg)))
        except Exception as exc:
            self.msg_queue.put(("FAILED", str(exc)))

    def _scan_failed(self, err_msg):
        self.scan_in_progress = False
        self.scan_btn.configure(state="normal", text="SCAN WI-FI")
        self.status_var.set(f"Status: Scan failed ({err_msg}).")
        messagebox.showerror(
            "Scan Error",
            f"Wi-Fi scan failed and cannot assess nearby networks:\n\n{err_msg}"
        )

    def _scan_completed(self, results, safer, hist, active_iface, is_portal, portal_msg):
        self.scan_in_progress = False
        self.scan_btn.configure(state="normal", text="SCAN WI-FI")
        self.scanned_results = results
        self.safer_candidates = safer
        self.history_df = hist
        self.selected_result = None

        count = len(results)
        self.status_var.set(f"Status: Scan completed. Found {count} Access Point(s).")
        self._set_active_connection_info(active_iface, is_portal, portal_msg)

        for item in self.tree.get_children():
            self.tree.delete(item)
        self.tree_iid_map = {}

        if not results:
            self.trust_btn.configure(state="disabled")
            messagebox.showinfo(
                "No Networks Visible",
                "Scan succeeded, but no Wi-Fi access points are currently in range."
            )
            return

        for idx, res in enumerate(results):
            status = res.get("Classification", STATUS_NEW_UNVERIFIED)
            if status == STATUS_HIGH_RISK:
                tag = "tag_high_risk"
            elif status == STATUS_KNOWN_CONSISTENT:
                tag = "tag_known"
            elif status == STATUS_SUSPICIOUS:
                tag = "tag_suspicious"
            else:
                tag = "tag_new"

            sig_val = res.get("Signal")
            sig_cell = f"{sig_val}%" if sig_val is not None else "Unavail."
            ch_cell = str(res.get("Channel", "Unavail."))
            score_cell = f"{res.get('RiskScore', 0)}/100"

            iid = self.tree.insert(
                "",
                "end",
                values=(
                    res.get("SSID", "<Hidden>"),
                    res.get("BSSID", "--"),
                    sig_cell,
                    ch_cell,
                    res.get("Security", "Unavailable"),
                    score_cell,
                    status
                ),
                tags=(tag,)
            )
            self.tree_iid_map[iid] = idx

        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])
            self.tree.focus(children[0])
            self._display_network_details(results[0])

    def _trust_selected_ap(self):
        if not self.selected_result:
            return
        ssid = self.selected_result.get("SSID", "")
        bssid = self.selected_result.get("BSSID", "")
        if not ssid or not bssid or bssid == "Unavailable":
            return

        confirm = messagebox.askyesno(
            "Confirm Trusted Baseline",
            f"Mark this specific Access Point as an established trusted baseline?\n\n"
            f"SSID: {ssid}\nBSSID: {bssid}\nSecurity: {self.selected_result.get('Security')}\n\n"
            "Only confirm if you physically/administratively verified this AP."
        )
        if not confirm:
            return

        mark_ap_trusted(ssid, bssid)
        self.status_var.set(f"Status: Marked {ssid} [{bssid}] as TRUSTED_BASELINE. Re-scan to refresh.")
        messagebox.showinfo("Baseline Updated", f"'{ssid}' [{bssid}] saved as trusted baseline.")

    # -----------------------------------------------------------------
    # SELECTION & DETAILS RENDERING
    # -----------------------------------------------------------------

    def _on_tree_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        iid = selected[0]
        idx = self.tree_iid_map.get(iid)
        if idx is not None and idx < len(self.scanned_results):
            self._display_network_details(self.scanned_results[idx])

    def _display_network_details(self, res):
        self.selected_result = res
        self.trust_btn.configure(state="normal")

        ssid = res.get("SSID", "")
        bssid = res.get("BSSID", "")
        status = res.get("Classification", STATUS_NEW_UNVERIFIED)

        if status == STATUS_HIGH_RISK:
            banner_bg = CLR_BANNER_EVIL
        elif status == STATUS_KNOWN_CONSISTENT:
            banner_bg = CLR_BANNER_SAFE
        elif status == STATUS_SUSPICIOUS:
            banner_bg = CLR_BANNER_SUSP
        else:
            banner_bg = CLR_BANNER_NEW

        self.banner_frame.configure(bg=banner_bg)
        self.banner_lbl.configure(bg=banner_bg, text=status)

        band_info = res.get("Band", "Unavailable")
        ch_text = f"{res.get('Channel', 'Unavailable')} ({band_info})"
        sec_text = f"{res.get('Security', 'Unavailable')} ({res.get('Encryption', 'Unavailable')})"

        self.lbl_det_ssid.configure(text=ssid or "<Hidden Network>")
        self.lbl_det_bssid.configure(text=f"{bssid} (OUI: {res.get('OUI', 'Unavailable')})")
        self.lbl_det_signal.configure(text=res.get("SignalDisplay", "Unavailable"))
        self.lbl_det_channel.configure(text=ch_text)
        self.lbl_det_security.configure(text=sec_text)
        self.lbl_det_radio.configure(text=res.get("Radio", "Unavailable"))

        knn = res.get("KNN_Pred", "Unknown")
        rf = res.get("RF_Pred", "Unknown")
        iso = res.get("IsoForest_Pred", "Unavailable")
        iso_score = res.get("IsoForest_Score")
        iso_text = f"{iso} ({iso_score:+.3f})" if isinstance(iso_score, (int, float)) else iso
        self.lbl_det_rf.configure(
            text=rf,
            fg=CLR_TAG_SAFE if rf == "Legitimate" else CLR_TAG_EVIL
        )
        self.lbl_det_knn.configure(
            text=knn,
            fg=CLR_TAG_SAFE if knn == "Legitimate" else CLR_TAG_EVIL
        )
        self.lbl_det_iso.configure(
            text=iso_text,
            fg=CLR_TAG_SAFE if iso == "Normal" else (CLR_TAG_SUSP if iso == "Anomaly" else CLR_TEXT_MUTED)
        )
        score = res.get("RiskScore", 0)
        self.lbl_det_score.configure(
            text=f"{score} / {res.get('RiskScoreMax', 100)} ({res.get('ML_Agreement', '')})",
            fg=CLR_TAG_EVIL if score >= 60 else (CLR_TAG_SUSP if score >= 25 else CLR_TAG_SAFE)
        )

        self.lbl_det_trust.configure(text=res.get("TrustState", "UNFAMILIAR"))

        ap_rec = get_ap_record(self.history_df, ssid, bssid) if self.history_df is not None else None
        if ap_rec is not None:
            self.lbl_det_first.configure(text=str(ap_rec.get("First Seen", "Recorded")))
            self.lbl_det_last.configure(text=str(ap_rec.get("Last Seen", "Recorded")))
            self.lbl_det_obs.configure(text=f"{ap_rec.get('Observation Count', 1)} prior scan(s)")
        else:
            self.lbl_det_first.configure(text="First observation in this scan")
            self.lbl_det_last.configure(text="Active observation now")
            self.lbl_det_obs.configure(text="0 prior scans (New network)")

        evidence_lines = []
        for reason in res.get("Reasons", []):
            evidence_lines.append(f"• {reason}")
        for warn in res.get("WarningIndicators", []):
            evidence_lines.append(f"• [WARNING] {warn}")
        if res.get("ScoreBreakdown"):
            evidence_lines.append("• Risk Score Contributors:")
            for item in res["ScoreBreakdown"]:
                evidence_lines.append(f"    +{item['points']} pts [{item['factor']}]: {item['reason']}")
        evidence_lines.append(f"• Risk Score Meaning: {res.get('RiskScoreMeaning', '')}")

        self.txt_evidence.configure(state="normal")
        self.txt_evidence.delete("1.0", "end")
        self.txt_evidence.insert("1.0", "\n".join(evidence_lines))
        self.txt_evidence.configure(state="disabled")

        self.lbl_det_verdict.configure(
            text=f"{res.get('RiskCategory', status)}\n({res.get('FinalDecision', '')})",
            fg=CLR_TAG_SAFE if status == STATUS_KNOWN_CONSISTENT else (CLR_TAG_EVIL if status == STATUS_HIGH_RISK else CLR_TAG_SUSP)
        )
        self.lbl_det_advice.configure(text=res.get("SummaryAdvice", ""))

    # -----------------------------------------------------------------
    # ACTIVE INTERFACE & GATEWAY STATUS
    # -----------------------------------------------------------------

    def _update_active_connection_pill(self):
        def _check():
            iface = get_active_wifi_interface()
            is_portal, portal_msg = check_captive_portal()
            self.msg_queue.put(("IFACE", (iface, is_portal, portal_msg)))
        threading.Thread(target=_check, daemon=True).start()

    def _set_active_connection_info(self, iface, is_portal, portal_msg):
        if iface.get("State") == "connected":
            ssid = iface.get("SSID", "Connected")
            band = iface.get("Band") or "Unknown Band"
            ch = iface.get("Channel")
            ch_str = f"Ch {ch}" if ch is not None else "Ch N/A"
            portal_note = " | Captive Portal Detected!" if is_portal else ""
            pill_text = f"Connected: {ssid} ({band}, {ch_str}){portal_note}"
            self.active_iface_lbl.configure(
                text=pill_text,
                bg="#FEF3C7" if is_portal else "#DCFCE7",
                fg="#92400E" if is_portal else "#166534"
            )
        else:
            self.active_iface_lbl.configure(
                text="Wi-Fi: Disconnected / Scanning Only",
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
