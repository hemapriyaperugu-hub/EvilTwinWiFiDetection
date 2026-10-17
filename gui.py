import threading
import tkinter as tk
from tkinter import ttk, messagebox

from src.history import load_scan_history
from src.utils import DetectionError, run_detection


APP_TITLE = "Wi-Fi Evil Twin Detection System"
APP_SUBTITLE = "Client-Side Wi-Fi Security Analysis"

COLOR_BG = "#f4f6fb"
COLOR_HEADER = "#0f2c59"
COLOR_ACCENT = "#1b4f9c"
COLOR_TEXT = "#1c2333"
COLOR_MUTED = "#5b6475"
COLOR_CARD = "#ffffff"
COLOR_LEGIT = "#1f7a4d"
COLOR_SUSPICIOUS = "#b7791f"
COLOR_EVIL = "#b42318"
COLOR_WARN_BG = "#fff4e5"


class EvilTwinApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1180x760")
        self.minsize(980, 640)
        self.configure(bg=COLOR_BG)

        self.results = []
        self.recommendation = None
        self.scan_in_progress = False
        self.tree_iid_to_index = {}

        self._configure_styles()
        self._build_layout()
        self.refresh_history()

    def _configure_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=COLOR_BG)
        style.configure("Card.TFrame", background=COLOR_CARD)
        style.configure("Header.TFrame", background=COLOR_HEADER)
        style.configure(
            "Header.TLabel",
            background=COLOR_HEADER,
            foreground="white",
            font=("Segoe UI", 20, "bold")
        )
        style.configure(
            "Subheader.TLabel",
            background=COLOR_HEADER,
            foreground="#d7e3f8",
            font=("Segoe UI", 11)
        )
        style.configure(
            "Title.TLabel",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            font=("Segoe UI", 11, "bold")
        )
        style.configure(
            "Body.TLabel",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            font=("Segoe UI", 10)
        )
        style.configure(
            "Muted.TLabel",
            background=COLOR_BG,
            foreground=COLOR_MUTED,
            font=("Segoe UI", 9)
        )
        style.configure(
            "CardTitle.TLabel",
            background=COLOR_CARD,
            foreground=COLOR_TEXT,
            font=("Segoe UI", 11, "bold")
        )
        style.configure(
            "Scan.TButton",
            font=("Segoe UI", 12, "bold"),
            padding=10
        )
        style.configure(
            "Treeview",
            font=("Segoe UI", 9),
            rowheight=26
        )
        style.configure(
            "Treeview.Heading",
            font=("Segoe UI", 9, "bold")
        )

    def _build_layout(self):
        header = ttk.Frame(self, style="Header.TFrame")
        header.pack(fill="x")

        ttk.Label(header, text=APP_TITLE, style="Header.TLabel").pack(
            anchor="w", padx=24, pady=(16, 2)
        )
        ttk.Label(header, text=APP_SUBTITLE, style="Subheader.TLabel").pack(
            anchor="w", padx=24, pady=(0, 16)
        )

        controls = ttk.Frame(self)
        controls.pack(fill="x", padx=20, pady=14)

        self.scan_button = ttk.Button(
            controls,
            text="🔍 Scan Wi-Fi Networks",
            style="Scan.TButton",
            command=self.start_scan
        )
        self.scan_button.pack(side="left")

        self.status_var = tk.StringVar(value="Ready. Click Scan Wi-Fi Networks to analyze nearby access points.")
        ttk.Label(controls, textvariable=self.status_var, style="Muted.TLabel").pack(
            side="left", padx=16
        )

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        self.results_tab = ttk.Frame(self.notebook)
        self.history_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="Scan Results")
        self.notebook.add(self.history_tab, text="Scan History")

        self._build_results_tab()
        self._build_history_tab()

    def _build_results_tab(self):
        warning_frame = ttk.Frame(self.results_tab)
        warning_frame.pack(fill="x", pady=(8, 8))

        self.warning_var = tk.StringVar(
            value="Do not connect to networks marked as suspicious or possible Evil Twin. This application never connects to Wi-Fi automatically."
        )
        warning = tk.Label(
            warning_frame,
            textvariable=self.warning_var,
            bg=COLOR_WARN_BG,
            fg="#7a4d00",
            font=("Segoe UI", 9),
            wraplength=1080,
            justify="left",
            padx=10,
            pady=8
        )
        warning.pack(fill="x")

        columns = (
            "ssid",
            "bssid",
            "signal",
            "channel",
            "security",
            "knn",
            "rf",
            "status"
        )

        table_frame = ttk.Frame(self.results_tab)
        table_frame.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        headings = {
            "ssid": "SSID",
            "bssid": "BSSID",
            "signal": "Signal",
            "channel": "Channel",
            "security": "Security",
            "knn": "KNN Result",
            "rf": "Random Forest Result",
            "status": "Final Status"
        }
        widths = {
            "ssid": 160,
            "bssid": 140,
            "signal": 80,
            "channel": 90,
            "security": 150,
            "knn": 150,
            "rf": 170,
            "status": 220
        }

        for key, label in headings.items():
            self.tree.heading(key, text=label)
            self.tree.column(key, width=widths[key], stretch=True)

        self.tree.tag_configure("legitimate", foreground=COLOR_LEGIT)
        self.tree.tag_configure("suspicious", foreground=COLOR_SUSPICIOUS)
        self.tree.tag_configure("evil", foreground=COLOR_EVIL)

        y_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=y_scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        y_scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select_network)

        bottom = ttk.Frame(self.results_tab)
        bottom.pack(fill="both", expand=False, pady=(12, 8))
        bottom.columnconfigure(0, weight=1)
        bottom.columnconfigure(1, weight=1)

        explain_card = ttk.Frame(bottom, style="Card.TFrame", padding=12)
        explain_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        ttk.Label(explain_card, text="Network Explanation", style="CardTitle.TLabel").pack(anchor="w")
        self.explanation = tk.Text(
            explain_card,
            height=12,
            wrap="word",
            font=("Segoe UI", 9),
            bg=COLOR_CARD,
            fg=COLOR_TEXT,
            relief="flat"
        )
        self.explanation.pack(fill="both", expand=True, pady=(8, 0))
        self.explanation.insert("1.0", "Select a network after scanning to see a feature-based explanation.")
        self.explanation.configure(state="disabled")

        rec_card = ttk.Frame(bottom, style="Card.TFrame", padding=12)
        rec_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        ttk.Label(rec_card, text="Safer Network Recommendation", style="CardTitle.TLabel").pack(anchor="w")
        self.recommendation_text = tk.Text(
            rec_card,
            height=12,
            wrap="word",
            font=("Segoe UI", 9),
            bg=COLOR_CARD,
            fg=COLOR_TEXT,
            relief="flat"
        )
        self.recommendation_text.pack(fill="both", expand=True, pady=(8, 0))
        self.recommendation_text.insert(
            "1.0",
            "After a scan, the application will recommend a safer observed network.\n\nIt will not connect to any network automatically."
        )
        self.recommendation_text.configure(state="disabled")

    def _build_history_tab(self):
        ttk.Label(
            self.history_tab,
            text="Saved scans from dataset/network_history.csv",
            style="Muted.TLabel"
        ).pack(anchor="w", pady=(8, 6))

        columns = (
            "timestamp",
            "ssid",
            "bssid",
            "signal",
            "channel",
            "security",
            "knn",
            "rf",
            "status"
        )
        self.history_tree = ttk.Treeview(
            self.history_tab,
            columns=columns,
            show="headings",
            selectmode="browse"
        )
        headings = {
            "timestamp": "Timestamp",
            "ssid": "SSID",
            "bssid": "BSSID",
            "signal": "Signal",
            "channel": "Channel",
            "security": "Security",
            "knn": "KNN",
            "rf": "Random Forest",
            "status": "Final Status"
        }
        for key, label in headings.items():
            self.history_tree.heading(key, text=label)
            self.history_tree.column(key, width=110, stretch=True)

        y_scroll = ttk.Scrollbar(self.history_tab, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=y_scroll.set)
        self.history_tree.pack(side="left", fill="both", expand=True)
        y_scroll.pack(side="right", fill="y")

    def _set_text(self, widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def start_scan(self):
        if self.scan_in_progress:
            return

        self.scan_in_progress = True
        self.scan_button.configure(state="disabled")
        self.status_var.set("Scanning nearby Wi-Fi networks with the built-in adapter...")
        self.warning_var.set("Scanning in progress. Visible networks will be classified after the Windows scan completes.")

        worker = threading.Thread(target=self._scan_worker, daemon=True)
        worker.start()

    def _scan_worker(self):
        try:
            results, recommendation, _features = run_detection()
            self.after(0, lambda: self._scan_success(results, recommendation))
        except DetectionError as exc:
            message = str(exc)
            self.after(0, lambda: self._scan_failure(message))
        except Exception:
            self.after(
                0,
                lambda: self._scan_failure(
                    "The scan could not be completed because of an unexpected application error."
                )
            )

    def _scan_failure(self, message):
        self.scan_in_progress = False
        self.scan_button.configure(state="normal")
        self.status_var.set("Scan failed.")
        self.warning_var.set(message)
        messagebox.showerror("Scan Error", message)

    def _scan_success(self, results, recommendation):
        self.scan_in_progress = False
        self.scan_button.configure(state="normal")
        self.results = results
        self.recommendation = recommendation
        self.status_var.set(f"Scan completed. {len(results)} network(s) classified.")
        self._fill_results_table(results)
        self._fill_recommendation(recommendation)
        self.refresh_history()

        suspicious_count = sum(1 for item in results if item["status_key"] != "legitimate")
        if suspicious_count:
            self.warning_var.set(
                f"{suspicious_count} network(s) were marked suspicious or possible Evil Twin. "
                "Do not connect to those networks. This application never connects automatically."
            )
        else:
            self.warning_var.set(
                "No network was marked as a possible Evil Twin by both models. "
                "Still verify security before connecting. This application never connects automatically."
            )

        if results:
            first = self.tree.get_children()
            if first:
                self.tree.selection_set(first[0])
                self.tree.focus(first[0])
                self.on_select_network()

    def _fill_results_table(self, results):
        for row_id in self.tree.get_children():
            self.tree.delete(row_id)
        self.tree_iid_to_index = {}

        for index, item in enumerate(results):
            status_icon = {
                "legitimate": "🟢 LEGITIMATE NETWORK",
                "suspicious": "🟡 POSSIBLY SUSPICIOUS — SUSPICIOUS / REVIEW REQUIRED",
                "evil": "🔴 POSSIBLE EVIL TWIN / SUSPICIOUS"
            }.get(item["status_key"], item["final_status"])

            iid = self.tree.insert(
                "",
                "end",
                values=(
                    item["display_ssid"],
                    item.get("BSSID", ""),
                    item.get("signal_display", ""),
                    item.get("channel_display", ""),
                    item.get("security_display", ""),
                    item.get("knn_label", ""),
                    item.get("rf_label", ""),
                    status_icon
                ),
                tags=(item["status_key"],)
            )
            self.tree_iid_to_index[iid] = index

    def _fill_recommendation(self, recommendation):
        if not recommendation:
            text = "No recommendation is available."
        elif not recommendation.get("ssid"):
            text = (
                "Recommended Network:\nNone\n\n"
                f"Reason:\n{recommendation.get('reason', '')}\n\n"
                f"Warning:\n{recommendation.get('warning', '')}"
            )
        else:
            text = (
                f"Recommended Network:\n{recommendation['ssid']}\n\n"
                f"Reason:\n{recommendation.get('reason', '')}\n\n"
                f"Warning:\n{recommendation.get('warning', '')}\n\n"
                "The application does not connect to this network. It is only a recommendation from the current scan."
            )
        self._set_text(self.recommendation_text, text)

    def on_select_network(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return
        index = self.tree_iid_to_index.get(selection[0])
        if index is None or index >= len(self.results):
            return
        self._set_text(self.explanation, self.results[index]["explanation"])

    def refresh_history(self):
        for row_id in self.history_tree.get_children():
            self.history_tree.delete(row_id)

        try:
            history = load_scan_history()
        except Exception:
            return

        if history is None or history.empty:
            return

        for _, row in history.iterrows():
            self.history_tree.insert(
                "",
                "end",
                values=(
                    row.get("Timestamp", ""),
                    row.get("SSID", ""),
                    row.get("BSSID", ""),
                    row.get("Signal", ""),
                    row.get("Channel", ""),
                    row.get("Authentication", ""),
                    row.get("KNN", ""),
                    row.get("RandomForest", ""),
                    row.get("FinalStatus", "")
                )
            )


def main():
    app = EvilTwinApp()
    app.mainloop()


if __name__ == "__main__":
    main()
