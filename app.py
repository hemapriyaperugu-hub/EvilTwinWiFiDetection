import csv
import io
import os
import sys
from datetime import datetime
from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for
)

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.dataset import build_training_dataset, seed_baseline_dataset
from src.db_manager import (
    acknowledge_alert,
    clear_scan_sessions,
    get_alerts,
    get_dashboard_stats,
    get_default_db_path,
    get_latest_result_for_ap,
    get_network_result_detail,
    get_scan_detail,
    get_scan_history,
    get_settings,
    get_unacknowledged_alert_count,
    init_db,
    record_scan_session,
    update_settings
)
from src.history import (
    clear_unverified_history,
    get_ap_record,
    get_default_history_path,
    load_history,
    mark_ap_trusted,
    unverify_ap,
    update_history
)
from src.paths import get_data_dir, get_resource_dir
from src.predict import analyze_scanned_networks, load_isolation_forest, load_models
from src.scanner import get_default_dataset_path, save_observations_to_csv, scan_wifi_detailed
from src.system_profiles import check_captive_portal, get_active_wifi_interface
from src.train import train_models


def ensure_models_ready():
    """Ensures serialized RF, KNN, and Isolation Forest models exist and load cleanly."""
    try:
        load_models()
        if load_isolation_forest() is None:
            raise FileNotFoundError("isolation_forest_model.pkl missing")
    except Exception:
        seed_baseline_dataset(overwrite_if_exists=False)
        build_training_dataset()
        train_models()


def create_app(db_path=None, history_path=None, observations_path=None, reports_dir=None):
    resource_dir = get_resource_dir()
    data_dir = get_data_dir()
    app = Flask(
        __name__,
        template_folder=os.path.join(resource_dir, "templates"),
        static_folder=os.path.join(resource_dir, "static"),
    )
    app.secret_key = os.environ.get("EVILTWIN_SECRET_KEY", "eviltwin-local-session-key")

    app.config["DB_PATH"] = db_path or get_default_db_path()
    app.config["HISTORY_PATH"] = history_path or get_default_history_path()
    app.config["OBSERVATIONS_PATH"] = observations_path or get_default_dataset_path()
    app.config["REPORTS_DIR"] = reports_dir or os.path.join(data_dir, "Reports")

    init_db(app.config["DB_PATH"])
    ensure_models_ready()

    @app.context_processor
    def inject_globals():
        return {
            "unack_alerts_count": get_unacknowledged_alert_count(app.config["DB_PATH"]),
            "current_endpoint": request.endpoint or ""
        }

    # -----------------------------------------------------------------
    # PAGE 1: DASHBOARD
    # -----------------------------------------------------------------
    @app.route("/")
    def dashboard():
        stats = get_dashboard_stats(app.config["DB_PATH"])
        return render_template("dashboard.html", stats=stats)

    @app.route("/api/dashboard")
    def api_dashboard():
        stats = get_dashboard_stats(app.config["DB_PATH"])
        return jsonify(stats)

    # -----------------------------------------------------------------
    # PAGE 2: WI-FI NETWORK SCANNER
    # -----------------------------------------------------------------
    @app.route("/scanner")
    def scanner_page():
        settings = get_settings(app.config["DB_PATH"])
        scans = get_scan_history(limit=1, db_path=app.config["DB_PATH"])
        latest_scan = None
        latest_results = []
        if scans:
            latest_scan, latest_results = get_scan_detail(scans[0]["id"], app.config["DB_PATH"])
        return render_template(
            "scanner.html",
            latest_scan=latest_scan,
            latest_results=latest_results,
            settings=settings
        )

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        db = app.config["DB_PATH"]
        hist_path = app.config["HISTORY_PATH"]
        obs_path = app.config["OBSERVATIONS_PATH"]

        settings = get_settings(db)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        scan_res = scan_wifi_detailed(timeout=settings["scan_timeout"])
        active_iface = get_active_wifi_interface()

        portal_info = None
        if settings["check_captive_portal"] and active_iface.get("State") == "connected":
            portal_info = check_captive_portal(timeout=3)

        if not scan_res["success"]:
            scan_id = record_scan_session(
                scan_status="FAILED",
                results=[],
                error_message=scan_res["error"],
                active_iface=active_iface,
                portal_info=portal_info,
                timestamp=ts,
                db_path=db
            )
            return jsonify({
                "success": False,
                "error": scan_res["error"],
                "scan_id": scan_id,
                "timestamp": ts,
                "unack_alerts": get_unacknowledged_alert_count(db)
            })

        scanned_networks = scan_res["networks"]
        if not scanned_networks:
            scan_id = record_scan_session(
                scan_status="EMPTY",
                results=[],
                error_message=None,
                active_iface=active_iface,
                portal_info=portal_info,
                timestamp=ts,
                db_path=db
            )
            scan_row, _ = get_scan_detail(scan_id, db)
            return jsonify({
                "success": True,
                "scan": scan_row,
                "results": [],
                "unack_alerts": get_unacknowledged_alert_count(db)
            })

        if settings["auto_save_observations"]:
            save_observations_to_csv(scanned_networks, csv_path=obs_path)

        history_df = load_history(hist_path)
        results, _ = analyze_scanned_networks(
            scanned_networks,
            history_df=history_df,
            suspicious_threshold=settings["suspicious_threshold"],
            high_risk_threshold=settings["high_risk_threshold"]
        )

        update_history(scanned_networks, history_path=hist_path, assessments=results)

        scan_id = record_scan_session(
            scan_status="SUCCESS",
            results=results,
            error_message=None,
            active_iface=active_iface,
            portal_info=portal_info,
            timestamp=ts,
            db_path=db
        )

        scan_row, db_results = get_scan_detail(scan_id, db)
        return jsonify({
            "success": True,
            "scan": scan_row,
            "results": db_results,
            "unack_alerts": get_unacknowledged_alert_count(db)
        })

    # -----------------------------------------------------------------
    # PAGE 3: NETWORK DETAILS PAGE
    # -----------------------------------------------------------------
    @app.route("/network/<int:result_id>")
    def network_details(result_id):
        db = app.config["DB_PATH"]
        hist_path = app.config["HISTORY_PATH"]
        result, parent_scan, past_observations = get_network_result_detail(result_id, db)
        if not result:
            flash("Network scan record not found.", "warning")
            return redirect(url_for("scanner_page"))

        history_df = load_history(hist_path)
        ap_record = get_ap_record(history_df, result["ssid"], result["bssid"])
        return render_template(
            "network_details.html",
            net=result,
            scan=parent_scan,
            ap_record=ap_record,
            past_observations=past_observations
        )

    @app.route("/network/lookup")
    def network_lookup():
        ssid = request.args.get("ssid", "")
        bssid = request.args.get("bssid", "")
        db = app.config["DB_PATH"]
        latest_id = get_latest_result_for_ap(ssid, bssid, db)
        if latest_id is not None:
            return redirect(url_for("network_details", result_id=latest_id))

        history_df = load_history(app.config["HISTORY_PATH"])
        ap_record = get_ap_record(history_df, ssid, bssid)
        if not ap_record:
            flash("No recorded details found for that access point.", "warning")
            return redirect(url_for("history_page"))

        synthetic_view = {
            "id": None,
            "scan_id": None,
            "ssid": ap_record.get("SSID", ssid),
            "bssid": ap_record.get("BSSID", bssid),
            "oui": ap_record.get("OUI", "Unavailable"),
            "signal_display": f"{ap_record.get('Last Signal')}%" if ap_record.get("Last Signal") not in ("", None, "Unavailable") else "Unavailable",
            "channel_display": ap_record.get("Last Channel", "Unavailable"),
            "band": ap_record.get("Band", "Unavailable"),
            "security": ap_record.get("Last Security", "Unavailable"),
            "encryption": ap_record.get("Encryption", "Unavailable"),
            "radio": "Unavailable",
            "classification": ap_record.get("Previous Classification", "UNVERIFIED NETWORK BUT SAFE"),
            "risk_score": 0,
            "knn_pred": "Not in recent scan",
            "knn_confidence": None,
            "rf_pred": "Not in recent scan",
            "rf_confidence": None,
            "isoforest_pred": "Not in recent scan",
            "isoforest_score": None,
            "ml_agreement": "Run a new scan for live ML evaluation",
            "trust_state": ap_record.get("Trust Status", "OBSERVED_UNVERIFIED"),
            "fingerprint": ap_record.get("Fingerprint", ""),
            "baseline_fingerprint": ap_record.get("Fingerprint", ""),
            "reasons": ["Record loaded from persistent AP baseline history (network_history.csv)."],
            "warnings": [w.strip() for w in str(ap_record.get("Suspicious Indicators", "")).split(";") if w.strip()],
            "score_breakdown": [],
            "changes": [c.strip() for c in str(ap_record.get("Changes", "")).split(";") if c.strip()],
            "missing_features": [],
            "final_decision": "Historical baseline view; run a live scan to evaluate current RF state.",
            "summary_advice": "Verify AP identity before connecting.",
            "risk_score_meaning": "No live scan score computed for historical-only lookup."
        }
        return render_template(
            "network_details.html",
            net=synthetic_view,
            scan=None,
            ap_record=ap_record,
            past_observations=[]
        )

    @app.route("/api/network/trust", methods=["POST"])
    def api_trust_network():
        data = request.get_json(silent=True) or request.form
        ssid = (data.get("ssid") or "").strip()
        bssid = (data.get("bssid") or "").strip()
        if not ssid or not bssid:
            return jsonify({"success": False, "error": "SSID and BSSID are required."}), 400

        ap_info = None
        latest_id = get_latest_result_for_ap(ssid, bssid, app.config["DB_PATH"])
        if latest_id is not None:
            res_row, _, _ = get_network_result_detail(latest_id, app.config["DB_PATH"])
            if res_row:
                ap_info = {
                    "SSID": res_row["ssid"],
                    "BSSID": res_row["bssid"],
                    "Security": res_row["security"],
                    "Encryption": res_row["encryption"],
                    "Channel": res_row["channel"],
                    "Band": res_row["band"],
                    "Signal": res_row["signal_pct"]
                }

        mark_ap_trusted(ssid, bssid, history_path=app.config["HISTORY_PATH"], ap_info=ap_info)
        return jsonify({
            "success": True,
            "message": f"'{ssid}' [{bssid}] manually verified and saved as TRUSTED_BASELINE. Re-scan to refresh classification."
        })

    @app.route("/api/network/untrust", methods=["POST"])
    def api_untrust_network():
        data = request.get_json(silent=True) or request.form
        ssid = (data.get("ssid") or "").strip()
        bssid = (data.get("bssid") or "").strip()
        if not ssid or not bssid:
            return jsonify({"success": False, "error": "SSID and BSSID are required."}), 400

        unverify_ap(ssid, bssid, history_path=app.config["HISTORY_PATH"])
        return jsonify({
            "success": True,
            "message": f"Manual verification revoked for '{ssid}' [{bssid}]. Status reverted to OBSERVED_UNVERIFIED."
        })

    # -----------------------------------------------------------------
    # PAGE 4: THREAT ALERTS
    # -----------------------------------------------------------------
    @app.route("/alerts")
    def alerts_page():
        severity = request.args.get("severity", "ALL").upper()
        only_unack = request.args.get("unack", "0") == "1"
        alerts = get_alerts(
            limit=200,
            severity=severity if severity in ("HIGH", "MEDIUM") else None,
            include_acknowledged=not only_unack,
            db_path=app.config["DB_PATH"]
        )
        return render_template(
            "alerts.html",
            alerts=alerts,
            active_severity=severity,
            only_unack=only_unack
        )

    @app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
    def api_ack_alert(alert_id):
        data = request.get_json(silent=True) or {}
        ack = bool(data.get("acknowledged", True))
        acknowledge_alert(alert_id, acknowledged=ack, db_path=app.config["DB_PATH"])
        return jsonify({
            "success": True,
            "unack_alerts": get_unacknowledged_alert_count(app.config["DB_PATH"])
        })

    # -----------------------------------------------------------------
    # PAGE 5: SCAN HISTORY & PERSISTENT AP FINGERPRINTS
    # -----------------------------------------------------------------
    @app.route("/history")
    def history_page():
        scans = get_scan_history(limit=100, db_path=app.config["DB_PATH"])
        hist_df = load_history(app.config["HISTORY_PATH"])
        ap_records = hist_df.to_dict(orient="records") if not hist_df.empty else []
        return render_template("history.html", scans=scans, ap_records=ap_records)

    @app.route("/history/scan/<int:scan_id>")
    def scan_detail_page(scan_id):
        scan_row, results = get_scan_detail(scan_id, app.config["DB_PATH"])
        if not scan_row:
            flash("Scan session not found.", "warning")
            return redirect(url_for("history_page"))
        return render_template("scan_detail.html", scan=scan_row, results=results)

    # -----------------------------------------------------------------
    # PAGE 6: REPORT GENERATION & EXPORTS
    # -----------------------------------------------------------------
    @app.route("/reports")
    def reports_page():
        scans = get_scan_history(limit=50, db_path=app.config["DB_PATH"])
        reports_dir = app.config["REPORTS_DIR"]
        os.makedirs(reports_dir, exist_ok=True)
        saved_files = sorted(
            [
                f for f in os.listdir(reports_dir)
                if f.endswith((".csv", ".html"))
            ],
            reverse=True
        )[:20]
        return render_template("reports.html", scans=scans, saved_files=saved_files)

    @app.route("/reports/export/csv/<int:scan_id>")
    def export_scan_csv(scan_id):
        scan_row, results = get_scan_detail(scan_id, app.config["DB_PATH"])
        if not scan_row:
            flash("Scan session not found for export.", "warning")
            return redirect(url_for("reports_page"))

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Scan ID", "Scan Timestamp", "SSID", "BSSID", "OUI",
            "Signal Quality", "Channel", "Band", "Security", "Encryption",
            "Classification", "Risk Score", "RF Primary Prediction", "RF Confidence %",
            "KNN Comparison Prediction", "KNN Confidence %",
            "Isolation Forest Anomaly", "IsoForest Score", "ML Consensus",
            "Trust Baseline", "Warnings", "Reasons"
        ])
        for r in results:
            writer.writerow([
                scan_row["id"],
                scan_row["timestamp"],
                r["ssid"],
                r["bssid"],
                r["oui"],
                r["signal_display"],
                r["channel_display"],
                r["band"],
                r["security"],
                r["encryption"],
                r["classification"],
                f"{r['risk_score']}/100",
                r["rf_pred"],
                r["rf_confidence"] if r["rf_confidence"] is not None else "N/A",
                r["knn_pred"],
                r["knn_confidence"] if r["knn_confidence"] is not None else "N/A",
                r.get("isoforest_pred") or "Unavailable",
                r["isoforest_score"] if r.get("isoforest_score") is not None else "N/A",
                r["ml_agreement"],
                r["trust_state"],
                " | ".join(r["warnings"]),
                " | ".join(r["reasons"])
            ])

        csv_text = output.getvalue()
        filename = f"eviltwin_scan_{scan_id}_{scan_row['timestamp'].replace(':', '-').replace(' ', '_')}.csv"
        reports_dir = app.config["REPORTS_DIR"]
        os.makedirs(reports_dir, exist_ok=True)
        with open(os.path.join(reports_dir, filename), "w", encoding="utf-8", newline="") as f:
            f.write(csv_text)

        return Response(
            csv_text,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    @app.route("/reports/export/html/<int:scan_id>")
    def export_scan_html(scan_id):
        scan_row, results = get_scan_detail(scan_id, app.config["DB_PATH"])
        if not scan_row:
            flash("Scan session not found for export.", "warning")
            return redirect(url_for("reports_page"))

        alerts = [a for a in get_alerts(limit=500, db_path=app.config["DB_PATH"]) if a["scan_id"] == scan_id]
        rendered = render_template(
            "report_printable.html",
            scan=scan_row,
            results=results,
            alerts=alerts,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        filename = f"eviltwin_report_{scan_id}_{scan_row['timestamp'].replace(':', '-').replace(' ', '_')}.html"
        reports_dir = app.config["REPORTS_DIR"]
        os.makedirs(reports_dir, exist_ok=True)
        with open(os.path.join(reports_dir, filename), "w", encoding="utf-8") as f:
            f.write(rendered)

        if request.args.get("download") == "1":
            return Response(
                rendered,
                mimetype="text/html",
                headers={"Content-Disposition": f"attachment; filename={filename}"}
            )
        return rendered

    @app.route("/reports/export/history-csv")
    def export_history_csv():
        hist_df = load_history(app.config["HISTORY_PATH"])
        csv_text = hist_df.to_csv(index=False)
        return Response(
            csv_text,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=network_history_export.csv"}
        )

    # -----------------------------------------------------------------
    # PAGE 7: SETTINGS
    # -----------------------------------------------------------------
    @app.route("/settings", methods=["GET", "POST"])
    def settings_page():
        db = app.config["DB_PATH"]
        hist_path = app.config["HISTORY_PATH"]

        if request.method == "POST":
            action = request.form.get("action", "save_settings")
            if action == "save_settings":
                try:
                    update_settings(
                        {
                            "scan_timeout": request.form.get("scan_timeout", 12),
                            "suspicious_threshold": request.form.get("suspicious_threshold", 25),
                            "high_risk_threshold": request.form.get("high_risk_threshold", 60),
                            "auto_save_observations": "auto_save_observations" in request.form,
                            "check_captive_portal": "check_captive_portal" in request.form
                        },
                        db_path=db
                    )
                    flash("Settings saved successfully.", "success")
                except ValueError as err:
                    flash(str(err), "danger")
            elif action == "clear_scans":
                clear_scan_sessions(db_path=db)
                flash("Stored scan sessions and alerts cleared from database.", "info")
            elif action == "clear_unverified_history":
                clear_unverified_history(history_path=hist_path)
                flash("Unverified and flagged passive history entries cleared; trusted baselines preserved.", "info")
            return redirect(url_for("settings_page"))

        settings = get_settings(db)
        hist_df = load_history(hist_path)
        scans = get_scan_history(limit=1000, db_path=db)
        info = {
            "python_version": sys.version.split()[0],
            "db_path": db,
            "history_path": hist_path,
            "history_count": len(hist_df),
            "scan_count": len(scans)
        }
        return render_template("settings.html", settings=settings, info=info)

    return app


app = create_app()


if __name__ == "__main__":
    print("============================================================")
    print("  Evil Twin Wi-Fi Attack Detection System - Web Application")
    print("  Local URL: http://127.0.0.1:5000")
    print("============================================================")
    app.run(host="127.0.0.1", port=5000, debug=False)
