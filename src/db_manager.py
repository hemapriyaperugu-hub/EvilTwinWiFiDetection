import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime

from .paths import get_data_dir


DEFAULT_SETTINGS = {
    "scan_timeout": "12",
    "suspicious_threshold": "25",
    "high_risk_threshold": "60",
    "auto_save_observations": "true",
    "check_captive_portal": "true"
}


def get_default_db_path():
    return os.path.join(get_data_dir(), "database", "eviltwin.db")


@contextmanager
def _connect(db_path=None):
    path = db_path or get_default_db_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path=None):
    """Initializes SQLite tables and default settings if not already present."""
    with _connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL,
                error_message TEXT,
                total_networks INTEGER NOT NULL DEFAULT 0,
                known_count INTEGER NOT NULL DEFAULT 0,
                new_count INTEGER NOT NULL DEFAULT 0,
                suspicious_count INTEGER NOT NULL DEFAULT 0,
                high_risk_count INTEGER NOT NULL DEFAULT 0,
                active_ssid TEXT,
                active_bssid TEXT,
                captive_portal_detected INTEGER NOT NULL DEFAULT 0,
                captive_portal_message TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                ssid TEXT NOT NULL,
                bssid TEXT NOT NULL,
                oui TEXT,
                signal_pct INTEGER,
                channel INTEGER,
                band TEXT,
                security TEXT,
                encryption TEXT,
                radio TEXT,
                classification TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                knn_pred TEXT,
                knn_confidence REAL,
                rf_pred TEXT,
                rf_confidence REAL,
                isoforest_pred TEXT,
                isoforest_score REAL,
                ml_agreement TEXT,
                trust_state TEXT,
                fingerprint TEXT,
                baseline_fingerprint TEXT,
                reasons_json TEXT NOT NULL DEFAULT '[]',
                warnings_json TEXT NOT NULL DEFAULT '[]',
                score_breakdown_json TEXT NOT NULL DEFAULT '[]',
                changes_json TEXT NOT NULL DEFAULT '[]',
                missing_features_json TEXT NOT NULL DEFAULT '[]',
                features_json TEXT NOT NULL DEFAULT '{}',
                final_decision TEXT,
                summary_advice TEXT,
                risk_score_meaning TEXT,
                is_dual_band INTEGER NOT NULL DEFAULT 0,
                is_saved_profile INTEGER NOT NULL DEFAULT 0,
                observed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                scan_result_id INTEGER REFERENCES scan_results(id) ON DELETE CASCADE,
                severity TEXT NOT NULL,
                ssid TEXT NOT NULL,
                bssid TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                classification TEXT NOT NULL,
                reason TEXT NOT NULL,
                warnings_json TEXT NOT NULL DEFAULT '[]',
                acknowledged INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        for k, v in DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
                (k, v)
            )
        # Safe migration for existing SQLite databases created prior to Isolation Forest
        existing_cols = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(scan_results)").fetchall()
        }
        if "isoforest_pred" not in existing_cols:
            conn.execute("ALTER TABLE scan_results ADD COLUMN isoforest_pred TEXT")
        if "isoforest_score" not in existing_cols:
            conn.execute("ALTER TABLE scan_results ADD COLUMN isoforest_score REAL")

        # Migrate earlier 4-state label wording cleanly while preserving scan records
        conn.execute(
            "UPDATE scan_results SET classification = 'UNVERIFIED NETWORK BUT SAFE' WHERE classification = 'UNVERIFIED / SAFE'"
        )
        conn.execute(
            "UPDATE scan_results SET classification = 'UNVERIFIED NETWORK AND UNSAFE' WHERE classification = 'UNVERIFIED / UNSAFE'"
        )
        conn.execute(
            "UPDATE alerts SET classification = 'UNVERIFIED NETWORK AND UNSAFE' WHERE classification = 'UNVERIFIED / UNSAFE'"
        )
        conn.commit()


def get_settings(db_path=None):
    """Returns typed application settings from SQLite."""
    init_db(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        raw = {r["key"]: r["value"] for r in rows}

    def _int(key, default):
        try:
            return int(raw.get(key, default))
        except (TypeError, ValueError):
            return int(default)

    def _bool(key, default):
        val = str(raw.get(key, default)).strip().lower()
        return val in ("true", "1", "yes", "on")

    return {
        "scan_timeout": max(3, min(60, _int("scan_timeout", DEFAULT_SETTINGS["scan_timeout"]))),
        "suspicious_threshold": max(10, min(80, _int("suspicious_threshold", DEFAULT_SETTINGS["suspicious_threshold"]))),
        "high_risk_threshold": max(30, min(95, _int("high_risk_threshold", DEFAULT_SETTINGS["high_risk_threshold"]))),
        "auto_save_observations": _bool("auto_save_observations", DEFAULT_SETTINGS["auto_save_observations"]),
        "check_captive_portal": _bool("check_captive_portal", DEFAULT_SETTINGS["check_captive_portal"])
    }


def update_settings(updates, db_path=None):
    """Validates and updates settings in SQLite."""
    init_db(db_path)
    current = get_settings(db_path)

    scan_timeout = int(updates.get("scan_timeout", current["scan_timeout"]))
    susp_thresh = int(updates.get("suspicious_threshold", current["suspicious_threshold"]))
    high_thresh = int(updates.get("high_risk_threshold", current["high_risk_threshold"]))

    if not (3 <= scan_timeout <= 60):
        raise ValueError("Scan timeout must be between 3 and 60 seconds.")
    if not (10 <= susp_thresh < high_thresh <= 95):
        raise ValueError("Thresholds must satisfy: 10 <= Suspicious Threshold < High-Risk Threshold <= 95.")

    auto_save = "true" if bool(updates.get("auto_save_observations", current["auto_save_observations"])) else "false"
    check_portal = "true" if bool(updates.get("check_captive_portal", current["check_captive_portal"])) else "false"

    to_save = {
        "scan_timeout": str(scan_timeout),
        "suspicious_threshold": str(susp_thresh),
        "high_risk_threshold": str(high_thresh),
        "auto_save_observations": auto_save,
        "check_captive_portal": check_portal
    }

    with _connect(db_path) as conn:
        for k, v in to_save.items():
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (k, v)
            )
        conn.commit()
    return get_settings(db_path)


def _safe_int_or_none(val):
    if val is None or val == "Unavailable" or val == "":
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _json_dumps_safe(obj):
    def _default(x):
        if isinstance(x, float) and x != x:  # NaN
            return None
        return str(x)
    clean = obj
    if isinstance(obj, dict):
        clean = {
            k: (None if isinstance(v, float) and v != v else v)
            for k, v in obj.items()
        }
    return json.dumps(clean, default=_default)


def record_scan_session(
    scan_status,
    results,
    error_message=None,
    active_iface=None,
    portal_info=None,
    timestamp=None,
    db_path=None
):
    """
    Persists a scan session, its analyzed AP results, and real threat alerts
    (for SUSPICIOUS / VERIFY and HIGH RISK / POSSIBLE EVIL TWIN) to SQLite.
    Returns the newly created scan_id.
    """
    init_db(db_path)
    ts = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = results or []

    known_cnt = sum(1 for r in results if r.get("Classification") in ("SAFE", "KNOWN / CONSISTENT"))
    new_cnt = sum(1 for r in results if r.get("Classification") in ("UNVERIFIED NETWORK BUT SAFE", "UNVERIFIED / SAFE", "NEW / UNVERIFIED"))
    susp_cnt = sum(1 for r in results if r.get("Classification") in ("UNVERIFIED NETWORK AND UNSAFE", "UNVERIFIED / UNSAFE", "SUSPICIOUS / VERIFY"))
    high_cnt = sum(1 for r in results if r.get("Classification") in ("UNSAFE", "HIGH RISK / POSSIBLE EVIL TWIN"))

    active_ssid = active_iface.get("SSID", "") if active_iface else ""
    active_bssid = active_iface.get("BSSID", "") if active_iface else ""
    portal_flag = 1 if (portal_info and portal_info[0]) else 0
    portal_msg = portal_info[1] if portal_info else ""

    with _connect(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (
                timestamp, status, error_message, total_networks,
                known_count, new_count, suspicious_count, high_risk_count,
                active_ssid, active_bssid, captive_portal_detected, captive_portal_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts, scan_status, error_message, len(results),
                known_cnt, new_cnt, susp_cnt, high_cnt,
                active_ssid, active_bssid, portal_flag, portal_msg
            )
        )
        scan_id = cur.lastrowid

        for r in results:
            res_cur = conn.execute(
                """
                INSERT INTO scan_results (
                    scan_id, ssid, bssid, oui, signal_pct, channel, band,
                    security, encryption, radio, classification, risk_score,
                    knn_pred, knn_confidence, rf_pred, rf_confidence,
                    isoforest_pred, isoforest_score, ml_agreement,
                    trust_state, fingerprint, baseline_fingerprint,
                    reasons_json, warnings_json, score_breakdown_json,
                    changes_json, missing_features_json, features_json,
                    final_decision, summary_advice, risk_score_meaning,
                    is_dual_band, is_saved_profile, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    r.get("SSID", "<Hidden Network>"),
                    r.get("BSSID", "Unavailable"),
                    r.get("OUI", "Unavailable"),
                    _safe_int_or_none(r.get("Signal")),
                    _safe_int_or_none(r.get("Channel")),
                    r.get("Band", "Unavailable"),
                    r.get("Security", "Unavailable"),
                    r.get("Encryption", "Unavailable"),
                    r.get("Radio", "Unavailable"),
                    r.get("Classification", "UNVERIFIED NETWORK BUT SAFE"),
                    int(r.get("RiskScore", 0)),
                    r.get("KNN_Pred", "Unknown"),
                    r.get("KNN_Confidence"),
                    r.get("RF_Pred", "Unknown"),
                    r.get("RF_Confidence"),
                    r.get("IsoForest_Pred", "Unavailable"),
                    r.get("IsoForest_Score"),
                    r.get("ML_Agreement", ""),
                    r.get("TrustState", ""),
                    r.get("Fingerprint", ""),
                    r.get("BaselineFingerprint") or "",
                    _json_dumps_safe(r.get("Reasons", [])),
                    _json_dumps_safe(r.get("WarningIndicators", [])),
                    _json_dumps_safe(r.get("ScoreBreakdown", [])),
                    _json_dumps_safe(r.get("Changes", [])),
                    _json_dumps_safe(r.get("MissingFeatures", [])),
                    _json_dumps_safe(r.get("Features", {})),
                    r.get("FinalDecision", ""),
                    r.get("SummaryAdvice", ""),
                    r.get("RiskScoreMeaning", ""),
                    1 if r.get("IsDualBand") else 0,
                    1 if r.get("IsSavedProfile") else 0,
                    ts
                )
            )
            result_id = res_cur.lastrowid

            cls = r.get("Classification", "")
            if cls in ("UNSAFE", "UNVERIFIED NETWORK AND UNSAFE", "UNVERIFIED / UNSAFE", "HIGH RISK / POSSIBLE EVIL TWIN", "SUSPICIOUS / VERIFY"):
                severity = "HIGH" if cls in ("UNSAFE", "HIGH RISK / POSSIBLE EVIL TWIN") else "MEDIUM"
                warnings = r.get("WarningIndicators") or []
                primary_reason = warnings[0] if warnings else r.get("FinalDecision", cls)
                conn.execute(
                    """
                    INSERT INTO alerts (
                        scan_id, scan_result_id, severity, ssid, bssid,
                        timestamp, risk_score, classification, reason, warnings_json, acknowledged
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        scan_id, result_id, severity,
                        r.get("SSID", "<Hidden Network>"),
                        r.get("BSSID", "Unavailable"),
                        ts,
                        int(r.get("RiskScore", 0)),
                        cls,
                        primary_reason,
                        _json_dumps_safe(warnings)
                    )
                )

        conn.commit()
    return scan_id


def _deserialize_result_row(row):
    d = dict(row)
    for col, key in [
        ("reasons_json", "reasons"),
        ("warnings_json", "warnings"),
        ("score_breakdown_json", "score_breakdown"),
        ("changes_json", "changes"),
        ("missing_features_json", "missing_features"),
        ("features_json", "features")
    ]:
        try:
            d[key] = json.loads(d.get(col) or ("{}" if key == "features" else "[]"))
        except Exception:
            d[key] = {} if key == "features" else []
    d["signal_display"] = f"{d['signal_pct']}%" if d.get("signal_pct") is not None else "Unavailable"
    d["channel_display"] = str(d["channel"]) if d.get("channel") is not None else "Unavailable"
    return d


def get_scan_history(limit=50, db_path=None):
    init_db(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan_detail(scan_id, db_path=None):
    init_db(db_path)
    with _connect(db_path) as conn:
        scan_row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan_row:
            return None, []
        res_rows = conn.execute(
            "SELECT * FROM scan_results WHERE scan_id = ? ORDER BY risk_score DESC, id ASC",
            (scan_id,)
        ).fetchall()
        return dict(scan_row), [_deserialize_result_row(r) for r in res_rows]


def get_network_result_detail(result_id, db_path=None):
    init_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM scan_results WHERE id = ?", (result_id,)).fetchone()
        if not row:
            return None, None, []
        result = _deserialize_result_row(row)
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (result["scan_id"],)).fetchone()
        past = conn.execute(
            """
            SELECT id, scan_id, observed_at, signal_pct, channel, security, classification, risk_score
            FROM scan_results
            WHERE ssid = ? AND bssid = ?
            ORDER BY id DESC LIMIT 15
            """,
            (result["ssid"], result["bssid"])
        ).fetchall()
        return result, (dict(scan) if scan else None), [dict(p) for p in past]


def get_latest_result_for_ap(ssid, bssid, db_path=None):
    init_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT id FROM scan_results
            WHERE ssid = ? AND LOWER(bssid) = LOWER(?)
            ORDER BY id DESC LIMIT 1
            """,
            (ssid, bssid)
        ).fetchone()
        if not row:
            return None
        return row["id"]


def get_alerts(limit=100, severity=None, include_acknowledged=True, db_path=None):
    init_db(db_path)
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if severity and severity in ("HIGH", "MEDIUM"):
        query += " AND severity = ?"
        params.append(severity)
    if not include_acknowledged:
        query += " AND acknowledged = 0"
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with _connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["warnings"] = json.loads(d.get("warnings_json") or "[]")
            except Exception:
                d["warnings"] = []
            out.append(d)
        return out


def get_unacknowledged_alert_count(db_path=None):
    init_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM alerts WHERE acknowledged = 0").fetchone()
        return int(row["cnt"]) if row else 0


def acknowledge_alert(alert_id, acknowledged=True, db_path=None):
    init_db(db_path)
    with _connect(db_path) as conn:
        conn.execute(
            "UPDATE alerts SET acknowledged = ? WHERE id = ?",
            (1 if acknowledged else 0, alert_id)
        )
        conn.commit()


def get_dashboard_stats(db_path=None):
    """
    Returns strictly real stored statistics for the Dashboard.
    Returns zeroed metrics and empty lists when no scans exist.
    """
    init_db(db_path)
    with _connect(db_path) as conn:
        total_scans_row = conn.execute("SELECT COUNT(*) AS cnt FROM scans").fetchone()
        total_scans = int(total_scans_row["cnt"]) if total_scans_row else 0

        latest_scan_row = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        latest_scan = dict(latest_scan_row) if latest_scan_row else None

        # Use latest successful scan with networks for live AP breakdown, or aggregate across scans
        latest_nonempty = conn.execute(
            "SELECT * FROM scans WHERE total_networks > 0 ORDER BY id DESC LIMIT 1"
        ).fetchone()

        if latest_nonempty:
            lid = latest_nonempty["id"]
            latest_results = [
                _deserialize_result_row(r)
                for r in conn.execute("SELECT * FROM scan_results WHERE scan_id = ?", (lid,)).fetchall()
            ]
        else:
            latest_results = []

        # Unique APs observed across all stored scans (latest status per (ssid, bssid))
        all_latest_ap_rows = conn.execute(
            """
            SELECT sr.*
            FROM scan_results sr
            INNER JOIN (
                SELECT ssid, bssid, MAX(id) AS max_id
                FROM scan_results
                GROUP BY ssid, bssid
            ) latest ON sr.id = latest.max_id
            ORDER BY sr.risk_score DESC, sr.id DESC
            """
        ).fetchall()
        unique_aps = [_deserialize_result_row(r) for r in all_latest_ap_rows]

        known_count = sum(1 for a in unique_aps if a["classification"] in ("SAFE", "KNOWN / CONSISTENT"))
        new_count = sum(1 for a in unique_aps if a["classification"] in ("UNVERIFIED NETWORK BUT SAFE", "UNVERIFIED / SAFE", "NEW / UNVERIFIED"))
        suspicious_count = sum(1 for a in unique_aps if a["classification"] in ("UNVERIFIED NETWORK AND UNSAFE", "UNVERIFIED / UNSAFE", "SUSPICIOUS / VERIFY"))
        high_risk_count = sum(1 for a in unique_aps if a["classification"] in ("UNSAFE", "HIGH RISK / POSSIBLE EVIL TWIN"))

        # Risk score distribution buckets across unique observed APs
        risk_buckets = {
            "0-24 (Low)": sum(1 for a in unique_aps if a["risk_score"] < 25),
            "25-59 (Moderate)": sum(1 for a in unique_aps if 25 <= a["risk_score"] < 60),
            "60-100 (High)": sum(1 for a in unique_aps if a["risk_score"] >= 60)
        }

        recent_scans = [
            dict(r) for r in conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 8").fetchall()
        ]
        timeline_scans = list(reversed(recent_scans))

        recent_alerts = get_alerts(limit=6, db_path=db_path)
        unack_alerts = get_unacknowledged_alert_count(db_path=db_path)

        suspicious_summary = [
            a for a in unique_aps
            if a["classification"] in ("UNSAFE", "UNVERIFIED NETWORK AND UNSAFE", "UNVERIFIED / UNSAFE", "HIGH RISK / POSSIBLE EVIL TWIN", "SUSPICIOUS / VERIFY")
        ][:8]

        return {
            "has_scans": total_scans > 0,
            "total_scans": total_scans,
            "total_networks_unique": len(unique_aps),
            "latest_scan_networks": len(latest_results),
            "known_count": known_count,
            "new_count": new_count,
            "suspicious_count": suspicious_count,
            "high_risk_count": high_risk_count,
            "unack_alerts": unack_alerts,
            "latest_scan": latest_scan,
            "recent_scans": recent_scans,
            "recent_alerts": recent_alerts,
            "suspicious_summary": suspicious_summary,
            "classification_counts": {
                "SAFE": known_count,
                "UNVERIFIED NETWORK BUT SAFE": new_count,
                "UNVERIFIED NETWORK AND UNSAFE": suspicious_count,
                "UNSAFE": high_risk_count
            },
            "risk_buckets": risk_buckets,
            "scan_timeline": [
                {
                    "id": s["id"],
                    "label": s["timestamp"][11:16] if len(s["timestamp"]) >= 16 else s["timestamp"],
                    "timestamp": s["timestamp"],
                    "total": s["total_networks"],
                    "flagged": s["suspicious_count"] + s["high_risk_count"]
                }
                for s in timeline_scans
            ]
        }


def clear_scan_sessions(db_path=None):
    """Deletes stored scan sessions and generated alerts from SQLite."""
    init_db(db_path)
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM scan_results")
        conn.execute("DELETE FROM scans")
        conn.commit()
