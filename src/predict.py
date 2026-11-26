import os
import sys
import joblib
import pandas as pd

from .features import (
    FEATURE_COLUMNS,
    analyze_scanned_relationships,
    classify_security_comparison,
    extract_ap_diagnostics,
    extract_features,
    generate_feature_explanations,
    get_compatible_security_tiers,
    get_security_tier,
    is_unavailable
)
from .history import (
    TRUST_ESTABLISHED,
    TRUST_FLAGGED,
    TRUST_UNVERIFIED,
    extract_oui,
    get_ap_record,
    get_known_encryptions_for_ssid,
    get_known_securities_for_ssid,
    get_verified_records_for_ssid,
    load_history,
    sanitize_bssid,
    sanitize_ssid
)
from .paths import get_data_dir, get_resource_dir
from .system_profiles import get_profile_security_details, get_saved_windows_profiles


# ============================================================
# MODEL PATHS & LOADING
# ============================================================

def get_model_paths():
    data_models = os.path.join(get_data_dir(), "models")
    res_models = os.path.join(get_resource_dir(), "models")

    def _pick(name):
        p_data = os.path.join(data_models, name)
        if os.path.exists(p_data):
            return p_data
        p_res = os.path.join(res_models, name)
        return p_res if os.path.exists(p_res) else p_data

    return {
        "knn": _pick("knn_model.pkl"),
        "random_forest": _pick("random_forest_model.pkl"),
        "isolation_forest": _pick("isolation_forest_model.pkl")
    }


def load_isolation_forest():
    """
    Loads trained Isolation Forest anomaly detector if available.
    Returns None gracefully if missing or unreadable (keeping load_models() 2-tuple compatible).
    """
    paths = get_model_paths()
    iso_path = paths.get("isolation_forest")
    if not iso_path or not os.path.exists(iso_path):
        return None
    try:
        return joblib.load(iso_path)
    except Exception:
        return None


def load_models():
    """
    Loads trained KNN and Random Forest models with robust error handling.
    Raises descriptive exceptions if models are missing or corrupt.
    """
    paths = get_model_paths()

    if not os.path.exists(paths["knn"]):
        raise FileNotFoundError(
            f"KNN model file not found at: {paths['knn']}\n"
            "Train models first using: python -m src.train"
        )

    if not os.path.exists(paths["random_forest"]):
        raise FileNotFoundError(
            f"Random Forest model file not found at: {paths['random_forest']}\n"
            "Train models first using: python -m src.train"
        )

    try:
        knn = joblib.load(paths["knn"])
    except Exception as e:
        raise ValueError(
            f"Corrupted or invalid KNN model file at {paths['knn']}: {e}\n"
            "Retrain models using: python -m src.train"
        )

    try:
        random_forest = joblib.load(paths["random_forest"])
    except Exception as e:
        raise ValueError(
            f"Corrupted or invalid Random Forest model file at {paths['random_forest']}: {e}\n"
            "Retrain models using: python -m src.train"
        )

    return knn, random_forest


def get_safe_badge(badge_char, fallback_text):
    try:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        badge_char.encode(encoding)
        return badge_char
    except Exception:
        return fallback_text


# ============================================================
# CLEAR, CONSISTENT CLASSIFICATION CONSTANTS
# ============================================================

STATUS_SAFE = "SAFE"
STATUS_UNVERIFIED_SAFE = "UNVERIFIED NETWORK BUT SAFE"
STATUS_UNVERIFIED_UNSAFE = "UNVERIFIED NETWORK AND UNSAFE"
STATUS_UNSAFE = "UNSAFE"

# Backward-compatible constants mapped directly to the 4 clear classifications
STATUS_KNOWN_CONSISTENT = STATUS_SAFE
STATUS_NEW_UNVERIFIED = STATUS_UNVERIFIED_SAFE
STATUS_SUSPICIOUS = STATUS_UNVERIFIED_UNSAFE
STATUS_HIGH_RISK = STATUS_UNSAFE

DESC_KNOWN_CONSISTENT = "SAFE — No suspicious indicators detected during this scan; matches your verified baseline fingerprint."
DESC_NEW_UNVERIFIED = "UNVERIFIED NETWORK BUT SAFE — Not registered/verified yet, but uses standard encryption with no suspicious indicators (okay to connect if you recognize it)."
DESC_SUSPICIOUS = "UNVERIFIED NETWORK AND UNSAFE — Not registered/verified and has suspicious indicators, unencrypted traffic, or missing security. Verify before connecting."
DESC_HIGH_RISK = "UNSAFE — Multiple independent indicators suggest a possible Evil Twin attack. Do not connect."

STATUS_LEGITIMATE = STATUS_SAFE
STATUS_NEW = STATUS_UNVERIFIED_SAFE
STATUS_EVIL_TWIN = STATUS_UNSAFE
RISK_LOWER = DESC_KNOWN_CONSISTENT
RISK_UNCERTAIN = DESC_SUSPICIOUS
RISK_HIGH = DESC_HIGH_RISK


# ============================================================
# EXPLAINABLE, CONSERVATIVE RISK WEIGHTS (0-100 SCALE)
# ============================================================
# Non-overlapping dimensions prevent double-counting correlated indicators.
# Missing attributes contribute 0 risk points and instead communicate uncertainty.
# Prior history flags contribute 0 risk points so repeated scans never self-escalate.

RISK_WEIGHTS = {
    "security_downgrade": 40,          # Genuine downgrade vs verified/secured baseline
    "security_shift_moderate": 25,     # Non-critical shift on manually verified AP (e.g. WPA3 -> WPA2)
    "unencrypted_network": 20,         # Open / WEP network without downgrade
    "bssid_collision": 30,             # Duplicate identical BSSID in same scan
    "bssid_ssid_mismatch": 25,         # BSSID previously seen under a different SSID
    "unfamiliar_bssid_known_ssid": 25, # Known/verified SSID broadcasting from unfamiliar BSSID
    "concurrent_duplicate_ssid": 10,   # Competing duplicate SSID (non-dual-band, non-same-OUI multi-AP)
    "channel_deviation": 10,           # Channel differs from baseline
    "signal_jump": 10,                 # >= 30% sudden signal jump vs previous observation of same AP
    "ml_both_attack": 20,              # Both RF (primary) and KNN (comparison) predict Evil Twin
    "ml_disagreement": 15,             # RF and KNN disagree
    "isoforest_anomaly": 10            # Isolation Forest unsupervised anomaly flag (supporting only)
}

THRESHOLD_SUSPICIOUS = 25
THRESHOLD_HIGH_RISK = 60


def describe_score_level(score, suspicious_threshold=THRESHOLD_SUSPICIOUS, high_risk_threshold=THRESHOLD_HIGH_RISK):
    """Explains what the numeric 0-100 risk score represents."""
    if score >= high_risk_threshold:
        return (
            f"Score {score}/100 (>= {high_risk_threshold}): High accumulated risk from "
            "multiple independent security, identity, or RF anomalies."
        )
    if score >= suspicious_threshold:
        return (
            f"Score {score}/100 ({suspicious_threshold}-{high_risk_threshold - 1}): "
            "Moderate risk / inconsistency requiring manual verification before connecting."
        )
    if score > 0:
        return (
            f"Score {score}/100 (1-{suspicious_threshold - 1}): Low/informational risk "
            "context only; insufficient evidence of malicious activity."
        )
    return "Score 0/100: No suspicious risk indicators triggered during this scan."


def _predict_with_confidence(model, model_input):
    """
    Runs model.predict() and extracts predicted-class probability from predict_proba()
    ONLY if supported by the model. Never fabricates confidence scores.
    Returns (prediction_int, confidence_pct_or_None, attack_prob_pct_or_None).
    """
    pred = int(model.predict(model_input)[0])
    conf_pct = None
    attack_prob_pct = None
    if hasattr(model, "predict_proba"):
        try:
            probs = model.predict_proba(model_input)[0]
            classes = list(getattr(model, "classes_", [0, 1]))
            if len(probs) >= 2 and 1 in classes and 0 in classes:
                idx_0 = classes.index(0)
                idx_1 = classes.index(1)
                p_legit = float(probs[idx_0])
                p_attack = float(probs[idx_1])
                attack_prob_pct = round(p_attack * 100.0, 1)
                chosen = p_attack if pred == 1 else p_legit
                conf_pct = round(chosen * 100.0, 1)
            elif len(probs) > pred:
                conf_pct = round(float(probs[pred]) * 100.0, 1)
        except Exception:
            conf_pct = None
            attack_prob_pct = None
    return pred, conf_pct, attack_prob_pct


# ============================================================
# EVIDENCE-BASED RISK ASSESSMENT ENGINE
# ============================================================

def assess_network_risk(
    network,
    features_row,
    knn_prediction,
    rf_prediction,
    ap_record=None,
    history_df=None,
    scan_context=None,
    suspicious_threshold=THRESHOLD_SUSPICIOUS,
    high_risk_threshold=THRESHOLD_HIGH_RISK,
    isoforest_prediction=1,
    isoforest_score=None
):
    """
    Conservative, explainable Wi-Fi risk assessment engine.

    Design invariants:
    - WPA2-Personal / CCMP or other standard configurations never trigger risk points alone.
    - Saved Windows profiles do not falsely flag WPA3-profile vs WPA2-CCMP transitions.
    - Missing fields contribute 0 risk points and communicate uncertainty.
    - Prior history flags never add self-amplifying points across repeated scans.
    - Repeated passive observations never auto-promote unverified APs to KNOWN / CONSISTENT.
    - HIGH RISK requires >= high_risk_threshold AND >= 2 independent warning indicators.
    """
    ssid = sanitize_ssid(network.get("SSID", ""))
    bssid = sanitize_bssid(network.get("BSSID", ""))

    same_ssid_count = int(features_row.get("SameSSIDCount", 1))
    bssid_known = int(features_row.get("BSSIDKnown", 0))
    raw_ch_match = features_row.get("ChannelMatch", 1)
    channel_match = 1 if pd.isna(raw_ch_match) else int(raw_ch_match)
    raw_sec_match = features_row.get("SecurityMatch", 1)
    security_match = 1 if pd.isna(raw_sec_match) else int(raw_sec_match)

    diag = extract_ap_diagnostics(network, features_row, history_df=history_df, context_info=scan_context)

    bssid_collision = bool(scan_context.get("bssid_collision", False)) if scan_context else False
    is_dual_band = bool(scan_context.get("is_dual_band", False)) if scan_context else False
    is_saved_profile = bool(scan_context.get("is_saved_profile", False)) if scan_context else False
    profile_security = scan_context.get("profile_security", "Unavailable") if scan_context else "Unavailable"
    partner_bssid = scan_context.get("partner_bssid", "") if scan_context else ""
    is_consistent_multiap = bool(
        scan_context.get("is_consistent_multiap", scan_context.get("is_enterprise_multiap", False))
    ) if scan_context else False

    obs_count = 0
    prior_trust = "UNFAMILIAR"
    prior_suspicious_str = ""
    if ap_record is not None:
        try:
            obs_count = int(ap_record.get("Observation Count", 1))
        except (ValueError, TypeError):
            obs_count = 1
        prior_trust = str(ap_record.get("Trust Status", TRUST_UNVERIFIED)).strip()
        prior_suspicious_str = str(ap_record.get("Suspicious Indicators", "")).strip()
        if prior_suspicious_str.lower() in ("nan", "none"):
            prior_suspicious_str = ""

    # Check explicitly verified baselines vs observed history for this SSID
    verified_ssid_df = get_verified_records_for_ssid(history_df, ssid) if history_df is not None else pd.DataFrame()
    has_verified_ssid_baseline = not verified_ssid_df.empty
    ssid_known_in_history = False
    if history_df is not None and not history_df.empty and "SSID" in history_df.columns and ssid:
        ssid_known_in_history = ssid in history_df["SSID"].astype(str).str.strip().values
    elif scan_context and scan_context.get("ssid_known_in_history"):
        ssid_known_in_history = True

    # Manual verification status applies ONLY when this exact (SSID, BSSID) is TRUSTED_BASELINE
    is_manually_verified_ap = (prior_trust == TRUST_ESTABLISHED and bssid_known == 1)

    # Security comparison hierarchy:
    # 1. Verified baseline records for this SSID (strictest, most trustworthy reference)
    # 2. Historical records for this SSID (flags only genuine downgrade, not formatting/mixed-mode)
    # 3. Saved Windows profile (flags ONLY critical downgrade to Open/WEP/WPA1 or Enterprise->Personal)
    sec_eval = "NO_BASELINE"
    sec_eval_source = "No verified baseline"

    if has_verified_ssid_baseline:
        ver_secs = set(verified_ssid_df["Security"].dropna().astype(str).tolist())
        ver_encs = set(verified_ssid_df["Encryption"].dropna().astype(str).tolist()) if "Encryption" in verified_ssid_df.columns else set()
        sec_eval = classify_security_comparison(network.get("Security"), network.get("Encryption"), ver_secs, ver_encs)
        sec_eval_source = "Verified Baseline"
    elif ssid_known_in_history:
        known_secs = get_known_securities_for_ssid(history_df, ssid)
        known_encs = get_known_encryptions_for_ssid(history_df, ssid)
        raw_eval = classify_security_comparison(network.get("Security"), network.get("Encryption"), known_secs, known_encs)
        # On unverified observed history, ignore non-critical WPA3->WPA2 preference differences
        sec_eval = "DOWNGRADE_CRITICAL" if raw_eval == "DOWNGRADE_CRITICAL" else ("UNAVAILABLE" if raw_eval == "UNAVAILABLE" else "MATCH")
        sec_eval_source = "Observed History"

    if sec_eval in ("NO_BASELINE", "MATCH") and is_saved_profile and not is_unavailable(profile_security):
        prof_eval = classify_security_comparison(network.get("Security"), network.get("Encryption"), {profile_security}, set())
        if prof_eval == "DOWNGRADE_CRITICAL":
            sec_eval = "DOWNGRADE_CRITICAL"
            sec_eval_source = "Saved Windows Profile"

    # Also respect explicit security_match=0 passed via compatibility wrapper (e.g. unit test stubs)
    if sec_eval == "NO_BASELINE" and security_match == 0 and scan_context and scan_context.get("ssid_known_in_history"):
        sec_eval = "DOWNGRADE_CRITICAL"
        sec_eval_source = "Baseline Context"

    sec_tier = diag["SecurityTier"]
    sec_bin = diag["SecurityBinary"]
    is_open_or_wep = (sec_bin == 0) or (sec_tier is not None and sec_tier <= 1)
    is_security_missing = is_unavailable(network.get("Security")) and (sec_bin is None)

    is_security_downgrade = (sec_eval == "DOWNGRADE_CRITICAL")
    is_security_shift = (sec_eval == "SHIFT_MODERATE")

    # Unfamiliar or unverified BSSID for a verified/known SSID:
    # - Dual-band partners or consistent same-OUI multi-AP clusters are NOT penalized.
    # - If the SSID has a manually verified baseline, any other BSSID for that SSID that
    #   is NOT itself manually verified remains unfamiliar/unverified across repeated scans!
    is_unfamiliar_bssid_known_ssid = (
        (
            (has_verified_ssid_baseline and not is_manually_verified_ap)
            or (ssid_known_in_history and bssid_known == 0)
        )
        and (not is_dual_band)
        and (not is_consistent_multiap)
        and bool(ssid)
        and ssid != "<Hidden Network>"
    )
    is_bssid_ssid_mismatch = len(diag["BSSIDOtherSSIDs"]) > 0
    is_concurrent_duplicate = (
        same_ssid_count >= 2
        and not is_dual_band
        and not is_consistent_multiap
    )
    is_channel_conflict = (
        (channel_match == 0)
        and (has_verified_ssid_baseline or ssid_known_in_history)
        and (not is_dual_band)
        and (diag["Channel"] is not None)
    )
    is_signal_jump = diag["SignalDelta"] is not None and abs(diag["SignalDelta"]) >= 30

    ml_both_attack = (knn_prediction == 1 and rf_prediction == 1)
    ml_both_legit = (knn_prediction == 0 and rf_prediction == 0)
    ml_disagree = (knn_prediction != rf_prediction)

    # --------------------------------------------------------
    # SCORING ENGINE (NON-OVERLAPPING DIMENSIONS, MAX 100)
    # --------------------------------------------------------
    score_breakdown = []
    independent_warnings = 0
    observed_evidence = []
    warning_indicators = []
    technical_limitations = [
        "Windows netsh station scanning cannot inspect raw 802.11 management frames (deauth floods, vendor IEs, beacon intervals).",
        "Passive scanning cannot verify RADIUS/TLS certificates or detect post-association captive portals before connecting."
    ]

    def add_score(factor_name, points, severity, source, reason):
        score_breakdown.append({
            "factor": factor_name,
            "points": points,
            "severity": severity,
            "source": source,
            "reason": reason
        })

    # 1. Security Dimension (mutually exclusive)
    if is_security_downgrade:
        add_score(
            "Security Downgrade",
            RISK_WEIGHTS["security_downgrade"],
            "HIGH",
            sec_eval_source,
            f"Observed security ({diag['Security']} / {diag['Encryption']}) is genuinely weaker than {sec_eval_source.lower()}."
        )
        warning_indicators.append(
            f"Security downgrade detected against {sec_eval_source.lower()}: observed {diag['Security']} / {diag['Encryption']}."
        )
        independent_warnings += 1
    elif is_security_shift:
        add_score(
            "Security Configuration Changed",
            RISK_WEIGHTS["security_shift_moderate"],
            "MODERATE",
            sec_eval_source,
            f"Observed security ({diag['Security']}) differs from verified baseline (non-critical shift within AES suites)."
        )
        warning_indicators.append(
            f"Security configuration changed compared to verified baseline: observed {diag['Security']} / {diag['Encryption']}."
        )
        independent_warnings += 1
    elif is_open_or_wep:
        add_score(
            "Unencrypted / Weak Network",
            RISK_WEIGHTS["unencrypted_network"],
            "MODERATE",
            "Security Analysis",
            f"Network uses weak or unencrypted security ({diag['Security']})."
        )
        warning_indicators.append(
            f"Unencrypted or legacy security ({diag['Security']}): traffic is exposed to passive eavesdropping."
        )
        independent_warnings += 1
    elif is_security_missing:
        observed_evidence.append("Security configuration is unavailable in scan output (no suspicious penalty applied; treated as uncertain).")
    else:
        observed_evidence.append(
            f"Standard cryptographic security observed: {diag['Security']} (Encryption: {diag['Encryption']})."
        )

    # 2. BSSID Identity Dimension (mutually exclusive)
    if bssid_collision:
        add_score(
            "Duplicate BSSID Collision",
            RISK_WEIGHTS["bssid_collision"],
            "HIGH",
            "BSSID Identity",
            "Identical BSSID observed multiple times simultaneously in the same scan."
        )
        warning_indicators.append(
            "Duplicate identical BSSID detected concurrently in this scan (possible MAC spoofing)."
        )
        independent_warnings += 1
    elif is_bssid_ssid_mismatch:
        add_score(
            "BSSID Changed SSID",
            RISK_WEIGHTS["bssid_ssid_mismatch"],
            "MODERATE",
            "BSSID Identity",
            f"BSSID '{bssid}' previously advertised different SSID(s): {', '.join(diag['BSSIDOtherSSIDs'])}."
        )
        warning_indicators.append(
            f"BSSID '{bssid}' was previously seen under different SSID(s): {', '.join(diag['BSSIDOtherSSIDs'])}."
        )
        independent_warnings += 1
    elif is_unfamiliar_bssid_known_ssid:
        add_score(
            "Unfamiliar BSSID for Known SSID",
            RISK_WEIGHTS["unfamiliar_bssid_known_ssid"],
            "MODERATE",
            "BSSID Identity",
            f"Known SSID '{ssid}' appeared with an unverified BSSID '{bssid}' (could be a repeater/mesh node or rogue AP)."
        )
        warning_indicators.append(
            f"Known SSID '{ssid}' observed with an unfamiliar BSSID '{bssid}' (OUI: {diag['OUI']}). Verify whether this is a legitimate AP/extender."
        )
        independent_warnings += 1
    elif bssid_known == 1:
        observed_evidence.append(
            f"BSSID '{bssid}' matches previous observation(s) for '{ssid}' ({obs_count} prior scan(s); trust: {prior_trust})."
        )
    else:
        observed_evidence.append(
            f"First observation of BSSID '{bssid}' (OUI: {diag['OUI']}) for '{ssid}'."
        )

    # 3. Concurrent Duplicate SSID Dimension
    if is_concurrent_duplicate:
        add_score(
            "Multiple APs Sharing SSID",
            RISK_WEIGHTS["concurrent_duplicate_ssid"],
            "LOW",
            "Multi-AP Context",
            f"{same_ssid_count} APs broadcast '{ssid}' simultaneously without dual-band or same-OUI hardware correlation."
        )
        if is_unfamiliar_bssid_known_ssid or is_security_downgrade:
            warning_indicators.append(
                f"Multiple access points ({same_ssid_count}) share '{ssid}' concurrently."
            )
        else:
            observed_evidence.append(
                f"Multiple access points ({same_ssid_count}) share '{ssid}' (common in mesh, repeater, or campus deployments)."
            )
    elif is_dual_band:
        observed_evidence.append(
            f"Dual-band router correlated: complementary radio ({partner_bssid}) shares OUI {diag['OUI']} with matching security."
        )
    elif is_consistent_multiap:
        observed_evidence.append(
            f"Consistent multi-AP deployment observed ({same_ssid_count} APs sharing '{ssid}' with matching OUI/Enterprise security)."
        )

    # 4. Channel / Band Dimension
    if diag["Channel"] is None:
        observed_evidence.append("Operating channel is unavailable in scan output (treated as uncertain).")
    elif is_channel_conflict:
        add_score(
            "Channel Changed vs Baseline",
            RISK_WEIGHTS["channel_deviation"],
            "LOW",
            "RF Telemetry",
            f"Channel {diag['Channel']} ({diag['Band']}) differs from baseline channel(s) (can happen naturally via router auto-channel)."
        )
        observed_evidence.append(
            f"Channel note: operating on channel {diag['Channel']} ({diag['Band']}), which differs from prior baseline channel(s)."
        )
        independent_warnings += 1
    else:
        observed_evidence.append(f"Operating on Wi-Fi channel {diag['Channel']} ({diag['Band']}).")

    # 5. Signal-Strength Dimension (high signal alone NEVER adds risk)
    if diag["Signal"] is None:
        observed_evidence.append("Signal quality is unavailable in scan output.")
    elif is_signal_jump:
        add_score(
            "Abrupt Signal Shift",
            RISK_WEIGHTS["signal_jump"],
            "LOW",
            "RF Telemetry",
            f"Signal shifted by {diag['SignalDelta']:+d}% compared to previous scan of this BSSID."
        )
        observed_evidence.append(
            f"Signal shift note: {diag['PreviousSignal']}% -> {diag['Signal']}% ({diag['SignalDelta']:+d}%)."
        )

    # 6. Machine Learning Supporting Evidence Dimension
    # Random Forest (primary) + KNN (comparison) + Isolation Forest (anomaly detection)
    if ml_both_attack:
        add_score(
            "ML Consensus: Evil Twin",
            RISK_WEIGHTS["ml_both_attack"],
            "MODERATE",
            "ML Consensus (RF + KNN)",
            "Both Random Forest (primary) and KNN (comparison) flagged feature pattern as suspicious (supporting indicator only)."
        )
        warning_indicators.append("ML consensus: Both Random Forest and KNN flagged feature vector as suspicious.")
        independent_warnings += 1
    elif ml_disagree:
        add_score(
            "ML Model Disagreement",
            RISK_WEIGHTS["ml_disagreement"],
            "LOW",
            "ML Consensus (RF vs KNN)",
            "Random Forest and KNN disagree; result requires human verification rather than automatic approval."
        )
        warning_indicators.append(
            f"ML model disagreement: Random Forest={'Legitimate' if rf_prediction == 0 else 'Evil Twin'}, "
            f"KNN={'Legitimate' if knn_prediction == 0 else 'Evil Twin'}."
        )
    else:
        observed_evidence.append("Supervised ML check: Both Random Forest (primary) and KNN (comparison) predict Legitimate.")

    if isoforest_prediction == -1:
        score_txt = f" (score: {isoforest_score:.3f})" if isoforest_score is not None else ""
        add_score(
            "Isolation Forest Anomaly",
            RISK_WEIGHTS["isoforest_anomaly"],
            "LOW",
            "Isolation Forest (Unsupervised)",
            f"Unsupervised Isolation Forest flagged unusual feature combination{score_txt}; supporting anomaly signal only."
        )
        observed_evidence.append(
            f"Isolation Forest anomaly note: feature vector differs from typical baseline patterns{score_txt}."
        )
    elif isoforest_prediction == 1:
        observed_evidence.append("Isolation Forest check: network characteristics fall within normal expected feature distribution.")

    # Informative note if saved profile has WPA3 while AP advertises WPA2-Personal / CCMP
    if is_saved_profile and not is_unavailable(profile_security):
        prof_tiers = get_compatible_security_tiers(profile_security)
        curr_tiers = get_compatible_security_tiers(network.get("Security"))
        if prof_tiers == {4} and curr_tiers == {3} and not is_security_downgrade and not is_security_shift:
            observed_evidence.append(
                f"Note: Windows saved profile lists {profile_security}, while AP beacon advertises WPA2-Personal / CCMP "
                "(common in WPA2/WPA3 transition mode; not treated as a downgrade without a verified strict-WPA3 baseline)."
            )

    # Record fingerprint changes from diagnostics
    for chg in diag["Changes"]:
        if "Security changed" in chg and not is_security_downgrade and not is_security_shift:
            continue
        if chg not in warning_indicators and chg not in observed_evidence:
            observed_evidence.append(f"Baseline comparison note: {chg}")

    risk_score = min(100, sum(item["points"] for item in score_breakdown))
    score_meaning = describe_score_level(
        risk_score,
        suspicious_threshold=suspicious_threshold,
        high_risk_threshold=high_risk_threshold
    )

    critical_missing = [f for f in diag["MissingFeatures"] if f in ("SSID", "BSSID", "Signal", "Channel", "Security")]
    has_prior_suspicious_note = (prior_trust == TRUST_FLAGGED) or bool(prior_suspicious_str)

    if is_manually_verified_ap:
        trust_state = f"MANUALLY_VERIFIED ({obs_count} observation(s))"
    elif prior_trust == TRUST_FLAGGED:
        trust_state = f"PREVIOUSLY_FLAGGED_UNVERIFIED ({obs_count} observation(s))"
    elif bssid_known == 1:
        trust_state = f"OBSERVED_UNVERIFIED ({obs_count} observation(s); repetition does not grant trust)"
    elif is_saved_profile:
        trust_state = "SAVED_PROFILE_SSID_ONLY (AP BSSID not manually verified)"
    else:
        trust_state = "UNFAMILIAR (First observation)"

    # ========================================================
    # CONSERVATIVE 4-STATE CLASSIFICATION DECISION
    # ========================================================
    if risk_score >= high_risk_threshold and independent_warnings >= 2:
        classification = STATUS_UNSAFE
        risk_category = DESC_HIGH_RISK
        badge = get_safe_badge("🔴", "[UNSAFE]")
        advice = (
            "DO NOT CONNECT. Multiple independent risk indicators suggest possible Evil Twin impersonation. "
            "Confirm the legitimate BSSID and security configuration with the network owner."
        )
        if ml_both_legit:
            final_decision = "UNSAFE: High-risk rule-based and fingerprint indicators override Legitimate ML predictions."
        else:
            final_decision = "UNSAFE: Multiple independent security, identity, and RF indicators support possible Evil Twin impersonation."

    elif (
        risk_score >= suspicious_threshold
        or is_security_downgrade
        or is_security_shift
        or is_unfamiliar_bssid_known_ssid
        or bssid_collision
        or is_bssid_ssid_mismatch
        or ml_disagree
        or ml_both_attack
        or is_open_or_wep
        or is_security_missing
    ):
        classification = STATUS_UNVERIFIED_UNSAFE
        risk_category = DESC_SUSPICIOUS
        badge = get_safe_badge("🟠", "[UNVERIFIED NETWORK AND UNSAFE]")
        if is_open_or_wep:
            advice = (
                f"UNVERIFIED NETWORK AND UNSAFE ({diag['Security']}). Traffic is unencrypted and can be intercepted. "
                "Avoid sensitive logins or use a VPN."
            )
            final_decision = f"UNVERIFIED NETWORK AND UNSAFE — Network uses {diag['Security']} (unencrypted/legacy security)."
        elif is_security_missing:
            advice = (
                "Security configuration is unavailable in scan output; cannot confirm encryption. "
                "Verify before connecting."
            )
            final_decision = "UNVERIFIED NETWORK AND UNSAFE — Security attribute is unavailable; treating security as unverified and unsafe."
        elif ml_both_legit:
            advice = (
                "VERIFY BEFORE CONNECTING. Inconsistencies or uncertain indicators were detected, "
                "which do not by themselves prove an attack. Confirm the AP identity before trusting."
            )
            final_decision = "UNVERIFIED NETWORK AND UNSAFE — Rule-based or identity indicators require verification despite Legitimate ML predictions."
        elif ml_disagree:
            advice = (
                "VERIFY BEFORE CONNECTING. ML models disagree; confirm the network identity before trusting."
            )
            final_decision = "UNVERIFIED NETWORK AND UNSAFE — Random Forest and KNN models disagree; flagged for manual review."
        else:
            advice = (
                "VERIFY BEFORE CONNECTING. Inconsistencies or uncertain indicators were detected. "
                "Confirm the AP identity before trusting."
            )
            final_decision = "UNVERIFIED NETWORK AND UNSAFE — Classified as unverified and unsafe due to detected security, BSSID, or ML risk indicators."

    elif (not is_manually_verified_ap) or (len(critical_missing) > 0):
        classification = STATUS_UNVERIFIED_SAFE
        risk_category = DESC_NEW_UNVERIFIED
        badge = get_safe_badge("🔵", "[UNVERIFIED NETWORK BUT SAFE]")
        if critical_missing:
            advice = (
                f"Standard encryption observed, though some RF attributes ({', '.join(critical_missing)}) were unavailable. "
                "Okay to connect if you recognize this network."
            )
            final_decision = (
                f"UNVERIFIED NETWORK BUT SAFE — Standard encryption present; non-security attributes ({', '.join(critical_missing)}) unavailable."
            )
        elif has_prior_suspicious_note:
            advice = (
                "Current scan shows standard encryption with no active suspicious indicators, though an earlier scan recorded warnings. "
                "Verify manually if this is your own network."
            )
            final_decision = (
                "UNVERIFIED NETWORK BUT SAFE — Re-evaluated cleanly from current evidence (no active anomalies; not registered yet)."
            )
        elif bssid_known == 1:
            advice = (
                "Observed previously with standard encryption and no suspicious indicators. "
                "Okay to connect if you recognize it; use 'Verify & Trust Baseline' to mark it SAFE."
            )
            final_decision = (
                "UNVERIFIED NETWORK BUT SAFE — Passively observed previously with no anomalies; repeated scans do not register or verify an AP."
            )
        else:
            advice = (
                "Not registered/verified yet, but uses standard encryption with no suspicious indicators detected. "
                "Okay to connect if you recognize the network name."
            )
            final_decision = (
                "UNVERIFIED NETWORK BUT SAFE — First-time observation with standard encryption and no suspicious indicators."
            )

    else:
        classification = STATUS_SAFE
        risk_category = DESC_KNOWN_CONSISTENT
        badge = get_safe_badge("🟢", "[SAFE]")
        advice = (
            "SAFE — Matches your manually verified baseline fingerprint with no suspicious anomalies. "
            "Note: passive scanning cannot guarantee absolute safety."
        )
        if warning_indicators or observed_evidence and is_channel_conflict:
            final_decision = (
                "SAFE — Matches manually verified baseline; minor RF channel note recorded."
            )
        else:
            final_decision = (
                "SAFE — Manually verified baseline fingerprint matches current observation with ML consensus."
            )

    return {
        "Classification": classification,
        "RiskCategory": risk_category,
        "RiskBadge": badge,
        "TrustState": trust_state,
        "AcademicStatus": classification,
        "SummaryAdvice": advice,
        "FinalDecision": final_decision,
        "RiskScore": risk_score,
        "RiskScoreMax": 100,
        "ScoreBreakdown": score_breakdown,
        "RiskScoreMeaning": score_meaning,
        "ObservedEvidence": observed_evidence,
        "WarningIndicators": warning_indicators,
        "TechnicalLimitations": technical_limitations,
        "Diagnostics": diag,
        "Changes": diag["Changes"]
    }


# ============================================================
# COMPATIBILITY WRAPPER FOR EXISTING SUITE
# ============================================================

def determine_final_classification(
    knn_pred,
    rf_pred,
    features_row,
    ap_record=None,
    ssid_known_in_history=False,
    scan_context=None
):
    """
    Backward-compatible entry point returning 5-tuple:
    (badge, final_status, risk_badge, risk_category, advice)
    """
    sec_val = features_row.get("Security", 1)
    sec_str = "Unavailable" if pd.isna(sec_val) else ("WPA2-Personal" if int(sec_val) == 1 else "Open")
    ch_val = features_row.get("Channel", 1)
    sig_val = features_row.get("Signal", 75)

    ctx = dict(scan_context or {})
    if ssid_known_in_history:
        ctx["ssid_known_in_history"] = True

    network_stub = {
        "SSID": ctx.get("ssid", "Simulated_AP"),
        "BSSID": ctx.get("bssid", "00:11:22:33:44:55"),
        "Signal": None if pd.isna(sig_val) else sig_val,
        "Channel": None if pd.isna(ch_val) else ch_val,
        "Security": sec_str,
        "Encryption": "CCMP" if sec_str == "WPA2-Personal" else ("None" if sec_str == "Open" else "Unavailable")
    }

    assessment = assess_network_risk(
        network=network_stub,
        features_row=features_row,
        knn_prediction=knn_pred,
        rf_prediction=rf_pred,
        ap_record=ap_record,
        history_df=None,
        scan_context=ctx
    )

    return (
        assessment["RiskBadge"],
        assessment["Classification"],
        assessment["RiskBadge"],
        assessment["RiskCategory"],
        assessment["SummaryAdvice"]
    )


# ============================================================
# ANALYZE SCANNED NETWORKS
# ============================================================

def _detect_consistent_multiap(scanned_networks):
    """
    Identifies SSIDs whose concurrently scanned APs form a consistent Enterprise
    or same-OUI secured multi-AP deployment (campus, office, or unified mesh).
    """
    multiap_ssids = set()
    by_ssid = {}
    for n in scanned_networks:
        ssid = sanitize_ssid(n.get("SSID", ""))
        if ssid and ssid != "<Hidden Network>":
            by_ssid.setdefault(ssid, []).append(n)

    for ssid, aps in by_ssid.items():
        if len(aps) < 2:
            continue
        tiers = [get_security_tier(a.get("Security")) for a in aps]
        # Enterprise multi-AP (all Enterprise with compatible security)
        if all(t is not None and t >= 5 for t in tiers):
            multiap_ssids.add(ssid)
            continue
        # Same-OUI secured multi-AP / mesh (all secured >= WPA2 and share vendor OUI)
        ouis = {extract_oui(a.get("BSSID", "")) for a in aps}
        if "Unavailable" not in ouis and len(ouis) == 1 and all(t is not None and t >= 3 for t in tiers):
            multiap_ssids.add(ssid)

    return multiap_ssids


def analyze_scanned_networks(
    scanned_networks,
    history_df=None,
    suspicious_threshold=THRESHOLD_SUSPICIOUS,
    high_risk_threshold=THRESHOLD_HIGH_RISK
):
    """
    Performs complete evidence-based risk assessment on scanned networks:
    1. Feature extraction (preserving unavailable attributes honestly)
    2. Dual-band & Enterprise/same-OUI multi-AP correlation
    3. Windows Saved Wi-Fi Profiles context check
    4. ML model inference (KNN + Random Forest + real probabilities if supported)
    5. Conservative Rule-Based Risk Scoring & 4-State Classification
    """
    if not scanned_networks:
        return [], []

    if history_df is None:
        history_df = load_history()

    knn, random_forest = load_models()
    iso_forest = load_isolation_forest()

    saved_profiles = get_saved_windows_profiles()
    profile_details_cache = {}
    for net in scanned_networks:
        ssid = sanitize_ssid(net.get("SSID", ""))
        if ssid and ssid in saved_profiles and ssid not in profile_details_cache:
            profile_details_cache[ssid] = get_profile_security_details(ssid)

    features_df = extract_features(
        scanned_networks,
        history_df=history_df,
        saved_profiles_details=profile_details_cache
    )
    relationships = analyze_scanned_relationships(scanned_networks)
    consistent_multiap_ssids = _detect_consistent_multiap(scanned_networks)

    all_bssids = [
        sanitize_bssid(n.get("BSSID", ""))
        for n in scanned_networks
        if sanitize_bssid(n.get("BSSID", ""))
    ]
    bssid_counts = pd.Series(all_bssids).value_counts().to_dict() if all_bssids else {}

    results = []
    safer_candidates = []

    for index, network in enumerate(scanned_networks):
        feature_row = features_df.iloc[index].to_dict()
        model_input = pd.DataFrame([feature_row])[FEATURE_COLUMNS]

        knn_prediction, knn_conf, knn_attack_prob = _predict_with_confidence(knn, model_input)
        rf_prediction, rf_conf, rf_attack_prob = _predict_with_confidence(random_forest, model_input)

        iso_pred = None
        iso_score = None
        if iso_forest is not None:
            try:
                iso_pred = int(iso_forest.predict(model_input)[0])
                iso_score = round(float(iso_forest.decision_function(model_input)[0]), 4)
            except Exception:
                iso_pred = None
                iso_score = None

        ssid = sanitize_ssid(network.get("SSID", ""))
        bssid = sanitize_bssid(network.get("BSSID", ""))
        ap_record = get_ap_record(history_df, ssid, bssid)

        is_saved = ssid in saved_profiles
        p_det = profile_details_cache.get(ssid, {})
        rel_info = relationships.get(bssid, {})
        is_dual_band = rel_info.get("is_dual_band", False)

        scan_context = {
            "ssid": ssid,
            "bssid": bssid,
            "bssid_collision": bool(bssid) and bssid_counts.get(bssid, 1) > 1,
            "is_dual_band": is_dual_band,
            "partner_bssid": rel_info.get("partner_bssid", ""),
            "is_saved_profile": is_saved,
            "profile_security": p_det.get("Authentication", "Unavailable"),
            "profile_cipher": p_det.get("Cipher", "Unavailable"),
            "is_consistent_multiap": ssid in consistent_multiap_ssids
        }

        assessment = assess_network_risk(
            network=network,
            features_row=feature_row,
            knn_prediction=knn_prediction,
            rf_prediction=rf_prediction,
            ap_record=ap_record,
            history_df=history_df,
            scan_context=scan_context,
            suspicious_threshold=suspicious_threshold,
            high_risk_threshold=high_risk_threshold,
            isoforest_prediction=iso_pred,
            isoforest_score=iso_score
        )

        reasons = generate_feature_explanations(network, feature_row, history_df, context_info=scan_context)
        diag = assessment["Diagnostics"]

        if knn_prediction == 0 and rf_prediction == 0:
            ml_agreement = "Agree (Legitimate)"
        elif knn_prediction == 1 and rf_prediction == 1:
            ml_agreement = "Agree (Evil Twin)"
        else:
            ml_agreement = "Disagree (Uncertain)"

        result = {
            "SSID": diag["SSID"],
            "BSSID": diag["BSSID"],
            "OUI": diag["OUI"],
            "Signal": diag["Signal"],
            "SignalDisplay": f"{diag['Signal']}%" if diag["Signal"] is not None else "Unavailable",
            "SignalDelta": diag["SignalDelta"],
            "Channel": diag["Channel"] if diag["Channel"] is not None else "Unavailable",
            "Band": diag["Band"],
            "Security": diag["Security"],
            "Encryption": diag["Encryption"],
            "Radio": network.get("Radio") or "Unavailable",
            "MissingFeatures": diag["MissingFeatures"],
            "Fingerprint": diag["CurrentFingerprint"],
            "BaselineFingerprint": diag["BaselineFingerprint"],
            "Changes": assessment["Changes"],
            "RF_Pred": "Legitimate" if rf_prediction == 0 else "Evil Twin",
            "RF_Confidence": rf_conf,
            "RF_AttackProb": rf_attack_prob,
            "KNN_Pred": "Legitimate" if knn_prediction == 0 else "Evil Twin",
            "KNN_Confidence": knn_conf,
            "KNN_AttackProb": knn_attack_prob,
            "IsoForest_Pred": "Normal" if iso_pred == 1 else ("Anomaly" if iso_pred == -1 else "Unavailable"),
            "IsoForest_Score": iso_score,
            "ML_Agreement": ml_agreement,
            "Classification": assessment["Classification"],
            "TrustState": assessment["TrustState"],
            "RiskCategory": assessment["RiskCategory"],
            "RiskBadge": assessment["RiskBadge"],
            "RiskScore": assessment["RiskScore"],
            "RiskScoreMax": assessment["RiskScoreMax"],
            "ScoreBreakdown": assessment["ScoreBreakdown"],
            "RiskScoreMeaning": assessment["RiskScoreMeaning"],
            "FinalDecision": assessment["FinalDecision"],
            "SummaryAdvice": assessment["SummaryAdvice"],
            "ObservedEvidence": assessment["ObservedEvidence"],
            "WarningIndicators": assessment["WarningIndicators"],
            "TechnicalLimitations": assessment["TechnicalLimitations"],
            "AcademicStatus": assessment["Classification"],
            "Badge": assessment["RiskBadge"],
            "FinalResult": assessment["Classification"],
            "VerdictBadge": assessment["RiskBadge"],
            "ConnectionVerdict": assessment["RiskCategory"],
            "ConnectionAdvice": assessment["SummaryAdvice"],
            "IsDualBand": is_dual_band,
            "IsSavedProfile": is_saved,
            "Reasons": reasons,
            "Features": feature_row
        }

        results.append(result)

        if assessment["Classification"] == STATUS_KNOWN_CONSISTENT:
            weight = 1
            if ap_record:
                try:
                    weight = int(ap_record.get("Observation Count", 1))
                except (ValueError, TypeError):
                    weight = 1
            safer_candidates.append({
                "SSID": diag["SSID"],
                "BSSID": diag["BSSID"],
                "Signal": diag["Signal"] if diag["Signal"] is not None else 0,
                "RiskCategory": assessment["RiskCategory"],
                "ObservationCount": weight
            })

    safer_candidates.sort(
        key=lambda item: (item["ObservationCount"], item["Signal"]),
        reverse=True
    )

    return results, safer_candidates


if __name__ == "__main__":
    print("==================================================")
    print("       RISK ASSESSMENT ENGINE READY               ")
    print("==================================================")
    try:
        load_models()
        print("Models loaded successfully. Risk assessment engine operational.")
    except Exception as err:
        print(f"Error loading models:\n{err}")
