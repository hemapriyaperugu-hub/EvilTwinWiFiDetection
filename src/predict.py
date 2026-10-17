import os
import sys
import joblib
import pandas as pd

from .features import (
    extract_features,
    generate_feature_explanations,
    analyze_scanned_relationships,
    FEATURE_COLUMNS
)
from .history import load_history, get_ap_record, get_trust_state
from .system_profiles import get_saved_windows_profiles, get_profile_security_details


# ============================================================
# MODEL PATHS & LOADING
# ============================================================

def get_model_paths():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "knn": os.path.join(base_dir, "models", "knn_model.pkl"),
        "random_forest": os.path.join(base_dir, "models", "random_forest_model.pkl")
    }


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


# ============================================================
# CONSOLE BADGES
# ============================================================

def get_safe_badge(badge_char, fallback_text):
    try:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        badge_char.encode(encoding)
        return badge_char
    except Exception:
        return fallback_text


# ============================================================
# THREE PRIMARY USER-FACING RISK CATEGORIES
# ============================================================

RISK_LOWER = "LOWER RISK — NO SIGNIFICANT WARNING INDICATORS DETECTED"
RISK_UNCERTAIN = "UNCERTAIN — VERIFY BEFORE CONNECTING"
RISK_HIGH = "HIGH RISK — DO NOT CONNECT"

# Internal Academic / Lifecycle Classifications
STATUS_LEGITIMATE = "LIKELY LEGITIMATE"
STATUS_NEW = "NEW / UNVERIFIED"
STATUS_SUSPICIOUS = "SUSPICIOUS — VERIFY NETWORK"
STATUS_EVIL_TWIN = "POSSIBLE EVIL TWIN"


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
    scan_context=None
):
    """
    Evidence-based risk assessment that evaluates all relevant information:
    - Advertised cryptographic security
    - Physical channel, band, and signal characteristics
    - SSID & BSSID relationships (dual-band hardware vs conflicting clones)
    - Windows saved profile baseline
    - Observation history (treated as one source of evidence, not the sole basis)
    - Machine learning consensus (KNN + Random Forest)

    Returns a rich evaluation dictionary with primary RiskCategory,
    internal TrustState, specific evidence, warnings, and limitations.
    """
    ssid = str(network.get("SSID", "")).strip()
    bssid = str(network.get("BSSID", "")).strip().lower()

    signal = int(features_row.get("Signal", 0))
    channel = int(features_row.get("Channel", 1))
    security_bin = int(features_row.get("Security", 1))
    same_ssid_count = int(features_row.get("SameSSIDCount", 1))
    bssid_known = int(features_row.get("BSSIDKnown", 0))
    channel_match = int(features_row.get("ChannelMatch", 1))
    security_match = int(features_row.get("SecurityMatch", 1))

    # Contextual flags
    bssid_collision = False
    is_dual_band = False
    is_saved_profile = False
    partner_bssid = ""

    if scan_context:
        bssid_collision = scan_context.get("bssid_collision", False)
        is_dual_band = scan_context.get("is_dual_band", False)
        is_saved_profile = scan_context.get("is_saved_profile", False)
        partner_bssid = scan_context.get("partner_bssid", "")

    obs_count = 0
    if ap_record is not None:
        try:
            obs_count = int(ap_record.get("Observation Count", 1))
        except (ValueError, TypeError):
            obs_count = 1

    # Check whether SSID was ever observed previously
    ssid_known_in_history = False
    if history_df is not None and not history_df.empty and "SSID" in history_df.columns:
        ssid_known_in_history = ssid in history_df["SSID"].astype(str).str.strip().values

    # Determine internal Trust State
    if is_saved_profile:
        trust_state = "USER_VERIFIED (Saved Profile)"
    elif bssid_known == 1 and obs_count >= 1:
        trust_state = f"PREVIOUSLY_OBSERVED ({obs_count} prior observation(s))"
    elif is_dual_band:
        trust_state = "HARDWARE_CORRELATED (Dual-Band Complementary Radio)"
    else:
        trust_state = "UNFAMILIAR (First Time Encountered on this Device)"

    observed_evidence = []
    warning_indicators = []
    technical_limitations = [
        "Windows passive station scanning operates via NDIS drivers; it cannot inspect raw 802.11 management frames (beacons, probe requests, deauthentication frames).",
        "Passive scanning cannot inspect TLS certificates, RADIUS servers, or captive portals prior to network association."
    ]

    # Evaluate Cryptographic Quality
    sec_desc = str(network.get("Security", "Unknown")).strip()
    enc_desc = str(network.get("Encryption", "CCMP")).strip()

    if "wpa3" in sec_desc.lower():
        observed_evidence.append(f"Modern cryptographic security: {sec_desc} enforces Protected Management Frames (PMF / 802.11w) by standard.")
    elif "wpa2" in sec_desc.lower():
        observed_evidence.append(f"Standard cryptographic security: {sec_desc} with {enc_desc} encryption present.")
    elif "enterprise" in sec_desc.lower() or "802.1x" in sec_desc.lower():
        observed_evidence.append(f"Enterprise cryptographic security: 802.1X/RADIUS authentication suite advertised ({sec_desc}).")
    elif security_bin == 0 or "open" in sec_desc.lower() or "none" in sec_desc.lower():
        warning_indicators.append("Unencrypted network: Open Wi-Fi advertises zero cryptographic encryption. Radio traffic can be observed by any listener in range.")

    # Evaluate Hardware & RF Relationship
    band_name = network.get("Band", "5 GHz" if (32 <= channel <= 177) else "2.4 GHz")
    if is_dual_band:
        observed_evidence.append(
            f"Dual-band router hardware correlated: Complementary radio detected ({partner_bssid}) "
            f"with matching vendor OUI, consecutive MAC addresses, and complementary {band_name} band."
        )
    elif same_ssid_count > 1:
        if not (is_dual_band or "enterprise" in sec_desc.lower()):
            warning_indicators.append(
                f"SSID multiplicity: {same_ssid_count} access points broadcast the same SSID concurrently without clear dual-band hardware signatures."
            )

    # Evaluate Physical RF Channels
    if (1 <= channel <= 14) or (32 <= channel <= 177):
        observed_evidence.append(f"Operating on standard authorized Wi-Fi channel {channel} ({band_name} band).")

    # Evaluate ML Consensus
    ml_both_attack = (knn_prediction == 1 and rf_prediction == 1)
    ml_both_legit = (knn_prediction == 0 and rf_prediction == 0)
    ml_disagree = (knn_prediction != rf_prediction)

    if ml_both_legit:
        observed_evidence.append("Machine learning consensus: Both K-Nearest Neighbors and Random Forest classify physical RF characteristics as Legitimate.")
    elif ml_disagree:
        warning_indicators.append(
            f"Model disagreement: KNN classified as {'Legitimate' if knn_prediction == 0 else 'Evil Twin'}, "
            f"while Random Forest classified as {'Legitimate' if rf_prediction == 0 else 'Evil Twin'}."
        )
    elif ml_both_attack:
        warning_indicators.append("Machine learning consensus: Both KNN and Random Forest classify RF characteristics as Rogue / Suspicious.")

    # Evaluate Anomaly Flags
    is_security_downgrade = (security_match == 0) and (ssid_known_in_history or is_saved_profile)
    is_channel_conflict = (channel_match == 0) and ssid_known_in_history and not is_dual_band
    is_concurrent_broadcast = (same_ssid_count >= 2) and not is_dual_band

    if is_security_downgrade:
        warning_indicators.append("CRITICAL: Advertised security configuration represents a downgrade compared to the known historical or saved profile.")

    if is_channel_conflict:
        warning_indicators.append(f"Channel discrepancy: Channel {channel} conflicts with known historical profile for this SSID.")

    if bssid_collision:
        warning_indicators.append("CRITICAL: Duplicate identical BSSID detected multiple times in the same scan session (potential MAC address spoofing).")

    if is_saved_profile and not is_security_downgrade:
        observed_evidence.append(f"User-verified baseline: Network matches a saved, user-configured Windows profile ('{ssid}').")

    # ========================================================
    # RISK CATEGORY ASSIGNMENT
    # ========================================================

    # Category 1: HIGH RISK — DO NOT CONNECT
    # Requires multiple relevant indicators or credible threat evidence
    if is_security_downgrade and (is_concurrent_broadcast or is_channel_conflict or ml_both_attack):
        return {
            "RiskCategory": RISK_HIGH,
            "RiskBadge": get_safe_badge("🔴", "[HIGH RISK]"),
            "TrustState": trust_state,
            "AcademicStatus": STATUS_EVIL_TWIN,
            "SummaryAdvice": "DO NOT CONNECT. Credible threat evidence indicates an active Evil Twin or rogue access point impersonating a known network with downgraded security.",
            "ObservedEvidence": observed_evidence,
            "WarningIndicators": warning_indicators,
            "TechnicalLimitations": technical_limitations
        }

    if (ssid_known_in_history or is_saved_profile) and bssid_known == 0 and is_channel_conflict and is_concurrent_broadcast and ml_both_attack:
        return {
            "RiskCategory": RISK_HIGH,
            "RiskBadge": get_safe_badge("🔴", "[HIGH RISK]"),
            "TrustState": trust_state,
            "AcademicStatus": STATUS_EVIL_TWIN,
            "SummaryAdvice": "DO NOT CONNECT. Multiple corroborating indicators (unverified BSSID, conflicting channel, concurrent competing broadcast, ML consensus) indicate a rogue clone.",
            "ObservedEvidence": observed_evidence,
            "WarningIndicators": warning_indicators,
            "TechnicalLimitations": technical_limitations
        }

    if bssid_collision and (is_security_downgrade or is_channel_conflict):
        return {
            "RiskCategory": RISK_HIGH,
            "RiskBadge": get_safe_badge("🔴", "[HIGH RISK]"),
            "TrustState": trust_state,
            "AcademicStatus": STATUS_EVIL_TWIN,
            "SummaryAdvice": "DO NOT CONNECT. MAC address collision detected in the same scan with conflicting operating parameters.",
            "ObservedEvidence": observed_evidence,
            "WarningIndicators": warning_indicators,
            "TechnicalLimitations": technical_limitations
        }

    # Category 2: UNCERTAIN — VERIFY BEFORE CONNECTING
    # Insufficient evidence, open network, model disagreement, or single unexpected change
    if security_bin == 0 or "open" in sec_desc.lower() or "none" in sec_desc.lower():
        return {
            "RiskCategory": RISK_UNCERTAIN,
            "RiskBadge": get_safe_badge("🟠", "[UNCERTAIN]"),
            "TrustState": trust_state,
            "AcademicStatus": STATUS_NEW if bssid_known == 0 else STATUS_SUSPICIOUS,
            "SummaryAdvice": "VERIFY BEFORE CONNECTING. Open unencrypted network with zero cryptographic protection. Anyone in range can eavesdrop on unencrypted communications. Use a VPN if connection is necessary.",
            "ObservedEvidence": observed_evidence,
            "WarningIndicators": warning_indicators,
            "TechnicalLimitations": technical_limitations
        }

    if ml_disagree or is_channel_conflict or is_security_downgrade:
        return {
            "RiskCategory": RISK_UNCERTAIN,
            "RiskBadge": get_safe_badge("🟠", "[UNCERTAIN]"),
            "TrustState": trust_state,
            "AcademicStatus": STATUS_SUSPICIOUS,
            "SummaryAdvice": "VERIFY BEFORE CONNECTING. Ambiguous or conflicting indicators observed. Verify the access point identity with venue staff or network administrator.",
            "ObservedEvidence": observed_evidence,
            "WarningIndicators": warning_indicators,
            "TechnicalLimitations": technical_limitations
        }

    # Category 3: LOWER RISK — NO SIGNIFICANT WARNING INDICATORS DETECTED
    # Available evidence is consistent with legitimate network; no significant warnings
    if is_saved_profile and security_match == 1 and not bssid_collision and not is_security_downgrade:
        return {
            "RiskCategory": RISK_LOWER,
            "RiskBadge": get_safe_badge("🟢", "[LOWER RISK]"),
            "TrustState": trust_state,
            "AcademicStatus": STATUS_LEGITIMATE,
            "SummaryAdvice": "No significant warning indicators detected. Matches your saved Windows profile with verified encryption and consistent hardware characteristics. Note: This is not an absolute guarantee of safety.",
            "ObservedEvidence": observed_evidence,
            "WarningIndicators": warning_indicators,
            "TechnicalLimitations": technical_limitations
        }

    if bssid_known == 1 and security_match == 1 and not bssid_collision:
        return {
            "RiskCategory": RISK_LOWER,
            "RiskBadge": get_safe_badge("🟢", "[LOWER RISK]"),
            "TrustState": trust_state,
            "AcademicStatus": STATUS_LEGITIMATE,
            "SummaryAdvice": "No significant warning indicators detected. Consistent with previous observations with stable channel and encryption characteristics. Note: This is not an absolute guarantee of safety.",
            "ObservedEvidence": observed_evidence,
            "WarningIndicators": warning_indicators,
            "TechnicalLimitations": technical_limitations
        }

    # For Unfamiliar Networks: Perform full risk assessment rather than blindly stopping at unfamiliar!
    if security_bin == 1 and not is_security_downgrade and not bssid_collision and not ml_both_attack:
        advice_text = (
            "No significant warning indicators detected. Network advertises standard robust encryption "
            "with valid Wi-Fi channel characteristics and no conflicting broadcasts. "
            "Because this network is unfamiliar to this machine, low risk reflects clean observed configuration, "
            "not verified identity. Connect only if you recognize the network name."
        )
        return {
            "RiskCategory": RISK_LOWER,
            "RiskBadge": get_safe_badge("🟢", "[LOWER RISK]"),
            "TrustState": trust_state,
            "AcademicStatus": STATUS_NEW,
            "SummaryAdvice": advice_text,
            "ObservedEvidence": observed_evidence,
            "WarningIndicators": warning_indicators,
            "TechnicalLimitations": technical_limitations
        }

    # Default fallback
    return {
        "RiskCategory": RISK_UNCERTAIN,
        "RiskBadge": get_safe_badge("🟠", "[UNCERTAIN]"),
        "TrustState": trust_state,
        "AcademicStatus": STATUS_NEW,
        "SummaryAdvice": "Available evidence is insufficient to confidently establish trust. Exercise normal caution.",
        "ObservedEvidence": observed_evidence,
        "WarningIndicators": warning_indicators,
        "TechnicalLimitations": technical_limitations
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
    network_stub = {
        "SSID": scan_context.get("ssid", "") if scan_context else "",
        "BSSID": "",
        "Signal": features_row.get("Signal", 0),
        "Channel": features_row.get("Channel", 1),
        "Security": "WPA2-Personal" if features_row.get("Security", 1) == 1 else "Open",
        "Encryption": "CCMP" if features_row.get("Security", 1) == 1 else "None",
        "Band": "5 GHz" if (32 <= features_row.get("Channel", 1) <= 177) else "2.4 GHz"
    }

    assessment = assess_network_risk(
        network=network_stub,
        features_row=features_row,
        knn_prediction=knn_pred,
        rf_prediction=rf_pred,
        ap_record=ap_record,
        history_df=None,
        scan_context=scan_context
    )

    badge = assessment["RiskBadge"]
    final_status = assessment["AcademicStatus"]
    verdict_badge = assessment["RiskBadge"]
    verdict = assessment["RiskCategory"]
    advice = assessment["SummaryAdvice"]

    return badge, final_status, verdict_badge, verdict, advice


# ============================================================
# ANALYZE SCANNED NETWORKS
# ============================================================

def analyze_scanned_networks(scanned_networks, history_df=None):
    """
    Performs complete evidence-based risk assessment on scanned networks:
    1. Feature extraction
    2. Dual-band router and multi-AP relationship correlation
    3. Windows Saved Wi-Fi Profiles correlation
    4. ML model inference (KNN + Random Forest)
    5. Multi-dimensional Evidence-Based Risk Evaluation
    6. Transparent Explanation & Technical Limitation Reporting
    7. Safer candidate ranking
    """
    if not scanned_networks:
        return [], []

    if history_df is None:
        history_df = load_history()

    knn, random_forest = load_models()

    features_df = extract_features(scanned_networks, history_df=history_df)
    relationships = analyze_scanned_relationships(scanned_networks)
    saved_profiles = get_saved_windows_profiles()

    all_bssids = [str(n.get("BSSID", "")).strip().lower() for n in scanned_networks if n.get("BSSID")]
    bssid_counts = pd.Series(all_bssids).value_counts().to_dict()

    results = []
    safer_candidates = []

    for index, network in enumerate(scanned_networks):
        feature_row = features_df.iloc[index].to_dict()
        model_input = pd.DataFrame([feature_row])[FEATURE_COLUMNS]

        knn_prediction = int(knn.predict(model_input)[0])
        rf_prediction = int(random_forest.predict(model_input)[0])

        ssid = str(network.get("SSID", "")).strip()
        bssid = str(network.get("BSSID", "")).strip().lower()

        ap_record = get_ap_record(history_df, ssid, bssid)

        is_saved = ssid in saved_profiles
        rel_info = relationships.get(bssid, {})
        is_dual_band = rel_info.get("is_dual_band", False)

        scan_context = {
            "ssid": ssid,
            "bssid_collision": bssid_counts.get(bssid, 1) > 1,
            "is_dual_band": is_dual_band,
            "partner_bssid": rel_info.get("partner_bssid", ""),
            "is_saved_profile": is_saved
        }

        # Perform Evidence-Based Risk Assessment
        assessment = assess_network_risk(
            network=network,
            features_row=feature_row,
            knn_prediction=knn_prediction,
            rf_prediction=rf_prediction,
            ap_record=ap_record,
            history_df=history_df,
            scan_context=scan_context
        )

        reasons = generate_feature_explanations(network, feature_row, history_df, context_info=scan_context)

        result = {
            "SSID": ssid,
            "BSSID": bssid,
            "Signal": feature_row.get("Signal", 0),
            "Channel": feature_row.get("Channel", 1),
            "Band": network.get("Band", "5 GHz" if (32 <= feature_row.get("Channel", 1) <= 177) else "2.4 GHz"),
            "Security": network.get("Security", "Unknown"),
            "Encryption": network.get("Encryption", "Unknown"),
            "Radio": network.get("Radio", "Unknown"),
            "KNN_Pred": "Legitimate" if knn_prediction == 0 else "Evil Twin",
            "RF_Pred": "Legitimate" if rf_prediction == 0 else "Evil Twin",
            "TrustState": assessment["TrustState"],
            "RiskCategory": assessment["RiskCategory"],
            "RiskBadge": assessment["RiskBadge"],
            "SummaryAdvice": assessment["SummaryAdvice"],
            "ObservedEvidence": assessment["ObservedEvidence"],
            "WarningIndicators": assessment["WarningIndicators"],
            "TechnicalLimitations": assessment["TechnicalLimitations"],
            "AcademicStatus": assessment["AcademicStatus"],
            "Badge": assessment["RiskBadge"],
            "FinalResult": assessment["AcademicStatus"],
            "VerdictBadge": assessment["RiskBadge"],
            "ConnectionVerdict": assessment["RiskCategory"],
            "ConnectionAdvice": assessment["SummaryAdvice"],
            "IsDualBand": is_dual_band,
            "IsSavedProfile": is_saved,
            "Reasons": reasons,
            "Features": feature_row
        }

        results.append(result)

        if assessment["RiskCategory"] == RISK_LOWER:
            weight = 1
            if is_saved:
                weight = 10
            elif ap_record:
                try:
                    weight = int(ap_record.get("Observation Count", 1))
                except (ValueError, TypeError):
                    weight = 1

            safer_candidates.append({
                "SSID": ssid,
                "BSSID": bssid,
                "Signal": feature_row.get("Signal", 0),
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
        k, r = load_models()
        print("Models loaded successfully. Risk assessment engine operational.")
    except Exception as err:
        print(f"Error loading models:\n{err}")