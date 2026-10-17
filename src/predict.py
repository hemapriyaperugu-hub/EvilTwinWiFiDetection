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
from .history import load_history, get_ap_record
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
# CLASSIFICATION & CONNECTION VERDICTS
# ============================================================

STATUS_LEGITIMATE = "LIKELY LEGITIMATE"
STATUS_NEW = "NEW / UNVERIFIED"
STATUS_SUSPICIOUS = "SUSPICIOUS — VERIFY NETWORK"
STATUS_EVIL_TWIN = "POSSIBLE EVIL TWIN"

VERDICT_SAFE = "SAFE TO CONNECT"
VERDICT_ACCEPTABLE = "ACCEPTABLE — PROCEED WITH CAUTION"
VERDICT_CAUTION = "CAUTION — VERIFY BEFORE CONNECTING"
VERDICT_DANGER = "DO NOT CONNECT — HIGH RISK"


# ============================================================
# TRANSPARENT DECISION LAYER
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
    Transparent, multi-layered decision engine combining:
    1. Machine Learning Consensus (KNN + Random Forest)
    2. Local Historical Profile (persistence across scans)
    3. Windows Saved Profile Store (user-trusted credentials)
    4. Hardware RF & Dual-Band Relationships (OUI, complementary bands)
    5. Actionable Connection Recommendation ("OK TO CONNECT" assessment)
    """
    bssid_known = int(features_row.get("BSSIDKnown", 0))
    channel_match = int(features_row.get("ChannelMatch", 1))
    security_match = int(features_row.get("SecurityMatch", 1))
    same_ssid_count = int(features_row.get("SameSSIDCount", 1))
    signal = int(features_row.get("Signal", 0))
    security_bin = int(features_row.get("Security", 1))

    obs_count = 0
    if ap_record is not None:
        try:
            obs_count = int(ap_record.get("Observation Count", 1))
        except (ValueError, TypeError):
            obs_count = 1

    # Contextual flags
    bssid_collision = False
    is_dual_band = False
    is_saved_profile = False

    if scan_context:
        bssid_collision = scan_context.get("bssid_collision", False)
        is_dual_band = scan_context.get("is_dual_band", False)
        is_saved_profile = scan_context.get("is_saved_profile", False)

    # Anomaly definitions
    is_security_downgrade = (security_match == 0) and (ssid_known_in_history or is_saved_profile)
    is_channel_conflict = (channel_match == 0) and ssid_known_in_history and not is_dual_band
    is_concurrent_broadcast = (same_ssid_count >= 2) and not is_dual_band

    ml_both_attack = (knn_pred == 1 and rf_pred == 1)
    ml_both_legit = (knn_pred == 0 and rf_pred == 0)
    ml_disagree = (knn_pred != rf_pred)

    # ========================================================
    # 1. EVALUATE FOR "POSSIBLE EVIL TWIN"
    # Strict requirement: Multiple independent corroborating indicators.
    # An unknown BSSID alone NEVER triggers an Evil Twin verdict.
    # ========================================================
    if is_security_downgrade and (is_concurrent_broadcast or is_channel_conflict or ml_both_attack):
        return (
            get_safe_badge("🔴", "[EVIL TWIN]"),
            STATUS_EVIL_TWIN,
            get_safe_badge("🚫", "[DO NOT CONNECT]"),
            VERDICT_DANGER,
            "Security downgrade detected on a known network alongside conflicting broadcasts. High probability of rogue AP."
        )

    if (ssid_known_in_history or is_saved_profile) and bssid_known == 0 and is_channel_conflict and is_concurrent_broadcast and ml_both_attack:
        return (
            get_safe_badge("🔴", "[EVIL TWIN]"),
            STATUS_EVIL_TWIN,
            get_safe_badge("🚫", "[DO NOT CONNECT]"),
            VERDICT_DANGER,
            "Unverified access point broadcasting concurrently with conflicting channel and ML attack consensus."
        )

    if bssid_collision and (is_security_downgrade or is_channel_conflict):
        return (
            get_safe_badge("🔴", "[EVIL TWIN]"),
            STATUS_EVIL_TWIN,
            get_safe_badge("🚫", "[DO NOT CONNECT]"),
            VERDICT_DANGER,
            "Duplicate BSSID collision with conflicting parameters detected in same scan (potential MAC spoofing)."
        )

    # ========================================================
    # 2. EVALUATE FOR "LIKELY LEGITIMATE" & "SAFE TO CONNECT"
    # Scenarios:
    # A. Saved Windows Wi-Fi profile + matching security + zero attack anomalies.
    # B. Known BSSID in history with matching parameters.
    # C. Verified Dual-band hardware (2.4 GHz + 5 GHz).
    # ========================================================
    target_ssid = scan_context.get("ssid", "") if scan_context else ""
    if is_saved_profile and security_match == 1 and not bssid_collision and not ml_both_attack and not is_security_downgrade:
        return (
            get_safe_badge("🟢", "[SAFE]"),
            STATUS_LEGITIMATE,
            get_safe_badge("🛡️", "[OK TO CONNECT]"),
            VERDICT_SAFE,
            f"Confirmed as your saved Windows Wi-Fi network ('{target_ssid}'). Security and encryption match your system profile. Safe to connect."
        )

    if bssid_known == 1 and ap_record is not None and not bssid_collision:
        if security_match == 1 and (channel_match == 1 or is_dual_band or same_ssid_count == 1) and not ml_both_attack:
            return (
                get_safe_badge("🟢", "[SAFE]"),
                STATUS_LEGITIMATE,
                get_safe_badge("🛡️", "[OK TO CONNECT]"),
                VERDICT_SAFE,
                "Previously observed network with consistent physical and cryptographic parameters. Safe to connect."
            )

    # ========================================================
    # 3. EVALUATE FOR MODEL DISAGREEMENT
    # Rule: If ML models disagree, return suspicious / verify network.
    # ========================================================
    if ml_disagree:
        return (
            get_safe_badge("🟠", "[SUSPICIOUS]"),
            STATUS_SUSPICIOUS,
            get_safe_badge("⚠️", "[CAUTION]"),
            VERDICT_CAUTION,
            "Machine learning models disagree on classification. Verify network identity before connecting."
        )

    # ========================================================
    # 4. EVALUATE FOR "NEW / UNVERIFIED"
    # Rule: First time encountering this network, or new AP in a legitimate multi-AP environment.
    # Distinguish safe-to-try vs open public Wi-Fi.
    # ========================================================
    if not ssid_known_in_history and bssid_known == 0:
        if not is_security_downgrade and not ml_both_attack:
            if security_bin == 1:
                # Secured new network
                return (
                    get_safe_badge("🟡", "[NEW]"),
                    STATUS_NEW,
                    get_safe_badge("ℹ️", "[ACCEPTABLE]"),
                    VERDICT_ACCEPTABLE,
                    "New secured network encountered for the first time. Standard WPA2/WPA3 encryption present. Acceptable to connect if you recognize the name."
                )
            else:
                # Open unencrypted network
                return (
                    get_safe_badge("🟡", "[NEW]"),
                    STATUS_NEW,
                    get_safe_badge("⚠️", "[CAUTION]"),
                    VERDICT_CAUTION,
                    "Open unencrypted Wi-Fi network. Anyone nearby can observe unencrypted traffic. Exercise caution or use a VPN."
                )

    if (ssid_known_in_history or is_saved_profile) and bssid_known == 0:
        if security_match == 1 and not is_security_downgrade and not ml_both_attack:
            return (
                get_safe_badge("🟡", "[NEW]"),
                STATUS_NEW,
                get_safe_badge("ℹ️", "[ACCEPTABLE]"),
                VERDICT_ACCEPTABLE,
                "New access point associated with a known SSID (e.g. campus mesh AP or secondary router). Security matches known profile."
            )

    # ========================================================
    # 5. EVALUATE FOR "SUSPICIOUS — VERIFY NETWORK"
    # Rule: Ambiguous, single anomaly, or unexpected parameter change.
    # ========================================================
    if is_security_downgrade or is_channel_conflict:
        return (
            get_safe_badge("🟠", "[SUSPICIOUS]"),
            STATUS_SUSPICIOUS,
            get_safe_badge("⚠️", "[CAUTION]"),
            VERDICT_CAUTION,
            "Anomalous security or channel configuration observed relative to known baseline. Verify credentials before connecting."
        )

    if bssid_known == 1 and (channel_match == 0 or security_match == 0):
        return (
            get_safe_badge("🟠", "[SUSPICIOUS]"),
            STATUS_SUSPICIOUS,
            get_safe_badge("⚠️", "[CAUTION]"),
            VERDICT_CAUTION,
            "Previously observed access point altered its operating parameters unexpectedly."
        )

    if ml_both_attack:
        return (
            get_safe_badge("🟠", "[SUSPICIOUS]"),
            STATUS_SUSPICIOUS,
            get_safe_badge("⚠️", "[CAUTION]"),
            VERDICT_CAUTION,
            "ML models flagged suspicious characteristics, but corroborating RF evidence is limited. Exercise caution."
        )

    # Default fallback
    return (
        get_safe_badge("🟡", "[NEW]"),
        STATUS_NEW,
        get_safe_badge("ℹ️", "[ACCEPTABLE]"),
        VERDICT_ACCEPTABLE,
        "Network observed for the first time without obvious attack indicators."
    )


# ============================================================
# ANALYZE SCANNED NETWORKS
# ============================================================

def analyze_scanned_networks(scanned_networks, history_df=None):
    """
    Performs complete detection pipeline on scanned networks:
    1. Feature extraction
    2. Dual-band router and multi-AP relationship correlation
    3. Windows Saved Wi-Fi Profiles correlation
    4. ML model inference (KNN + Random Forest)
    5. Actionable Connection Recommendation ("OK to Connect")
    6. Safer candidate ranking
    """
    if not scanned_networks:
        return [], []

    if history_df is None:
        history_df = load_history()

    knn, random_forest = load_models()

    features_df = extract_features(scanned_networks, history_df=history_df)

    # Correlate dual-band hardware and multi-AP relationships
    relationships = analyze_scanned_relationships(scanned_networks)

    # Correlate saved Windows profiles
    saved_profiles = get_saved_windows_profiles()

    all_bssids = [str(n.get("BSSID", "")).strip().lower() for n in scanned_networks if n.get("BSSID")]
    bssid_counts = pd.Series(all_bssids).value_counts().to_dict()

    results = []
    legitimate_candidates = []

    for index, network in enumerate(scanned_networks):
        feature_row = features_df.iloc[index].to_dict()
        model_input = pd.DataFrame([feature_row])[FEATURE_COLUMNS]

        knn_prediction = int(knn.predict(model_input)[0])
        rf_prediction = int(random_forest.predict(model_input)[0])

        ssid = str(network.get("SSID", "")).strip()
        bssid = str(network.get("BSSID", "")).strip().lower()

        ap_record = get_ap_record(history_df, ssid, bssid)

        known_ssid = False
        if history_df is not None and not history_df.empty and "SSID" in history_df.columns:
            known_ssid = ssid in history_df["SSID"].astype(str).str.strip().values

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

        badge, final_status, verdict_badge, verdict, advice = determine_final_classification(
            knn_prediction,
            rf_prediction,
            feature_row,
            ap_record,
            ssid_known_in_history=known_ssid,
            scan_context=scan_context
        )

        context_info = {
            "is_saved_profile": is_saved,
            "is_dual_band": is_dual_band,
            "partner_bssid": rel_info.get("partner_bssid", "")
        }
        reasons = generate_feature_explanations(network, feature_row, history_df, context_info=context_info)

        if knn_prediction != rf_prediction:
            reasons.append(
                f"Model evaluation: KNN predicted {'Legitimate' if knn_prediction == 0 else 'Evil Twin'}, "
                f"while Random Forest predicted {'Legitimate' if rf_prediction == 0 else 'Evil Twin'}."
            )

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
            "Badge": badge,
            "FinalResult": final_status,
            "VerdictBadge": verdict_badge,
            "ConnectionVerdict": verdict,
            "ConnectionAdvice": advice,
            "IsDualBand": is_dual_band,
            "IsSavedProfile": is_saved,
            "Reasons": reasons,
            "Features": feature_row
        }

        results.append(result)

        if final_status == STATUS_LEGITIMATE or verdict == VERDICT_SAFE:
            obs_cnt = 1
            if ap_record:
                try:
                    obs_cnt = int(ap_record.get("Observation Count", 1))
                except (ValueError, TypeError):
                    obs_cnt = 1
            elif is_saved:
                obs_cnt = 5  # Saved profile weight

            legitimate_candidates.append({
                "SSID": ssid,
                "BSSID": bssid,
                "Signal": feature_row.get("Signal", 0),
                "ObservationCount": obs_cnt
            })

    legitimate_candidates.sort(
        key=lambda item: (item["ObservationCount"], item["Signal"]),
        reverse=True
    )

    return results, legitimate_candidates


if __name__ == "__main__":
    print("==================================================")
    print("             PREDICTION MODULE                    ")
    print("==================================================")
    try:
        k, r = load_models()
        print("Models loaded successfully. Pipeline is ready.")
    except Exception as err:
        print(f"Error loading models:\n{err}")