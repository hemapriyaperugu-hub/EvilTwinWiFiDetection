import os
import sys
import joblib
import pandas as pd

from .features import (
    extract_features,
    generate_feature_explanations,
    FEATURE_COLUMNS
)
from .history import load_history, get_ap_record


# ============================================================
# MODEL PATHS
# ============================================================

def get_model_paths():

    base_dir = os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )

    return {
        "knn": os.path.join(
            base_dir,
            "models",
            "knn_model.pkl"
        ),

        "random_forest": os.path.join(
            base_dir,
            "models",
            "random_forest_model.pkl"
        )
    }


# ============================================================
# LOAD TRAINED MODELS
# ============================================================

def load_models():

    paths = get_model_paths()

    if not os.path.exists(paths["knn"]):
        raise FileNotFoundError(
            f"KNN model not found:\n{paths['knn']}\n\n"
            "Train the models once using:\n"
            "python -m src.train"
        )

    if not os.path.exists(paths["random_forest"]):
        raise FileNotFoundError(
            f"Random Forest model not found:\n"
            f"{paths['random_forest']}\n\n"
            "Train the models once using:\n"
            "python -m src.train"
        )

    knn = joblib.load(paths["knn"])
    random_forest = joblib.load(
        paths["random_forest"]
    )

    return knn, random_forest


# ============================================================
# SAFE CONSOLE BADGES
# ============================================================

def get_safe_badge(badge_char, fallback_text):

    try:

        encoding = (
            getattr(
                sys.stdout,
                "encoding",
                None
            )
            or "utf-8"
        )

        badge_char.encode(encoding)

        return badge_char

    except Exception:

        return fallback_text


# ============================================================
# FINAL DECISION LOGIC
# ============================================================

def determine_final_classification(
    knn_pred,
    rf_pred,
    features_row,
    ap_record,
    ssid_known_in_history=False
):

    """
    Final classification.

    IMPORTANT:

    Unknown BSSID does NOT automatically mean
    Evil Twin.

    Possible results:

        LIKELY LEGITIMATE
        NEW / UNVERIFIED
        SUSPICIOUS / VERIFY NETWORK
        POSSIBLE EVIL TWIN
    """

    bssid_known = int(
        features_row.get(
            "BSSIDKnown",
            0
        )
    )

    channel_match = int(
        features_row.get(
            "ChannelMatch",
            1
        )
    )

    security_match = int(
        features_row.get(
            "SecurityMatch",
            1
        )
    )

    same_ssid_count = int(
        features_row.get(
            "SameSSIDCount",
            1
        )
    )

    signal = int(
        features_row.get(
            "Signal",
            0
        )
    )

    # ========================================================
    # 1. MODEL DISAGREEMENT
    # ========================================================
    #
    # Example:
    #
    # KNN = Evil Twin
    # RF  = Legitimate
    #
    # Result:
    #
    # SUSPICIOUS / VERIFY NETWORK
    #
    # This check MUST happen before the NEW network check.
    # ========================================================

    if knn_pred != rf_pred:

        return (
            get_safe_badge(
                "🟠",
                "[SUSPICIOUS]"
            ),
            "SUSPICIOUS / VERIFY NETWORK"
        )

    # ========================================================
    # 2. KNOWN ACCESS POINT
    # ========================================================

    if (
        ap_record is not None
        and bssid_known == 1
    ):

        observation_count = int(
            ap_record.get(
                "Observation Count",
                1
            )
        )

        # Known AP + both models say legitimate
        # + characteristics match
        if (
            channel_match == 1
            and security_match == 1
            and knn_pred == 0
            and rf_pred == 0
        ):

            return (
                get_safe_badge(
                    "🟢",
                    "[SAFE]"
                ),
                "LIKELY LEGITIMATE"
            )

        # Known AP but characteristics changed
        if observation_count >= 2:

            return (
                get_safe_badge(
                    "🟠",
                    "[SUSPICIOUS]"
                ),
                "SUSPICIOUS / VERIFY NETWORK"
            )

    # ========================================================
    # 3. COMPLETELY NEW NETWORK
    # ========================================================
    #
    # A new network is NOT automatically Evil Twin.
    #
    # This is especially important for:
    #
    # - Personal hotspots
    # - Home routers
    # - Hotel Wi-Fi
    # - New college networks
    # - Networks encountered while travelling
    # ========================================================

    if (
        not ssid_known_in_history
        and bssid_known == 0
    ):

        # Both models say legitimate
        if (
            knn_pred == 0
            and rf_pred == 0
        ):

            return (
                get_safe_badge(
                    "🟡",
                    "[NEW]"
                ),
                "NEW / UNVERIFIED"
            )

        # Both models say Evil Twin.
        # We still require supporting evidence.

        anomaly_count = 0

        if channel_match == 0:
            anomaly_count += 1

        if security_match == 0:
            anomaly_count += 1

        if same_ssid_count >= 2:
            anomaly_count += 1

        # Strong supporting evidence
        if (
            anomaly_count >= 2
            and signal >= 85
        ):

            return (
                get_safe_badge(
                    "🔴",
                    "[EVIL TWIN]"
                ),
                "POSSIBLE EVIL TWIN"
            )

        # Not enough evidence
        return (
            get_safe_badge(
                "🟠",
                "[SUSPICIOUS]"
            ),
            "SUSPICIOUS / VERIFY NETWORK"
        )

    # ========================================================
    # 4. NEW BSSID WITH KNOWN SSID
    # ========================================================
    #
    # Example:
    #
    # College Wi-Fi
    #     AP1
    #     AP2
    #     AP3
    #     AP4
    #
    # A new BSSID does NOT automatically mean Evil Twin.
    # ========================================================

    if (
        ssid_known_in_history
        and bssid_known == 0
    ):

        anomalies = 0

        if channel_match == 0:
            anomalies += 1

        if security_match == 0:
            anomalies += 1

        # Multiple anomalies + both ML models agree
        if (
            anomalies >= 2
            and signal >= 85
            and knn_pred == 1
            and rf_pred == 1
        ):

            return (
                get_safe_badge(
                    "🔴",
                    "[EVIL TWIN]"
                ),
                "POSSIBLE EVIL TWIN"
            )

        # Otherwise it is simply a new AP
        # belonging to a known SSID.
        return (
            get_safe_badge(
                "🟡",
                "[NEW]"
            ),
            "NEW / UNVERIFIED"
        )

    # ========================================================
    # 5. BOTH MODELS SAY EVIL TWIN
    # ========================================================

    if (
        knn_pred == 1
        and rf_pred == 1
    ):

        anomaly_count = 0

        if bssid_known == 0:
            anomaly_count += 1

        if channel_match == 0:
            anomaly_count += 1

        if security_match == 0:
            anomaly_count += 1

        if same_ssid_count >= 2:
            anomaly_count += 1

        # Multiple supporting indicators
        if anomaly_count >= 2:

            return (
                get_safe_badge(
                    "🔴",
                    "[EVIL TWIN]"
                ),
                "POSSIBLE EVIL TWIN"
            )

        # ML says Evil Twin but evidence is weak
        return (
            get_safe_badge(
                "🟠",
                "[SUSPICIOUS]"
            ),
            "SUSPICIOUS / VERIFY NETWORK"
        )

    # ========================================================
    # 6. BOTH MODELS SAY LEGITIMATE
    # ========================================================

    if (
        knn_pred == 0
        and rf_pred == 0
    ):

        if bssid_known == 1:

            return (
                get_safe_badge(
                    "🟢",
                    "[SAFE]"
                ),
                "LIKELY LEGITIMATE"
            )

        return (
            get_safe_badge(
                "🟡",
                "[NEW]"
            ),
            "NEW / UNVERIFIED"
        )

    # ========================================================
    # FALLBACK
    # ========================================================

    return (
        get_safe_badge(
            "🟠",
            "[SUSPICIOUS]"
        ),
        "SUSPICIOUS / VERIFY NETWORK"
    )


# ============================================================
# ANALYZE SCANNED NETWORKS
# ============================================================

def analyze_scanned_networks(
    scanned_networks,
    history_df=None
):

    if not scanned_networks:

        return [], []

    # Load history if not supplied
    if history_df is None:

        history_df = load_history()

    # Load existing trained models.
    #
    # IMPORTANT:
    # This DOES NOT train the models.
    #
    # It only loads the .pkl files.
    knn, random_forest = load_models()

    # ========================================================
    # FEATURE EXTRACTION
    # ========================================================

    features_df = extract_features(
        scanned_networks,
        history_df=history_df
    )

    results = []

    legitimate_candidates = []

    # ========================================================
    # ANALYZE EACH ACCESS POINT
    # ========================================================

    for index, network in enumerate(
        scanned_networks
    ):

        feature_row = (
            features_df
            .iloc[index]
            .to_dict()
        )

        # Keep feature order exactly the same
        # as used during training.
        model_input = pd.DataFrame(
            [feature_row]
        )[FEATURE_COLUMNS]

        # ----------------------------------------------------
        # KNN prediction
        # ----------------------------------------------------

        knn_prediction = int(
            knn.predict(
                model_input
            )[0]
        )

        # ----------------------------------------------------
        # Random Forest prediction
        # ----------------------------------------------------

        rf_prediction = int(
            random_forest.predict(
                model_input
            )[0]
        )

        # ----------------------------------------------------
        # Network information
        # ----------------------------------------------------

        ssid = str(
            network.get(
                "SSID",
                ""
            )
        ).strip()

        bssid = str(
            network.get(
                "BSSID",
                ""
            )
        ).strip().lower()

        # ----------------------------------------------------
        # Search history
        # ----------------------------------------------------

        ap_record = get_ap_record(
            history_df,
            ssid,
            bssid
        )

        # ----------------------------------------------------
        # Check whether SSID has been seen before
        # ----------------------------------------------------

        known_ssid = False

        if (
            history_df is not None
            and not history_df.empty
            and "SSID" in history_df.columns
        ):

            known_ssid = (
                ssid
                in history_df[
                    "SSID"
                ]
                .astype(str)
                .str.strip()
                .values
            )

        # ----------------------------------------------------
        # Final classification
        # ----------------------------------------------------

        badge, final_status = (
            determine_final_classification(
                knn_prediction,
                rf_prediction,
                feature_row,
                ap_record,
                ssid_known_in_history=known_ssid
            )
        )

        # ----------------------------------------------------
        # Generate explanation
        # ----------------------------------------------------

        reasons = (
            generate_feature_explanations(
                network,
                feature_row,
                history_df
            )
        )

        # ----------------------------------------------------
        # Result object
        # ----------------------------------------------------

        result = {

            "SSID": ssid,

            "BSSID": bssid,

            "Signal": feature_row.get(
                "Signal",
                0
            ),

            "Channel": feature_row.get(
                "Channel",
                1
            ),

            "Security": network.get(
                "Security",
                "Unknown"
            ),

            "KNN_Pred": (
                "Legitimate"
                if knn_prediction == 0
                else "Evil Twin"
            ),

            "RF_Pred": (
                "Legitimate"
                if rf_prediction == 0
                else "Evil Twin"
            ),

            "Badge": badge,

            "FinalResult": final_status,

            "Reasons": reasons,

            "Features": feature_row
        }

        results.append(result)

        # ----------------------------------------------------
        # Safer network candidates
        # ----------------------------------------------------

        if final_status == "LIKELY LEGITIMATE":

            observation_count = 1

            if ap_record:

                observation_count = int(
                    ap_record.get(
                        "Observation Count",
                        1
                    )
                )

            legitimate_candidates.append({

                "SSID": ssid,

                "BSSID": bssid,

                "Signal": feature_row.get(
                    "Signal",
                    0
                ),

                "ObservationCount":
                    observation_count
            })

    # ========================================================
    # SORT SAFER NETWORKS
    # ========================================================

    legitimate_candidates.sort(
        key=lambda item: (
            item["ObservationCount"],
            item["Signal"]
        ),
        reverse=True
    )

    return (
        results,
        legitimate_candidates
    )


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    print(
        "=================================================="
    )

    print(
        "             PREDICTION MODULE"
    )

    print(
        "=================================================="
    )

    try:

        knn, random_forest = load_models()

        print(
            "KNN model loaded successfully."
        )

        print(
            "Random Forest model loaded successfully."
        )

        print(
            "\nModels are ready."
        )

        print(
            "No training was performed."
        )

    except Exception as error:

        print(
            f"\nError loading models:\n{error}"
        )