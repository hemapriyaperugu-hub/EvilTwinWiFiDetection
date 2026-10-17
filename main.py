import sys
import os

# Enable UTF-8 console output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.scanner import scan_wifi, save_observations_to_csv
from src.history import load_history, update_history
from src.predict import analyze_scanned_networks
from src.dataset import seed_baseline_dataset, build_training_dataset
from src.train import train_models


def ensure_models_ready():
    """
    Models are trained ONLY if the .pkl files do not exist.

    Normal scans NEVER retrain the models.
    """

    base_dir = os.path.dirname(os.path.abspath(__file__))

    knn_path = os.path.join(
        base_dir,
        "models",
        "knn_model.pkl"
    )

    rf_path = os.path.join(
        base_dir,
        "models",
        "random_forest_model.pkl"
    )

    if not os.path.exists(knn_path) or not os.path.exists(rf_path):

        print("Models not found.")
        print("Creating and training models for the first time...")

        seed_baseline_dataset()
        build_training_dataset()
        train_models()

        print("\nModels trained and saved successfully.")
        print("Future scans will reuse these models.\n")


def main():

    print("======================================================================")
    print("       SOFTWARE-BASED EVIL TWIN DETECTION IN PUBLIC WI-FI")
    print("       Algorithms: KNN + Random Forest")
    print("======================================================================\n")

    # Train ONLY if models do not already exist.
    ensure_models_ready()

    # ---------------------------------------------------------
    # STEP 1 - Scan Wi-Fi
    # ---------------------------------------------------------

    print("[Step 1] Scanning nearby Wi-Fi networks using built-in adapter...")

    scanned_networks = scan_wifi()

    if not scanned_networks:

        print(
            "No Wi-Fi access points detected. "
            "Ensure Wi-Fi adapter is turned on."
        )

        return

    print(
        f"Found {len(scanned_networks)} "
        f"Access Point(s) visible."
    )

    # ---------------------------------------------------------
    # STEP 2 - Save raw observation
    # ---------------------------------------------------------

    save_observations_to_csv(scanned_networks)

    print(
        "Raw observation(s) recorded in "
        "dataset/wifi_observations.csv."
    )

    # ---------------------------------------------------------
    # STEP 3 - Load history BEFORE updating it
    #
    # This is important.
    # The current scan must first be classified as new/known.
    # ---------------------------------------------------------

    history_df = load_history()

    # ---------------------------------------------------------
    # STEP 4 - Detection
    # ---------------------------------------------------------

    results, safer_candidates = analyze_scanned_networks(
        scanned_networks,
        history_df=history_df
    )

    # ---------------------------------------------------------
    # STEP 5 - Detection report
    # ---------------------------------------------------------

    print("\n======================================================================")
    print("                         DETECTION REPORT")
    print("======================================================================")

    for i, res in enumerate(results, start=1):

        print(f"\n[AP {i}]")

        print(f"  SSID           : {res['SSID']}")
        print(f"  BSSID (MAC)    : {res['BSSID']}")
        print(f"  Signal         : {res['Signal']}%")
        print(f"  Channel        : {res['Channel']}")
        print(f"  Security       : {res['Security']}")

        print("\n  ML Predictions:")

        print(
            f"    - KNN Model          : "
            f"{res['KNN_Pred']}"
        )

        print(
            f"    - Random Forest      : "
            f"{res['RF_Pred']}"
        )

        print("\n  Evidence:")

        for reason in res["Reasons"]:
            print(f"    * {reason}")

        print(
            f"\n  Final Result   : "
            f"{res['Badge']} {res['FinalResult']}"
        )

        print("-" * 70)

    # ---------------------------------------------------------
    # STEP 6 - Safer network recommendation
    # ---------------------------------------------------------

    print("\n======================================================================")
    print("                   SAFER NETWORK RECOMMENDATION")
    print("======================================================================")

    if safer_candidates:

        top = safer_candidates[0]

        print(
            f"  Suggested Network : "
            f"{top['SSID']}"
        )

        print(
            f"  BSSID (MAC)       : "
            f"{top['BSSID']}"
        )

        print(
            f"  Signal Strength   : "
            f"{top['Signal']}%"
        )

        print(
            f"  Historical Scans  : "
            f"{top['ObservationCount']} observation(s)"
        )

        print(
            "  Status            : "
            "Likely legitimate based on current observations."
        )

        print(
            "  Notice            : "
            "Absolute safety cannot be guaranteed."
        )

        print(
            "                      "
            "The system will NOT automatically connect."
        )

    else:

        print(
            "  No previously verified legitimate networks "
            "currently available."
        )

        print(
            "  New networks are shown as "
            "NEW / UNVERIFIED."
        )

    # ---------------------------------------------------------
    # STEP 7 - UPDATE HISTORY
    #
    # IMPORTANT:
    # ALL observed networks are recorded.
    #
    # This does NOT mean they are trusted.
    # History simply remembers that the AP was observed.
    # ---------------------------------------------------------

    update_history(scanned_networks)

    print("\n======================================================================")
    print(
        "Network history updated in "
        "dataset/network_history.csv."
    )

    print(
        "No model retraining was performed."
    )

    print(
        "Scan cycle completed successfully."
    )

    print("======================================================================\n")


if __name__ == "__main__":
    main()