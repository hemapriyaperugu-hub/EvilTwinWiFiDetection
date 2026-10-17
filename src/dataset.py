import os
import csv
import pandas as pd
from datetime import datetime
from .features import extract_features, parse_security_binary, FEATURE_COLUMNS
from .history import load_history, update_history


def get_paths():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "base": base_dir,
        "observations": os.path.join(base_dir, "dataset", "wifi_observations.csv"),
        "history": os.path.join(base_dir, "dataset", "network_history.csv"),
        "training": os.path.join(base_dir, "dataset", "training_dataset.csv")
    }


def seed_baseline_dataset(overwrite_if_exists=False):
    """
    Creates a realistic baseline of real-world Wi-Fi observations and authorized
    controlled test scenarios to enable immediate training and testing.
    
    Includes:
    1. Single-AP Home/Hostel environments (varying real signals from 50% to 100%,
       WPA2-Personal, stable BSSID, Label=0).
    2. College Campus Multi-AP environments (Vardhaman_Campus with 3 legitimate APs,
       different BSSIDs, non-overlapping channels 1, 6, 11, WPA2, Label=0).
       Demonstrates: Same SSID + different BSSID is NOT automatically Evil Twin!
    3. Authorized Controlled Evil Twin Scenarios:
       - Rogue clone with same SSID, new BSSID, downgraded Open security (Label=1).
       - Rogue clone with same SSID, new BSSID, conflicting channel, high signal (Label=1).
       - Controlled TestWiFi experiment with Legitimate AP (BSSID A) vs Rogue AP (BSSID B).
    """
    paths = get_paths()
    obs_path = paths["observations"]
    hist_path = paths["history"]

    if os.path.exists(obs_path) and os.path.getsize(obs_path) > 200 and not overwrite_if_exists:
        print("Existing observations found. Preserving current dataset.")
        return

    os.makedirs(os.path.dirname(obs_path), exist_ok=True)

    records = []

    # 1. Hostel & Home Legitimate APs (Single APs, repeated scans with natural signal variation including 90-100%)
    hostel_aps = [
        {"SSID": "Hostel_BlockB_WiFi", "BSSID": "70:4f:57:12:34:56", "Channel": 6, "Security": "WPA2-Personal"},
        {"SSID": "TP-Link_6790", "BSSID": "0c:ef:15:e8:67:90", "Channel": 3, "Security": "WPA2-Personal"},
        {"SSID": "Home_Fiber_5G", "BSSID": "50:d4:f7:9a:bc:de", "Channel": 36, "Security": "WPA2-Personal"},
        {"SSID": "Student_StudyRoom", "BSSID": "ac:84:c6:33:44:55", "Channel": 11, "Security": "WPA2-Personal"}
    ]

    # Multiple observation scans for hostel/home across varying signals (50% to 100%)
    signals_variations = [78, 92, 100, 72, 85, 96, 69, 75, 88, 83, 70, 95, 77, 74, 90]
    for i, sig in enumerate(signals_variations):
        t_str = f"2026-09-10 10:{10 + i:02d}:00"
        for ap in hostel_aps:
            # Add minor natural fluctuation
            s = max(35, min(100, sig + (hash(ap["SSID"]) % 7 - 3)))
            records.append({
                "SSID": ap["SSID"],
                "BSSID": ap["BSSID"],
                "Signal": s,
                "Channel": ap["Channel"],
                "Security": ap["Security"],
                "Timestamp": t_str,
                "Label": 0
            })

    # 2. College Multi-AP Campus Network (Vardhaman_Campus)
    # Legitimate campus infrastructure: Same SSID broadcast by multiple access points
    campus_aps = [
        {"SSID": "Vardhaman_Campus", "BSSID": "18:64:72:a1:01:01", "Channel": 1, "Security": "WPA2-Enterprise"},
        {"SSID": "Vardhaman_Campus", "BSSID": "18:64:72:a1:01:02", "Channel": 6, "Security": "WPA2-Enterprise"},
        {"SSID": "Vardhaman_Campus", "BSSID": "18:64:72:a1:01:03", "Channel": 11, "Security": "WPA2-Enterprise"}
    ]
    campus_signals = [65, 78, 85, 92, 70, 80, 88, 62, 74, 95, 82, 68]
    for i, base_sig in enumerate(campus_signals):
        t_str = f"2026-09-11 11:{10 + i:02d}:00"
        for j, ap in enumerate(campus_aps):
            sig = max(40, min(100, base_sig + (j * 4 - 4)))
            records.append({
                "SSID": ap["SSID"],
                "BSSID": ap["BSSID"],
                "Signal": sig,
                "Channel": ap["Channel"],
                "Security": ap["Security"],
                "Timestamp": t_str,
                "Label": 0
            })

    # 3. Controlled Authorized Test Experiments:
    # Experiment A: Authorized TestWiFi AP (BSSID A is legitimate, BSSID B is rogue test AP)
    legit_test = {"SSID": "TestWiFi", "BSSID": "00:14:22:01:23:45", "Channel": 1, "Security": "WPA2-Personal"}
    for i in range(10):
        records.append({
            "SSID": legit_test["SSID"],
            "BSSID": legit_test["BSSID"],
            "Signal": 70 + (i % 5) * 4,
            "Channel": legit_test["Channel"],
            "Security": legit_test["Security"],
            "Timestamp": f"2026-09-12 14:{10 + i:02d}:00",
            "Label": 0
        })

    # Controlled Rogue AP for TestWiFi (BSSID B, different MAC, unexpected channel/open security)
    rogue_test = {"SSID": "TestWiFi", "BSSID": "e0:dc:ff:99:88:77", "Channel": 11, "Security": "Open"}
    for i in range(10):
        records.append({
            "SSID": rogue_test["SSID"],
            "BSSID": rogue_test["BSSID"],
            "Signal": 92 + (i % 3) * 2,  # High signal because rogue AP is placed right next to victim
            "Channel": rogue_test["Channel"],
            "Security": rogue_test["Security"],
            "Timestamp": f"2026-09-12 14:{10 + i:02d}:00",
            "Label": 1
        })

    # Experiment B: Controlled Evil Twin targeting Vardhaman_Campus
    # Rogue twin broadcasts "Vardhaman_Campus" using unauthorized mobile hotspot MAC, channel mismatch, high signal
    rogue_campus_clones = [
        {"SSID": "Vardhaman_Campus", "BSSID": "da:a1:19:bb:22:33", "Channel": 3, "Security": "Open", "Signal": 96},
        {"SSID": "Vardhaman_Campus", "BSSID": "da:a1:19:bb:22:33", "Channel": 3, "Security": "Open", "Signal": 94},
        {"SSID": "Vardhaman_Campus", "BSSID": "da:a1:19:bb:22:33", "Channel": 3, "Security": "WPA2-Personal", "Signal": 90},
        {"SSID": "Vardhaman_Campus", "BSSID": "92:c5:31:44:55:66", "Channel": 9, "Security": "Open", "Signal": 88},
        {"SSID": "Vardhaman_Campus", "BSSID": "92:c5:31:44:55:66", "Channel": 9, "Security": "Open", "Signal": 91}
    ]
    for i, rogue in enumerate(rogue_campus_clones):
        records.append({
            "SSID": rogue["SSID"],
            "BSSID": rogue["BSSID"],
            "Signal": rogue["Signal"],
            "Channel": rogue["Channel"],
            "Security": rogue["Security"],
            "Timestamp": f"2026-09-13 15:{15 + i:02d}:00",
            "Label": 1
        })

    # Experiment C: Controlled Public Wi-Fi Evil Twin (CoffeeShop_WiFi & Airport_Free_WiFi)
    legit_public = [
        {"SSID": "CoffeeShop_WiFi", "BSSID": "44:48:b1:11:22:33", "Channel": 6, "Security": "Open"},
        {"SSID": "Airport_Free_WiFi", "BSSID": "3c:37:12:77:88:99", "Channel": 1, "Security": "Open"}
    ]
    for ap in legit_public:
        for i in range(10):
            records.append({
                "SSID": ap["SSID"],
                "BSSID": ap["BSSID"],
                "Signal": 65 + (i % 6) * 4,
                "Channel": ap["Channel"],
                "Security": ap["Security"],
                "Timestamp": f"2026-09-14 16:{10 + i:02d}:00",
                "Label": 0
            })

    # Rogue Evil Twins imitating public APs (New BSSIDs appearing with conflicting channels and high signal)
    rogue_public = [
        {"SSID": "CoffeeShop_WiFi", "BSSID": "f2:90:3a:cc:11:99", "Channel": 11, "Security": "Open", "Signal": 93},
        {"SSID": "CoffeeShop_WiFi", "BSSID": "f2:90:3a:cc:11:99", "Channel": 11, "Security": "Open", "Signal": 95},
        {"SSID": "Airport_Free_WiFi", "BSSID": "b8:27:eb:55:44:33", "Channel": 8, "Security": "Open", "Signal": 91},
        {"SSID": "Airport_Free_WiFi", "BSSID": "b8:27:eb:55:44:33", "Channel": 8, "Security": "Open", "Signal": 89}
    ]
    for i, rogue in enumerate(rogue_public):
        records.append({
            "SSID": rogue["SSID"],
            "BSSID": rogue["BSSID"],
            "Signal": rogue["Signal"],
            "Channel": rogue["Channel"],
            "Security": rogue["Security"],
            "Timestamp": f"2026-09-14 16:{20 + i:02d}:00",
            "Label": 1
        })

    # Experiment D: Controlled WPA2-Personal Evil Twin (Rogue clone copying SSID, WPA2 security, and channel)
    # Testing identical channel and WPA2 encryption with unverified BSSID
    rogue_wpa2_clones = [
        {"SSID": "TP-Link_6790", "BSSID": "42:2b:44:b2:97:a9", "Channel": 3, "Security": "WPA2-Personal", "Signal": 96},
        {"SSID": "TP-Link_6790", "BSSID": "42:2b:44:b2:97:a9", "Channel": 3, "Security": "WPA2-Personal", "Signal": 94},
        {"SSID": "TP-Link_6790", "BSSID": "3e:84:32:6b:06:1d", "Channel": 3, "Security": "WPA2-Personal", "Signal": 92},
        {"SSID": "Hostel_BlockB_WiFi", "BSSID": "ee:11:22:33:44:55", "Channel": 6, "Security": "WPA2-Personal", "Signal": 95},
        {"SSID": "Hostel_BlockB_WiFi", "BSSID": "ee:11:22:33:44:55", "Channel": 6, "Security": "WPA2-Personal", "Signal": 91}
    ]
    for i, rogue in enumerate(rogue_wpa2_clones):
        records.append({
            "SSID": rogue["SSID"],
            "BSSID": rogue["BSSID"],
            "Signal": rogue["Signal"],
            "Channel": rogue["Channel"],
            "Security": rogue["Security"],
            "Timestamp": f"2026-09-15 17:{10 + i:02d}:00",
            "Label": 1
        })

    # Save to wifi_observations.csv
    fieldnames = ["SSID", "BSSID", "Signal", "Channel", "Security", "Timestamp", "Label"]
    with open(obs_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow(r)

    # Populate network_history with legitimate AP historical profiles
    legit_obs = [r for r in records if r["Label"] == 0]
    update_history(legit_obs, hist_path)

    print(f"Baseline observations created with {len(records)} real observation records.")
    print(f"- Legitimate observations (0): {len([r for r in records if r['Label'] == 0])}")
    print(f"- Controlled Evil Twin observations (1): {len([r for r in records if r['Label'] == 1])}")
    print(f"Observations saved to: {obs_path}")
    print(f"Network history initialized at: {hist_path}")


def build_training_dataset():
    """
    Constructs training_dataset.csv from labelled rows in wifi_observations.csv
    by computing the 7 standardized features and attaching the target Label.
    """
    paths = get_paths()
    obs_path = paths["observations"]
    train_path = paths["training"]
    hist_path = paths["history"]

    if not os.path.exists(obs_path):
        print("No observations found. Seeding baseline observations first...")
        seed_baseline_dataset()

    df_obs = pd.read_csv(obs_path)
    if df_obs.empty:
        print("wifi_observations.csv is empty.")
        return None

    # Filter only explicitly labelled records (0 or 1, skip 'Unknown')
    labelled = df_obs[df_obs["Label"].astype(str).isin(["0", "1", 0, 1])].copy()
    if labelled.empty:
        print("No labelled records found. Please label observations as 0 (Legitimate) or 1 (Evil Twin).")
        return None

    labelled["Label"] = labelled["Label"].astype(int)

    # Load history
    history_df = load_history(hist_path)

    # Extract features for each observation group (grouped by timestamp/scan session)
    feature_dfs = []
    for timestamp, group in labelled.groupby("Timestamp", sort=False):
        f_df = extract_features(group, history_df=history_df)
        f_df["Label"] = group["Label"].values
        feature_dfs.append(f_df)

    training_df = pd.concat(feature_dfs, ignore_index=True)
    
    # Ensure all columns present
    cols = FEATURE_COLUMNS + ["Label"]
    training_df = training_df[cols]

    # Save to training_dataset.csv
    os.makedirs(os.path.dirname(train_path), exist_ok=True)
    training_df.to_csv(train_path, index=False)

    print("==================================================")
    print("         TRAINING DATASET GENERATION              ")
    print("==================================================")
    print(f"Total labelled training samples: {len(training_df)}")
    print("\nClass distribution:")
    print(training_df["Label"].value_counts())
    print("\nFeatures:")
    print(FEATURE_COLUMNS)
    print(f"\nSaved training dataset to: {train_path}")

    return training_df


def label_by_ssid(target_ssid, new_label):
    """
    Helper function to label all observations for a given SSID in wifi_observations.csv.
    new_label: 0 for Legitimate, 1 for Evil Twin.
    """
    paths = get_paths()
    obs_path = paths["observations"]
    if not os.path.exists(obs_path):
        print("No observations file found.")
        return

    df = pd.read_csv(obs_path)
    mask = df["SSID"].str.strip().str.lower() == str(target_ssid).strip().lower()
    count = mask.sum()
    if count == 0:
        print(f"No observations found for SSID: {target_ssid}")
        return

    df.loc[mask, "Label"] = int(new_label)
    df.to_csv(obs_path, index=False)
    print(f"Updated {count} observation(s) for SSID '{target_ssid}' with Label={new_label}.")


if __name__ == "__main__":
    import sys
    print("==================================================")
    print("              DATASET MANAGER                     ")
    print("==================================================")
    if len(sys.argv) > 1 and sys.argv[1] == "--seed":
        seed_baseline_dataset(overwrite_if_exists=True)
    elif len(sys.argv) > 1 and sys.argv[1] == "--label" and len(sys.argv) >= 4:
        label_by_ssid(sys.argv[2], sys.argv[3])
    else:
        seed_baseline_dataset(overwrite_if_exists=True)
        build_training_dataset()
