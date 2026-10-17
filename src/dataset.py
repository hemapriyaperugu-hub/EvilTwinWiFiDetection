import os
import csv
import pandas as pd
from datetime import datetime
from .features import extract_features, FEATURE_COLUMNS
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
    Creates a realistic, rigorous baseline dataset of real-world Wi-Fi observations
    and controlled experimental scenarios.

    Ensures balanced and realistic representation:
    1. Legitimate Known APs (Label=0, BSSIDKnown=1, signals 40-100%).
    2. Legitimate New/Unverified APs (Label=0, BSSIDKnown=0, signals 45-100%).
       (Ensures model NEVER equates unknown BSSID alone with Evil Twin).
    3. Multi-AP Enterprise Campus Wi-Fi (Vardhaman_Campus, channels 1, 6, 11, Label=0).
    4. Dual-Band Home Routers (2.4 GHz channel 6 + 5 GHz channel 44, Label=0).
    5. Controlled Evil Twin Attack Scenarios:
       - Security Downgrade attack (WPA2 -> Open rogue twin, Label=1).
       - Channel conflict + concurrent broadcast attack (Label=1).
       - Enterprise Downgrade attack (Enterprise -> Personal rogue twin, Label=1).
       - Cloned MAC / Spoofed BSSID collision attack (Label=1).
       - Varied attack signals (60-96%) reflecting varied physical distances.
    """
    paths = get_paths()
    obs_path = paths["observations"]
    hist_path = paths["history"]

    if os.path.exists(obs_path) and os.path.getsize(obs_path) > 200 and not overwrite_if_exists:
        return

    os.makedirs(os.path.dirname(obs_path), exist_ok=True)

    records = []

    # ------------------------------------------------------------------
    # 1. Historical Legitimate Access Points (will be placed in history)
    # ------------------------------------------------------------------
    known_legit_aps = [
        {"SSID": "Hostel_BlockB_WiFi", "BSSID": "70:4f:57:12:34:56", "Channel": 6, "Security": "WPA2-Personal"},
        {"SSID": "TP-Link_6790", "BSSID": "0c:ef:15:e8:67:90", "Channel": 3, "Security": "WPA2-Personal"},
        {"SSID": "Home_Fiber_5G", "BSSID": "50:d4:f7:9a:bc:de", "Channel": 36, "Security": "WPA2-Personal"},
        {"SSID": "Student_StudyRoom", "BSSID": "ac:84:c6:33:44:55", "Channel": 11, "Security": "WPA2-Personal"},
        {"SSID": "Vardhaman_Campus", "BSSID": "18:64:72:a1:01:01", "Channel": 1, "Security": "WPA2-Enterprise"},
        {"SSID": "Vardhaman_Campus", "BSSID": "18:64:72:a1:01:02", "Channel": 6, "Security": "WPA2-Enterprise"},
        {"SSID": "Vardhaman_Campus", "BSSID": "18:64:72:a1:01:03", "Channel": 11, "Security": "WPA2-Enterprise"},
        {"SSID": "TestWiFi", "BSSID": "00:14:22:01:23:45", "Channel": 1, "Security": "WPA2-Personal"},
        {"SSID": "CoffeeShop_WiFi", "BSSID": "44:48:b1:11:22:33", "Channel": 6, "Security": "Open"},
        {"SSID": "Airport_Free_WiFi", "BSSID": "3c:37:12:77:88:99", "Channel": 1, "Security": "Open"}
    ]

    # Pre-populate history with these known APs
    hist_entries = []
    for ap in known_legit_aps:
        hist_entries.append({
            "SSID": ap["SSID"],
            "BSSID": ap["BSSID"],
            "Channel": str(ap["Channel"]),
            "Security": ap["Security"],
            "First Seen": "2026-09-01 09:00:00",
            "Last Seen": "2026-09-15 18:00:00",
            "Observation Count": 10
        })
    hist_df = pd.DataFrame(hist_entries)
    hist_df.to_csv(hist_path, index=False)

    # ------------------------------------------------------------------
    # 2. Observations of Known Legitimate APs across realistic signals
    # ------------------------------------------------------------------
    signals_variations = [55, 68, 75, 82, 88, 92, 98, 100, 62, 70, 85, 90]
    for i, sig in enumerate(signals_variations):
        t_str = f"2026-09-10 10:{i:02d}:00"
        for ap in known_legit_aps[:4]:
            s = max(40, min(100, sig + (hash(ap["SSID"]) % 7 - 3)))
            records.append({
                "SSID": ap["SSID"],
                "BSSID": ap["BSSID"],
                "Signal": s,
                "Channel": ap["Channel"],
                "Security": ap["Security"],
                "Timestamp": t_str,
                "Label": 0,
                "Group": f"legit_known_{ap['SSID']}"
            })

    # Campus Multi-AP scans (Multiple APs broadcasting concurrently, Label=0)
    for i, base_sig in enumerate([65, 74, 82, 88, 92, 78]):
        t_str = f"2026-09-11 11:{i:02d}:00"
        for j, ap in enumerate(known_legit_aps[4:7]):
            records.append({
                "SSID": ap["SSID"],
                "BSSID": ap["BSSID"],
                "Signal": max(45, min(100, base_sig + (j * 4 - 4))),
                "Channel": ap["Channel"],
                "Security": ap["Security"],
                "Timestamp": t_str,
                "Label": 0,
                "Group": "legit_campus_multiap"
            })

    # Public Wi-Fi legitimate scans (Open security, Label=0)
    for i, sig in enumerate([60, 72, 80, 86, 94]):
        t_str = f"2026-09-12 12:{i:02d}:00"
        for ap in known_legit_aps[8:]:
            records.append({
                "SSID": ap["SSID"],
                "BSSID": ap["BSSID"],
                "Signal": sig,
                "Channel": ap["Channel"],
                "Security": ap["Security"],
                "Timestamp": t_str,
                "Label": 0,
                "Group": f"legit_public_{ap['SSID']}"
            })

    # ------------------------------------------------------------------
    # 3. CRITICAL: Legitimate NEW / UNVERIFIED Networks (BSSID NOT in history, Label=0)
    # This prevents the model from associating unverified BSSID with an attack!
    # ------------------------------------------------------------------
    new_legit_networks = [
        {"SSID": "SHIVA", "BSSID": "16:32:51:69:ea:63", "Channel": 44, "Security": "WPA2-Personal"},
        {"SSID": "Friends_Hostel_5G", "BSSID": "24:4b:fe:11:22:33", "Channel": 36, "Security": "WPA2-Personal"},
        {"SSID": "Library_Guest", "BSSID": "8c:15:c7:44:55:66", "Channel": 6, "Security": "WPA2-Personal"},
        {"SSID": "Metro_Free_WiFi", "BSSID": "90:9a:4a:77:88:99", "Channel": 1, "Security": "Open"},
        {"SSID": "Cafe_Barista", "BSSID": "68:d7:9a:12:34:78", "Channel": 11, "Security": "WPA2-Personal"},
        {"SSID": "Personal_Hotspot", "BSSID": "da:a1:19:33:44:55", "Channel": 6, "Security": "WPA2-Personal"},
        {"SSID": "Lab_302_WiFi", "BSSID": "34:2e:b7:88:99:aa", "Channel": 40, "Security": "WPA2-Personal"},
        {"SSID": "Faculty_Lounge", "BSSID": "50:c7:bf:ab:cd:ef", "Channel": 1, "Security": "WPA2-Personal"}
    ]

    for i, ap in enumerate(new_legit_networks):
        for s in [52, 68, 78, 88, 95, 100]:
            records.append({
                "SSID": ap["SSID"],
                "BSSID": ap["BSSID"],
                "Signal": s,
                "Channel": ap["Channel"],
                "Security": ap["Security"],
                "Timestamp": f"2026-09-13 14:{i:02d}:{s % 60:02d}",
                "Label": 0,
                "Group": f"legit_new_{ap['SSID']}"
            })

    # Legitimate Dual-band router (Same SSID broadcast on 2.4 GHz ch 6 and 5 GHz ch 44)
    for s in [65, 80, 92, 100]:
        t_str = f"2026-09-13 16:{s % 60:02d}:00"
        records.append({
            "SSID": "DualBand_Home",
            "BSSID": "60:32:b1:01:02:03",
            "Signal": s,
            "Channel": 6,
            "Security": "WPA2-Personal",
            "Timestamp": t_str,
            "Label": 0,
            "Group": "legit_dualband"
        })
        records.append({
            "SSID": "DualBand_Home",
            "BSSID": "60:32:b1:01:02:04",
            "Signal": max(40, s - 8),
            "Channel": 44,
            "Security": "WPA2-Personal",
            "Timestamp": t_str,
            "Label": 0,
            "Group": "legit_dualband"
        })

    # ------------------------------------------------------------------
    # 4. Controlled Evil Twin Attack Scenarios (Label=1)
    # ------------------------------------------------------------------
    # Attack Scenario A: Rogue AP with Security Downgrade (WPA2 -> Open)
    rogue_downgrades = [
        {"SSID": "TestWiFi", "BSSID": "e0:dc:ff:99:88:77", "Channel": 11, "Security": "Open", "Signals": [72, 85, 92, 96]},
        {"SSID": "Hostel_BlockB_WiFi", "BSSID": "ee:11:22:33:44:55", "Channel": 1, "Security": "Open", "Signals": [68, 82, 90, 95]},
        {"SSID": "Vardhaman_Campus", "BSSID": "da:a1:19:bb:22:33", "Channel": 3, "Security": "Open", "Signals": [75, 88, 94]}
    ]
    for i, r in enumerate(rogue_downgrades):
        for sig in r["Signals"]:
            records.append({
                "SSID": r["SSID"],
                "BSSID": r["BSSID"],
                "Signal": sig,
                "Channel": r["Channel"],
                "Security": r["Security"],
                "Timestamp": f"2026-09-14 10:{i:02d}:{sig % 60:02d}",
                "Label": 1,
                "Group": f"rogue_downgrade_{r['SSID']}"
            })

    # Attack Scenario B: Rogue AP targeting Enterprise Network (Enterprise -> Personal downgrade)
    for sig in [70, 84, 91, 95]:
        records.append({
            "SSID": "Vardhaman_Campus",
            "BSSID": "92:c5:31:44:55:66",
            "Channel": 9,
            "Security": "WPA2-Personal",
            "Timestamp": f"2026-09-14 11:20:{sig % 60:02d}",
            "Label": 1,
            "Group": "rogue_enterprise_downgrade"
        })

    # Attack Scenario C: Concurrent Rogue AP clone on Conflicting Channel with high proximity signal
    rogue_channel_conflicts = [
        {"SSID": "TP-Link_6790", "BSSID": "42:2b:44:b2:97:a9", "Channel": 11, "Security": "WPA2-Personal", "Signals": [82, 92, 96]},
        {"SSID": "CoffeeShop_WiFi", "BSSID": "f2:90:3a:cc:11:99", "Channel": 11, "Security": "Open", "Signals": [86, 94]},
        {"SSID": "Airport_Free_WiFi", "BSSID": "b8:27:eb:55:44:33", "Channel": 8, "Security": "Open", "Signals": [88, 93]}
    ]
    for i, r in enumerate(rogue_channel_conflicts):
        for sig in r["Signals"]:
            records.append({
                "SSID": r["SSID"],
                "BSSID": r["BSSID"],
                "Signal": sig,
                "Channel": r["Channel"],
                "Security": r["Security"],
                "Timestamp": f"2026-09-14 15:{i:02d}:{sig % 60:02d}",
                "Label": 1,
                "Group": f"rogue_channel_conflict_{r['SSID']}"
            })

    # Attack Scenario D: Cloned MAC Spoofing (Attacker copies legitimate BSSID)
    # Causes concurrent duplicate in same scan session with conflicting channel or signal
    for sig in [78, 89, 95]:
        records.append({
            "SSID": "TP-Link_6790",
            "BSSID": "0c:ef:15:e8:67:90",  # Cloned MAC of legitimate AP
            "Signal": sig,
            "Channel": 11,  # Conflicting channel
            "Security": "WPA2-Personal",
            "Timestamp": f"2026-09-15 16:30:{sig % 60:02d}",
            "Label": 1,
            "Group": "rogue_mac_spoofing"
        })

    # Save to wifi_observations.csv
    fieldnames = ["SSID", "BSSID", "Signal", "Channel", "Security", "Timestamp", "Label", "Group"]
    with open(obs_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow(r)

    print(f"Realistic baseline generated with {len(records)} total records.")
    print(f"- Legitimate samples (0) : {len([r for r in records if r['Label'] == 0])}")
    print(f"- Evil Twin samples (1) : {len([r for r in records if r['Label'] == 1])}")


def build_training_dataset():
    """
    Constructs training_dataset.csv from labelled records in wifi_observations.csv.
    Extracts standardized features while preserving Group identifiers for
    leakage-free group-based evaluation.
    """
    paths = get_paths()
    obs_path = paths["observations"]
    train_path = paths["training"]
    hist_path = paths["history"]

    if not os.path.exists(obs_path):
        seed_baseline_dataset(overwrite_if_exists=True)

    df_obs = pd.read_csv(obs_path)
    if df_obs.empty:
        return None

    labelled = df_obs[df_obs["Label"].astype(str).isin(["0", "1", 0, 1])].copy()
    if labelled.empty:
        return None

    labelled["Label"] = labelled["Label"].astype(int)
    history_df = load_history(hist_path)

    feature_dfs = []
    for timestamp, group in labelled.groupby("Timestamp", sort=False):
        f_df = extract_features(group, history_df=history_df)
        f_df["Label"] = group["Label"].values
        if "Group" in group.columns:
            f_df["Group"] = group["Group"].values
        else:
            f_df["Group"] = group["SSID"].values
        feature_dfs.append(f_df)

    training_df = pd.concat(feature_dfs, ignore_index=True)

    cols = FEATURE_COLUMNS + ["Label", "Group"]
    training_df = training_df[cols]

    os.makedirs(os.path.dirname(train_path), exist_ok=True)
    training_df.to_csv(train_path, index=False)

    print("==================================================")
    print("         TRAINING DATASET GENERATED               ")
    print("==================================================")
    print(f"Total labelled samples: {len(training_df)}")
    print("Class distribution:")
    print(training_df["Label"].value_counts())
    print("\nBSSIDKnown vs Label distribution:")
    print(pd.crosstab(training_df["BSSIDKnown"], training_df["Label"]))
    print(f"\nSaved to: {train_path}")

    return training_df


if __name__ == "__main__":
    seed_baseline_dataset(overwrite_if_exists=True)
    build_training_dataset()
