import os
import pandas as pd
from .features import extract_features, FEATURE_COLUMNS
from .history import (
    HISTORY_COLUMNS,
    TRUST_ESTABLISHED,
    compute_fingerprint,
    extract_oui,
    load_history,
    save_history_safely
)
from .paths import get_data_dir


def get_paths():
    base_dir = get_data_dir()
    return {
        "base": base_dir,
        "observations": os.path.join(base_dir, "dataset", "wifi_observations.csv"),
        "history": os.path.join(base_dir, "dataset", "network_history.csv"),
        "training": os.path.join(base_dir, "dataset", "training_dataset.csv")
    }


def _get_seeded_baseline_aps():
    return [
        {"SSID": "Hostel_BlockB_WiFi", "BSSID": "70:4f:57:12:34:56", "Channel": 6, "Security": "WPA2-Personal", "Encryption": "CCMP", "Band": "2.4 GHz"},
        {"SSID": "TP-Link_6790", "BSSID": "0c:ef:15:e8:67:90", "Channel": 3, "Security": "WPA2-Personal", "Encryption": "CCMP", "Band": "2.4 GHz"},
        {"SSID": "Home_Fiber_5G", "BSSID": "50:d4:f7:9a:bc:de", "Channel": 36, "Security": "WPA2-Personal", "Encryption": "CCMP", "Band": "5 GHz"},
        {"SSID": "Student_StudyRoom", "BSSID": "ac:84:c6:33:44:55", "Channel": 11, "Security": "WPA2-Personal", "Encryption": "CCMP", "Band": "2.4 GHz"},
        {"SSID": "Vardhaman_Campus", "BSSID": "18:64:72:a1:01:01", "Channel": 1, "Security": "WPA2-Enterprise", "Encryption": "CCMP", "Band": "2.4 GHz"},
        {"SSID": "Vardhaman_Campus", "BSSID": "18:64:72:a1:01:02", "Channel": 6, "Security": "WPA2-Enterprise", "Encryption": "CCMP", "Band": "2.4 GHz"},
        {"SSID": "Vardhaman_Campus", "BSSID": "18:64:72:a1:01:03", "Channel": 11, "Security": "WPA2-Enterprise", "Encryption": "CCMP", "Band": "2.4 GHz"},
        {"SSID": "TestWiFi", "BSSID": "00:14:22:01:23:45", "Channel": 1, "Security": "WPA2-Personal", "Encryption": "CCMP", "Band": "2.4 GHz"},
        {"SSID": "CoffeeShop_WiFi", "BSSID": "44:48:b1:11:22:33", "Channel": 6, "Security": "Open", "Encryption": "None", "Band": "2.4 GHz"},
        {"SSID": "Airport_Free_WiFi", "BSSID": "3c:37:12:77:88:99", "Channel": 1, "Security": "Open", "Encryption": "None", "Band": "2.4 GHz"}
    ]


def seed_baseline_dataset(overwrite_if_exists=False):
    """
    Creates a realistic controlled baseline dataset for ML training and evaluation,
    while preserving any existing unlabelled real-world scan observations (Label='Unknown')
    and any non-seeded user records in network_history.csv.
    """
    paths = get_paths()
    obs_path = paths["observations"]
    hist_path = paths["history"]

    if os.path.exists(obs_path) and os.path.getsize(obs_path) > 200 and not overwrite_if_exists:
        return

    os.makedirs(os.path.dirname(obs_path), exist_ok=True)
    known_legit_aps = _get_seeded_baseline_aps()

    # Preserve existing non-seeded history entries while ensuring seeded baselines use HISTORY_COLUMNS
    existing_hist = load_history(hist_path) if os.path.exists(hist_path) else pd.DataFrame(columns=HISTORY_COLUMNS)
    seeded_keys = {(ap["SSID"], ap["BSSID"]) for ap in known_legit_aps}

    hist_rows = []
    for ap in known_legit_aps:
        ch_str = str(ap["Channel"])
        hist_rows.append({
            "SSID": ap["SSID"],
            "BSSID": ap["BSSID"],
            "Security": ap["Security"],
            "Encryption": ap["Encryption"],
            "Channel": ch_str,
            "Band": ap["Band"],
            "Signal": "75",
            "Last Signal": "75",
            "Last Channel": ch_str,
            "Last Security": ap["Security"],
            "OUI": extract_oui(ap["BSSID"]),
            "Fingerprint": compute_fingerprint(ap["SSID"], ap["BSSID"], ap["Security"], ap["Encryption"], ch_str, ap["Band"]),
            "First Seen": "2026-09-01 09:00:00",
            "Last Seen": "2026-09-15 18:00:00",
            "Observation Count": 10,
            "Previous Classification": "KNOWN / CONSISTENT",
            "Trust Status": TRUST_ESTABLISHED,
            "Suspicious Indicators": "",
            "Changes": ""
        })

    if not existing_hist.empty:
        for _, r in existing_hist.iterrows():
            if (r["SSID"], r["BSSID"]) not in seeded_keys:
                hist_rows.append(r.to_dict())

    save_history_safely(pd.DataFrame(hist_rows, columns=HISTORY_COLUMNS), hist_path)

    records = []

    # 1. Known Legitimate APs (consistent)
    signals_variations = [55, 68, 75, 82, 88, 92, 98, 100, 62, 70, 85, 90]
    for i, sig in enumerate(signals_variations):
        t_str = f"2026-09-10 10:{i:02d}:00"
        for ap in known_legit_aps[:4]:
            s = max(40, min(100, sig + (sum(ord(c) for c in ap["SSID"]) % 7 - 3)))
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

    # 1b. Legitimate Auto-Channel Shifts (same BSSID + same security, channel changed)
    # Prevents models from treating ChannelMatch==0 alone as an Evil Twin
    for i, (ch_shift, sig) in enumerate([(2, 74), (6, 80), (11, 69), (1, 86)]):
        records.append({
            "SSID": "TP-Link_6790",
            "BSSID": "0c:ef:15:e8:67:90",
            "Signal": sig,
            "Channel": ch_shift,
            "Security": "WPA2-Personal",
            "Timestamp": f"2026-09-10 15:{i:02d}:00",
            "Label": 0,
            "Group": "legit_channel_shift_tplink"
        })
    for i, (ch_shift, sig) in enumerate([(40, 72), (44, 79), (48, 84), (149, 68)]):
        records.append({
            "SSID": "Home_Fiber_5G",
            "BSSID": "50:d4:f7:9a:bc:de",
            "Signal": sig,
            "Channel": ch_shift,
            "Security": "WPA2-Personal",
            "Timestamp": f"2026-09-10 16:{i:02d}:00",
            "Label": 0,
            "Group": "legit_channel_shift_fiber"
        })

    # 2. Campus Multi-AP scans (Label=0)
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

    # 2b. Public Open Wi-Fi legitimate scans (Label=0)
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

    # 3. Legitimate New / Unverified Networks (BSSIDKnown=0, Label=0)
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

    # Dual-Band router (Label=0)
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

    # 4. Controlled Evil Twin Attack Scenarios (Label=1)
    # Note: Concurrent legitimate AP is also present in the same scan Timestamp
    # where realistic so SameSSIDCount accurately reflects concurrent clones.

    # Scenario A1: Concurrent Security Downgrade on different channel
    rogue_downgrades = [
        {
            "SSID": "TestWiFi", "LegitBSSID": "00:14:22:01:23:45", "LegitCh": 1, "LegitSec": "WPA2-Personal",
            "RogueBSSID": "e0:dc:ff:99:88:77", "RogueCh": 11, "RogueSec": "Open", "Signals": [72, 85, 92, 96]
        },
        {
            "SSID": "Hostel_BlockB_WiFi", "LegitBSSID": "70:4f:57:12:34:56", "LegitCh": 6, "LegitSec": "WPA2-Personal",
            "RogueBSSID": "ee:11:22:33:44:55", "RogueCh": 1, "RogueSec": "Open", "Signals": [68, 82, 90, 95]
        },
        {
            "SSID": "Vardhaman_Campus", "LegitBSSID": "18:64:72:a1:01:01", "LegitCh": 1, "LegitSec": "WPA2-Enterprise",
            "RogueBSSID": "da:a1:19:bb:22:33", "RogueCh": 3, "RogueSec": "Open", "Signals": [75, 88, 94]
        }
    ]
    for i, r in enumerate(rogue_downgrades):
        for k, sig in enumerate(r["Signals"]):
            t_str = f"2026-09-14 10:{i:02d}:{k:02d}"
            records.append({
                "SSID": r["SSID"], "BSSID": r["LegitBSSID"], "Signal": max(45, sig - 18),
                "Channel": r["LegitCh"], "Security": r["LegitSec"], "Timestamp": t_str,
                "Label": 0, "Group": f"legit_during_attack_{r['SSID']}"
            })
            records.append({
                "SSID": r["SSID"], "BSSID": r["RogueBSSID"], "Signal": sig,
                "Channel": r["RogueCh"], "Security": r["RogueSec"], "Timestamp": t_str,
                "Label": 1, "Group": f"rogue_downgrade_{r['SSID']}"
            })

    # Scenario A2: Same-Channel Security Downgrade (ChannelMatch=1, SecurityMatch=0)
    same_chan_rogues = [
        {
            "SSID": "Student_StudyRoom", "LegitBSSID": "ac:84:c6:33:44:55", "Ch": 11, "LegitSec": "WPA2-Personal",
            "RogueBSSID": "f6:12:34:56:78:90", "RogueSec": "Open", "Signals": [81, 89, 95]
        },
        {
            "SSID": "Home_Fiber_5G", "LegitBSSID": "50:d4:f7:9a:bc:de", "Ch": 36, "LegitSec": "WPA2-Personal",
            "RogueBSSID": "aa:11:22:33:44:99", "RogueSec": "Open", "Signals": [77, 86, 93]
        }
    ]
    for i, r in enumerate(same_chan_rogues):
        for k, sig in enumerate(r["Signals"]):
            t_str = f"2026-09-14 12:{i:02d}:{k:02d}"
            records.append({
                "SSID": r["SSID"], "BSSID": r["LegitBSSID"], "Signal": max(45, sig - 15),
                "Channel": r["Ch"], "Security": r["LegitSec"], "Timestamp": t_str,
                "Label": 0, "Group": f"legit_during_samech_{r['SSID']}"
            })
            records.append({
                "SSID": r["SSID"], "BSSID": r["RogueBSSID"], "Signal": sig,
                "Channel": r["Ch"], "Security": r["RogueSec"], "Timestamp": t_str,
                "Label": 1, "Group": f"rogue_samech_downgrade_{r['SSID']}"
            })

    # Scenario B: Enterprise -> Personal Downgrade (fixing missing Signal bug!)
    for k, sig in enumerate([70, 84, 91, 95]):
        t_str = f"2026-09-14 11:20:{k:02d}"
        records.append({
            "SSID": "Vardhaman_Campus", "BSSID": "18:64:72:a1:01:02", "Signal": max(45, sig - 16),
            "Channel": 6, "Security": "WPA2-Enterprise", "Timestamp": t_str,
            "Label": 0, "Group": "legit_during_ent_attack"
        })
        records.append({
            "SSID": "Vardhaman_Campus", "BSSID": "92:c5:31:44:55:66", "Signal": sig,
            "Channel": 9, "Security": "WPA2-Personal", "Timestamp": t_str,
            "Label": 1, "Group": "rogue_enterprise_downgrade"
        })

    # Scenario C: Concurrent Conflicting Clone (same security, conflicting channel + BSSID)
    rogue_channel_conflicts = [
        {
            "SSID": "TP-Link_6790", "LegitBSSID": "0c:ef:15:e8:67:90", "LegitCh": 3, "Sec": "WPA2-Personal",
            "RogueBSSID": "42:2b:44:b2:97:a9", "RogueCh": 11, "Signals": [82, 92, 96]
        },
        {
            "SSID": "CoffeeShop_WiFi", "LegitBSSID": "44:48:b1:11:22:33", "LegitCh": 6, "Sec": "Open",
            "RogueBSSID": "f2:90:3a:cc:11:99", "RogueCh": 11, "Signals": [86, 94, 97]
        },
        {
            "SSID": "Airport_Free_WiFi", "LegitBSSID": "3c:37:12:77:88:99", "LegitCh": 1, "Sec": "Open",
            "RogueBSSID": "b8:27:eb:55:44:33", "RogueCh": 8, "Signals": [88, 93, 98]
        }
    ]
    for i, r in enumerate(rogue_channel_conflicts):
        for k, sig in enumerate(r["Signals"]):
            t_str = f"2026-09-14 15:{i:02d}:{k:02d}"
            records.append({
                "SSID": r["SSID"], "BSSID": r["LegitBSSID"], "Signal": max(45, sig - 20),
                "Channel": r["LegitCh"], "Security": r["Sec"], "Timestamp": t_str,
                "Label": 0, "Group": f"legit_during_conflict_{r['SSID']}"
            })
            records.append({
                "SSID": r["SSID"], "BSSID": r["RogueBSSID"], "Signal": sig,
                "Channel": r["RogueCh"], "Security": r["Sec"], "Timestamp": t_str,
                "Label": 1, "Group": f"rogue_channel_conflict_{r['SSID']}"
            })

    # Scenario D: Cloned MAC Spoofing (concurrent duplicate BSSID on conflicting channel)
    for k, sig in enumerate([78, 89, 95]):
        t_str = f"2026-09-15 16:30:{k:02d}"
        records.append({
            "SSID": "TP-Link_6790", "BSSID": "0c:ef:15:e8:67:90", "Signal": max(45, sig - 18),
            "Channel": 3, "Security": "WPA2-Personal", "Timestamp": t_str,
            "Label": 0, "Group": "legit_during_mac_spoof"
        })
        records.append({
            "SSID": "TP-Link_6790", "BSSID": "0c:ef:15:e8:67:90", "Signal": sig,
            "Channel": 11, "Security": "WPA2-Personal", "Timestamp": t_str,
            "Label": 1, "Group": "rogue_mac_spoofing"
        })

    # Preserve any existing unlabelled real-world scan rows (Label == 'Unknown')
    unknown_rows = []
    if os.path.exists(obs_path) and os.path.getsize(obs_path) > 0:
        try:
            old_obs = pd.read_csv(obs_path, dtype=str)
            if not old_obs.empty and "Label" in old_obs.columns:
                unk = old_obs[~old_obs["Label"].astype(str).isin(["0", "1"])].copy()
                if not unk.empty:
                    if "Group" not in unk.columns:
                        unk["Group"] = ""
                    unknown_rows = unk.to_dict(orient="records")
        except Exception:
            unknown_rows = []

    fieldnames = ["SSID", "BSSID", "Signal", "Channel", "Security", "Timestamp", "Label", "Group"]
    out_df = pd.DataFrame(records + unknown_rows, columns=fieldnames)
    out_df.to_csv(obs_path, index=False)

    print(f"Controlled baseline generated with {len(records)} labelled records (+ {len(unknown_rows)} preserved real scan rows).")
    print(f"- Legitimate samples (0): {len([r for r in records if r['Label'] == 0])}")
    print(f"- Evil Twin samples (1) : {len([r for r in records if r['Label'] == 1])}")


def build_training_dataset():
    """
    Constructs training_dataset.csv from labelled records in wifi_observations.csv.
    Uses only the established baseline history for feature comparison and preserves
    Group identifiers for leakage-free group-based evaluation.
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

    labelled = df_obs[df_obs["Label"].astype(str).isin(["0", "1", "0.0", "1.0"])].copy()
    if labelled.empty:
        return None

    labelled["Label"] = labelled["Label"].astype(float).astype(int)
    full_hist = load_history(hist_path)
    # Use only trusted baseline records when constructing training features so
    # passive unlabelled scans do not leak into training features.
    if "Trust Status" in full_hist.columns:
        history_df = full_hist[full_hist["Trust Status"] == TRUST_ESTABLISHED].copy()
    else:
        history_df = full_hist

    feature_dfs = []
    for _, group in labelled.groupby("Timestamp", sort=False):
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
