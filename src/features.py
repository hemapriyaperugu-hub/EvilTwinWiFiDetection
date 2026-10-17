import re
import pandas as pd
from .history import (
    load_history,
    is_bssid_known,
    get_known_channels_for_ssid,
    get_known_securities_for_ssid,
    get_ap_record
)

FEATURE_COLUMNS = [
    "Signal",
    "Channel",
    "Security",
    "SameSSIDCount",
    "BSSIDKnown",
    "ChannelMatch",
    "SecurityMatch"
]


def parse_signal(val):
    """Parses signal value into an integer percentage (0-100)."""
    if pd.isna(val):
        return 0
    match = re.search(r"(\d+)", str(val))
    return int(match.group(1)) if match else 0


def parse_channel(val):
    """Parses channel into an integer."""
    if pd.isna(val):
        return 1
    match = re.search(r"(\d+)", str(val))
    return int(match.group(1)) if match else 1


def parse_security_binary(val):
    """
    Returns:
    0 = Open / None
    1 = Secured (WPA, WPA2, WPA3, WEP, 802.1X)
    """
    if pd.isna(val):
        return 0
    val_lower = str(val).strip().lower()
    if "open" in val_lower or "none" in val_lower or val_lower == "0":
        return 0
    return 1


def extract_features(scan_records, history_df=None):
    """
    Extracts standardized 7-feature DataFrame for a list of scanned APs.
    scan_records: list of dicts or pandas DataFrame.
    history_df: network history DataFrame (loaded automatically if None).
    """
    if history_df is None:
        history_df = load_history()

    if isinstance(scan_records, list):
        df = pd.DataFrame(scan_records)
    else:
        df = scan_records.copy()

    if df.empty:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    # Compute SameSSIDCount across the current scan
    ssid_counts = df["SSID"].astype(str).str.strip().value_counts().to_dict()

    feature_rows = []

    for _, row in df.iterrows():
        ssid = str(row.get("SSID", "")).strip()
        bssid = str(row.get("BSSID", "")).strip().lower()
        signal = parse_signal(row.get("Signal", 0))
        channel = parse_channel(row.get("Channel", 1))
        sec_raw = row.get("Security", "Unknown")
        security = parse_security_binary(sec_raw)

        same_ssid_count = ssid_counts.get(ssid, 1)

        # 1. BSSIDKnown: 1 if BSSID seen in history, 0 otherwise
        bssid_known = 1 if is_bssid_known(history_df, ssid, bssid) else 0

        # Check historical parameters for this SSID
        known_channels = get_known_channels_for_ssid(history_df, ssid)
        known_securities = get_known_securities_for_ssid(history_df, ssid)

        # 2. ChannelMatch:
        # If SSID was seen before, does this channel match any historical channel for this SSID?
        # If SSID is brand new, default to 1 (no historical conflict).
        if len(known_channels) > 0:
            channel_match = 1 if channel in known_channels else 0
        else:
            channel_match = 1

        # 3. SecurityMatch:
        # If SSID was seen before, does this security binary match historical security?
        # If SSID is brand new, default to 1 (no historical conflict).
        if len(known_securities) > 0:
            known_binaries = {parse_security_binary(s) for s in known_securities}
            security_match = 1 if security in known_binaries else 0
        else:
            security_match = 1

        feature_rows.append({
            "Signal": signal,
            "Channel": channel,
            "Security": security,
            "SameSSIDCount": same_ssid_count,
            "BSSIDKnown": bssid_known,
            "ChannelMatch": channel_match,
            "SecurityMatch": security_match
        })

    return pd.DataFrame(feature_rows, columns=FEATURE_COLUMNS)


def generate_feature_explanations(network_info, features_row, history_df=None):
    """
    Generates dynamic, evidence-based reason bullet points for a detected AP
    by comparing current observation against history and feature values.
    """
    if history_df is None:
        history_df = load_history()

    reasons = []
    ssid = str(network_info.get("SSID", "")).strip()
    bssid = str(network_info.get("BSSID", "")).strip().lower()
    signal = features_row.get("Signal", 0)
    channel = features_row.get("Channel", 1)
    security = features_row.get("Security", 1)
    same_ssid_count = features_row.get("SameSSIDCount", 1)
    bssid_known = features_row.get("BSSIDKnown", 0)
    channel_match = features_row.get("ChannelMatch", 1)
    security_match = features_row.get("SecurityMatch", 1)

    ap_rec = get_ap_record(history_df, ssid, bssid)

    # BSSID reason
    if bssid_known == 1 and ap_rec is not None:
        obs_count = ap_rec.get("Observation Count", 1)
        reasons.append(f"BSSID was previously observed in history ({obs_count} prior observation(s)).")
    elif bssid_known == 1:
        reasons.append("BSSID matches a known physical access point.")
    else:
        reasons.append("BSSID has not been observed before (new / unverified MAC address).")

    # SSID Multiplicity reason
    if same_ssid_count > 1:
        reasons.append(f"Multiple APs ({same_ssid_count}) are broadcasting this same SSID simultaneously.")
    else:
        reasons.append("SSID is unique in this scan (no conflicting broadcast).")

    # Channel match reason
    known_channels = get_known_channels_for_ssid(history_df, ssid)
    if len(known_channels) > 0:
        if channel_match == 1:
            reasons.append(f"Operating channel ({channel}) matches historical profile for this SSID.")
        else:
            reasons.append(f"Operating channel ({channel}) differs from historical channel(s) ({list(known_channels)}) for this SSID.")
    else:
        reasons.append(f"Operating on channel {channel} (first time this SSID is recorded).")

    # Security match reason
    known_secs = get_known_securities_for_ssid(history_df, ssid)
    if len(known_secs) > 0:
        if security_match == 1:
            reasons.append("Security encryption matches previous legitimate observations.")
        else:
            reasons.append("Security type has changed or downgraded compared to previous observations.")
    else:
        sec_desc = "Secured" if security == 1 else "Open (Unencrypted)"
        reasons.append(f"Network is configured as {sec_desc}.")

    # Signal observation
    reasons.append(f"Observed signal strength is {signal}%.")

    return reasons


if __name__ == "__main__":
    print("==================================================")
    print("           FEATURE EXTRACTION MODULE              ")
    print("==================================================")
    print("Feature columns:", FEATURE_COLUMNS)
