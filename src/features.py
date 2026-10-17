import re
import pandas as pd
from .history import (
    load_history,
    is_bssid_known,
    get_known_channels_for_ssid,
    get_known_securities_for_ssid,
    get_ap_record
)
from .system_profiles import get_saved_windows_profiles, get_profile_security_details

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
    if pd.isna(val) or val is None:
        return 0
    match = re.search(r"(\d+)", str(val))
    if not match:
        return 0
    num = int(match.group(1))
    return max(0, min(100, num))


def parse_channel(val):
    """Parses channel into an integer."""
    if pd.isna(val) or val is None:
        return 1
    match = re.search(r"(\d+)", str(val))
    return int(match.group(1)) if match else 1


def parse_security_binary(val):
    """
    Returns:
    0 = Open / None
    1 = Secured (WPA, WPA2, WPA3, WEP, 802.1X)
    """
    if pd.isna(val) or val is None:
        return 0
    val_lower = str(val).strip().lower()
    if not val_lower or "open" in val_lower or "none" in val_lower or val_lower == "0":
        return 0
    return 1


def get_security_tier(val):
    """
    Categorizes security protocol into hierarchy tiers:
    0 = Open / None
    1 = WEP
    2 = WPA-Personal
    3 = WPA2-Personal
    4 = WPA3-Personal
    5 = WPA2-Enterprise
    6 = WPA3-Enterprise
    """
    if pd.isna(val) or val is None:
        return 0
    s = str(val).strip().lower()
    if "wpa3" in s and "enterprise" in s:
        return 6
    if "enterprise" in s or "802.1x" in s:
        return 5
    if "wpa3" in s:
        return 4
    if "wpa2" in s:
        return 3
    if "wpa" in s:
        return 2
    if "wep" in s:
        return 1
    if "open" in s or "none" in s or s == "0":
        return 0
    return 3


def check_security_match(current_sec_raw, known_securities_set):
    """
    Determines if current security matches or is compatible with historical security.
    Detects security downgrade attacks (e.g. Enterprise -> Personal, WPA2/3 -> Open).
    Returns 1 if matching/compatible or SSID is new, 0 if downgraded or unexpected.
    """
    if not known_securities_set:
        return 1

    current_tier = get_security_tier(current_sec_raw)
    current_bin = parse_security_binary(current_sec_raw)

    known_tiers = {get_security_tier(s) for s in known_securities_set}
    known_bins = {parse_security_binary(s) for s in known_securities_set}

    # If any known profile was Secured and current is Open -> severe downgrade
    if max(known_bins) == 1 and current_bin == 0:
        return 0

    # If known was Enterprise and current is Personal -> downgrade
    if max(known_tiers) >= 5 and current_tier < 5:
        return 0

    # If current tier is within known tiers or upgrades
    if current_tier in known_tiers or current_tier >= min(known_tiers):
        return 1

    return 0


def is_dual_band_pair(ap_a, ap_b):
    """
    Checks if two access points with the same SSID represent the complementary
    2.4 GHz and 5 GHz radios of a single legitimate physical router.

    Signatures of legitimate dual-band hardware:
    1. Identical vendor OUI (first 3 octets, e.g. '16:32:51' == '16:32:51').
    2. Consecutive or near-consecutive MACs (differing by <= 4 in last octet, e.g. ea:62 and ea:63).
    3. Complementary frequency bands (one in 2.4 GHz ch 1-14, other in 5 GHz ch 36-165).
    4. Identical or compatible security tier.
    """
    bssid_a = str(ap_a.get("BSSID", "")).strip().lower()
    bssid_b = str(ap_b.get("BSSID", "")).strip().lower()
    chan_a = parse_channel(ap_a.get("Channel", 1))
    chan_b = parse_channel(ap_b.get("Channel", 1))

    if not bssid_a or not bssid_b or bssid_a == bssid_b:
        return False

    parts_a = bssid_a.split(":")
    parts_b = bssid_b.split(":")
    if len(parts_a) != 6 or len(parts_b) != 6:
        return False

    # Check matching OUI (first 3 octets)
    if parts_a[:3] != parts_b[:3]:
        return False

    # Check MAC distance
    try:
        last_a = int(parts_a[5], 16)
        last_b = int(parts_b[5], 16)
        if abs(last_a - last_b) > 4:
            return False
    except ValueError:
        return False

    # Check complementary frequency bands
    is_24_a = 1 <= chan_a <= 14
    is_5g_a = 32 <= chan_a <= 177
    is_24_b = 1 <= chan_b <= 14
    is_5g_b = 32 <= chan_b <= 177

    complementary_bands = (is_24_a and is_5g_b) or (is_5g_a and is_24_b)
    if not complementary_bands:
        return False

    # Check security compatibility
    sec_a = parse_security_binary(ap_a.get("Security", ""))
    sec_b = parse_security_binary(ap_b.get("Security", ""))
    if sec_a != sec_b:
        return False

    return True


def analyze_scanned_relationships(scan_records):
    """
    Analyzes contextual relationships among scanned APs:
    - Identifies dual-band router pairs (2.4 GHz + 5 GHz).
    - Identifies campus multi-AP deployments.
    - Identifies suspicious duplicate collisions.
    Returns a dict mapping bssid -> relationship info dictionary.
    """
    relationships = {}
    if not scan_records:
        return relationships

    records = scan_records if isinstance(scan_records, list) else scan_records.to_dict(orient="records")

    # Group by SSID
    by_ssid = {}
    for r in records:
        ssid = str(r.get("SSID", "")).strip()
        by_ssid.setdefault(ssid, []).append(r)

    for ssid, aps in by_ssid.items():
        if len(aps) >= 2:
            # Check pairwise for dual-band router signatures
            for i in range(len(aps)):
                bssid_i = str(aps[i].get("BSSID", "")).strip().lower()
                for j in range(i + 1, len(aps)):
                    bssid_j = str(aps[j].get("BSSID", "")).strip().lower()
                    if is_dual_band_pair(aps[i], aps[j]):
                        relationships[bssid_i] = {
                            "is_dual_band": True,
                            "partner_bssid": bssid_j,
                            "note": "Legitimate Dual-Band router (2.4 GHz + 5 GHz complementary radios with matching vendor OUI)"
                        }
                        relationships[bssid_j] = {
                            "is_dual_band": True,
                            "partner_bssid": bssid_i,
                            "note": "Legitimate Dual-Band router (2.4 GHz + 5 GHz complementary radios with matching vendor OUI)"
                        }

    return relationships


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
    elif isinstance(scan_records, pd.DataFrame):
        df = scan_records.copy()
    else:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    if df.empty:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    # Compute SameSSIDCount across the current scan session
    ssid_clean_series = df["SSID"].astype(str).str.strip()
    ssid_counts = ssid_clean_series.value_counts().to_dict()

    feature_rows = []

    for _, row in df.iterrows():
        ssid = str(row.get("SSID", "")).strip()
        bssid = str(row.get("BSSID", "")).strip().lower()
        signal = parse_signal(row.get("Signal", 0))
        channel = parse_channel(row.get("Channel", 1))
        sec_raw = row.get("Security", "Unknown")
        security = parse_security_binary(sec_raw)

        same_ssid_count = ssid_counts.get(ssid, 1)

        # 1. BSSIDKnown: 1 if BSSID previously seen in history, 0 otherwise
        bssid_known = 1 if is_bssid_known(history_df, ssid, bssid) else 0

        # Check historical parameters for this SSID
        known_channels = get_known_channels_for_ssid(history_df, ssid)
        known_securities = get_known_securities_for_ssid(history_df, ssid)

        # 2. ChannelMatch:
        if len(known_channels) > 0:
            channel_match = 1 if channel in known_channels else 0
        else:
            channel_match = 1

        # 3. SecurityMatch:
        if len(known_securities) > 0:
            security_match = check_security_match(sec_raw, known_securities)
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


def generate_feature_explanations(network_info, features_row, history_df=None, context_info=None):
    """
    Generates dynamic, evidence-based reason bullet points for a detected AP
    by comparing current observation against history, Windows profiles, and physical RF features.
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

    # Windows Saved Profile check
    if context_info and context_info.get("is_saved_profile"):
        p_sec = context_info.get("profile_security", "")
        reasons.append(f"SSID matches a saved, user-configured Windows Wi-Fi profile ('{ssid}').")

    # Dual-Band Router correlation
    if context_info and context_info.get("is_dual_band"):
        partner = context_info.get("partner_bssid", "")
        reasons.append(
            f"Dual-band hardware correlated: Complementary radio detected ({partner}) "
            f"with matching vendor OUI and consecutive MAC addresses."
        )

    # BSSID reason
    if bssid_known == 1 and ap_rec is not None:
        obs_count = ap_rec.get("Observation Count", 1)
        reasons.append(f"BSSID was previously observed in history ({obs_count} prior observation(s)).")
    elif bssid_known == 1:
        reasons.append("BSSID matches a known physical access point.")
    elif not (context_info and context_info.get("is_saved_profile")):
        reasons.append("BSSID has not been observed before on this device (new / unverified MAC address).")

    # SSID Multiplicity reason
    if same_ssid_count > 1:
        if context_info and context_info.get("is_dual_band"):
            reasons.append(f"Multi-band broadcast: {same_ssid_count} radios (2.4 GHz + 5 GHz) broadcast this SSID from the same router.")
        else:
            reasons.append(f"Multiple APs ({same_ssid_count}) are broadcasting this same SSID simultaneously (campus/mesh or competing clone).")
    else:
        reasons.append("SSID is unique in this scan (no conflicting concurrent broadcast).")

    # Channel match reason
    known_channels = get_known_channels_for_ssid(history_df, ssid)
    band_name = "5 GHz" if (32 <= channel <= 177) else "2.4 GHz"
    if len(known_channels) > 0:
        if channel_match == 1:
            reasons.append(f"Operating channel {channel} ({band_name} band) matches historical profile for this SSID.")
        else:
            reasons.append(f"Operating channel {channel} ({band_name} band) differs from historical channel(s) ({sorted(list(known_channels))}) for this SSID.")
    else:
        reasons.append(f"Operating on channel {channel} ({band_name} band).")

    # Security match reason
    known_secs = get_known_securities_for_ssid(history_df, ssid)
    if len(known_secs) > 0:
        if security_match == 1:
            reasons.append("Security configuration matches or is compatible with previous legitimate observations.")
        else:
            reasons.append("Security type has changed or downgraded compared to previous observations.")
    else:
        sec_desc = network_info.get("Security", "Secured" if security == 1 else "Open (Unencrypted)")
        reasons.append(f"Network is configured as {sec_desc}.")

    # Radio & Cipher capability if present
    if network_info.get("Radio"):
        reasons.append(f"Physical PHY layer: {network_info['Radio']} with {network_info.get('Encryption', 'standard')} cipher.")

    # Signal observation
    reasons.append(f"Observed signal strength is {signal}%.")

    return reasons


if __name__ == "__main__":
    print("==================================================")
    print("           FEATURE EXTRACTION MODULE              ")
    print("==================================================")
    print("Feature columns:", FEATURE_COLUMNS)
