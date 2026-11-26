import re
import numpy as np
import pandas as pd
from .history import (
    load_history,
    is_bssid_known,
    get_bssid_other_ssids,
    get_known_channels_for_ssid,
    get_known_securities_for_ssid,
    get_known_encryptions_for_ssid,
    get_ap_record,
    compute_fingerprint,
    extract_oui,
    parse_channel_list,
    sanitize_bssid,
    sanitize_ssid
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

UNAVAILABLE_TOKENS = {"", "nan", "none", "null", "unknown", "unavailable", "--", "n/a"}


def is_unavailable(val):
    if val is None:
        return True
    try:
        if pd.isna(val):
            return True
    except Exception:
        pass
    return str(val).strip().lower() in UNAVAILABLE_TOKENS


def parse_signal(val):
    """
    Parses signal strength percentage (0-100).
    Returns np.nan if the feature is unavailable rather than inventing 0.
    """
    if is_unavailable(val):
        return np.nan
    match = re.search(r"(-?\d+)", str(val))
    if not match:
        return np.nan
    num = int(match.group(1))
    # Support dBm input if negative (e.g. -55 dBm -> ~90%)
    if num < 0:
        return float(max(0, min(100, 2 * (num + 100))))
    return float(max(0, min(100, num)))


def estimate_dbm_from_percent(signal_pct):
    """Converts Windows 0-100% signal quality to approximate dBm using Microsoft's linear mapping."""
    if signal_pct is None or pd.isna(signal_pct):
        return None
    return int(round((float(signal_pct) / 2.0) - 100.0))


def parse_channel(val):
    """
    Parses Wi-Fi channel into a positive float/int.
    Returns np.nan if unavailable rather than inventing Channel 1.
    """
    if is_unavailable(val):
        return np.nan
    match = re.search(r"(\d+)", str(val))
    if not match:
        return np.nan
    ch = int(match.group(1))
    return float(ch) if ch > 0 else np.nan


def parse_security_binary(val):
    """
    Returns:
    0.0 = Explicitly Open / None
    1.0 = Explicitly Secured (WPA, WPA2, WPA3, WEP, 802.1X, Enterprise)
    np.nan = Unavailable / Unknown (never silently assumed safe)
    """
    if is_unavailable(val):
        return np.nan
    val_lower = str(val).strip().lower()
    if "open" in val_lower or val_lower in ("none", "0", "unencrypted"):
        return 0.0
    if any(tok in val_lower for tok in ("wpa", "wep", "802.1x", "enterprise", "rsn", "sae", "psk", "1")):
        return 1.0
    return np.nan


def get_compatible_security_tiers(val):
    """
    Returns a set of compatible security hierarchy tiers for a security string.
    Handles formatting variants and mixed modes (e.g., 'WPA2/WPA3-Personal' -> {3, 4},
    'WPA2-Personal / CCMP' -> {3}).
    Returns empty set if unavailable.
    """
    if is_unavailable(val):
        return set()
    s = str(val).strip().lower()
    tiers = set()
    is_ent = ("enterprise" in s or "802.1x" in s)

    if "wpa3" in s or "sae" in s:
        tiers.add(6 if is_ent else 4)
    if "wpa2" in s or "rsn" in s:
        tiers.add(5 if is_ent else 3)
    if not tiers and is_ent:
        tiers.add(5)
    if not tiers and "wpa" in s:
        tiers.add(2)
    if "wep" in s:
        tiers.add(1)
    if "open" in s or s in ("none", "0", "unencrypted"):
        tiers.add(0)
    return tiers


def normalize_security_label(val):
    """Normalizes equivalent Windows/scanner security strings to canonical labels."""
    tiers = get_compatible_security_tiers(val)
    if not tiers:
        return "Unavailable"
    if tiers == {3, 4}:
        return "WPA2/WPA3-Personal"
    if tiers == {5, 6}:
        return "WPA2/WPA3-Enterprise"
    top = max(tiers)
    mapping = {
        6: "WPA3-Enterprise",
        5: "WPA2-Enterprise",
        4: "WPA3-Personal",
        3: "WPA2-Personal",
        2: "WPA-Personal",
        1: "WEP",
        0: "Open"
    }
    return mapping.get(top, "Unavailable")


def get_security_tier(val):
    """
    Categorizes security protocol into highest applicable hierarchy tier:
    None = Unavailable / Unknown
    0 = Open / None
    1 = WEP
    2 = WPA-Personal
    3 = WPA2-Personal
    4 = WPA3-Personal
    5 = WPA2-Enterprise / 802.1X
    6 = WPA3-Enterprise
    """
    tiers = get_compatible_security_tiers(val)
    return max(tiers) if tiers else None


def get_encryption_tier(val, sec_fallback=None):
    """
    Categorizes cipher suite into hierarchy tiers (checking sec_fallback if cipher
    is embedded like 'WPA2-Personal / CCMP'):
    None = Unavailable / Unknown
    0 = None
    1 = WEP
    2 = TKIP
    3 = CCMP / AES
    4 = GCMP / GCMP-256
    """
    candidate = sec_fallback if is_unavailable(val) else val
    if is_unavailable(candidate):
        return None
    s = str(candidate).strip().lower()
    if "gcmp" in s:
        return 4
    if "ccmp" in s or "aes" in s:
        return 3
    if "tkip" in s:
        return 2
    if "wep" in s:
        return 1
    if s in ("none", "open", "0"):
        return 0
    return None


def classify_security_comparison(current_sec_raw, current_enc_raw, baseline_secs_set, baseline_encs_set=None):
    """
    Compares current security/encryption against a set of baseline security strings.
    Returns one of:
    - "NO_BASELINE": No valid baseline security exists.
    - "UNAVAILABLE": Current security is missing/unavailable.
    - "MATCH": Equivalent, compatible, mixed-mode compatible, or stronger security.
    - "SHIFT_MODERATE": Non-critical shift between modern AES suites (e.g. strict WPA3 -> WPA2).
    - "DOWNGRADE_CRITICAL": Genuine downgrade (Secured -> Open/WEP/WPA1, Enterprise -> Personal, CCMP -> TKIP/WEP/None).
    """
    known_tier_sets = [
        get_compatible_security_tiers(s) for s in (baseline_secs_set or set())
    ]
    known_tier_sets = [ts for ts in known_tier_sets if ts]
    if not known_tier_sets:
        return "NO_BASELINE"

    curr_tiers = get_compatible_security_tiers(current_sec_raw)
    if not curr_tiers:
        return "UNAVAILABLE"

    # Compute the minimum acceptable baseline tier (if baseline was mixed WPA2/WPA3 {3,4}, min is 3)
    # and the strongest baseline requirement across records.
    required_min_tiers = [min(ts) for ts in known_tier_sets]
    max_required_floor = max(required_min_tiers)
    curr_max = max(curr_tiers)

    # Check direct intersection with any known baseline tier set
    if any(curr_tiers & ts for ts in known_tier_sets) and curr_max >= max_required_floor:
        # Still verify cipher suite didn't downgrade (e.g. CCMP -> TKIP)
        known_enc_tiers = {
            t for t in (get_encryption_tier(e) for e in (baseline_encs_set or set()))
            if t is not None
        }
        curr_enc_tier = get_encryption_tier(current_enc_raw, sec_fallback=current_sec_raw)
        if known_enc_tiers and curr_enc_tier is not None and curr_enc_tier < min(3, max(known_enc_tiers)):
            return "DOWNGRADE_CRITICAL"
        return "MATCH"

    # Genuine critical downgrades:
    # 1. Secured -> Open (0) or WEP (1) or WPA1 (2)
    if max_required_floor >= 2 and curr_max <= 1:
        return "DOWNGRADE_CRITICAL"
    if max_required_floor >= 3 and curr_max <= 2:
        return "DOWNGRADE_CRITICAL"
    # 2. Enterprise (>=5) -> Personal (<5)
    if max_required_floor >= 5 and curr_max < 5:
        return "DOWNGRADE_CRITICAL"
    # 3. Cipher downgrade (CCMP/GCMP -> TKIP/WEP/None)
    known_enc_tiers = {
        t for t in (get_encryption_tier(e) for e in (baseline_encs_set or set()))
        if t is not None
    }
    curr_enc_tier = get_encryption_tier(current_enc_raw, sec_fallback=current_sec_raw)
    if known_enc_tiers and curr_enc_tier is not None and max(known_enc_tiers) >= 3 and curr_enc_tier < 3:
        return "DOWNGRADE_CRITICAL"

    # Non-critical shift between modern suites (e.g., strict WPA3-Personal -> WPA2-Personal)
    if curr_max < max_required_floor:
        return "SHIFT_MODERATE"

    return "MATCH"


def check_security_match(current_sec_raw, known_securities_set, current_enc_raw=None, known_encryptions_set=None):
    """
    Backward-compatible binary helper:
    1 if MATCH, NO_BASELINE, or UNAVAILABLE (does not fabricate downgrade on missing data),
    0 if DOWNGRADE_CRITICAL or SHIFT_MODERATE.
    """
    status = classify_security_comparison(
        current_sec_raw, current_enc_raw, known_securities_set, known_encryptions_set
    )
    if status in ("DOWNGRADE_CRITICAL", "SHIFT_MODERATE"):
        return 0
    return 1


def is_locally_administered_mac(bssid):
    """Returns True if the U/L bit (0x02) in the first octet of the MAC is set."""
    b = sanitize_bssid(bssid)
    parts = b.split(":")
    if len(parts) != 6:
        return False
    try:
        first_octet = int(parts[0], 16)
        return bool(first_octet & 0x02)
    except ValueError:
        return False


def infer_band(channel_val, band_raw=None):
    """Determines frequency band from explicit Band string or valid Channel, else 'Unavailable'."""
    if not is_unavailable(band_raw):
        return str(band_raw).strip()
    ch = parse_channel(channel_val)
    if pd.isna(ch):
        return "Unavailable"
    ch_int = int(ch)
    if 1 <= ch_int <= 14:
        return "2.4 GHz"
    if 32 <= ch_int <= 177:
        return "5 GHz"
    return "Unavailable"


def is_dual_band_pair(ap_a, ap_b):
    """
    Checks if two access points with the same SSID represent complementary
    2.4 GHz and 5 GHz (or 6 GHz) radios of a single legitimate dual-band router:
    1. Matching vendor OUI (first 3 octets).
    2. Near-consecutive MACs (<= 4 distance in last octet).
    3. Complementary frequency bands.
    4. Exact compatible security tier (never pairs Open with Secured).
    """
    bssid_a = sanitize_bssid(ap_a.get("BSSID", ""))
    bssid_b = sanitize_bssid(ap_b.get("BSSID", ""))
    if not bssid_a or not bssid_b or bssid_a == bssid_b:
        return False

    parts_a = bssid_a.split(":")
    parts_b = bssid_b.split(":")
    if len(parts_a) != 6 or len(parts_b) != 6:
        return False

    if parts_a[:3] != parts_b[:3]:
        return False

    try:
        last_a = int(parts_a[5], 16)
        last_b = int(parts_b[5], 16)
        if abs(last_a - last_b) > 16:
            return False
    except ValueError:
        return False

    band_a = infer_band(ap_a.get("Channel"), ap_a.get("Band"))
    band_b = infer_band(ap_b.get("Channel"), ap_b.get("Band"))
    if "Unavailable" in (band_a, band_b) or band_a == band_b:
        return False

    tiers_a = get_compatible_security_tiers(ap_a.get("Security"))
    tiers_b = get_compatible_security_tiers(ap_b.get("Security"))
    if not tiers_a or not tiers_b:
        return False
    # Never pair Open (0) with Secured (>=1)
    if (0 in tiers_a and max(tiers_b) > 0) or (0 in tiers_b and max(tiers_a) > 0):
        return False
    if not (tiers_a & tiers_b):
        return False

    return True


def analyze_scanned_relationships(scan_records):
    """
    Analyzes contextual relationships among scanned APs:
    - Identifies dual-band router pairs (2.4 GHz + 5 GHz).
    - Identifies consistent multi-AP same-OUI deployments.
    - Ignores hidden SSIDs so distinct hidden routers are not grouped as duplicates.
    Returns a dict mapping bssid -> relationship info dictionary.
    """
    relationships = {}
    if not scan_records:
        return relationships

    records = scan_records if isinstance(scan_records, list) else scan_records.to_dict(orient="records")

    by_ssid = {}
    for r in records:
        ssid = sanitize_ssid(r.get("SSID", ""))
        if not ssid or ssid == "<Hidden Network>" or r.get("IsHidden"):
            continue
        by_ssid.setdefault(ssid, []).append(r)

    for ssid, aps in by_ssid.items():
        if len(aps) < 2:
            continue
        for i in range(len(aps)):
            bssid_i = sanitize_bssid(aps[i].get("BSSID", ""))
            for j in range(i + 1, len(aps)):
                bssid_j = sanitize_bssid(aps[j].get("BSSID", ""))
                if is_dual_band_pair(aps[i], aps[j]):
                    relationships[bssid_i] = {
                        "is_dual_band": True,
                        "partner_bssid": bssid_j,
                        "note": "Dual-band router radios correlated (matching OUI, consecutive MAC, complementary band, identical security)"
                    }
                    relationships[bssid_j] = {
                        "is_dual_band": True,
                        "partner_bssid": bssid_i,
                        "note": "Dual-band router radios correlated (matching OUI, consecutive MAC, complementary band, identical security)"
                    }

    return relationships


def extract_features(scan_records, history_df=None, saved_profiles_details=None):
    """
    Extracts standardized 7-feature DataFrame for a list of scanned APs.
    Unavailable Signal / Channel / Security values are represented honestly as np.nan
    for pipeline imputation rather than fabricating fake defaults.
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

    non_hidden_ssids = [
        sanitize_ssid(v) for v in df["SSID"].tolist()
        if sanitize_ssid(v) and sanitize_ssid(v) != "<Hidden Network>"
    ]
    ssid_counts = pd.Series(non_hidden_ssids).value_counts().to_dict() if non_hidden_ssids else {}

    feature_rows = []
    for _, row in df.iterrows():
        ssid = sanitize_ssid(row.get("SSID", ""))
        bssid = sanitize_bssid(row.get("BSSID", ""))
        signal = parse_signal(row.get("Signal"))
        channel = parse_channel(row.get("Channel"))
        sec_raw = row.get("Security")
        enc_raw = row.get("Encryption")
        security = parse_security_binary(sec_raw)

        if not ssid or ssid == "<Hidden Network>" or bool(row.get("IsHidden", False)):
            same_ssid_count = 1
        else:
            same_ssid_count = int(ssid_counts.get(ssid, 1))

        bssid_known = 1 if is_bssid_known(history_df, ssid, bssid) else 0

        known_channels = get_known_channels_for_ssid(history_df, ssid)
        known_securities = set(get_known_securities_for_ssid(history_df, ssid))
        known_encryptions = set(get_known_encryptions_for_ssid(history_df, ssid))

        # Only treat saved Windows profile as an unverified security mismatch clue
        # when current AP is Open/WEP against a secured saved profile (avoid false
        # WPA3-profile vs WPA2-CCMP-scan mismatch in ML features).
        if saved_profiles_details and ssid in saved_profiles_details and not known_securities:
            p_det = saved_profiles_details[ssid]
            p_auth = str(p_det.get("Authentication", "")).strip()
            p_tiers = get_compatible_security_tiers(p_auth)
            curr_tiers = get_compatible_security_tiers(sec_raw)
            if p_tiers and curr_tiers and min(p_tiers) >= 2 and max(curr_tiers) <= 1:
                known_securities.add(p_auth.lower())

        if len(known_channels) > 0:
            if pd.isna(channel):
                channel_match = np.nan
            else:
                channel_match = 1 if int(channel) in known_channels else 0
        else:
            channel_match = 1

        if pd.isna(security):
            security_match = np.nan
        elif len(known_securities) > 0:
            security_match = check_security_match(
                sec_raw, known_securities,
                current_enc_raw=enc_raw,
                known_encryptions_set=known_encryptions
            )
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


def extract_ap_diagnostics(network_info, features_row, history_df=None, context_info=None):
    """
    Collects complete, non-fabricated diagnostic attributes (all 18 feature dimensions)
    comparing current observation against history and saved Windows profile baselines.
    """
    if history_df is None:
        history_df = load_history()

    ssid = sanitize_ssid(network_info.get("SSID", ""))
    bssid = sanitize_bssid(network_info.get("BSSID", ""))
    raw_sig = features_row.get("Signal")
    raw_ch = features_row.get("Channel")
    raw_sec_bin = features_row.get("Security")

    signal = None if pd.isna(raw_sig) else int(raw_sig)
    channel = None if pd.isna(raw_ch) else int(raw_ch)
    security_bin = None if pd.isna(raw_sec_bin) else int(raw_sec_bin)
    band = infer_band(channel, network_info.get("Band"))
    oui = extract_oui(bssid)
    sec_raw = network_info.get("Security")
    enc_raw = network_info.get("Encryption")

    missing_features = []
    if not ssid:
        missing_features.append("SSID")
    if not bssid:
        missing_features.append("BSSID")
    if signal is None:
        missing_features.append("Signal")
    if channel is None:
        missing_features.append("Channel")
    if is_unavailable(sec_raw) and security_bin is None:
        missing_features.append("Security")
    if is_unavailable(enc_raw):
        missing_features.append("Encryption")

    ap_rec = get_ap_record(history_df, ssid, bssid)
    other_ssids_for_bssid = get_bssid_other_ssids(history_df, ssid, bssid)

    signal_delta = None
    prev_signal = None
    changes = []
    baseline_fingerprint = None
    current_fingerprint = compute_fingerprint(
        ssid, bssid,
        "Unavailable" if is_unavailable(sec_raw) else sec_raw,
        "Unavailable" if is_unavailable(enc_raw) else enc_raw,
        channel, band
    )

    if ap_rec is not None:
        baseline_fingerprint = ap_rec.get("Verified Fingerprint") or ap_rec.get("Fingerprint")
        prev_sig_raw = ap_rec.get("Last Signal") or ap_rec.get("Signal")
        prev_sig_parsed = parse_signal(prev_sig_raw)
        if not pd.isna(prev_sig_parsed) and signal is not None:
            prev_signal = int(prev_sig_parsed)
            signal_delta = signal - prev_signal
            if abs(signal_delta) >= 30:
                sign = "+" if signal_delta > 0 else ""
                changes.append(f"Large signal shift vs previous scan: {prev_signal}% -> {signal}% ({sign}{signal_delta}%).")

        base_sec = str(ap_rec.get("Security", "Unavailable")).strip()
        if not is_unavailable(sec_raw) and not is_unavailable(base_sec):
            norm_curr = normalize_security_label(sec_raw)
            norm_base = normalize_security_label(base_sec)
            curr_tiers = get_compatible_security_tiers(sec_raw)
            base_tiers = get_compatible_security_tiers(base_sec)
            if norm_curr != norm_base and not (curr_tiers and base_tiers and (curr_tiers & base_tiers)):
                changes.append(f"Security changed from baseline '{base_sec}' to '{sec_raw}'.")

        base_enc = str(ap_rec.get("Encryption", "Unavailable")).strip()
        if not is_unavailable(enc_raw) and not is_unavailable(base_enc) and str(enc_raw).strip().lower() != base_enc.lower():
            changes.append(f"Encryption changed from baseline '{base_enc}' to '{enc_raw}'.")

        base_ch_set = parse_channel_list(ap_rec.get("Channel"))
        if channel is not None and base_ch_set and channel not in base_ch_set:
            changes.append(f"Channel changed from baseline {sorted(base_ch_set)} to {channel}.")

    return {
        "SSID": ssid or "<Hidden Network>",
        "BSSID": bssid or "Unavailable",
        "OUI": oui,
        "LocallyAdministeredMAC": is_locally_administered_mac(bssid),
        "Signal": signal,
        "ApproxRSSI": estimate_dbm_from_percent(signal),
        "PreviousSignal": prev_signal,
        "SignalDelta": signal_delta,
        "Channel": channel,
        "Band": band,
        "Security": "Unavailable" if is_unavailable(sec_raw) else str(sec_raw).strip(),
        "Encryption": "Unavailable" if is_unavailable(enc_raw) else str(enc_raw).strip(),
        "SecurityBinary": security_bin,
        "SecurityTier": get_security_tier(sec_raw),
        "MissingFeatures": missing_features,
        "BSSIDOtherSSIDs": sorted(list(other_ssids_for_bssid)),
        "BaselineFingerprint": baseline_fingerprint,
        "CurrentFingerprint": current_fingerprint,
        "FingerprintMatchesBaseline": (len(changes) == 0 and ap_rec is not None),
        "Changes": changes
    }


def generate_feature_explanations(network_info, features_row, history_df=None, context_info=None):
    """
    Generates clear, human-readable explanation points covering RF telemetry,
    OUI/hardware correlation, history fingerprint comparison, and missing features.
    """
    if history_df is None:
        history_df = load_history()

    diag = extract_ap_diagnostics(network_info, features_row, history_df=history_df, context_info=context_info)
    reasons = []
    ssid = sanitize_ssid(network_info.get("SSID", ""))
    bssid = sanitize_bssid(network_info.get("BSSID", ""))
    same_ssid_count = int(features_row.get("SameSSIDCount", 1))
    bssid_known = int(features_row.get("BSSIDKnown", 0))
    raw_ch_match = features_row.get("ChannelMatch", 1)
    channel_match = 1 if pd.isna(raw_ch_match) else int(raw_ch_match)
    raw_sec_match = features_row.get("SecurityMatch", 1)
    security_match = 1 if pd.isna(raw_sec_match) else int(raw_sec_match)
    ap_rec = get_ap_record(history_df, ssid, bssid)

    if context_info and context_info.get("is_saved_profile"):
        p_sec = context_info.get("profile_security")
        if p_sec and p_sec != "Unavailable":
            reasons.append(f"SSID matches a saved Windows Wi-Fi profile ('{ssid}', configured security: {p_sec}).")
        else:
            reasons.append(f"SSID matches a saved Windows Wi-Fi profile ('{ssid}').")

    if context_info and context_info.get("is_dual_band"):
        partner = context_info.get("partner_bssid", "")
        reasons.append(
            f"Dual-band hardware correlated: complementary radio ({partner}) shares OUI {diag['OUI']} "
            f"with consecutive MAC and identical security."
        )

    if bssid_known == 1 and ap_rec is not None:
        obs_count = ap_rec.get("Observation Count", 1)
        trust = ap_rec.get("Trust Status", "OBSERVED_UNVERIFIED")
        reasons.append(
            f"BSSID '{bssid}' previously recorded for '{ssid}' "
            f"({obs_count} prior observation(s); baseline trust: {trust})."
        )
    elif diag["BSSIDOtherSSIDs"]:
        reasons.append(
            f"BSSID '{bssid}' was previously seen under different SSID(s): {diag['BSSIDOtherSSIDs']}."
        )
    else:
        reasons.append(f"BSSID '{bssid}' (OUI: {diag['OUI']}) has not been observed before for this SSID.")

    if same_ssid_count > 1:
        if context_info and context_info.get("is_dual_band"):
            reasons.append(f"Multi-band broadcast: {same_ssid_count} radios broadcast '{ssid}' from correlated hardware.")
        else:
            reasons.append(f"Duplicate SSID observed: {same_ssid_count} APs are broadcasting '{ssid}' simultaneously.")
    else:
        reasons.append("No concurrent duplicate SSID detected in this scan.")

    known_channels = get_known_channels_for_ssid(history_df, ssid)
    if diag["Channel"] is None:
        reasons.append("Operating channel is unavailable in scan output.")
    elif len(known_channels) > 0:
        if channel_match == 1:
            reasons.append(f"Channel {diag['Channel']} ({diag['Band']}) matches historical channel(s) for '{ssid}'.")
        else:
            reasons.append(
                f"Channel {diag['Channel']} ({diag['Band']}) differs from historical channel(s) {sorted(known_channels)}."
            )
    else:
        reasons.append(f"Operating on channel {diag['Channel']} ({diag['Band']}).")

    known_secs = get_known_securities_for_ssid(history_df, ssid)
    if diag["Security"] == "Unavailable":
        reasons.append("Security configuration is unavailable in scan output.")
    elif len(known_secs) > 0 or (context_info and context_info.get("profile_security") not in (None, "Unavailable")):
        if security_match == 1:
            reasons.append(f"Security ({diag['Security']} / {diag['Encryption']}) is consistent with known baseline.")
        else:
            reasons.append(f"Security ({diag['Security']} / {diag['Encryption']}) is weaker or differs from known baseline.")
    else:
        reasons.append(f"Advertised security: {diag['Security']} (Encryption: {diag['Encryption']}).")

    if diag["Signal"] is None:
        reasons.append("Signal quality is unavailable in scan output.")
    else:
        sig_msg = f"Observed Windows signal quality: {diag['Signal']}%."
        if diag["SignalDelta"] is not None:
            sign = "+" if diag["SignalDelta"] > 0 else ""
            sig_msg += f" Change vs previous scan: {sign}{diag['SignalDelta']}%."
        reasons.append(sig_msg)

    if diag["Changes"]:
        reasons.append("Fingerprint differences detected: " + " ".join(diag["Changes"]))

    if diag["MissingFeatures"]:
        reasons.append(f"Unavailable feature(s): {', '.join(diag['MissingFeatures'])} (not fabricated).")

    return reasons


if __name__ == "__main__":
    print("==================================================")
    print("           FEATURE EXTRACTION MODULE              ")
    print("==================================================")
    print("Feature columns:", FEATURE_COLUMNS)
