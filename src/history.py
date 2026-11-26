import os
import re
import tempfile
from datetime import datetime
import pandas as pd

from .paths import get_data_dir


TRUST_ESTABLISHED = "TRUSTED_BASELINE"
TRUST_UNVERIFIED = "OBSERVED_UNVERIFIED"
TRUST_FLAGGED = "FLAGGED_SUSPICIOUS"

HISTORY_COLUMNS = [
    "SSID",
    "BSSID",
    "Security",
    "Encryption",
    "Channel",
    "Band",
    "Signal",
    "Last Signal",
    "Last Channel",
    "Last Security",
    "OUI",
    "Fingerprint",
    "First Seen",
    "Last Seen",
    "Observation Count",
    "Previous Classification",
    "Trust Status",
    "Verified",
    "Verified At",
    "Verified Fingerprint",
    "Suspicious Indicators",
    "Changes"
]


def get_default_history_path():
    return os.path.join(get_data_dir(), "dataset", "network_history.csv")


def sanitize_bssid(val):
    if val is None or pd.isna(val):
        return ""
    val_str = str(val).strip().lower().replace("-", ":")
    if val_str in ["nan", "none", "null", "unavailable", ""]:
        return ""
    return val_str


def sanitize_ssid(val):
    if val is None or pd.isna(val):
        return ""
    val_str = str(val).strip()
    if val_str.lower() in ["nan", "none", "null"]:
        return ""
    return val_str


def _clean_text(val, default="Unavailable"):
    if val is None or pd.isna(val):
        return default
    s = str(val).strip()
    if not s or s.lower() in ("nan", "none", "null", "unknown"):
        return default
    return s


def extract_oui(bssid):
    """Returns the first 3 octets (xx:xx:xx) of a normalized MAC address, or 'Unavailable'."""
    b = sanitize_bssid(bssid)
    parts = b.split(":")
    if len(parts) >= 3 and all(len(p) == 2 for p in parts[:3]):
        return ":".join(parts[:3])
    return "Unavailable"


def parse_channel_list(channel_str):
    """
    Parses channel string (which can be '6', '1, 6', '36; 44', etc.)
    into a set of integer channels.
    """
    if channel_str is None or pd.isna(channel_str):
        return set()
    s = str(channel_str).strip()
    if not s or s.lower() in ("nan", "none", "unavailable", "unknown"):
        return set()
    matches = re.findall(r"\b(\d+)\b", s)
    return {int(m) for m in matches if int(m) > 0}


def compute_fingerprint(ssid, bssid, security, encryption=None, channel=None, band=None):
    """
    Builds a readable, deterministic baseline fingerprint string for an AP.
    Used to detect configuration changes across scans.
    """
    s_ssid = sanitize_ssid(ssid) or "<Hidden>"
    s_bssid = sanitize_bssid(bssid) or "Unavailable"
    s_sec = _clean_text(security)
    s_enc = _clean_text(encryption)
    channels = sorted(list(parse_channel_list(channel)))
    s_ch = ",".join(str(c) for c in channels) if channels else "Unavailable"
    s_band = _clean_text(band)
    s_oui = extract_oui(s_bssid)
    return (
        f"ssid={s_ssid}|bssid={s_bssid}|oui={s_oui}|"
        f"sec={s_sec}|enc={s_enc}|ch={s_ch}|band={s_band}"
    )


def _merge_semicolon_items(existing_str, new_items):
    """Merges semicolon-delimited diagnostic strings without duplicates or loss."""
    items = []
    seen = set()
    for part in str(existing_str or "").split(";"):
        p = part.strip()
        if p and p.lower() not in ("nan", "none") and p not in seen:
            seen.add(p)
            items.append(p)
    for item in (new_items or []):
        p = str(item).strip()
        if p and p not in seen:
            seen.add(p)
            items.append(p)
    return "; ".join(items)


def load_history(history_path=None):
    """
    Loads network history from CSV with validation, legacy migration, and error resilience.
    Returns a clean pandas DataFrame with guaranteed HISTORY_COLUMNS.
    Legacy records without Trust Status default to OBSERVED_UNVERIFIED (never auto-trusted).
    """
    if history_path is None:
        history_path = get_default_history_path()

    if not os.path.exists(history_path) or os.path.getsize(history_path) == 0:
        return pd.DataFrame(columns=HISTORY_COLUMNS)

    try:
        df = pd.read_csv(history_path, dtype=str)
        if df.empty:
            return pd.DataFrame(columns=HISTORY_COLUMNS)

        had_trust_col = "Trust Status" in df.columns

        for col in HISTORY_COLUMNS:
            if col not in df.columns:
                df[col] = ""

        df["SSID"] = df["SSID"].apply(sanitize_ssid)
        df["BSSID"] = df["BSSID"].apply(sanitize_bssid)
        valid_mask = (df["SSID"] != "") | (df["BSSID"] != "")
        df = df[valid_mask].copy()

        df["Observation Count"] = pd.to_numeric(
            df["Observation Count"], errors="coerce"
        ).fillna(1).astype(int)

        df["Security"] = df["Security"].apply(lambda v: _clean_text(v, "Unavailable"))
        df["Encryption"] = df["Encryption"].apply(lambda v: _clean_text(v, "Unavailable"))
        df["Channel"] = df["Channel"].apply(lambda v: _clean_text(v, "Unavailable"))
        df["Band"] = df["Band"].apply(lambda v: _clean_text(v, "Unavailable"))
        df["Signal"] = df["Signal"].apply(lambda v: _clean_text(v, "Unavailable"))

        df["Last Signal"] = df.apply(
            lambda r: _clean_text(r["Last Signal"], r["Signal"]), axis=1
        )
        df["Last Channel"] = df.apply(
            lambda r: _clean_text(r["Last Channel"], r["Channel"]), axis=1
        )
        df["Last Security"] = df.apply(
            lambda r: _clean_text(r["Last Security"], r["Security"]), axis=1
        )
        df["OUI"] = df.apply(
            lambda r: _clean_text(r["OUI"], extract_oui(r["BSSID"])), axis=1
        )
        df["First Seen"] = df["First Seen"].fillna("").astype(str)
        df["Last Seen"] = df["Last Seen"].fillna("").astype(str)
        df["Previous Classification"] = df["Previous Classification"].apply(
            lambda v: _clean_text(v, "UNVERIFIED")
        )

        if had_trust_col:
            df["Trust Status"] = df["Trust Status"].apply(
                lambda v: v.strip() if str(v).strip() in (TRUST_ESTABLISHED, TRUST_UNVERIFIED, TRUST_FLAGGED) else TRUST_UNVERIFIED
            )
        else:
            df["Trust Status"] = TRUST_UNVERIFIED

        df["Suspicious Indicators"] = df["Suspicious Indicators"].fillna("").astype(str)
        df["Changes"] = df["Changes"].fillna("").astype(str)

        df["Fingerprint"] = df.apply(
            lambda r: r["Fingerprint"].strip() if str(r["Fingerprint"]).strip() and str(r["Fingerprint"]).strip().lower() != "nan"
            else compute_fingerprint(r["SSID"], r["BSSID"], r["Security"], r["Encryption"], r["Channel"], r["Band"]),
            axis=1
        )
        df["Verified"] = df.apply(
            lambda r: "Yes" if (str(r.get("Verified", "")).strip().lower() == "yes" or r["Trust Status"] == TRUST_ESTABLISHED) else "No",
            axis=1
        )
        df["Verified At"] = df["Verified At"].fillna("").astype(str).apply(lambda s: "" if s.strip().lower() in ("nan", "none") else s.strip())
        df["Verified Fingerprint"] = df.apply(
            lambda r: r["Verified Fingerprint"].strip()
            if str(r.get("Verified Fingerprint", "")).strip() and str(r.get("Verified Fingerprint", "")).strip().lower() not in ("nan", "none")
            else (r["Fingerprint"] if r["Verified"] == "Yes" else ""),
            axis=1
        )

        return df[HISTORY_COLUMNS].reset_index(drop=True)

    except Exception as e:
        print(f"Warning: Could not read history file ({e}). Starting with clean history.")
        return pd.DataFrame(columns=HISTORY_COLUMNS)


def save_history_safely(history_df, history_path):
    """
    Saves history DataFrame safely using an atomic write pattern
    to prevent file corruption if interrupted.
    """
    os.makedirs(os.path.dirname(os.path.abspath(history_path)), exist_ok=True)
    dir_name = os.path.dirname(os.path.abspath(history_path))

    with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, newline="", encoding="utf-8") as tf:
        temp_name = tf.name
        history_df.to_csv(tf, index=False)

    try:
        os.replace(temp_name, history_path)
    except Exception:
        try:
            if os.path.exists(history_path):
                os.remove(history_path)
            os.rename(temp_name, history_path)
        except Exception:
            history_df.to_csv(history_path, index=False)
            if os.path.exists(temp_name):
                try:
                    os.remove(temp_name)
                except Exception:
                    pass


def _build_assessment_lookup(obs_list, assessments):
    """Maps observation index and (ssid, bssid) to its assessment dict if provided."""
    by_idx = {}
    by_key = {}
    if not assessments:
        return by_idx, by_key
    if isinstance(assessments, list) and len(assessments) == len(obs_list):
        for i, a in enumerate(assessments):
            if isinstance(a, dict):
                by_idx[i] = a
    for a in (assessments if isinstance(assessments, list) else []):
        if isinstance(a, dict):
            key = (sanitize_ssid(a.get("SSID", "")), sanitize_bssid(a.get("BSSID", "")))
            by_key[key] = a
    return by_idx, by_key


def update_history(observations, history_path=None, assessments=None, mark_trusted=False):
    """
    Updates network history with observed APs while preserving baseline integrity:
    - Never auto-promotes unverified or suspicious networks to TRUSTED_BASELINE.
    - Never erases prior suspicious indicators or baseline security/channel on anomalies.
    - Tracks signal, channel, and security changes between observations.
    """
    if history_path is None:
        history_path = get_default_history_path()

    history_df = load_history(history_path)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if isinstance(observations, pd.DataFrame):
        obs_list = observations.to_dict(orient="records")
    elif isinstance(observations, list):
        obs_list = observations
    else:
        return history_df

    by_idx, by_key = _build_assessment_lookup(obs_list, assessments)

    for idx, obs in enumerate(obs_list):
        ssid = sanitize_ssid(obs.get("SSID", ""))
        bssid = sanitize_bssid(obs.get("BSSID", ""))
        if not ssid and not bssid:
            continue

        obs_time = _clean_text(obs.get("Timestamp"), now_str)
        cur_sec = _clean_text(obs.get("Security"), "Unavailable")
        cur_enc = _clean_text(obs.get("Encryption"), "Unavailable")
        cur_ch_set = parse_channel_list(obs.get("Channel"))
        cur_ch_str = ", ".join(str(c) for c in sorted(cur_ch_set)) if cur_ch_set else "Unavailable"
        cur_band = _clean_text(obs.get("Band"), "Unavailable")
        if cur_band == "Unavailable" and cur_ch_set:
            ch0 = next(iter(cur_ch_set))
            if 1 <= ch0 <= 14:
                cur_band = "2.4 GHz"
            elif 32 <= ch0 <= 177:
                cur_band = "5 GHz"

        raw_sig = obs.get("Signal")
        cur_sig = "Unavailable"
        if raw_sig is not None and not pd.isna(raw_sig) and str(raw_sig).strip() != "":
            m_sig = re.search(r"(\d+)", str(raw_sig))
            if m_sig:
                cur_sig = str(max(0, min(100, int(m_sig.group(1)))))

        assessment = by_idx.get(idx) or by_key.get((ssid, bssid))
        cls_label = "UNVERIFIED NETWORK BUT SAFE"
        warn_list = []
        change_list = []
        is_flagged = False
        if assessment:
            cls_label = str(
                assessment.get("Classification")
                or assessment.get("AcademicStatus")
                or "UNVERIFIED NETWORK BUT SAFE"
            )
            warn_list = list(assessment.get("WarningIndicators") or [])
            change_list = list(assessment.get("Changes") or [])
            cls_upper = cls_label.strip().upper()
            if (
                cls_upper in ("UNSAFE", "UNVERIFIED NETWORK AND UNSAFE", "UNVERIFIED / UNSAFE")
                or "SUSPICIOUS" in cls_upper
                or "HIGH RISK" in cls_upper
                or "EVIL TWIN" in cls_upper
            ):
                is_flagged = True

        match_idx = None
        if not history_df.empty:
            match_mask = (
                (history_df["SSID"].str.strip() == ssid) &
                (history_df["BSSID"].str.strip().str.lower() == bssid)
            )
            matches = history_df[match_mask]
            if not matches.empty:
                match_idx = matches.index[0]

        if match_idx is not None:
            history_df.at[match_idx, "Last Seen"] = obs_time
            current_count = int(history_df.at[match_idx, "Observation Count"])
            history_df.at[match_idx, "Observation Count"] = current_count + 1

            base_sec = str(history_df.at[match_idx, "Security"]).strip()
            base_enc = str(history_df.at[match_idx, "Encryption"]).strip()
            base_ch = str(history_df.at[match_idx, "Channel"]).strip()
            base_band = str(history_df.at[match_idx, "Band"]).strip()
            prev_sig = str(history_df.at[match_idx, "Last Signal"]).strip()
            existing_trust = str(history_df.at[match_idx, "Trust Status"]).strip()

            # Track changes compared to baseline and last observation
            detected_changes = list(change_list)
            if cur_sec != "Unavailable" and base_sec != "Unavailable" and cur_sec.lower() != base_sec.lower():
                detected_changes.append(f"Security changed: {base_sec} -> {cur_sec}")
            if cur_enc != "Unavailable" and base_enc != "Unavailable" and cur_enc.lower() != base_enc.lower():
                detected_changes.append(f"Encryption changed: {base_enc} -> {cur_enc}")
            if cur_ch_set:
                base_ch_set = parse_channel_list(base_ch)
                if base_ch_set and not cur_ch_set.issubset(base_ch_set):
                    detected_changes.append(f"Channel changed: {base_ch} -> {cur_ch_str}")
            if cur_sig != "Unavailable" and prev_sig not in ("", "Unavailable"):
                try:
                    delta = int(cur_sig) - int(prev_sig)
                    if abs(delta) >= 15:
                        sign = "+" if delta > 0 else ""
                        detected_changes.append(f"Signal shifted: {prev_sig}% -> {cur_sig}% ({sign}{delta}%)")
                except ValueError:
                    pass

            # Update Last-* fields without poisoning baseline fields
            if cur_sig != "Unavailable":
                history_df.at[match_idx, "Last Signal"] = cur_sig
            if cur_ch_str != "Unavailable":
                history_df.at[match_idx, "Last Channel"] = cur_ch_str
            if cur_sec != "Unavailable":
                history_df.at[match_idx, "Last Security"] = cur_sec

            # Fill missing baseline fields ONLY if previously Unavailable and no conflict flagged
            if not is_flagged:
                if base_sec == "Unavailable" and cur_sec != "Unavailable":
                    history_df.at[match_idx, "Security"] = cur_sec
                if base_enc == "Unavailable" and cur_enc != "Unavailable":
                    history_df.at[match_idx, "Encryption"] = cur_enc
                if base_ch == "Unavailable" and cur_ch_str != "Unavailable":
                    history_df.at[match_idx, "Channel"] = cur_ch_str
                if base_band == "Unavailable" and cur_band != "Unavailable":
                    history_df.at[match_idx, "Band"] = cur_band
                if str(history_df.at[match_idx, "Signal"]).strip() == "Unavailable" and cur_sig != "Unavailable":
                    history_df.at[match_idx, "Signal"] = cur_sig

            # Trust state rules: never auto-promote; never clear FLAGGED_SUSPICIOUS automatically
            if mark_trusted and not is_flagged:
                new_trust = TRUST_ESTABLISHED
            elif existing_trust == TRUST_FLAGGED or is_flagged:
                new_trust = TRUST_FLAGGED
            elif existing_trust == TRUST_ESTABLISHED:
                new_trust = TRUST_ESTABLISHED
            else:
                new_trust = TRUST_UNVERIFIED

            history_df.at[match_idx, "Trust Status"] = new_trust
            if assessment:
                history_df.at[match_idx, "Previous Classification"] = cls_label
            history_df.at[match_idx, "Suspicious Indicators"] = _merge_semicolon_items(
                history_df.at[match_idx, "Suspicious Indicators"], warn_list
            )
            history_df.at[match_idx, "Changes"] = _merge_semicolon_items(
                history_df.at[match_idx, "Changes"], detected_changes
            )
            history_df.at[match_idx, "Fingerprint"] = compute_fingerprint(
                ssid,
                bssid,
                history_df.at[match_idx, "Security"],
                history_df.at[match_idx, "Encryption"],
                history_df.at[match_idx, "Channel"],
                history_df.at[match_idx, "Band"]
            )
            if new_trust == TRUST_ESTABLISHED:
                history_df.at[match_idx, "Verified"] = "Yes"
                if not str(history_df.at[match_idx, "Verified At"]).strip():
                    history_df.at[match_idx, "Verified At"] = obs_time
                if not str(history_df.at[match_idx, "Verified Fingerprint"]).strip():
                    history_df.at[match_idx, "Verified Fingerprint"] = history_df.at[match_idx, "Fingerprint"]
            else:
                history_df.at[match_idx, "Verified"] = "No"
        else:
            if mark_trusted and not is_flagged:
                new_trust = TRUST_ESTABLISHED
            elif is_flagged:
                new_trust = TRUST_FLAGGED
            else:
                new_trust = TRUST_UNVERIFIED

            fp = compute_fingerprint(ssid, bssid, cur_sec, cur_enc, cur_ch_str, cur_band)
            new_entry = {
                "SSID": ssid,
                "BSSID": bssid,
                "Security": cur_sec,
                "Encryption": cur_enc,
                "Channel": cur_ch_str,
                "Band": cur_band,
                "Signal": cur_sig,
                "Last Signal": cur_sig,
                "Last Channel": cur_ch_str,
                "Last Security": cur_sec,
                "OUI": extract_oui(bssid),
                "Fingerprint": fp,
                "First Seen": obs_time,
                "Last Seen": obs_time,
                "Observation Count": 1,
                "Previous Classification": cls_label if assessment else "UNVERIFIED NETWORK BUT SAFE",
                "Trust Status": new_trust,
                "Verified": "Yes" if new_trust == TRUST_ESTABLISHED else "No",
                "Verified At": obs_time if new_trust == TRUST_ESTABLISHED else "",
                "Verified Fingerprint": fp if new_trust == TRUST_ESTABLISHED else "",
                "Suspicious Indicators": _merge_semicolon_items("", warn_list),
                "Changes": _merge_semicolon_items("", change_list)
            }
            new_row_df = pd.DataFrame([new_entry])
            if history_df.empty:
                history_df = new_row_df
            else:
                history_df = pd.concat([history_df, new_row_df], ignore_index=True)

    save_history_safely(history_df, history_path)
    return history_df


def mark_ap_trusted(ssid, bssid, history_path=None, ap_info=None):
    """
    Explicitly marks an AP record in history as TRUSTED_BASELINE (manually verified),
    records Verified At & Verified Fingerprint, and clears prior false-alarm indicators.
    Never called automatically by passive scans.
    """
    if history_path is None:
        history_path = get_default_history_path()

    history_df = load_history(history_path)
    ssid_clean = sanitize_ssid(ssid)
    bssid_clean = sanitize_bssid(bssid)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if history_df.empty and ap_info:
        return update_history([ap_info], history_path=history_path, mark_trusted=True)

    if history_df.empty:
        return history_df

    mask = (
        (history_df["SSID"].str.strip() == ssid_clean) &
        (history_df["BSSID"].str.lower() == bssid_clean)
    )
    if mask.any():
        for idx in history_df[mask].index:
            # Fill any previously Unavailable baseline attributes from ap_info if supplied
            if ap_info:
                for col, key in [
                    ("Security", "Security"),
                    ("Encryption", "Encryption"),
                    ("Channel", "Channel"),
                    ("Band", "Band"),
                    ("Signal", "Signal")
                ]:
                    val = _clean_text(ap_info.get(key), "Unavailable")
                    if val != "Unavailable" and str(history_df.at[idx, col]).strip() == "Unavailable":
                        history_df.at[idx, col] = val

            fp = compute_fingerprint(
                ssid_clean,
                bssid_clean,
                history_df.at[idx, "Security"],
                history_df.at[idx, "Encryption"],
                history_df.at[idx, "Channel"],
                history_df.at[idx, "Band"]
            )
            history_df.at[idx, "Fingerprint"] = fp
            history_df.at[idx, "Trust Status"] = TRUST_ESTABLISHED
            history_df.at[idx, "Verified"] = "Yes"
            history_df.at[idx, "Verified At"] = now_str
            history_df.at[idx, "Verified Fingerprint"] = fp
            history_df.at[idx, "Previous Classification"] = "SAFE"
            history_df.at[idx, "Suspicious Indicators"] = ""
        save_history_safely(history_df, history_path)
    elif ap_info:
        return update_history([ap_info], history_path=history_path, mark_trusted=True)
    return history_df


def unverify_ap(ssid, bssid, history_path=None):
    """
    Reverses manual verification for a specific (SSID, BSSID), returning it
    to OBSERVED_UNVERIFIED so manual trust is fully reversible.
    """
    if history_path is None:
        history_path = get_default_history_path()

    history_df = load_history(history_path)
    if history_df.empty:
        return history_df

    ssid_clean = sanitize_ssid(ssid)
    bssid_clean = sanitize_bssid(bssid)
    mask = (
        (history_df["SSID"].str.strip() == ssid_clean) &
        (history_df["BSSID"].str.lower() == bssid_clean)
    )
    if mask.any():
        history_df.loc[mask, "Trust Status"] = TRUST_UNVERIFIED
        history_df.loc[mask, "Verified"] = "No"
        history_df.loc[mask, "Verified At"] = ""
        history_df.loc[mask, "Verified Fingerprint"] = ""
        history_df.loc[mask, "Previous Classification"] = "UNVERIFIED NETWORK BUT SAFE"
        save_history_safely(history_df, history_path)
    return history_df


def get_verified_records_for_ssid(history_df, ssid):
    """Returns DataFrame subset of manually verified / TRUSTED_BASELINE rows for an SSID."""
    if history_df is None or history_df.empty:
        return pd.DataFrame(columns=HISTORY_COLUMNS)
    ssid_clean = sanitize_ssid(ssid)
    if not ssid_clean:
        return pd.DataFrame(columns=HISTORY_COLUMNS)
    return history_df[
        (history_df["SSID"].str.strip() == ssid_clean) &
        (history_df["Trust Status"] == TRUST_ESTABLISHED)
    ].copy()


def clear_unverified_history(history_path=None):
    """
    Removes non-trusted (OBSERVED_UNVERIFIED and FLAGGED_SUSPICIOUS) records
    while preserving explicitly established TRUSTED_BASELINE fingerprints.
    """
    if history_path is None:
        history_path = get_default_history_path()
    history_df = load_history(history_path)
    if history_df.empty:
        return history_df
    kept = history_df[history_df["Trust Status"] == TRUST_ESTABLISHED].copy()
    save_history_safely(kept, history_path)
    return kept


def is_bssid_known(history_df, ssid, bssid):
    """
    Checks if a specific (SSID, BSSID) pair has been recorded before in history.
    Does NOT match globally across unrelated SSIDs so SSID-repurposing is never masked.
    """
    if history_df is None or history_df.empty:
        return False
    bssid_clean = sanitize_bssid(bssid)
    if not bssid_clean:
        return False

    ssid_clean = sanitize_ssid(ssid)
    if ssid_clean:
        ssid_match = history_df[
            (history_df["SSID"].str.strip() == ssid_clean) &
            (history_df["BSSID"].str.lower() == bssid_clean)
        ]
        return not ssid_match.empty

    return bssid_clean in history_df["BSSID"].str.lower().values


def get_bssid_other_ssids(history_df, ssid, bssid):
    """
    Returns set of OTHER SSIDs previously associated with this exact BSSID.
    Detects repurposed/spoofed APs switching SSIDs.
    """
    if history_df is None or history_df.empty:
        return set()
    bssid_clean = sanitize_bssid(bssid)
    ssid_clean = sanitize_ssid(ssid)
    if not bssid_clean:
        return set()
    matches = history_df[
        (history_df["BSSID"].str.lower() == bssid_clean) &
        (history_df["SSID"].str.strip() != ssid_clean) &
        (history_df["SSID"].str.strip() != "")
    ]
    if matches.empty:
        return set()
    return set(matches["SSID"].str.strip().tolist())


def get_ap_record(history_df, ssid, bssid):
    """Returns history record for a specific (SSID, BSSID) pair."""
    if history_df is None or history_df.empty:
        return None
    ssid_clean = sanitize_ssid(ssid)
    bssid_clean = sanitize_bssid(bssid)
    match = history_df[
        (history_df["SSID"].str.strip() == ssid_clean) &
        (history_df["BSSID"].str.lower() == bssid_clean)
    ]
    if not match.empty:
        return match.iloc[0].to_dict()
    return None


def get_known_channels_for_ssid(history_df, ssid):
    """Returns set of baseline channels previously observed for an SSID."""
    if history_df is None or history_df.empty:
        return set()
    ssid_clean = sanitize_ssid(ssid)
    matches = history_df[history_df["SSID"].str.strip() == ssid_clean]
    if matches.empty:
        return set()

    channels = set()
    for c_val in matches["Channel"].dropna():
        channels.update(parse_channel_list(c_val))
    return channels


def get_known_securities_for_ssid(history_df, ssid):
    """Returns set of baseline security descriptions previously observed for an SSID."""
    if history_df is None or history_df.empty:
        return set()
    ssid_clean = sanitize_ssid(ssid)
    matches = history_df[history_df["SSID"].str.strip() == ssid_clean]
    if matches.empty:
        return set()
    secs = set()
    for val in matches["Security"].dropna():
        s = str(val).strip().lower()
        if s and s not in ("unavailable", "unknown", "nan", "none"):
            secs.add(s)
    return secs


def get_known_encryptions_for_ssid(history_df, ssid):
    """Returns set of baseline encryption ciphers previously observed for an SSID."""
    if history_df is None or history_df.empty:
        return set()
    ssid_clean = sanitize_ssid(ssid)
    if "Encryption" not in history_df.columns:
        return set()
    matches = history_df[history_df["SSID"].str.strip() == ssid_clean]
    if matches.empty:
        return set()
    encs = set()
    for val in matches["Encryption"].dropna():
        e = str(val).strip().lower()
        if e and e not in ("unavailable", "unknown", "nan", ""):
            encs.add(e)
    return encs


def get_trust_state(history_df, ssid, bssid, saved_profiles=None):
    """
    Returns internal trust state string for an AP:
    - 'FLAGGED_SUSPICIOUS': Previously flagged suspicious/high-risk in history.
    - 'TRUSTED_BASELINE': Explicitly verified baseline in history.
    - 'USER_VERIFIED': Matches saved Windows profile (still requires BSSID & security check).
    - 'OBSERVED_UNVERIFIED': Passively observed before without verification.
    - 'UNFAMILIAR': Never observed before.
    """
    ssid_clean = sanitize_ssid(ssid)
    bssid_clean = sanitize_bssid(bssid)

    rec = get_ap_record(history_df, ssid_clean, bssid_clean)
    if rec is not None:
        trust = str(rec.get("Trust Status", TRUST_UNVERIFIED)).strip()
        if trust == TRUST_FLAGGED:
            return TRUST_FLAGGED
        if trust == TRUST_ESTABLISHED:
            return TRUST_ESTABLISHED

    if saved_profiles and ssid_clean in saved_profiles:
        return "USER_VERIFIED"

    if rec is not None:
        return TRUST_UNVERIFIED

    return "UNFAMILIAR"


if __name__ == "__main__":
    print("==================================================")
    print("           NETWORK HISTORY SYSTEM                 ")
    print("==================================================")
    hist = load_history()
    print(f"Current history contains {len(hist)} unique Access Point(s).")
    if not hist.empty:
        print(hist[["SSID", "BSSID", "Security", "Channel", "Observation Count", "Trust Status"]].head(10).to_string(index=False))
