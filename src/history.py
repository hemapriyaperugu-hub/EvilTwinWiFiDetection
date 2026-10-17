import os
import re
import tempfile
import pandas as pd
from datetime import datetime


HISTORY_COLUMNS = [
    "SSID",
    "BSSID",
    "Channel",
    "Security",
    "First Seen",
    "Last Seen",
    "Observation Count"
]


def get_default_history_path():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "dataset", "network_history.csv")


def sanitize_bssid(val):
    if val is None or pd.isna(val):
        return ""
    val_str = str(val).strip().lower()
    if val_str in ["nan", "none", "null"]:
        return ""
    return val_str


def sanitize_ssid(val):
    if val is None or pd.isna(val):
        return ""
    val_str = str(val).strip()
    if val_str.lower() in ["nan", "none", "null"]:
        return ""
    return val_str


def parse_channel_list(channel_str):
    """
    Parses channel string (which can be '6', '1, 6', '36; 44', etc.)
    into a set of integer channels.
    """
    if pd.isna(channel_str) or channel_str is None:
        return set()
    matches = re.findall(r"\b(\d+)\b", str(channel_str))
    return {int(m) for m in matches}


def load_history(history_path=None):
    """
    Loads network history from CSV with validation and error resilience.
    Returns a clean pandas DataFrame with guaranteed standard columns.
    Handles empty files, missing files, or corrupted data without crashing.
    """
    if history_path is None:
        history_path = get_default_history_path()

    if not os.path.exists(history_path) or os.path.getsize(history_path) == 0:
        return pd.DataFrame(columns=HISTORY_COLUMNS)

    try:
        df = pd.read_csv(history_path, dtype=str)
        if df.empty:
            return pd.DataFrame(columns=HISTORY_COLUMNS)

        # Ensure all required columns exist
        for col in HISTORY_COLUMNS:
            if col not in df.columns:
                df[col] = ""

        # Filter out corrupted rows where both SSID and BSSID are missing/empty/NaN
        df["SSID"] = df["SSID"].apply(sanitize_ssid)
        df["BSSID"] = df["BSSID"].apply(sanitize_bssid)
        valid_mask = (df["SSID"] != "") | (df["BSSID"] != "")
        df = df[valid_mask].copy()

        # Clean Observation Count
        df["Observation Count"] = pd.to_numeric(
            df["Observation Count"], errors="coerce"
        ).fillna(1).astype(int)

        df["Channel"] = df["Channel"].fillna("1").astype(str)
        df["Security"] = df["Security"].fillna("Unknown").astype(str)
        df["First Seen"] = df["First Seen"].fillna("").astype(str)
        df["Last Seen"] = df["Last Seen"].fillna("").astype(str)

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

    # Write to a temporary file first
    with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, newline="", encoding="utf-8") as tf:
        temp_name = tf.name
        history_df.to_csv(tf, index=False)

    # Atomic replace
    try:
        os.replace(temp_name, history_path)
    except Exception:
        # Fallback if replace is locked on Windows
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


def update_history(observations, history_path=None):
    """
    Updates network history with a list of observed APs.
    Matches primarily on (SSID, BSSID).
    - If already present: updates Last Seen, appends new Channel (multi-band support),
      updates Security, and increments Observation Count.
    - If new: creates a new AP entry with Observation Count = 1.
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

    for obs in obs_list:
        ssid = sanitize_ssid(obs.get("SSID", ""))
        bssid = sanitize_bssid(obs.get("BSSID", ""))
        channel_val = obs.get("Channel", 1)
        security = str(obs.get("Security", "Unknown")).strip()
        obs_time = str(obs.get("Timestamp", now_str)).strip() or now_str

        if not ssid and not bssid:
            continue

        new_channels = parse_channel_list(channel_val)

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
            # Existing AP
            history_df.at[match_idx, "Last Seen"] = obs_time

            # Merge channels so multi-band / multi-channel observations are preserved
            existing_channels = parse_channel_list(history_df.at[match_idx, "Channel"])
            combined_channels = sorted(list(existing_channels | new_channels))
            if combined_channels:
                history_df.at[match_idx, "Channel"] = ", ".join(str(c) for c in combined_channels)

            # Update security if changed (or retain known security)
            if security and security != "Unknown":
                history_df.at[match_idx, "Security"] = security

            current_count = int(history_df.at[match_idx, "Observation Count"])
            history_df.at[match_idx, "Observation Count"] = current_count + 1
        else:
            # New AP entry
            channel_str = ", ".join(str(c) for c in sorted(list(new_channels))) if new_channels else str(channel_val)
            new_entry = {
                "SSID": ssid,
                "BSSID": bssid,
                "Channel": channel_str,
                "Security": security,
                "First Seen": obs_time,
                "Last Seen": obs_time,
                "Observation Count": 1
            }
            new_row_df = pd.DataFrame([new_entry])
            if history_df.empty:
                history_df = new_row_df
            else:
                history_df = pd.concat([history_df, new_row_df], ignore_index=True)

    save_history_safely(history_df, history_path)
    return history_df


def is_bssid_known(history_df, ssid, bssid):
    """
    Checks if a specific BSSID has been recorded before in history for this SSID
    or globally if SSID is blank.
    """
    if history_df is None or history_df.empty:
        return False
    bssid_clean = sanitize_bssid(bssid)
    if not bssid_clean:
        return False

    ssid_clean = sanitize_ssid(ssid)
    if ssid_clean:
        # Check specifically for this SSID first
        ssid_match = history_df[
            (history_df["SSID"].str.strip() == ssid_clean) &
            (history_df["BSSID"].str.lower() == bssid_clean)
        ]
        if not ssid_match.empty:
            return True

    # Also check if BSSID is known globally
    return bssid_clean in history_df["BSSID"].str.lower().values


def get_ap_record(history_df, ssid, bssid):
    """
    Returns history record for a specific (SSID, BSSID) pair.
    """
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
    """
    Returns set of channels previously observed for an SSID across all known APs.
    """
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
    """
    Returns set of security descriptions previously observed for an SSID.
    """
    if history_df is None or history_df.empty:
        return set()
    ssid_clean = sanitize_ssid(ssid)
    matches = history_df[history_df["SSID"].str.strip() == ssid_clean]
    if matches.empty:
        return set()
    return set(matches["Security"].dropna().str.strip().str.lower().tolist())


if __name__ == "__main__":
    print("==================================================")
    print("           NETWORK HISTORY SYSTEM                 ")
    print("==================================================")
    hist = load_history()
    print(f"Current history contains {len(hist)} unique Access Point(s).")
    if not hist.empty:
        print(hist.head(10).to_string(index=False))
