import os
import pandas as pd
from datetime import datetime


def get_default_history_path():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "dataset", "network_history.csv")


HISTORY_COLUMNS = [
    "SSID",
    "BSSID",
    "Channel",
    "Security",
    "First Seen",
    "Last Seen",
    "Observation Count"
]


def load_history(history_path=None):
    """
    Loads network history from CSV.
    Returns a pandas DataFrame with standard columns.
    """
    if history_path is None:
        history_path = get_default_history_path()

    if os.path.exists(history_path) and os.path.getsize(history_path) > 0:
        try:
            df = pd.read_csv(history_path)
            # Ensure proper types
            if not df.empty:
                df["SSID"] = df["SSID"].astype(str)
                df["BSSID"] = df["BSSID"].astype(str).str.lower()
                df["Observation Count"] = pd.to_numeric(df["Observation Count"], errors="coerce").fillna(1).astype(int)
            return df
        except Exception as e:
            print(f"Warning: Could not read history file ({e}). Starting fresh.")

    return pd.DataFrame(columns=HISTORY_COLUMNS)


def update_history(observations, history_path=None):
    """
    Updates network history with a list of observed APs.
    Matches primarily on (SSID, BSSID).
    - If already present: updates Last Seen, Channel, Security, and increments Observation Count.
    - If new: creates a new AP entry with Observation Count = 1.
    """
    if history_path is None:
        history_path = get_default_history_path()

    os.makedirs(os.path.dirname(history_path), exist_ok=True)
    history_df = load_history(history_path)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Convert observations to list of dicts if DataFrame was passed
    if isinstance(observations, pd.DataFrame):
        obs_list = observations.to_dict(orient="records")
    else:
        obs_list = observations

    for obs in obs_list:
        ssid = str(obs.get("SSID", "")).strip()
        bssid = str(obs.get("BSSID", "")).strip().lower()
        channel = obs.get("Channel", 1)
        security = str(obs.get("Security", "Unknown")).strip()
        obs_time = str(obs.get("Timestamp", now_str)).strip()

        if not ssid and not bssid:
            continue

        # Look up existing entry matching both SSID and BSSID
        match_idx = None
        if not history_df.empty:
            match_mask = (history_df["SSID"].str.strip() == ssid) & (history_df["BSSID"].str.strip() == bssid)
            matches = history_df[match_mask]
            if not matches.empty:
                match_idx = matches.index[0]

        if match_idx is not None:
            # Existing AP: update last seen and increment count
            history_df.at[match_idx, "Last Seen"] = obs_time
            history_df.at[match_idx, "Channel"] = channel
            history_df.at[match_idx, "Security"] = security
            current_count = int(history_df.at[match_idx, "Observation Count"])
            history_df.at[match_idx, "Observation Count"] = current_count + 1
        else:
            # New AP entry
            new_entry = {
                "SSID": ssid,
                "BSSID": bssid,
                "Channel": channel,
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

    history_df.to_csv(history_path, index=False)
    return history_df


def is_bssid_known(history_df, ssid, bssid):
    """
    Checks if a specific BSSID has been recorded before in history.
    """
    if history_df.empty:
        return False
    bssid_clean = str(bssid).strip().lower()
    return bssid_clean in history_df["BSSID"].str.lower().values


def get_ap_record(history_df, ssid, bssid):
    """
    Returns history record for a specific (SSID, BSSID) pair.
    """
    if history_df.empty:
        return None
    match = history_df[
        (history_df["SSID"].str.strip() == str(ssid).strip()) &
        (history_df["BSSID"].str.lower() == str(bssid).strip().lower())
    ]
    if not match.empty:
        return match.iloc[0].to_dict()
    return None


def get_known_channels_for_ssid(history_df, ssid):
    """
    Returns set of channels previously observed for an SSID.
    """
    if history_df.empty:
        return set()
    matches = history_df[history_df["SSID"].str.strip() == str(ssid).strip()]
    if matches.empty:
        return set()
    return set(pd.to_numeric(matches["Channel"], errors="coerce").dropna().astype(int).tolist())


def get_known_securities_for_ssid(history_df, ssid):
    """
    Returns set of security descriptions previously observed for an SSID.
    """
    if history_df.empty:
        return set()
    matches = history_df[history_df["SSID"].str.strip() == str(ssid).strip()]
    if matches.empty:
        return set()
    return set(matches["Security"].str.strip().str.lower().tolist())


if __name__ == "__main__":
    print("==================================================")
    print("           NETWORK HISTORY SYSTEM                 ")
    print("==================================================")
    hist = load_history()
    print(f"Current history contains {len(hist)} unique Access Point(s).")
    if not hist.empty:
        print(hist.to_string(index=False))
