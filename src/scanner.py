import csv
import locale
import os
import re
import subprocess
from datetime import datetime

from .paths import get_data_dir


MAC_PATTERN = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")


def get_default_dataset_path():
    return os.path.join(get_data_dir(), "dataset", "wifi_observations.csv")


def normalize_bssid(raw_bssid):
    """Normalizes a MAC address string to lowercase colon-separated format, or '' if invalid."""
    if not raw_bssid:
        return ""
    cleaned = str(raw_bssid).strip().lower().replace("-", ":")
    if MAC_PATTERN.match(cleaned):
        return cleaned
    return ""


def infer_band_from_channel(channel):
    """Infers Wi-Fi frequency band from a valid integer channel, or returns None."""
    if channel is None:
        return None
    try:
        ch = int(channel)
    except (TypeError, ValueError):
        return None
    if 1 <= ch <= 14:
        return "2.4 GHz"
    if 32 <= ch <= 177:
        return "5 GHz"
    return None


def _decode_subprocess_output(raw_bytes):
    """Decodes Windows netsh output without silently dropping Unicode SSID characters."""
    if not raw_bytes:
        return ""
    for encoding in ("utf-8", locale.getpreferredencoding(False) or "cp1252"):
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def parse_netsh_output(raw_output, timestamp=None):
    """
    Parses output from `netsh wlan show networks mode=bssid`.
    Preserves Unicode SSIDs, multiple BSSIDs per SSID, and represents
    unavailable attributes as None instead of fabricating fake defaults.
    """
    if not raw_output:
        return []

    scan_ts = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    networks = []
    current_ssid = ""
    current_is_hidden = False
    current_auth = None
    current_enc = None
    current_net_type = None
    current_ap = None

    for raw_line in raw_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # SSID header: e.g., 'SSID 1 : NetworkName' (or 'SSID 1 :' for hidden)
        ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if ssid_match:
            if current_ap is not None:
                networks.append(current_ap)
                current_ap = None

            raw_ssid = ssid_match.group(1).strip()
            if not raw_ssid:
                current_ssid = "<Hidden Network>"
                current_is_hidden = True
            else:
                current_ssid = raw_ssid
                current_is_hidden = False
            current_auth = None
            current_enc = None
            current_net_type = None
            continue

        if line.lower().startswith("network type"):
            parts = line.split(":", 1)
            if len(parts) > 1 and parts[1].strip():
                current_net_type = parts[1].strip()
            continue

        if line.lower().startswith("authentication"):
            parts = line.split(":", 1)
            if len(parts) > 1 and parts[1].strip():
                current_auth = parts[1].strip()
            continue

        if line.lower().startswith("encryption"):
            parts = line.split(":", 1)
            if len(parts) > 1 and parts[1].strip():
                current_enc = parts[1].strip()
            continue

        # BSSID header: e.g., 'BSSID 1 : 0c:ef:15:e8:67:90'
        bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*(.+)$", line)
        if bssid_match:
            if current_ap is not None:
                networks.append(current_ap)

            bssid_mac = normalize_bssid(bssid_match.group(1))
            if not bssid_mac:
                current_ap = None
                continue

            current_ap = {
                "SSID": current_ssid,
                "IsHidden": current_is_hidden,
                "BSSID": bssid_mac,
                "Signal": None,
                "Channel": None,
                "Band": None,
                "Security": current_auth,
                "Encryption": current_enc,
                "NetworkType": current_net_type,
                "Radio": None,
                "Timestamp": scan_ts,
                "Label": "Unknown"
            }
            continue

        if current_ap is None:
            continue

        if line.lower().startswith("signal"):
            signal_match = re.search(r"(\d+)\s*%", line)
            if signal_match:
                val = int(signal_match.group(1))
                current_ap["Signal"] = max(0, min(100, val))
            continue

        if line.lower().startswith("channel"):
            chan_match = re.search(r"Channel\s*:\s*(\d+)", line, re.IGNORECASE)
            if chan_match:
                ch = int(chan_match.group(1))
                if ch > 0:
                    current_ap["Channel"] = ch
                    if current_ap["Band"] is None:
                        current_ap["Band"] = infer_band_from_channel(ch)
            continue

        if line.lower().startswith("band"):
            parts = line.split(":", 1)
            if len(parts) > 1 and parts[1].strip():
                current_ap["Band"] = parts[1].strip()
            continue

        if line.lower().startswith("radio type"):
            parts = line.split(":", 1)
            if len(parts) > 1 and parts[1].strip():
                current_ap["Radio"] = parts[1].strip()
            continue

        if "basic rates" in line.lower():
            parts = line.split(":", 1)
            if len(parts) > 1 and parts[1].strip():
                current_ap["BasicRates"] = parts[1].strip()
            continue

        if "other rates" in line.lower():
            parts = line.split(":", 1)
            if len(parts) > 1 and parts[1].strip():
                current_ap["OtherRates"] = parts[1].strip()
            continue

    if current_ap is not None:
        networks.append(current_ap)

    return networks


def scan_wifi_detailed(timeout=12):
    """
    Executes Windows `netsh wlan show networks mode=bssid` without modifying
    any adapter or system network settings.

    Returns a structured status dictionary so callers can distinguish an empty
    RF environment (success=True, networks=[]) from a scanner error (success=False):
    {
        "success": bool,
        "networks": list[dict],
        "error": str | None
    }
    """
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            timeout=timeout
        )
    except FileNotFoundError:
        err = "'netsh' command not found. This scanner requires a Windows environment."
        return {"success": False, "networks": [], "error": err}
    except subprocess.TimeoutExpired:
        err = f"Wi-Fi scan timed out after {timeout} seconds."
        return {"success": False, "networks": [], "error": err}
    except Exception as e:
        err = f"Error executing netsh command: {e}"
        return {"success": False, "networks": [], "error": err}

    stdout_text = _decode_subprocess_output(result.stdout)
    stderr_text = _decode_subprocess_output(result.stderr)

    if result.returncode != 0:
        err_msg = stderr_text.strip() or stdout_text.strip() or f"netsh exited with code {result.returncode}"
        lower_err = err_msg.lower()
        if "wlansvc" in lower_err or "service" in lower_err:
            friendly = f"Windows WLAN AutoConfig service (wlansvc) is not running ({err_msg})."
        elif "interface" in lower_err or "not found" in lower_err:
            friendly = f"No active Wi-Fi interface detected or Wi-Fi adapter is disabled ({err_msg})."
        else:
            friendly = f"Wi-Fi scanner failed: {err_msg}"
        return {"success": False, "networks": [], "error": friendly}

    networks = parse_netsh_output(stdout_text)
    return {"success": True, "networks": networks, "error": None}


def scan_wifi():
    """
    Backward-compatible scanner wrapper returning list of scanned AP dictionaries.
    Prints scanner error notices clearly if scanning failed.
    """
    scan_res = scan_wifi_detailed()
    if not scan_res["success"]:
        print(f"Notice: {scan_res['error']}")
        return []
    return scan_res["networks"]


def save_observations_to_csv(networks, csv_path=None):
    """
    Appends scanned networks to wifi_observations.csv.
    Preserves existing CSV column layout while recording unavailable values as empty
    strings rather than inventing synthetic values.
    """
    if not networks:
        return

    if csv_path is None:
        csv_path = get_default_dataset_path()

    try:
        os.makedirs(os.path.dirname(os.path.abspath(csv_path)), exist_ok=True)
        file_exists = os.path.exists(csv_path) and os.path.getsize(csv_path) > 0

        fieldnames = ["SSID", "BSSID", "Signal", "Channel", "Security", "Timestamp", "Label"]

        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            if not file_exists:
                writer.writeheader()
            for net in networks:
                sig = net.get("Signal")
                ch = net.get("Channel")
                sec = net.get("Security")
                writer.writerow({
                    "SSID": net.get("SSID", ""),
                    "BSSID": normalize_bssid(net.get("BSSID", "")) or str(net.get("BSSID", "")).lower(),
                    "Signal": "" if sig is None else sig,
                    "Channel": "" if ch is None else ch,
                    "Security": "Unavailable" if sec is None else sec,
                    "Timestamp": net.get("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    "Label": net.get("Label", "Unknown")
                })
    except Exception as e:
        print(f"Warning: Could not save observation to CSV ({e}). Continuing operation.")


if __name__ == "__main__":
    print("==================================================")
    print("      REAL WI-FI SCANNER (WINDOWS NETSH)          ")
    print("==================================================")
    print("Scanning nearby access points using built-in adapter...\n")
    res = scan_wifi_detailed()
    if not res["success"]:
        print(f"[ERROR] Scan failed: {res['error']}")
    elif not res["networks"]:
        print("Scan succeeded: No Wi-Fi networks currently in range.")
    else:
        scanned = res["networks"]
        print(f"Found {len(scanned)} Access Point(s):\n")
        print(f"{'SSID':<25} {'BSSID (MAC)':<20} {'Signal':<12} {'Channel':<10} {'Security':<18}")
        print("-" * 90)
        for net in scanned:
            sig = f"{net['Signal']}%" if net.get("Signal") is not None else "Unavailable"
            ch = str(net["Channel"]) if net.get("Channel") is not None else "Unavailable"
            sec = net.get("Security") or "Unavailable"
            print(f"{net['SSID']:<25} {net['BSSID']:<20} {sig:<12} {ch:<10} {sec:<18}")
        save_observations_to_csv(scanned)
        print("-" * 90)
        print(f"Saved {len(scanned)} observation(s) to dataset/wifi_observations.csv")
