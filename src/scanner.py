import subprocess
import re
import csv
import os
from datetime import datetime


def get_default_dataset_path():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "dataset", "wifi_observations.csv")


def scan_wifi():
    """
    Scans nearby Wi-Fi networks using Windows netsh command:
    netsh wlan show networks mode=bssid
    Returns a list of dictionaries with real AP observations.
    Gracefully handles missing permissions, disabled Wi-Fi adapters,
    or stopped wlansvc services.
    """
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )
        if result.returncode != 0:
            err_msg = result.stderr.strip() or result.stdout.strip()
            if "wlansvc" in err_msg.lower() or "service" in err_msg.lower():
                print("Notice: Windows WLAN AutoConfig service (wlansvc) is not running.")
            elif "interface" in err_msg.lower():
                print("Notice: No active Wi-Fi interface detected or Wi-Fi adapter is disabled.")
            else:
                print(f"Notice from Wi-Fi scanner: {err_msg}")
            return []

        raw_output = result.stdout
    except FileNotFoundError:
        print("Error: 'netsh' command not found. This scanner requires a Windows environment.")
        return []
    except Exception as e:
        print(f"Error executing netsh command: {e}")
        return []

    networks = []
    current_ssid = ""
    current_auth = "Unknown"
    current_enc = "Unknown"
    current_ap = None

    for line in raw_output.splitlines():
        line = line.strip()

        # Check for SSID header: e.g., 'SSID 1 : NetworkName'
        ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if ssid_match:
            if current_ap is not None:
                networks.append(current_ap)
                current_ap = None

            current_ssid = ssid_match.group(1).strip()
            if not current_ssid:
                current_ssid = "<Hidden Network>"
            current_auth = "Unknown"
            current_enc = "Unknown"
            continue

        # Authentication line
        if line.startswith("Authentication"):
            parts = line.split(":", 1)
            if len(parts) > 1:
                current_auth = parts[1].strip()
            continue

        # Encryption line
        if line.startswith("Encryption"):
            parts = line.split(":", 1)
            if len(parts) > 1:
                current_enc = parts[1].strip()
            continue

        # BSSID header: e.g., 'BSSID 1 : 0c:ef:15:e8:67:90'
        bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*([0-9a-fA-F:-]+)", line)
        if bssid_match:
            if current_ap is not None:
                networks.append(current_ap)

            bssid_mac = bssid_match.group(1).strip().lower()
            current_ap = {
                "SSID": current_ssid,
                "BSSID": bssid_mac,
                "Signal": 0,
                "Channel": 1,
                "Security": current_auth,
                "Encryption": current_enc,
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Label": "Unknown"
            }
            continue

        # Signal line: e.g., 'Signal : 100%'
        if current_ap is not None and line.startswith("Signal"):
            signal_match = re.search(r"(\d+)%", line)
            if signal_match:
                current_ap["Signal"] = int(signal_match.group(1))
            continue

        # Channel line: e.g., 'Channel : 3'
        if current_ap is not None and line.startswith("Channel"):
            chan_match = re.search(r"Channel\s*:\s*(\d+)", line)
            if chan_match:
                current_ap["Channel"] = int(chan_match.group(1))
            continue

        # Band: e.g. 'Band : 5 GHz'
        if current_ap is not None and line.startswith("Band"):
            parts = line.split(":", 1)
            if len(parts) > 1:
                current_ap["Band"] = parts[1].strip()
            continue

        # Radio type: e.g. 'Radio type : 802.11ax'
        if current_ap is not None and line.startswith("Radio type"):
            parts = line.split(":", 1)
            if len(parts) > 1:
                current_ap["Radio"] = parts[1].strip()
            continue

        # Basic rates: e.g. 'Basic rates (Mbps) : 6 12 24'
        if current_ap is not None and "basic rates" in line.lower():
            parts = line.split(":", 1)
            if len(parts) > 1:
                current_ap["BasicRates"] = parts[1].strip()
            continue

        # Other rates: e.g. 'Other rates (Mbps) : 9 18 36 48 54'
        if current_ap is not None and "other rates" in line.lower():
            parts = line.split(":", 1)
            if len(parts) > 1:
                current_ap["OtherRates"] = parts[1].strip()
            continue

    if current_ap is not None:
        networks.append(current_ap)

    return networks


def save_observations_to_csv(networks, csv_path=None):
    """
    Appends scanned networks to wifi_observations.csv.
    Maintains raw real observations with timestamps and error safety.
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
                writer.writerow({
                    "SSID": net.get("SSID", ""),
                    "BSSID": str(net.get("BSSID", "")).lower(),
                    "Signal": net.get("Signal", 0),
                    "Channel": net.get("Channel", 1),
                    "Security": net.get("Security", "Unknown"),
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
    scanned = scan_wifi()
    if not scanned:
        print("No Wi-Fi networks found or Wi-Fi adapter is turned off.")
    else:
        print(f"Found {len(scanned)} Access Point(s):\n")
        print(f"{'SSID':<25} {'BSSID (MAC)':<20} {'Signal':<8} {'Channel':<8} {'Security':<15}")
        print("-" * 80)
        for net in scanned:
            sig = f"{net['Signal']}%"
            print(f"{net['SSID']:<25} {net['BSSID']:<20} {sig:<8} {str(net['Channel']):<8} {net['Security']:<15}")
        save_observations_to_csv(scanned)
        print("-" * 80)
        print(f"Saved {len(scanned)} observation(s) to dataset/wifi_observations.csv")
