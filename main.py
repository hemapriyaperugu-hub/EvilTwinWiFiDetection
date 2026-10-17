import sys
import os

# Enable UTF-8 console output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.scanner import scan_wifi, save_observations_to_csv
from src.history import load_history, update_history
from src.predict import (
    analyze_scanned_networks,
    load_models,
    STATUS_LEGITIMATE,
    STATUS_NEW,
    STATUS_SUSPICIOUS,
    STATUS_EVIL_TWIN,
    VERDICT_SAFE,
    VERDICT_ACCEPTABLE,
    VERDICT_CAUTION,
    VERDICT_DANGER
)
from src.system_profiles import (
    get_active_wifi_interface,
    get_default_gateway_and_ip,
    check_captive_portal
)
from src.dataset import seed_baseline_dataset, build_training_dataset
from src.train import train_models


def ensure_models_ready():
    """
    Ensures valid trained models exist before running detection.
    Retrains ONLY if model files are missing or unreadable.
    """
    try:
        load_models()
    except Exception as e:
        print(f"Notice: Model files missing or need initialization ({e}).")
        print("Initializing baseline dataset and training models...")
        seed_baseline_dataset(overwrite_if_exists=False)
        build_training_dataset()
        train_models()
        print("\nModels initialized successfully. Future scans will reuse them.\n")


def display_active_connection_analysis():
    """
    Inspects and displays active connection health, Gateway MAC alignment,
    DNS servers, and Captive Portal interception test.
    """
    iface = get_active_wifi_interface()
    if iface.get("State") != "connected":
        return

    print("======================================================================")
    print("                CURRENT ACTIVE WI-FI CONNECTION STATUS")
    print("======================================================================")
    print(f"  Connected SSID     : {iface.get('SSID')}")
    print(f"  Connected BSSID    : {iface.get('BSSID')}")
    print(f"  Operating Band     : {iface.get('Band')} (Channel {iface.get('Channel')})")
    print(f"  Signal (RSSI)      : {iface.get('Signal')}%")
    print(f"  Physical Radio     : {iface.get('Radio')} with {iface.get('Cipher')} encryption")
    print(f"  Security Suite     : {iface.get('Authentication')}")

    net_info = get_default_gateway_and_ip()
    if net_info.get("IP"):
        print(f"\n  Client IPv4        : {net_info['IP']}")
        print(f"  Default Gateway IP : {net_info['Gateway_IP'] or 'N/A'}")
        if net_info.get("Gateway_MAC"):
            print(f"  Default Gateway MAC: {net_info['Gateway_MAC']}")
            # Compare Gateway MAC and Wi-Fi BSSID OUI
            gw_oui = net_info['Gateway_MAC'][:8]
            ap_oui = iface.get('BSSID', '')[:8]
            if gw_oui and ap_oui and gw_oui == ap_oui:
                print("  Gateway Integrity  : Gateway MAC matches Wi-Fi Access Point hardware OUI (legitimate router).")
            elif net_info['Gateway_MAC']:
                print("  Gateway Integrity  : Separate router/bridge MAC detected on local network.")
        if net_info.get("DNS_Servers"):
            print(f"  DNS Server(s)      : {', '.join(net_info['DNS_Servers'])}")

    # Captive portal check
    is_portal, portal_msg = check_captive_portal()
    if is_portal:
        print(f"\n  [!] Captive Portal : {portal_msg}")
        print("      WARNING: Traffic is currently being intercepted by a login page.")
    else:
        print(f"  Captive Portal     : {portal_msg}")

    print("======================================================================\n")


def main():
    print("======================================================================")
    print("       SOFTWARE-BASED EVIL TWIN DETECTION IN PUBLIC WI-FI")
    print("       Algorithms: K-Nearest Neighbors (KNN) + Random Forest")
    print("======================================================================\n")

    # Ensure models exist and are valid
    ensure_models_ready()

    # Display active connection diagnostics if currently connected
    display_active_connection_analysis()

    # ---------------------------------------------------------
    # STEP 1 - Scan Wi-Fi
    # ---------------------------------------------------------
    print("[Step 1] Scanning nearby Wi-Fi networks using built-in adapter...")
    scanned_networks = scan_wifi()

    if not scanned_networks:
        print("\n[!] No Wi-Fi access points detected in range.")
        print("    Troubleshooting steps:")
        print("    1. Verify Wi-Fi is toggled ON in Windows Settings.")
        print("    2. Ensure the WLAN AutoConfig service is active.")
        print("    3. Check that your Wi-Fi adapter is enabled.\n")
        return

    print(f"Found {len(scanned_networks)} Access Point(s) visible.\n")

    # ---------------------------------------------------------
    # STEP 2 - Save raw observation
    # ---------------------------------------------------------
    save_observations_to_csv(scanned_networks)

    # ---------------------------------------------------------
    # STEP 3 - Load history BEFORE updating it
    # ---------------------------------------------------------
    history_df = load_history()

    # ---------------------------------------------------------
    # STEP 4 - Run Detection Analysis
    # ---------------------------------------------------------
    results, safer_candidates = analyze_scanned_networks(
        scanned_networks,
        history_df=history_df
    )

    # ---------------------------------------------------------
    # STEP 5 - Detection report
    # ---------------------------------------------------------
    print("======================================================================")
    print("                DETECTION & CONNECTION DECISION REPORT")
    print("======================================================================")

    for i, res in enumerate(results, start=1):
        print(f"\n[AP {i}]")
        print(f"  SSID               : {res['SSID']}")
        print(f"  BSSID (MAC)        : {res['BSSID']}")
        print(f"  Frequency Band     : {res['Band']} (Channel {res['Channel']})")
        print(f"  Signal Strength    : {res['Signal']}%")
        print(f"  Advertised Security: {res['Security']} ({res.get('Encryption', 'CCMP')})")
        if res.get("Radio") and res["Radio"] != "Unknown":
            print(f"  PHY Radio Type     : {res['Radio']}")

        print("\n  Machine Learning Evaluation:")
        print(f"    - KNN Classifier     : {res['KNN_Pred']}")
        print(f"    - Random Forest      : {res['RF_Pred']}")

        print("\n  Evidence & Analysis:")
        for reason in res["Reasons"]:
            print(f"    * {reason}")

        print(f"\n  Threat Assessment  : {res['Badge']} {res['FinalResult']}")
        print(f"  CONNECTION VERDICT : {res['VerdictBadge']} {res['ConnectionVerdict']}")
        print(f"  Action Advice      : {res['ConnectionAdvice']}")
        print("-" * 70)

    # ---------------------------------------------------------
    # STEP 6 - Safer network recommendation
    # ---------------------------------------------------------
    print("\n======================================================================")
    print("                   RECOMMENDED NETWORK FOR CONNECTION")
    print("======================================================================")

    if safer_candidates:
        top = safer_candidates[0]
        print(f"  Suggested SSID     : {top['SSID']}")
        print(f"  BSSID (MAC)        : {top['BSSID']}")
        print(f"  Signal Strength    : {top['Signal']}%")
        print(f"  Confidence Level   : {top['ObservationCount']} observation / profile weight")
        print("  Status             : Verified safe. Zero attack or spoofing indicators.")
        print("  Notice             : System does not auto-connect; use Windows Wi-Fi menu.")
    else:
        print("  No pre-verified networks in range.")
        print("  Unfamiliar networks should be checked against the Connection Verdict above.")

    # ---------------------------------------------------------
    # STEP 7 - Update local network history
    # ---------------------------------------------------------
    update_history(scanned_networks)
    print("\n======================================================================")
    print("Network history updated in dataset/network_history.csv.")
    print("Scan cycle completed successfully.")
    print("======================================================================\n")


if __name__ == "__main__":
    main()