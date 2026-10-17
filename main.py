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
    RISK_LOWER,
    RISK_UNCERTAIN,
    RISK_HIGH
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
    print("       EVIDENCE-BASED WI-FI CONNECTION RISK ASSESSMENT SYSTEM")
    print("       Multi-Dimensional Analysis: ML (KNN + RF) + RF + Cryptography")
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
    # STEP 4 - Run Multi-Dimensional Risk Assessment
    # ---------------------------------------------------------
    results, safer_candidates = analyze_scanned_networks(
        scanned_networks,
        history_df=history_df
    )

    # ---------------------------------------------------------
    # STEP 5 - Risk Assessment Report
    # ---------------------------------------------------------
    print("======================================================================")
    print("              EVIDENCE-BASED WI-FI RISK ASSESSMENT REPORT")
    print("======================================================================")

    for i, res in enumerate(results, start=1):
        print(f"\n[AP {i}]")
        print(f"  SSID               : {res['SSID']}")
        print(f"  BSSID (MAC)        : {res['BSSID']}")
        print(f"  Frequency Band     : {res['Band']} (Channel {res['Channel']})")
        print(f"  Signal Strength    : {res['Signal']}%")
        print(f"  Advertised Security: {res['Security']} ({res.get('Encryption', 'CCMP')})")
        if res.get("Radio") and res["Radio"] != "Unknown":
            print(f"  Physical Radio PHY : {res['Radio']}")

        print(f"\n  Trust Baseline     : {res['TrustState']}")

        print("\n  Machine Learning Evaluation:")
        print(f"    - KNN Model          : {res['KNN_Pred']}")
        print(f"    - Random Forest      : {res['RF_Pred']}")

        print("\n  Observed Evidence & Factors:")
        for ev in res["ObservedEvidence"]:
            print(f"    [+] {ev}")

        if res["WarningIndicators"]:
            print("\n  Warning Indicators & Anomalies:")
            for warn in res["WarningIndicators"]:
                print(f"    [!] {warn}")

        print(f"\n  RISK ASSESSMENT    : {res['RiskBadge']} {res['RiskCategory']}")
        print(f"  ACTION ADVICE      : {res['SummaryAdvice']}")
        print("-" * 70)

    # ---------------------------------------------------------
    # STEP 6 - Lower-Risk Network Recommendations
    # ---------------------------------------------------------
    print("\n======================================================================")
    print("              RECOMMENDED LOWER-RISK NETWORKS IN RANGE")
    print("======================================================================\n")

    if safer_candidates:
        for rank, cand in enumerate(safer_candidates[:3], start=1):
            print(f"  {rank}. SSID: {cand['SSID']} [{cand['BSSID']}]")
            print(f"     Signal Strength  : {cand['Signal']}%")
            print(f"     Assessment Status: {cand['RiskCategory']}")
            print()
        print("  Notice: System does not connect automatically; choose your network via Windows Wi-Fi menu.")
    else:
        print("  No networks currently meet the Lower-Risk criteria.")
        print("  Check the individual Warning Indicators and Action Advice above.")

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