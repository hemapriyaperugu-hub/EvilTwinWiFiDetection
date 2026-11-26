import sys

# Enable UTF-8 console output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.scanner import scan_wifi_detailed, save_observations_to_csv
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

    sig_val = iface.get("Signal")
    sig_str = f"{sig_val}%" if sig_val is not None else "Unavailable"
    ch_val = iface.get("Channel")
    ch_str = str(ch_val) if ch_val is not None else "Unavailable"

    print("======================================================================")
    print("                CURRENT ACTIVE WI-FI CONNECTION STATUS")
    print("======================================================================")
    print(f"  Connected SSID     : {iface.get('SSID') or 'Unavailable'}")
    print(f"  Connected BSSID    : {iface.get('BSSID') or 'Unavailable'}")
    print(f"  Operating Band     : {iface.get('Band') or 'Unavailable'} (Channel {ch_str})")
    print(f"  Signal             : {sig_str}")
    print(f"  Physical Radio     : {iface.get('Radio') or 'Unavailable'} with {iface.get('Cipher') or 'Unavailable'} encryption")
    print(f"  Security Suite     : {iface.get('Authentication') or 'Unavailable'}")

    net_info = get_default_gateway_and_ip()
    if net_info.get("IP"):
        print(f"\n  Client IPv4        : {net_info['IP']}")
        print(f"  Default Gateway IP : {net_info['Gateway_IP'] or 'N/A'}")
        if net_info.get("Gateway_MAC"):
            print(f"  Default Gateway MAC: {net_info['Gateway_MAC']}")
            gw_oui = net_info['Gateway_MAC'][:8]
            ap_oui = iface.get('BSSID', '')[:8]
            if gw_oui and ap_oui and gw_oui == ap_oui:
                print("  Gateway Integrity  : Gateway MAC matches Wi-Fi Access Point hardware OUI.")
            elif net_info['Gateway_MAC']:
                print("  Gateway Integrity  : Separate router/bridge MAC detected on local network.")
        if net_info.get("DNS_Servers"):
            print(f"  DNS Server(s)      : {', '.join(net_info['DNS_Servers'])}")

    is_portal, portal_msg = check_captive_portal()
    if is_portal:
        print(f"\n  [!] Captive Portal : {portal_msg}")
        print("      WARNING: Traffic is currently being intercepted by a login page.")
    else:
        print(f"  Captive Portal     : {portal_msg}")

    print("======================================================================\n")


def main():
    print("======================================================================")
    print("       EVIDENCE-BASED WI-FI EVIL TWIN DETECTION SYSTEM")
    print("       Multi-Dimensional Analysis: Rules + History + ML (KNN & RF)")
    print("======================================================================\n")

    ensure_models_ready()
    display_active_connection_analysis()

    # ---------------------------------------------------------
    # STEP 1 - Scan Wi-Fi
    # ---------------------------------------------------------
    print("[Step 1] Scanning nearby Wi-Fi networks using built-in adapter...")
    scan_res = scan_wifi_detailed()

    if not scan_res["success"]:
        print(f"\n[ERROR] Wi-Fi scan failed: {scan_res['error']}")
        print("    A failed scan is NOT treated as a safe network environment.")
        print("    Troubleshooting steps:")
        print("    1. Verify Wi-Fi is toggled ON in Windows Settings.")
        print("    2. Ensure the WLAN AutoConfig service (wlansvc) is running.")
        print("    3. Check that your Wi-Fi adapter is enabled.\n")
        return

    scanned_networks = scan_res["networks"]
    if not scanned_networks:
        print("\n[!] Scan succeeded, but no Wi-Fi access points are currently in range.\n")
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
        print(f"  BSSID              : {res['BSSID']} (OUI: {res['OUI']})")
        print(f"  Security           : {res['Security']} (Encryption: {res['Encryption']})")
        print(f"  Channel            : {res['Channel']} ({res['Band']})")
        print(f"  Signal             : {res['SignalDisplay']}")
        if res.get("Radio") and res["Radio"] != "Unavailable":
            print(f"  Physical Radio PHY : {res['Radio']}")
        if res.get("MissingFeatures"):
            print(f"  Unavailable Fields : {', '.join(res['MissingFeatures'])}")

        print(f"\n  Classification     : {res['RiskBadge']} {res['RiskCategory']}")
        print(f"  Trust Baseline     : {res['TrustState']}")

        print("\n  Reasons:")
        for reason in res["Reasons"]:
            print(f"    - {reason}")
        if res["WarningIndicators"]:
            for warn in res["WarningIndicators"]:
                print(f"    - [WARNING] {warn}")

        knn_conf_str = f" (confidence: {res['KNN_Confidence']}%)" if res.get("KNN_Confidence") is not None else ""
        rf_conf_str = f" (confidence: {res['RF_Confidence']}%)" if res.get("RF_Confidence") is not None else ""
        iso_score_str = f" (score: {res['IsoForest_Score']})" if res.get("IsoForest_Score") is not None else ""
        print("\n  ML Results:")
        print(f"    - Random Forest (Primary)    : {res['RF_Pred']}{rf_conf_str}")
        print(f"    - KNN (Comparison)           : {res['KNN_Pred']}{knn_conf_str}")
        print(f"    - Isolation Forest (Anomaly) : {res.get('IsoForest_Pred', 'Unavailable')}{iso_score_str}")
        print(f"    - Supervised Consensus       : {res['ML_Agreement']}")

        print("\n  Final Decision:")
        print(f"    - {res['FinalDecision']}")
        print(f"    - Advice: {res['SummaryAdvice']}")

        print("\n  Risk Score:")
        print(f"    - {res['RiskScore']} / {res['RiskScoreMax']} — {res['RiskScoreMeaning']}")
        if res["ScoreBreakdown"]:
            for item in res["ScoreBreakdown"]:
                print(f"      * +{item['points']} pts [{item['factor']}]: {item['reason']}")
        else:
            print("      * +0 pts: No warning indicators contributed to risk score.")

        print("-" * 70)

    # ---------------------------------------------------------
    # STEP 6 - Known & Consistent Network Summary
    # ---------------------------------------------------------
    print("\n======================================================================")
    print("              SAFE (VERIFIED BASELINE) NETWORKS IN RANGE")
    print("======================================================================\n")

    if safer_candidates:
        for rank, cand in enumerate(safer_candidates[:3], start=1):
            print(f"  {rank}. SSID: {cand['SSID']} [{cand['BSSID']}]")
            print(f"     Signal Strength  : {cand['Signal']}%")
            print(f"     Status           : {cand['RiskCategory']}")
            print()
        print("  Notice: System does not connect automatically; verify before connecting.")
    else:
        print("  No networks currently meet the verified SAFE baseline criteria.")
        print("  Review Classification, Reasons, and Risk Score details above.")

    # ---------------------------------------------------------
    # STEP 7 - Update local network history with assessment context
    # ---------------------------------------------------------
    update_history(scanned_networks, assessments=results)
    print("\n======================================================================")
    print("Network history updated in dataset/network_history.csv.")
    print("Scan cycle completed successfully.")
    print("======================================================================\n")


if __name__ == "__main__":
    main()
