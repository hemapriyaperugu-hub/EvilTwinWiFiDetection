import os
import sys
import unittest

# Ensure project root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Enable UTF-8 console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.history import load_history, update_history, is_bssid_known, get_ap_record
from src.features import extract_features
from src.predict import (
    load_models,
    analyze_scanned_networks,
    determine_final_classification,
    get_safe_badge
)


class TestEvilTwinScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.history_df = load_history()
        cls.knn, cls.rf = load_models()

    def test_scenario_1_known_ssid_and_bssid(self):
        """
        Test 1: Known SSID + known BSSID appears again.
        Expected: Recognized as previously observed AP, not flagged as new/suspicious.
        """
        print("\n=======================================================")
        print("TEST 1: Known SSID + Known BSSID Appears Again")
        print("=======================================================")
        known_ssid = "TP-Link_6790"
        known_bssid = "0c:ef:15:e8:67:90"

        # Check history recognition
        is_known = is_bssid_known(self.history_df, known_ssid, known_bssid)
        ap_rec = get_ap_record(self.history_df, known_ssid, known_bssid)

        self.assertTrue(is_known, f"Expected {known_bssid} to be known in history.")
        self.assertIsNotNone(ap_rec, "Expected to find AP history record.")

        initial_count = int(ap_rec["Observation Count"])
        print(f"Recognized AP: {known_ssid} [{known_bssid}]")
        print(f"Prior Observation Count: {initial_count}")

        # Simulate scan and prediction
        scan = [{
            "SSID": known_ssid,
            "BSSID": known_bssid,
            "Signal": 85,
            "Channel": 3,
            "Security": "WPA2-Personal",
            "Timestamp": "2026-09-18 12:30:00"
        }]
        results, _ = analyze_scanned_networks(scan, history_df=self.history_df)
        self.assertEqual(len(results), 1)
        res = results[0]

        print(f"ML Consensus: KNN={res['KNN_Pred']}, RF={res['RF_Pred']}")
        print(f"Final Result: {res['Badge']} {res['FinalResult']}")
        print("Explanations:")
        for r in res["Reasons"]:
            print(f"  * {r}")

        self.assertEqual(res["FinalResult"], "LIKELY LEGITIMATE")
        self.assertIn("previously observed", res["Reasons"][0].lower())
        print("--> TEST 1 PASSED: Known AP correctly recognized without false alarm.")

    def test_scenario_2_same_ssid_different_bssid(self):
        """
        Test 2: Same SSID + different BSSID (Legitimate College Multi-AP network).
        Expected: NOT automatically classified as Evil Twin.
        """
        print("\n=======================================================")
        print("TEST 2: Same SSID + Different BSSID (Campus Multi-AP)")
        print("=======================================================")
        campus_scan = [
            {
                "SSID": "Vardhaman_Campus",
                "BSSID": "18:64:72:a1:01:01",
                "Signal": 75,
                "Channel": 1,
                "Security": "WPA2-Enterprise",
                "Timestamp": "2026-09-18 12:35:00"
            },
            {
                "SSID": "Vardhaman_Campus",
                "BSSID": "18:64:72:a1:01:02",
                "Signal": 70,
                "Channel": 6,
                "Security": "WPA2-Enterprise",
                "Timestamp": "2026-09-18 12:35:00"
            }
        ]

        results, _ = analyze_scanned_networks(campus_scan, history_df=self.history_df)
        self.assertEqual(len(results), 2)

        for i, res in enumerate(results, start=1):
            print(f"\nAP {i}: {res['SSID']} [{res['BSSID']}]")
            print(f"  Channel={res['Channel']}, Signal={res['Signal']}%, Security={res['Security']}")
            print(f"  Result: {res['Badge']} {res['FinalResult']}")
            # Crucial requirement: Must NOT be automatically marked Evil Twin!
            self.assertNotEqual(res["FinalResult"], "POSSIBLE EVIL TWIN")

        print("--> TEST 2 PASSED: Multi-AP enterprise Wi-Fi is NOT falsely marked as Evil Twin.")

    def test_scenario_3_rssi_fluctuations(self):
        """
        Test 3: Known AP with normal RSSI / Signal fluctuations.
        Expected: Classification remains stable (no random flipping between legitimate & evil twin).
        """
        print("\n=======================================================")
        print("TEST 3: Stability Under Normal Signal Fluctuations")
        print("=======================================================")
        test_signals = [70, 63, 85, 58, 72, 95]
        ssid = "TP-Link_6790"
        bssid = "0c:ef:15:e8:67:90"

        for sig in test_signals:
            scan = [{
                "SSID": ssid,
                "BSSID": bssid,
                "Signal": sig,
                "Channel": 3,
                "Security": "WPA2-Personal",
                "Timestamp": "2026-09-18 12:40:00"
            }]
            results, _ = analyze_scanned_networks(scan, history_df=self.history_df)
            res = results[0]
            print(f"Signal: {sig:3d}% -> Result: {res['Badge']} {res['FinalResult']}")
            self.assertEqual(res["FinalResult"], "LIKELY LEGITIMATE",
                             f"Signal {sig}% caused unstable classification!")

        print("--> TEST 3 PASSED: Classification remained 100% stable across all signal fluctuations.")

    def test_scenario_4_controlled_suspicious_experiment(self):
        """
        Test 4: Controlled same-SSID suspicious experiment.
        Expected: System flags anomalous characteristics (unknown BSSID, security downgrade, channel change).
        """
        print("\n=======================================================")
        print("TEST 4: Controlled Same-SSID Suspicious Experiment")
        print("=======================================================")
        experiment_scan = [
            # Legitimate AP A
            {
                "SSID": "TestWiFi",
                "BSSID": "00:14:22:01:23:45",
                "Signal": 70,
                "Channel": 1,
                "Security": "WPA2-Personal",
                "Timestamp": "2026-09-18 12:45:00"
            },
            # Controlled Rogue Twin B (Different BSSID, Channel mismatch, Open security, High signal)
            {
                "SSID": "TestWiFi",
                "BSSID": "e0:dc:ff:99:88:77",
                "Signal": 94,
                "Channel": 11,
                "Security": "Open",
                "Timestamp": "2026-09-18 12:45:00"
            }
        ]

        results, _ = analyze_scanned_networks(experiment_scan, history_df=self.history_df)
        self.assertEqual(len(results), 2)

        legit_res = results[0]
        rogue_res = results[1]

        print(f"Legitimate AP: {legit_res['SSID']} [{legit_res['BSSID']}] -> {legit_res['Badge']} {legit_res['FinalResult']}")
        print(f"Rogue Twin   : {rogue_res['SSID']} [{rogue_res['BSSID']}] -> {rogue_res['Badge']} {rogue_res['FinalResult']}")
        print("Rogue AP Reasons:")
        for r in rogue_res["Reasons"]:
            print(f"  * {r}")

        self.assertEqual(legit_res["FinalResult"], "LIKELY LEGITIMATE")
        self.assertIn(rogue_res["FinalResult"], ["POSSIBLE EVIL TWIN", "SUSPICIOUS / VERIFY NETWORK"])
        self.assertEqual(rogue_res["Features"]["BSSIDKnown"], 0)
        self.assertEqual(rogue_res["Features"]["SecurityMatch"], 0)
        self.assertEqual(rogue_res["Features"]["ChannelMatch"], 0)

        print("--> TEST 4 PASSED: System identified anomalous rogue AP characteristics.")

    def test_scenario_5_model_disagreement(self):
        """
        Test 5: KNN and Random Forest disagree.
        Expected: Final decision is 🟡 SUSPICIOUS / VERIFY NETWORK.
        """
        print("\n=======================================================")
        print("TEST 5: Machine Learning Models Disagree")
        print("=======================================================")
        # Synthetic disagreement test on unverified network
        f_row = {
            "Signal": 82,
            "Channel": 4,
            "Security": 1,
            "SameSSIDCount": 2,
            "BSSIDKnown": 0,
            "ChannelMatch": 0,
            "SecurityMatch": 1
        }
        # Case A: KNN=1, RF=0
        badge_a, status_a = determine_final_classification(knn_pred=1, rf_pred=0, features_row=f_row, ap_record=None)
        print(f"Case A (KNN=Evil Twin, RF=Legitimate): {badge_a} {status_a}")
        self.assertEqual(status_a, "SUSPICIOUS / VERIFY NETWORK")

        # Case B: KNN=0, RF=1
        badge_b, status_b = determine_final_classification(knn_pred=0, rf_pred=1, features_row=f_row, ap_record=None)
        print(f"Case B (KNN=Legitimate, RF=Evil Twin): {badge_b} {status_b}")
        self.assertEqual(status_b, "SUSPICIOUS / VERIFY NETWORK")

        print("--> TEST 5 PASSED: Model disagreement properly yields SUSPICIOUS / VERIFY NETWORK.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
