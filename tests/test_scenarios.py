import os
import sys
import tempfile
import unittest
from unittest import mock
import pandas as pd

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

from src.history import (
    load_history,
    update_history,
    is_bssid_known,
    get_ap_record,
    get_known_channels_for_ssid,
    get_known_securities_for_ssid
)
from src.features import extract_features
from src.predict import (
    load_models,
    analyze_scanned_networks,
    determine_final_classification,
    STATUS_LEGITIMATE,
    STATUS_NEW,
    STATUS_SUSPICIOUS,
    STATUS_EVIL_TWIN,
    RISK_LOWER,
    RISK_UNCERTAIN,
    RISK_HIGH
)


class TestEvilTwinScenarios(unittest.TestCase):
    """
    Repeatable, unit-level validation suite covering all 12 required scenarios
    for client-side Wi-Fi Evil Twin Detection.
    """

    @classmethod
    def setUpClass(cls):
        cls.knn, cls.rf = load_models()

    def setUp(self):
        # Create an isolated temporary history directory for tests that mutate history
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_hist_path = os.path.join(self.temp_dir.name, "network_history.csv")

        # Seed the isolated history with standard baseline APs
        initial_records = [
            {
                "SSID": "TP-Link_6790",
                "BSSID": "0c:ef:15:e8:67:90",
                "Channel": "3",
                "Security": "WPA2-Personal",
                "Timestamp": "2026-09-01 10:00:00"
            },
            {
                "SSID": "Vardhaman_Campus",
                "BSSID": "18:64:72:a1:01:01",
                "Channel": "1",
                "Security": "WPA2-Enterprise",
                "Timestamp": "2026-09-01 10:00:00"
            },
            {
                "SSID": "TestWiFi",
                "BSSID": "00:14:22:01:23:45",
                "Channel": "1",
                "Security": "WPA2-Personal",
                "Timestamp": "2026-09-01 10:00:00"
            }
        ]
        self.isolated_history = update_history(initial_records, self.temp_hist_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    # ------------------------------------------------------------------
    # Scenario 1: A previously observed network with consistent attributes
    # ------------------------------------------------------------------
    def test_scenario_01_previously_observed_consistent_network(self):
        scan = [{
            "SSID": "TP-Link_6790",
            "BSSID": "0c:ef:15:e8:67:90",
            "Signal": 82,
            "Channel": 3,
            "Security": "WPA2-Personal",
            "Timestamp": "2026-10-01 12:00:00"
        }]
        results, safer = analyze_scanned_networks(scan, history_df=self.isolated_history)
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["FinalResult"], STATUS_LEGITIMATE)
        self.assertTrue(len(safer) > 0)
        self.assertEqual(safer[0]["SSID"], "TP-Link_6790")

    # ------------------------------------------------------------------
    # Scenario 2: A legitimate network observed for the first time
    # ------------------------------------------------------------------
    def test_scenario_02_first_time_observed_network(self):
        scan = [{
            "SSID": "BrandNew_HomeRouter",
            "BSSID": "aa:bb:cc:11:22:33",
            "Signal": 88,
            "Channel": 6,
            "Security": "WPA2-Personal",
            "Timestamp": "2026-10-01 12:05:00"
        }]
        results, _ = analyze_scanned_networks(scan, history_df=self.isolated_history)
        self.assertEqual(len(results), 1)
        res = results[0]
        # Crucial: Unfamiliar BSSID alone MUST NOT be labelled Evil Twin
        self.assertEqual(res["FinalResult"], STATUS_NEW)
        self.assertNotEqual(res["FinalResult"], STATUS_EVIL_TWIN)

    # ------------------------------------------------------------------
    # Scenario 3: A familiar SSID with a new BSSID (Campus/Mesh expansion)
    # ------------------------------------------------------------------
    def test_scenario_03_familiar_ssid_with_new_bssid(self):
        scan = [{
            "SSID": "Vardhaman_Campus",
            "BSSID": "18:64:72:a1:01:99",  # New AP node
            "Signal": 76,
            "Channel": 1,
            "Security": "WPA2-Enterprise",
            "Timestamp": "2026-10-01 12:10:00"
        }]
        results, _ = analyze_scanned_networks(scan, history_df=self.isolated_history)
        self.assertEqual(len(results), 1)
        res = results[0]
        # Multi-AP node must NOT be flagged as Evil Twin without anomalous indicators
        self.assertIn(res["FinalResult"], [STATUS_NEW, STATUS_LEGITIMATE])
        self.assertNotEqual(res["FinalResult"], STATUS_EVIL_TWIN)

    # ------------------------------------------------------------------
    # Scenario 4: Known BSSID with changed channel or signal fluctuation
    # ------------------------------------------------------------------
    def test_scenario_04_known_bssid_with_signal_fluctuation_or_channel_shift(self):
        fluctuating_signals = [45, 65, 82, 95, 100]
        for sig in fluctuating_signals:
            scan = [{
                "SSID": "TP-Link_6790",
                "BSSID": "0c:ef:15:e8:67:90",
                "Signal": sig,
                "Channel": 3,
                "Security": "WPA2-Personal",
                "Timestamp": "2026-10-01 12:15:00"
            }]
            results, _ = analyze_scanned_networks(scan, history_df=self.isolated_history)
            self.assertEqual(
                results[0]["FinalResult"],
                STATUS_LEGITIMATE,
                f"Signal {sig}% caused unstable classification!"
            )

    # ------------------------------------------------------------------
    # Scenario 5: A network with missing security or other attributes
    # ------------------------------------------------------------------
    def test_scenario_05_missing_attributes_graceful_handling(self):
        scan = [{
            "SSID": "Incomplete_AP",
            "BSSID": "de:ad:be:ef:00:01",
            "Signal": None,       # Missing signal
            "Channel": None,      # Missing channel
            "Security": None,     # Missing security
            "Timestamp": "2026-10-01 12:20:00"
        }]
        # Must execute without throwing exceptions
        results, _ = analyze_scanned_networks(scan, history_df=self.isolated_history)
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertIn(res["FinalResult"], [STATUS_NEW, STATUS_SUSPICIOUS])
        self.assertNotEqual(res["FinalResult"], STATUS_EVIL_TWIN)

    # ------------------------------------------------------------------
    # Scenario 6: Two legitimate access points sharing the same SSID
    # ------------------------------------------------------------------
    def test_scenario_06_two_legitimate_aps_sharing_same_ssid(self):
        # Multi-AP campus deployment visible concurrently
        scan = [
            {
                "SSID": "Vardhaman_Campus",
                "BSSID": "18:64:72:a1:01:01",
                "Signal": 78,
                "Channel": 1,
                "Security": "WPA2-Enterprise",
                "Timestamp": "2026-10-01 12:25:00"
            },
            {
                "SSID": "Vardhaman_Campus",
                "BSSID": "18:64:72:a1:01:02",
                "Signal": 72,
                "Channel": 6,
                "Security": "WPA2-Enterprise",
                "Timestamp": "2026-10-01 12:25:00"
            }
        ]
        results, _ = analyze_scanned_networks(scan, history_df=self.isolated_history)
        self.assertEqual(len(results), 2)
        for res in results:
            self.assertNotEqual(
                res["FinalResult"],
                STATUS_EVIL_TWIN,
                f"Legitimate campus AP {res['BSSID']} was falsely flagged as Evil Twin!"
            )

    # ------------------------------------------------------------------
    # Scenario 7: Disagreement between KNN and Random Forest
    # ------------------------------------------------------------------
    def test_scenario_07_model_disagreement_handling(self):
        f_row = {
            "Signal": 75,
            "Channel": 6,
            "Security": 1,
            "SameSSIDCount": 1,
            "BSSIDKnown": 0,
            "ChannelMatch": 1,
            "SecurityMatch": 1
        }
        badge, status, *rest = determine_final_classification(
            knn_pred=1,
            rf_pred=0,
            features_row=f_row,
            ap_record=None,
            ssid_known_in_history=False
        )
        self.assertEqual(status, STATUS_SUSPICIOUS)

    # ------------------------------------------------------------------
    # Scenario 8: Suspicious combination of multiple independent indicators
    # ------------------------------------------------------------------
    def test_scenario_08_multiple_independent_indicators_trigger_evil_twin(self):
        # Known secured SSID 'TestWiFi' cloned with:
        # 1. Unverified BSSID
        # 2. Security downgraded from WPA2 to Open
        # 3. Conflicting channel 11 (known channel is 1)
        # 4. Concurrent duplicate broadcast
        scan = [
            {
                "SSID": "TestWiFi",
                "BSSID": "00:14:22:01:23:45",  # Legitimate AP
                "Signal": 68,
                "Channel": 1,
                "Security": "WPA2-Personal",
                "Timestamp": "2026-10-01 12:30:00"
            },
            {
                "SSID": "TestWiFi",
                "BSSID": "e0:dc:ff:99:88:77",  # Rogue Clone
                "Signal": 94,
                "Channel": 11,
                "Security": "Open",
                "Timestamp": "2026-10-01 12:30:00"
            }
        ]
        results, _ = analyze_scanned_networks(scan, history_df=self.isolated_history)
        self.assertEqual(len(results), 2)
        legit_res = results[0]
        rogue_res = results[1]

        self.assertEqual(legit_res["FinalResult"], STATUS_LEGITIMATE)
        self.assertEqual(rogue_res["FinalResult"], STATUS_EVIL_TWIN)
        self.assertIn("downgraded", str(rogue_res["Reasons"]).lower())

    # ------------------------------------------------------------------
    # Scenario 9: Empty or corrupted network-history file
    # ------------------------------------------------------------------
    def test_scenario_09_corrupted_history_file_resilience(self):
        corrupt_path = os.path.join(self.temp_dir.name, "corrupt_history.csv")

        # Case A: Totally corrupted file with garbage binary/text
        with open(corrupt_path, "w", encoding="utf-8") as f:
            f.write("%%INVALID_CSV_DATA$$\n123,456\nfoo,bar,baz\n")

        df = load_history(corrupt_path)
        self.assertIsInstance(df, pd.DataFrame)
        # Should not crash and should return valid columns
        self.assertTrue("SSID" in df.columns)
        self.assertTrue("BSSID" in df.columns)

        # Case B: Completely empty file (0 bytes)
        with open(corrupt_path, "w", encoding="utf-8") as f:
            f.write("")

        df_empty = load_history(corrupt_path)
        self.assertTrue(df_empty.empty)
        self.assertEqual(len(df_empty.columns), 7)

    # ------------------------------------------------------------------
    # Scenario 10: Unavailable or malformed model file
    # ------------------------------------------------------------------
    def test_scenario_10_missing_or_malformed_model_handling(self):
        # Temporarily mock paths to non-existent model files
        non_existent_paths = {
            "knn": os.path.join(self.temp_dir.name, "missing_knn.pkl"),
            "random_forest": os.path.join(self.temp_dir.name, "missing_rf.pkl")
        }
        with mock.patch("src.predict.get_model_paths", return_value=non_existent_paths):
            with self.assertRaises(FileNotFoundError):
                load_models()

        # Case B: Corrupted pickle file (invalid bytes)
        with open(non_existent_paths["knn"], "wb") as f:
            f.write(b"NOT_A_VALID_PICKLE")
        with open(non_existent_paths["random_forest"], "wb") as f:
            f.write(b"NOT_A_VALID_PICKLE")

        with mock.patch("src.predict.get_model_paths", return_value=non_existent_paths):
            with self.assertRaises(ValueError):
                load_models()

    # ------------------------------------------------------------------
    # Scenario 11: Wi-Fi scan returning no networks
    # ------------------------------------------------------------------
    def test_scenario_11_empty_wifi_scan_handling(self):
        empty_scan = []
        results, safer = analyze_scanned_networks(empty_scan, history_df=self.isolated_history)
        self.assertEqual(results, [])
        self.assertEqual(safer, [])

    # ------------------------------------------------------------------
    # Scenario 12: Repeated scan of an unchanged network
    # ------------------------------------------------------------------
    def test_scenario_12_repeated_scan_of_unchanged_network(self):
        initial_scan = [{
            "SSID": "LivingRoom_WiFi",
            "BSSID": "50:d4:f7:11:22:33",
            "Signal": 80,
            "Channel": 6,
            "Security": "WPA2-Personal",
            "Timestamp": "2026-10-01 13:00:00"
        }]

        # Scan 1: First time observed
        res1, _ = analyze_scanned_networks(initial_scan, history_df=self.isolated_history)
        self.assertEqual(res1[0]["FinalResult"], STATUS_NEW)

        # Update history with Scan 1
        updated_hist = update_history(initial_scan, self.temp_hist_path)
        ap_rec = get_ap_record(updated_hist, "LivingRoom_WiFi", "50:d4:f7:11:22:33")
        self.assertIsNotNone(ap_rec)
        self.assertEqual(int(ap_rec["Observation Count"]), 1)

        # Scan 2: Second time observed (unchanged parameters)
        res2, safer = analyze_scanned_networks(initial_scan, history_df=updated_hist)
        self.assertEqual(res2[0]["FinalResult"], STATUS_LEGITIMATE)
        self.assertTrue(any(c["SSID"] == "LivingRoom_WiFi" for c in safer))

        # Update history with Scan 2
        updated_hist2 = update_history(initial_scan, self.temp_hist_path)
        ap_rec2 = get_ap_record(updated_hist2, "LivingRoom_WiFi", "50:d4:f7:11:22:33")
        self.assertEqual(int(ap_rec2["Observation Count"]), 2)

    # ------------------------------------------------------------------
    # Scenario 13: Dual-Band Router (2.4 GHz + 5 GHz complementary radios)
    # ------------------------------------------------------------------
    def test_scenario_13_dual_band_router_recognized_as_safe(self):
        # Textbook dual-band router scenario: SHIVA on ch 6 (2.4 GHz) and ch 44 (5 GHz)
        # Consecutive MAC addresses (ea:62 and ea:63), matching OUI, matching WPA2 security
        dual_band_scan = [
            {
                "SSID": "SHIVA",
                "BSSID": "16:32:51:69:ea:62",
                "Signal": 95,
                "Channel": 6,
                "Security": "WPA2-Personal",
                "Timestamp": "2026-10-01 14:00:00"
            },
            {
                "SSID": "SHIVA",
                "BSSID": "16:32:51:69:ea:63",
                "Signal": 100,
                "Channel": 44,
                "Security": "WPA2-Personal",
                "Timestamp": "2026-10-01 14:00:00"
            }
        ]
        results, safer = analyze_scanned_networks(dual_band_scan, history_df=self.isolated_history)
        self.assertEqual(len(results), 2)
        for res in results:
            self.assertTrue(res["IsDualBand"], f"Failed to detect dual-band partner for {res['BSSID']}")
            # Both radios must NEVER be flagged as Evil Twin!
            self.assertNotEqual(res["FinalResult"], STATUS_EVIL_TWIN)
            # Verdict must reflect lower risk or acceptable to connect
            self.assertIn(res["ConnectionVerdict"], [RISK_LOWER, RISK_UNCERTAIN])

    # ------------------------------------------------------------------
    # Scenario 14: Saved Windows Profile Correlation
    # ------------------------------------------------------------------
    def test_scenario_14_saved_profile_correlation_yields_safe_verdict(self):
        # Simulate an AP matching a saved profile 'SHIVA'
        scan = [{
            "SSID": "SHIVA",
            "BSSID": "16:32:51:69:ea:63",
            "Signal": 100,
            "Channel": 44,
            "Security": "WPA2-Personal",
            "Timestamp": "2026-10-01 14:10:00"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={"SHIVA": {"name": "SHIVA"}}):
            results, safer = analyze_scanned_networks(scan, history_df=self.isolated_history)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["FinalResult"], STATUS_LEGITIMATE)
            self.assertEqual(results[0]["ConnectionVerdict"], RISK_LOWER)

    # ------------------------------------------------------------------
    # Scenario 15: Captive Portal Probe Simulation
    # ------------------------------------------------------------------
    def test_scenario_15_captive_portal_probe_simulation(self):
        from src.system_profiles import check_captive_portal
        # Mock HTTP 302 redirect (Captive Portal detected)
        mock_resp = mock.MagicMock()
        mock_resp.getcode.return_value = 302
        mock_resp.headers = {"Location": "http://hotspot.login.com"}
        mock_resp.__enter__.return_value = mock_resp
        with mock.patch("urllib.request.urlopen", return_value=mock_resp):
            is_portal, msg = check_captive_portal()
            self.assertTrue(is_portal)
            self.assertIn("Captive portal detected", msg)

        # Mock HTTP 204 No Content (Direct Internet, no captive portal)
        mock_resp_204 = mock.MagicMock()
        mock_resp_204.getcode.return_value = 204
        mock_resp_204.__enter__.return_value = mock_resp_204
        with mock.patch("urllib.request.urlopen", return_value=mock_resp_204):
            is_portal_204, msg_204 = check_captive_portal()
            self.assertFalse(is_portal_204)
            self.assertIn("Direct Internet connectivity", msg_204)


if __name__ == "__main__":
    unittest.main(verbosity=2)
