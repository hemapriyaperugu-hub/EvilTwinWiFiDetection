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

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.history import (
    HISTORY_COLUMNS,
    TRUST_ESTABLISHED,
    TRUST_FLAGGED,
    TRUST_UNVERIFIED,
    get_ap_record,
    load_history,
    mark_ap_trusted,
    unverify_ap,
    update_history
)
from src.features import classify_security_comparison, normalize_security_label
from src.scanner import parse_netsh_output, scan_wifi_detailed
from src.predict import (
    STATUS_HIGH_RISK,
    STATUS_KNOWN_CONSISTENT,
    STATUS_NEW_UNVERIFIED,
    STATUS_SUSPICIOUS,
    analyze_scanned_networks,
    determine_final_classification,
    load_isolation_forest,
    load_models
)


class _AlwaysLegitModel:
    """Deterministic stub model that always predicts 0 (Legitimate) for testing rule overrides."""
    def predict(self, X):
        return [0] * len(X)


class TestEvilTwinScenarios(unittest.TestCase):
    """
    Comprehensive deterministic test suite verifying false-negative prevention,
    no auto-trust on repeated scans, rule/ML integration, history integrity,
    and Windows netsh scanner parsing.
    """

    @classmethod
    def setUpClass(cls):
        cls.knn, cls.rf = load_models()

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_hist_path = os.path.join(self.temp_dir.name, "network_history.csv")

        # Explicitly establish known trusted baseline APs (mark_trusted=True)
        initial_records = [
            {
                "SSID": "TP-Link_6790",
                "BSSID": "0c:ef:15:e8:67:90",
                "Channel": 3,
                "Band": "2.4 GHz",
                "Signal": 80,
                "Security": "WPA2-Personal",
                "Encryption": "CCMP",
                "Timestamp": "2026-09-01 10:00:00"
            },
            {
                "SSID": "Vardhaman_Campus",
                "BSSID": "18:64:72:a1:01:01",
                "Channel": 1,
                "Band": "2.4 GHz",
                "Signal": 78,
                "Security": "WPA2-Enterprise",
                "Encryption": "CCMP",
                "Timestamp": "2026-09-01 10:00:00"
            },
            {
                "SSID": "Vardhaman_Campus",
                "BSSID": "18:64:72:a1:01:02",
                "Channel": 6,
                "Band": "2.4 GHz",
                "Signal": 74,
                "Security": "WPA2-Enterprise",
                "Encryption": "CCMP",
                "Timestamp": "2026-09-01 10:00:00"
            },
            {
                "SSID": "TestWiFi",
                "BSSID": "00:14:22:01:23:45",
                "Channel": 1,
                "Band": "2.4 GHz",
                "Signal": 76,
                "Security": "WPA2-Personal",
                "Encryption": "CCMP",
                "Timestamp": "2026-09-01 10:00:00"
            }
        ]
        self.isolated_history = update_history(
            initial_records, self.temp_hist_path, mark_trusted=True
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    # ------------------------------------------------------------------
    # Test 1: Known legitimate network -> KNOWN / CONSISTENT
    # ------------------------------------------------------------------
    def test_01_known_legitimate_network(self):
        scan = [{
            "SSID": "TP-Link_6790",
            "BSSID": "0c:ef:15:e8:67:90",
            "Signal": 82,
            "Channel": 3,
            "Security": "WPA2-Personal",
            "Encryption": "CCMP",
            "Timestamp": "2026-10-01 12:00:00"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            results, safer = analyze_scanned_networks(scan, history_df=self.isolated_history)
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["Classification"], STATUS_KNOWN_CONSISTENT)
        self.assertIn("No suspicious indicators detected during this scan", res["RiskCategory"])
        self.assertEqual(len(safer), 1)

    # ------------------------------------------------------------------
    # Test 2: New network -> NEW / UNVERIFIED
    # ------------------------------------------------------------------
    def test_02_new_network(self):
        scan = [{
            "SSID": "BrandNew_HomeRouter",
            "BSSID": "aa:bb:cc:11:22:33",
            "Signal": 88,
            "Channel": 6,
            "Security": "WPA2-Personal",
            "Encryption": "CCMP",
            "Timestamp": "2026-10-01 12:05:00"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            results, safer = analyze_scanned_networks(scan, history_df=self.isolated_history)
        res = results[0]
        self.assertEqual(res["Classification"], STATUS_NEW_UNVERIFIED)
        self.assertEqual(safer, [])

    # ------------------------------------------------------------------
    # Test 3: Same SSID, new BSSID -> SUSPICIOUS / VERIFY (not auto Evil Twin)
    # ------------------------------------------------------------------
    def test_03_same_ssid_new_bssid(self):
        scan = [{
            "SSID": "TP-Link_6790",
            "BSSID": "aa:bb:cc:44:55:66",  # Unfamiliar BSSID for known SSID
            "Signal": 76,
            "Channel": 3,
            "Security": "WPA2-Personal",
            "Encryption": "CCMP",
            "Timestamp": "2026-10-01 12:10:00"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            results, _ = analyze_scanned_networks(scan, history_df=self.isolated_history)
        res = results[0]
        self.assertEqual(res["Classification"], STATUS_SUSPICIOUS)
        self.assertNotEqual(res["Classification"], STATUS_HIGH_RISK)
        self.assertIn("unfamiliar bssid", str(res["WarningIndicators"]).lower())

    # ------------------------------------------------------------------
    # Test 4: Same SSID, weaker security -> Elevated risk + mismatch warning
    # ------------------------------------------------------------------
    def test_04_same_ssid_weaker_security(self):
        scan = [{
            "SSID": "TestWiFi",
            "BSSID": "e0:dc:ff:99:88:77",
            "Signal": 90,
            "Channel": 1,
            "Security": "Open",
            "Encryption": "None",
            "Timestamp": "2026-10-01 12:15:00"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            results, _ = analyze_scanned_networks(scan, history_df=self.isolated_history)
        res = results[0]
        self.assertIn(res["Classification"], [STATUS_SUSPICIOUS, STATUS_HIGH_RISK])
        self.assertGreaterEqual(res["RiskScore"], 60)
        self.assertIn("downgrade", str(res["WarningIndicators"]).lower())

    # ------------------------------------------------------------------
    # Test 5: Repeated suspicious network MUST NOT become legitimate
    # ------------------------------------------------------------------
    def test_05_repeated_suspicious_network_never_promoted(self):
        suspicious_ap = [{
            "SSID": "TestWiFi",
            "BSSID": "de:ad:be:ef:11:22",  # Unfamiliar BSSID for known SSID
            "Signal": 85,
            "Channel": 1,
            "Security": "WPA2-Personal",
            "Encryption": "CCMP",
            "Timestamp": "2026-10-01 12:20:00"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            for scan_num in range(1, 6):
                hist_df = load_history(self.temp_hist_path)
                results, safer = analyze_scanned_networks(suspicious_ap, history_df=hist_df)
                res = results[0]
                self.assertIn(
                    res["Classification"],
                    [STATUS_SUSPICIOUS, STATUS_HIGH_RISK],
                    f"Scan #{scan_num} falsely trusted suspicious AP!"
                )
                self.assertNotEqual(res["Classification"], STATUS_KNOWN_CONSISTENT)
                self.assertEqual(safer, [])
                update_history(suspicious_ap, self.temp_hist_path, assessments=results)

        final_hist = load_history(self.temp_hist_path)
        rec = get_ap_record(final_hist, "TestWiFi", "de:ad:be:ef:11:22")
        self.assertIsNotNone(rec)
        self.assertEqual(int(rec["Observation Count"]), 5)
        self.assertEqual(rec["Trust Status"], TRUST_FLAGGED)

    # ------------------------------------------------------------------
    # Test 6: Known BSSID with altered security -> anomaly warning across scans
    # ------------------------------------------------------------------
    def test_06_known_bssid_altered_security(self):
        altered_scan = [{
            "SSID": "TestWiFi",
            "BSSID": "00:14:22:01:23:45",  # Known baseline BSSID
            "Signal": 78,
            "Channel": 1,
            "Security": "Open",             # Downgraded from WPA2-Personal!
            "Encryption": "None",
            "Timestamp": "2026-10-01 12:25:00"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            res1, _ = analyze_scanned_networks(altered_scan, history_df=self.isolated_history)
            self.assertIn(res1[0]["Classification"], [STATUS_SUSPICIOUS, STATUS_HIGH_RISK])
            self.assertIn("security", str(res1[0]["WarningIndicators"]).lower())

            # Update history and ensure baseline security was NOT overwritten by Open!
            hist2 = update_history(altered_scan, self.temp_hist_path, assessments=res1)
            rec = get_ap_record(hist2, "TestWiFi", "00:14:22:01:23:45")
            self.assertEqual(rec["Security"], "WPA2-Personal")
            self.assertEqual(rec["Last Security"], "Open")
            self.assertEqual(rec["Trust Status"], TRUST_FLAGGED)

            # Second scan still detects the anomaly!
            res2, _ = analyze_scanned_networks(altered_scan, history_df=hist2)
            self.assertIn(res2[0]["Classification"], [STATUS_SUSPICIOUS, STATUS_HIGH_RISK])

    # ------------------------------------------------------------------
    # Test 7: ML model disagreement -> Uncertain / SUSPICIOUS + explanation
    # ------------------------------------------------------------------
    def test_07_ml_model_disagreement(self):
        f_row = {
            "Signal": 75.0,
            "Channel": 6.0,
            "Security": 1.0,
            "SameSSIDCount": 1,
            "BSSIDKnown": 0,
            "ChannelMatch": 1,
            "SecurityMatch": 1
        }
        badge, status, _, category, advice = determine_final_classification(
            knn_pred=1,
            rf_pred=0,
            features_row=f_row,
            ap_record=None,
            ssid_known_in_history=False
        )
        self.assertEqual(status, STATUS_SUSPICIOUS)
        self.assertIn("verify", advice.lower())

    # ------------------------------------------------------------------
    # Test 8: ML predicts legitimate, strong suspicious evidence overrides ML
    # ------------------------------------------------------------------
    def test_08_ml_legitimate_overridden_by_strong_rules(self):
        scan = [
            {
                "SSID": "TestWiFi",
                "BSSID": "00:14:22:01:23:45",
                "Signal": 65,
                "Channel": 1,
                "Security": "WPA2-Personal",
                "Encryption": "CCMP",
                "Timestamp": "2026-10-01 12:30:00"
            },
            {
                "SSID": "TestWiFi",
                "BSSID": "e0:dc:ff:99:88:77",
                "Signal": 94,
                "Channel": 11,
                "Security": "Open",
                "Encryption": "None",
                "Timestamp": "2026-10-01 12:30:00"
            }
        ]
        stub = _AlwaysLegitModel()
        with mock.patch("src.predict.load_models", return_value=(stub, stub)):
            with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
                results, _ = analyze_scanned_networks(scan, history_df=self.isolated_history)

        rogue = results[1]
        self.assertEqual(rogue["KNN_Pred"], "Legitimate")
        self.assertEqual(rogue["RF_Pred"], "Legitimate")
        self.assertEqual(rogue["Classification"], STATUS_HIGH_RISK)
        self.assertIn("override", rogue["FinalDecision"].lower())

    # ------------------------------------------------------------------
    # Test 9: Multiple legitimate APs sharing the same SSID
    # ------------------------------------------------------------------
    def test_09_multiple_legitimate_aps_same_ssid(self):
        # Case A: Known Enterprise multi-AP deployment
        campus_scan = [
            {
                "SSID": "Vardhaman_Campus",
                "BSSID": "18:64:72:a1:01:01",
                "Signal": 78,
                "Channel": 1,
                "Security": "WPA2-Enterprise",
                "Encryption": "CCMP",
                "Timestamp": "2026-10-01 12:35:00"
            },
            {
                "SSID": "Vardhaman_Campus",
                "BSSID": "18:64:72:a1:01:02",
                "Signal": 72,
                "Channel": 6,
                "Security": "WPA2-Enterprise",
                "Encryption": "CCMP",
                "Timestamp": "2026-10-01 12:35:00"
            }
        ]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            res_campus, _ = analyze_scanned_networks(campus_scan, history_df=self.isolated_history)
        for r in res_campus:
            self.assertEqual(r["Classification"], STATUS_KNOWN_CONSISTENT)
            self.assertNotEqual(r["Classification"], STATUS_HIGH_RISK)

        # Case B: Dual-band home router (new, not in history)
        dual_scan = [
            {
                "SSID": "SHIVA",
                "BSSID": "16:32:51:69:ea:62",
                "Signal": 92,
                "Channel": 6,
                "Security": "WPA2-Personal",
                "Encryption": "CCMP",
                "Timestamp": "2026-10-01 12:36:00"
            },
            {
                "SSID": "SHIVA",
                "BSSID": "16:32:51:69:ea:63",
                "Signal": 96,
                "Channel": 44,
                "Security": "WPA2-Personal",
                "Encryption": "CCMP",
                "Timestamp": "2026-10-01 12:36:00"
            }
        ]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            res_dual, _ = analyze_scanned_networks(dual_scan, history_df=self.isolated_history)
        for r in res_dual:
            self.assertTrue(r["IsDualBand"])
            self.assertNotEqual(r["Classification"], STATUS_HIGH_RISK)
            self.assertEqual(r["Classification"], STATUS_NEW_UNVERIFIED)

    # ------------------------------------------------------------------
    # Test 10: Missing information -> unverified/uncertain, no fabrication
    # ------------------------------------------------------------------
    def test_10_missing_information_no_fabrication(self):
        scan = [{
            "SSID": "Incomplete_AP",
            "BSSID": "de:ad:be:ef:00:01",
            "Signal": None,
            "Channel": None,
            "Security": None,
            "Encryption": None,
            "Timestamp": "2026-10-01 12:40:00"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            results, _ = analyze_scanned_networks(scan, history_df=self.isolated_history)
        res = results[0]
        self.assertIn(res["Classification"], [STATUS_NEW_UNVERIFIED, STATUS_SUSPICIOUS])
        self.assertNotEqual(res["Classification"], STATUS_KNOWN_CONSISTENT)
        self.assertIsNone(res["Signal"])
        self.assertEqual(res["SignalDisplay"], "Unavailable")
        self.assertEqual(res["Channel"], "Unavailable")
        self.assertEqual(res["Security"], "Unavailable")
        self.assertIn("Signal", res["MissingFeatures"])
        self.assertIn("Channel", res["MissingFeatures"])
        self.assertIn("Security", res["MissingFeatures"])

    # ------------------------------------------------------------------
    # Test 11: First scan vs second scan consistency (no auto-trust)
    # ------------------------------------------------------------------
    def test_11_first_vs_second_scan_no_auto_trust(self):
        scan = [{
            "SSID": "LivingRoom_WiFi",
            "BSSID": "50:d4:f7:11:22:33",
            "Signal": 80,
            "Channel": 6,
            "Security": "WPA2-Personal",
            "Encryption": "CCMP",
            "Timestamp": "2026-10-01 13:00:00"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            res1, safer1 = analyze_scanned_networks(scan, history_df=self.isolated_history)
            self.assertEqual(res1[0]["Classification"], STATUS_NEW_UNVERIFIED)
            self.assertEqual(safer1, [])

            hist2 = update_history(scan, self.temp_hist_path, assessments=res1)
            rec = get_ap_record(hist2, "LivingRoom_WiFi", "50:d4:f7:11:22:33")
            self.assertEqual(int(rec["Observation Count"]), 1)
            self.assertEqual(rec["Trust Status"], TRUST_UNVERIFIED)

            # Second scan of identical unverified AP MUST NOT flip to KNOWN / CONSISTENT!
            res2, safer2 = analyze_scanned_networks(scan, history_df=hist2)
            self.assertEqual(res2[0]["Classification"], STATUS_NEW_UNVERIFIED)
            self.assertEqual(safer2, [])

    # ------------------------------------------------------------------
    # Test 12: History poisoning / incorrect previous classification
    # ------------------------------------------------------------------
    def test_12_history_poisoning_still_reevaluated(self):
        # Simulate a poisoned history row where an Open Evil Twin of TestWiFi
        # was erroneously saved as TRUSTED_BASELINE & KNOWN / CONSISTENT.
        poisoned_df = self.isolated_history.copy()
        poisoned_row = pd.DataFrame([{
            "SSID": "TestWiFi",
            "BSSID": "ee:ee:ee:99:88:77",
            "Security": "Open",
            "Encryption": "None",
            "Channel": "11",
            "Band": "2.4 GHz",
            "Signal": "92",
            "Last Signal": "92",
            "Last Channel": "11",
            "Last Security": "Open",
            "OUI": "ee:ee:ee",
            "Fingerprint": "poisoned",
            "First Seen": "2026-09-20 10:00:00",
            "Last Seen": "2026-09-21 10:00:00",
            "Observation Count": 15,
            "Previous Classification": STATUS_KNOWN_CONSISTENT,
            "Trust Status": TRUST_ESTABLISHED,
            "Suspicious Indicators": "",
            "Changes": ""
        }], columns=HISTORY_COLUMNS)
        poisoned_df = pd.concat([poisoned_df, poisoned_row], ignore_index=True)

        scan = [{
            "SSID": "TestWiFi",
            "BSSID": "ee:ee:ee:99:88:77",
            "Signal": 92,
            "Channel": 11,
            "Security": "Open",
            "Encryption": "None",
            "Timestamp": "2026-10-01 13:10:00"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            results, safer = analyze_scanned_networks(scan, history_df=poisoned_df)
        res = results[0]
        self.assertIn(res["Classification"], [STATUS_SUSPICIOUS, STATUS_HIGH_RISK])
        self.assertNotEqual(res["Classification"], STATUS_KNOWN_CONSISTENT)
        self.assertEqual(safer, [])

    # ------------------------------------------------------------------
    # Additional Robustness Tests: Scanner, Corruption, Models, Captive Portal
    # ------------------------------------------------------------------
    def test_13_netsh_parser_unicode_multibssid_and_missing_fields(self):
        sample_output = (
            "Interface name : Wi-Fi\n"
            "There are 2 networks currently visible.\n\n"
            "SSID 1 : Café_WiFi_☕\n"
            "    Network type            : Infrastructure\n"
            "    Authentication          : WPA2-Personal\n"
            "    Encryption              : CCMP\n"
            "    BSSID 1                 : AA-BB-CC-11-22-33\n"
            "         Signal             : 84%\n"
            "         Radio type         : 802.11ac\n"
            "         Band               : 5 GHz\n"
            "         Channel            : 44\n"
            "    BSSID 2                 : AA:BB:CC:11:22:32\n"
            "         Radio type         : 802.11n\n"
            "\n"
            "SSID 2 :\n"
            "    Network type            : Infrastructure\n"
            "    Authentication          : Open\n"
            "    Encryption              : None\n"
            "    BSSID 1                 : 12:34:56:78:9a:bc\n"
            "         Signal             : 60%\n"
            "         Channel            : 6\n"
        )
        parsed = parse_netsh_output(sample_output, timestamp="2026-10-01 14:00:00")
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0]["SSID"], "Café_WiFi_☕")
        self.assertEqual(parsed[0]["BSSID"], "aa:bb:cc:11:22:33")
        self.assertEqual(parsed[0]["Signal"], 84)
        self.assertEqual(parsed[0]["Channel"], 44)
        # BSSID 2 omitted Signal and Channel -> MUST remain None (not fabricated!)
        self.assertIsNone(parsed[1]["Signal"])
        self.assertIsNone(parsed[1]["Channel"])
        self.assertEqual(parsed[2]["SSID"], "<Hidden Network>")
        self.assertTrue(parsed[2]["IsHidden"])

    def test_14_scanner_failure_not_treated_as_empty_safe(self):
        failed_proc = mock.MagicMock(returncode=1, stdout=b"", stderr=b"The WLAN AutoConfig service has not started.")
        with mock.patch("subprocess.run", return_value=failed_proc):
            res = scan_wifi_detailed()
        self.assertFalse(res["success"])
        self.assertIsNotNone(res["error"])
        self.assertEqual(res["networks"], [])

    def test_15_corrupted_history_and_missing_models_resilience(self):
        corrupt_path = os.path.join(self.temp_dir.name, "corrupt_history.csv")
        with open(corrupt_path, "w", encoding="utf-8") as f:
            f.write("%%INVALID_CSV_DATA$$\n123,456\nfoo,bar,baz\n")
        df = load_history(corrupt_path)
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(list(df.columns), HISTORY_COLUMNS)

        with open(corrupt_path, "w", encoding="utf-8") as f:
            f.write("")
        df_empty = load_history(corrupt_path)
        self.assertTrue(df_empty.empty)
        self.assertEqual(list(df_empty.columns), HISTORY_COLUMNS)

        non_existent_paths = {
            "knn": os.path.join(self.temp_dir.name, "missing_knn.pkl"),
            "random_forest": os.path.join(self.temp_dir.name, "missing_rf.pkl")
        }
        with mock.patch("src.predict.get_model_paths", return_value=non_existent_paths):
            with self.assertRaises(FileNotFoundError):
                load_models()

    def test_16_saved_profile_does_not_blindly_trust_unfamiliar_bssid(self):
        # Even if 'CoffeeShop' is a saved Windows profile, an unknown BSSID must NOT
        # be auto-trusted as KNOWN / CONSISTENT!
        scan = [{
            "SSID": "SavedOfficeWiFi",
            "BSSID": "99:88:77:66:55:44",
            "Signal": 90,
            "Channel": 6,
            "Security": "Open",
            "Encryption": "None",
            "Timestamp": "2026-10-01 14:15:00"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={"SavedOfficeWiFi": {"name": "SavedOfficeWiFi"}}):
            with mock.patch("src.predict.get_profile_security_details", return_value={"Authentication": "WPA2-Enterprise", "Cipher": "CCMP", "PMF_Enabled": False}):
                results, safer = analyze_scanned_networks(scan, history_df=self.isolated_history)
        self.assertEqual(results[0]["Classification"], STATUS_SUSPICIOUS)
        self.assertEqual(safer, [])

    def test_17_scanner_empty_and_invalid_output_and_ml_confidence(self):
        self.assertEqual(parse_netsh_output(""), [])
        self.assertEqual(parse_netsh_output("Random invalid text\nNo SSID headers here"), [])

        scan = [{
            "SSID": "TP-Link_6790",
            "BSSID": "0c:ef:15:e8:67:90",
            "Signal": 80,
            "Channel": 3,
            "Security": "WPA2-Personal",
            "Encryption": "CCMP",
            "Timestamp": "2026-10-01 14:20:00"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            results, _ = analyze_scanned_networks(scan, history_df=self.isolated_history)
        # Real models support predict_proba -> numeric confidence between 0 and 100
        self.assertIsNotNone(results[0]["KNN_Confidence"])
        self.assertIsNotNone(results[0]["RF_Confidence"])
        self.assertEqual(results[0]["SignalDisplay"], "80%")

    def test_18_shiva_home_wifi_regression_wpa2_ccmp_no_false_positive(self):
        """
        Exact regression test reproducing the SHIVA false positive:
        SSID=SHIVA, BSSID=16:32:51:69:ea:63, Signal=100%, Channel=44,
        Security=WPA2-Personal, Encryption=CCMP, with saved Windows profile
        reporting WPA3-Personal or WPA2-Personal across repeated scans.
        """
        shiva_scan = [{
            "SSID": "SHIVA",
            "BSSID": "16:32:51:69:ea:63",
            "Signal": 100,
            "Channel": 44,
            "Band": "5 GHz",
            "Security": "WPA2-Personal",
            "Encryption": "CCMP",
            "Radio": "802.11ac",
            "Timestamp": "2026-11-26 14:09:01"
        }]
        # Pre-seed 13 unverified observations like real network_history.csv
        for _ in range(3):
            update_history(shiva_scan, self.temp_hist_path)

        for prof_auth in [None, "WPA2-Personal", "WPA3-Personal", "WPA2/WPA3-Personal"]:
            profs = {"SHIVA": {"name": "SHIVA"}} if prof_auth else {}
            pdet = {"Authentication": prof_auth, "Cipher": "CCMP", "PMF_Enabled": False} if prof_auth else {}
            with mock.patch("src.predict.get_saved_windows_profiles", return_value=profs):
                with mock.patch("src.predict.get_profile_security_details", return_value=pdet):
                    for _ in range(3):
                        hist_df = load_history(self.temp_hist_path)
                        results, _ = analyze_scanned_networks(shiva_scan, history_df=hist_df)
                        res = results[0]
                        self.assertNotEqual(res["Classification"], STATUS_HIGH_RISK)
                        self.assertEqual(res["Classification"], STATUS_NEW_UNVERIFIED)
                        self.assertEqual(res["RiskScore"], 0)
                        self.assertNotIn("Security mismatch", str(res["WarningIndicators"]))
                        update_history(shiva_scan, self.temp_hist_path, assessments=results)

    def test_19_mobile_hotspot_strong_signal_and_new_ap(self):
        hotspot_scan = [
            {
                "SSID": "MyPhone_Hotspot",
                "BSSID": "da:a1:19:44:55:66",
                "Signal": 100,
                "Channel": 149,
                "Band": "5 GHz",
                "Security": "WPA3-Personal",
                "Encryption": "CCMP"
            },
            {
                "SSID": "AndroidAP_100",
                "BSSID": "02:11:22:33:44:55",
                "Signal": 99,
                "Channel": 6,
                "Band": "2.4 GHz",
                "Security": "WPA2-Personal",
                "Encryption": "CCMP"
            }
        ]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            results, _ = analyze_scanned_networks(hotspot_scan, history_df=self.isolated_history)
        for res in results:
            self.assertEqual(res["Classification"], STATUS_NEW_UNVERIFIED)
            self.assertEqual(res["RiskScore"], 0)

    def test_20_mesh_repeater_college_and_nonconsecutive_dualband(self):
        # A. Legitimate Mesh Wi-Fi (mixed OUIs, matching WPA2-Personal / CCMP)
        mesh_scan = [
            {"SSID": "HomeMesh", "BSSID": "a0:b1:c2:00:00:01", "Signal": 90, "Channel": 36, "Security": "WPA2-Personal", "Encryption": "CCMP"},
            {"SSID": "HomeMesh", "BSSID": "a0:b1:c2:00:00:02", "Signal": 65, "Channel": 36, "Security": "WPA2-Personal", "Encryption": "CCMP"},
            {"SSID": "HomeMesh", "BSSID": "d4:e5:f6:00:00:03", "Signal": 52, "Channel": 6, "Security": "WPA2-Personal", "Encryption": "CCMP"}
        ]
        # B. Legitimate College Wi-Fi (WPA2-Personal multi-AP same OUI)
        college_scan = [
            {"SSID": "College_Main", "BSSID": "00:1a:2b:11:22:01", "Signal": 82, "Channel": 1, "Security": "WPA2-Personal", "Encryption": "CCMP"},
            {"SSID": "College_Main", "BSSID": "00:1a:2b:11:22:02", "Signal": 70, "Channel": 6, "Security": "WPA2-Personal", "Encryption": "CCMP"}
        ]
        # C. Dual-band router with non-consecutive MAC offset (e.g., +8)
        dual_scan = [
            {"SSID": "AsusHome", "BSSID": "2c:fd:a1:10:20:30", "Signal": 95, "Channel": 6, "Security": "WPA2-Personal", "Encryption": "CCMP"},
            {"SSID": "AsusHome", "BSSID": "2c:fd:a1:10:20:38", "Signal": 92, "Channel": 149, "Security": "WPA2-Personal", "Encryption": "CCMP"}
        ]
        # D. Repeater on verified SSID TP-Link_6790 (same WPA2 security, new BSSID)
        repeater_scan = [
            {"SSID": "TP-Link_6790", "BSSID": "0c:ef:15:e8:67:90", "Signal": 60, "Channel": 3, "Security": "WPA2-Personal", "Encryption": "CCMP"},
            {"SSID": "TP-Link_6790", "BSSID": "b0:be:76:aa:bb:cc", "Signal": 96, "Channel": 3, "Security": "WPA2-Personal", "Encryption": "CCMP"}
        ]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            for sc in (mesh_scan, college_scan, dual_scan):
                res, _ = analyze_scanned_networks(sc, history_df=self.isolated_history)
                for r in res:
                    self.assertEqual(r["Classification"], STATUS_NEW_UNVERIFIED)
                    self.assertNotEqual(r["Classification"], STATUS_HIGH_RISK)

            rep_res, _ = analyze_scanned_networks(repeater_scan, history_df=self.isolated_history)
            self.assertEqual(rep_res[0]["Classification"], STATUS_KNOWN_CONSISTENT)
            self.assertEqual(rep_res[1]["Classification"], STATUS_SUSPICIOUS)
            self.assertNotEqual(rep_res[1]["Classification"], STATUS_HIGH_RISK)

    def test_21_security_text_normalization_and_mixed_mode(self):
        self.assertEqual(normalize_security_label("WPA2-Personal / CCMP"), "WPA2-Personal")
        self.assertEqual(normalize_security_label("WPA2PSK"), "WPA2-Personal")
        self.assertEqual(normalize_security_label("WPA2/WPA3-Personal"), "WPA2/WPA3-Personal")
        self.assertEqual(classify_security_comparison("WPA2-Personal / CCMP", None, {"WPA2-Personal"}), "MATCH")
        self.assertEqual(classify_security_comparison("WPA2-Personal", "CCMP", {"WPA2/WPA3-Personal"}), "MATCH")
        self.assertEqual(classify_security_comparison("Open", "None", {"WPA2-Personal"}, {"CCMP"}), "DOWNGRADE_CRITICAL")
        self.assertEqual(classify_security_comparison("WPA2-Personal", "TKIP", {"WPA2-Personal"}, {"CCMP"}), "DOWNGRADE_CRITICAL")
        self.assertEqual(classify_security_comparison("WPA2-Personal", "CCMP", {"WPA3-Personal"}), "SHIFT_MODERATE")

    def test_22_missing_fields_zero_risk_points_and_uncertainty(self):
        scan = [{
            "SSID": "Partial_AP",
            "BSSID": "aa:11:22:33:44:55",
            "Signal": None,
            "Channel": None,
            "Security": None,
            "Encryption": None
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            results, _ = analyze_scanned_networks(scan, history_df=self.isolated_history)
        res = results[0]
        self.assertEqual(res["Classification"], STATUS_SUSPICIOUS)  # UNVERIFIED NETWORK AND UNSAFE when Security is unavailable
        self.assertEqual(res["RiskScore"], 0)
        self.assertIn("unavailable", res["FinalDecision"].lower())

        # When Security IS WPA2-Personal and only Signal/Channel are missing -> UNVERIFIED NETWORK BUT SAFE, RiskScore 0
        scan_secured = [{
            "SSID": "Partial_Secured_AP",
            "BSSID": "aa:11:22:33:44:56",
            "Signal": None,
            "Channel": None,
            "Security": "WPA2-Personal",
            "Encryption": "CCMP"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            results2, _ = analyze_scanned_networks(scan_secured, history_df=self.isolated_history)
        self.assertEqual(results2[0]["Classification"], STATUS_NEW_UNVERIFIED)
        self.assertEqual(results2[0]["RiskScore"], 0)

    def test_23_manual_verification_reversible_and_change_detection(self):
        home_ap = [{
            "SSID": "SHIVA",
            "BSSID": "16:32:51:69:ea:63",
            "Signal": 100,
            "Channel": 44,
            "Band": "5 GHz",
            "Security": "WPA2-Personal",
            "Encryption": "CCMP"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            res1, _ = analyze_scanned_networks(home_ap, history_df=self.isolated_history)
            self.assertEqual(res1[0]["Classification"], STATUS_NEW_UNVERIFIED)
            update_history(home_ap, self.temp_hist_path, assessments=res1)

            # Manual verification promotes to TRUSTED_BASELINE
            hist_verified = mark_ap_trusted("SHIVA", "16:32:51:69:ea:63", self.temp_hist_path)
            rec = get_ap_record(hist_verified, "SHIVA", "16:32:51:69:ea:63")
            self.assertEqual(rec["Verified"], "Yes")
            self.assertTrue(bool(rec["Verified Fingerprint"]))

            res2, _ = analyze_scanned_networks(home_ap, history_df=hist_verified)
            self.assertEqual(res2[0]["Classification"], STATUS_KNOWN_CONSISTENT)

            # Significant fingerprint change on verified AP (downgraded to Open)
            altered_ap = [{
                "SSID": "SHIVA",
                "BSSID": "16:32:51:69:ea:63",
                "Signal": 100,
                "Channel": 11,
                "Band": "2.4 GHz",
                "Security": "Open",
                "Encryption": "None"
            }]
            res3, _ = analyze_scanned_networks(altered_ap, history_df=hist_verified)
            self.assertIn(res3[0]["Classification"], [STATUS_SUSPICIOUS, STATUS_HIGH_RISK])

            # Reversible verification
            hist_unverified = unverify_ap("SHIVA", "16:32:51:69:ea:63", self.temp_hist_path)
            rec_rev = get_ap_record(hist_unverified, "SHIVA", "16:32:51:69:ea:63")
            self.assertEqual(rec_rev["Verified"], "No")
            self.assertEqual(rec_rev["Trust Status"], TRUST_UNVERIFIED)

            res4, _ = analyze_scanned_networks(home_ap, history_df=hist_unverified)
            self.assertEqual(res4[0]["Classification"], STATUS_NEW_UNVERIFIED)

    def test_24_legitimate_ap_mislabelled_suspicious_in_history_reevaluated(self):
        # Simulate Test 26: Legitimate network previously flagged FLAGGED_SUSPICIOUS in history
        bad_hist = self.isolated_history.copy()
        row = pd.DataFrame([{
            "SSID": "HomeGoodAP",
            "BSSID": "11:aa:22:bb:33:cc",
            "Security": "WPA2-Personal",
            "Encryption": "CCMP",
            "Channel": "6",
            "Band": "2.4 GHz",
            "Signal": "85",
            "Last Signal": "85",
            "Last Channel": "6",
            "Last Security": "WPA2-Personal",
            "OUI": "11:aa:22",
            "Fingerprint": "fp",
            "First Seen": "2026-10-01 10:00:00",
            "Last Seen": "2026-10-01 10:05:00",
            "Observation Count": 2,
            "Previous Classification": STATUS_SUSPICIOUS,
            "Trust Status": TRUST_FLAGGED,
            "Verified": "No",
            "Verified At": "",
            "Verified Fingerprint": "",
            "Suspicious Indicators": "Prior false alarm",
            "Changes": ""
        }], columns=HISTORY_COLUMNS)
        bad_hist = pd.concat([bad_hist, row], ignore_index=True)

        scan = [{
            "SSID": "HomeGoodAP",
            "BSSID": "11:aa:22:bb:33:cc",
            "Signal": 85,
            "Channel": 6,
            "Band": "2.4 GHz",
            "Security": "WPA2-Personal",
            "Encryption": "CCMP"
        }]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            results, safer = analyze_scanned_networks(scan, history_df=bad_hist)
        # Re-evaluated cleanly: NOT HIGH RISK, NOT SUSPICIOUS, and NOT auto-promoted to SAFE
        self.assertEqual(results[0]["Classification"], STATUS_NEW_UNVERIFIED)
        self.assertEqual(results[0]["RiskScore"], 0)
        self.assertEqual(safer, [])

    def test_25_isolation_forest_and_gopu_home_weak_signal_no_false_positive(self):
        """Isolation Forest loads cleanly, supports unseen anomaly scoring, and never false-positives weak home routers."""
        iso_model = load_isolation_forest()
        self.assertIsNotNone(iso_model)

        # Simulate GOPU HOME with weak 10% signal and router auto-channel shift (1 -> 6)
        hist = pd.DataFrame([{
            "SSID": "GOPU HOME",
            "BSSID": "00:eb:d8:a9:20:3d",
            "OUI": "00:eb:d8",
            "Channel": 1,
            "Band": "2.4 GHz",
            "Last Signal": 10,
            "Last Channel": 1,
            "Security": "WPA2-Personal",
            "Encryption": "CCMP",
            "Last Security": "WPA2-Personal",
            "First Seen": "2026-11-26 14:00:00",
            "Last Seen": "2026-11-26 14:05:00",
            "Observation Count": 1,
            "Trust Status": TRUST_UNVERIFIED,
            "Previous Classification": STATUS_NEW_UNVERIFIED,
            "Last Risk Score": 0,
            "Suspicious Indicators": "",
            "Baseline Fingerprint": "00:eb:d8:a9:20:3d|WPA2-Personal|CCMP|1|2.4 GHz",
            "Last Fingerprint": "00:eb:d8:a9:20:3d|WPA2-Personal|CCMP|1|2.4 GHz",
            "Verified": "No",
            "Verified At": "",
            "Verified Fingerprint": ""
        }], columns=HISTORY_COLUMNS)

        scan = [
            {
                "SSID": "SHIVA",
                "BSSID": "16:32:51:69:ea:63",
                "Signal": 100,
                "Channel": 44,
                "Band": "5 GHz",
                "Security": "WPA2-Personal",
                "Encryption": "CCMP"
            },
            {
                "SSID": "Buddi ^_^",
                "BSSID": "0e:e1:ba:d6:12:8c",
                "Signal": 100,
                "Channel": 1,
                "Band": "2.4 GHz",
                "Security": "WPA2-Personal",
                "Encryption": "CCMP"
            },
            {
                "SSID": "GOPU HOME",
                "BSSID": "00:eb:d8:a9:20:3d",
                "Signal": 10,
                "Channel": 6,
                "Band": "2.4 GHz",
                "Security": "WPA2-Personal",
                "Encryption": "CCMP"
            }
        ]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            results, _ = analyze_scanned_networks(scan, history_df=hist)

        by_ssid = {r["SSID"]: r for r in results}
        self.assertEqual(by_ssid["SHIVA"]["IsoForest_Pred"], "Normal")
        self.assertEqual(by_ssid["SHIVA"]["Classification"], STATUS_NEW_UNVERIFIED)
        self.assertEqual(by_ssid["Buddi ^_^"]["IsoForest_Pred"], "Normal")
        self.assertEqual(by_ssid["Buddi ^_^"]["Classification"], STATUS_NEW_UNVERIFIED)
        self.assertEqual(by_ssid["GOPU HOME"]["Classification"], STATUS_NEW_UNVERIFIED)
        self.assertLess(by_ssid["GOPU HOME"]["RiskScore"], 25)

        # Synthetic Isolation Forest outlier alone adds +10 supporting points, never UNSAFE alone
        class _AlwaysAnomalyIso:
            def predict(self, X):
                return [-1] * len(X)
            def decision_function(self, X):
                return [-0.15] * len(X)

        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            with mock.patch("src.predict.load_models", return_value=(_AlwaysLegitModel(), _AlwaysLegitModel())):
                with mock.patch("src.predict.load_isolation_forest", return_value=_AlwaysAnomalyIso()):
                    anom_res, _ = analyze_scanned_networks([scan[0]], history_df=pd.DataFrame(columns=HISTORY_COLUMNS))
        self.assertEqual(anom_res[0]["IsoForest_Pred"], "Anomaly")
        self.assertEqual(anom_res[0]["RiskScore"], 10)
        self.assertEqual(anom_res[0]["Classification"], STATUS_NEW_UNVERIFIED)

    def test_26_dual_band_shiva_auto_channel_and_single_band_dropout(self):
        """Dual-band partner radios (2.4 GHz ea:62 + 5 GHz ea:63) never false-positive via ML or dropout."""
        hist = pd.DataFrame([
            {
                "SSID": "SHIVA",
                "BSSID": "16:32:51:69:ea:63",
                "Security": "WPA2-Personal",
                "Encryption": "CCMP",
                "Channel": 44,
                "Band": "5 GHz",
                "Signal": 100,
                "Last Signal": 100,
                "Last Channel": 44,
                "Last Security": "WPA2-Personal",
                "OUI": "16:32:51",
                "Fingerprint": "ssid=SHIVA|bssid=16:32:51:69:ea:63|oui=16:32:51|sec=WPA2-Personal|enc=CCMP|ch=44|band=5 GHz",
                "First Seen": "2026-10-17 12:57:33",
                "Last Seen": "2026-11-26 21:25:39",
                "Observation Count": 38,
                "Previous Classification": "SAFE",
                "Trust Status": TRUST_ESTABLISHED,
                "Verified": "Yes",
                "Verified At": "2026-11-26 14:33:34",
                "Verified Fingerprint": "ssid=SHIVA|bssid=16:32:51:69:ea:63|oui=16:32:51|sec=WPA2-Personal|enc=CCMP|ch=44|band=5 GHz",
                "Suspicious Indicators": "",
                "Changes": ""
            },
            {
                "SSID": "SHIVA",
                "BSSID": "16:32:51:69:ea:62",
                "Security": "WPA2-Personal",
                "Encryption": "CCMP",
                "Channel": 6,
                "Band": "2.4 GHz",
                "Signal": 100,
                "Last Signal": 100,
                "Last Channel": 1,
                "Last Security": "WPA2-Personal",
                "OUI": "16:32:51",
                "Fingerprint": "ssid=SHIVA|bssid=16:32:51:69:ea:62|oui=16:32:51|sec=WPA2-Personal|enc=CCMP|ch=6|band=2.4 GHz",
                "First Seen": "2026-10-17 13:05:20",
                "Last Seen": "2026-11-26 21:25:39",
                "Observation Count": 5,
                "Previous Classification": "UNVERIFIED NETWORK BUT SAFE",
                "Trust Status": TRUST_UNVERIFIED,
                "Verified": "No",
                "Verified At": "",
                "Verified Fingerprint": "",
                "Suspicious Indicators": "",
                "Changes": ""
            }
        ], columns=HISTORY_COLUMNS)

        both_bands = [
            {"SSID": "SHIVA", "BSSID": "16:32:51:69:ea:62", "Signal": 100, "Channel": 1, "Band": "2.4 GHz", "Security": "WPA2-Personal", "Encryption": "CCMP"},
            {"SSID": "SHIVA", "BSSID": "16:32:51:69:ea:63", "Signal": 100, "Channel": 44, "Band": "5 GHz", "Security": "WPA2-Personal", "Encryption": "CCMP"},
        ]
        with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
            res_both, _ = analyze_scanned_networks(both_bands, history_df=hist)
            by_bssid = {r["BSSID"]: r for r in res_both}
            self.assertEqual(by_bssid["16:32:51:69:ea:63"]["Classification"], STATUS_KNOWN_CONSISTENT)
            self.assertEqual(by_bssid["16:32:51:69:ea:62"]["Classification"], STATUS_NEW_UNVERIFIED)
            self.assertEqual(by_bssid["16:32:51:69:ea:62"]["RiskScore"], 0)

            # Even if 5 GHz radio drops out of one scan, 2.4 GHz still correlates with verified 5 GHz partner
            res_single, _ = analyze_scanned_networks([both_bands[0]], history_df=hist)
            self.assertEqual(res_single[0]["Classification"], STATUS_NEW_UNVERIFIED)
            self.assertLess(res_single[0]["RiskScore"], 25)


class TestWebApplicationAndDatabase(unittest.TestCase):
    """
    End-to-end integration tests for Flask backend, SQLite persistence,
    alerts, history, report exports, and settings.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_eviltwin.db")
        self.hist_path = os.path.join(self.temp_dir.name, "network_history.csv")
        self.obs_path = os.path.join(self.temp_dir.name, "wifi_observations.csv")
        self.reports_dir = os.path.join(self.temp_dir.name, "Reports")

        # Seed one trusted baseline AP in isolated history
        update_history(
            [{
                "SSID": "TestWiFi",
                "BSSID": "00:14:22:01:23:45",
                "Channel": 1,
                "Band": "2.4 GHz",
                "Signal": 76,
                "Security": "WPA2-Personal",
                "Encryption": "CCMP",
                "Timestamp": "2026-09-01 10:00:00"
            }],
            self.hist_path,
            mark_trusted=True
        )

        from app import create_app
        self.app = create_app(
            db_path=self.db_path,
            history_path=self.hist_path,
            observations_path=self.obs_path,
            reports_dir=self.reports_dir
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_web_01_empty_dashboard_and_pages_load(self):
        for route in ["/", "/scanner", "/alerts", "/history", "/reports", "/settings"]:
            resp = self.client.get(route)
            self.assertEqual(resp.status_code, 200, f"GET {route} failed")

        dash = self.client.get("/").get_data(as_text=True)
        self.assertIn("No Wi-Fi Scans Performed Yet", dash)

    def test_web_02_scan_flow_alerts_details_history_and_reports(self):
        mock_scan_payload = {
            "success": True,
            "error": None,
            "networks": [
                {
                    "SSID": "TestWiFi",
                    "BSSID": "00:14:22:01:23:45",
                    "Signal": 78,
                    "Channel": 1,
                    "Band": "2.4 GHz",
                    "Security": "WPA2-Personal",
                    "Encryption": "CCMP",
                    "Radio": "802.11n"
                },
                {
                    "SSID": "TestWiFi",
                    "BSSID": "ee:dd:cc:11:22:33",
                    "Signal": 93,
                    "Channel": 6,
                    "Band": "2.4 GHz",
                    "Security": "Open",
                    "Encryption": "None",
                    "Radio": "802.11n"
                },
                {
                    "SSID": "NewGuestNet",
                    "BSSID": "11:22:33:44:55:66",
                    "Signal": 65,
                    "Channel": 11,
                    "Band": "2.4 GHz",
                    "Security": "WPA2-Personal",
                    "Encryption": "CCMP",
                    "Radio": "802.11ac"
                }
            ]
        }

        with mock.patch("app.scan_wifi_detailed", return_value=mock_scan_payload):
            with mock.patch("app.get_active_wifi_interface", return_value={"State": "disconnected"}):
                with mock.patch("src.predict.get_saved_windows_profiles", return_value={}):
                    resp = self.client.post("/api/scan")

        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertTrue(payload["success"])
        self.assertEqual(len(payload["results"]), 3)
        scan_id = payload["scan"]["id"]

        classifications = {r["bssid"]: r["classification"] for r in payload["results"]}
        self.assertEqual(classifications["00:14:22:01:23:45"], STATUS_KNOWN_CONSISTENT)
        self.assertEqual(classifications["ee:dd:cc:11:22:33"], STATUS_HIGH_RISK)
        self.assertEqual(classifications["11:22:33:44:55:66"], STATUS_NEW_UNVERIFIED)

        # Dashboard shows real stored counts (no longer empty state)
        dash_html = self.client.get("/").get_data(as_text=True)
        self.assertNotIn("No Wi-Fi Scans Performed Yet", dash_html)
        self.assertIn("TestWiFi", dash_html)

        # Network Details page works
        rogue_id = next(r["id"] for r in payload["results"] if r["bssid"] == "ee:dd:cc:11:22:33")
        det_resp = self.client.get(f"/network/{rogue_id}")
        self.assertEqual(det_resp.status_code, 200)
        det_html = det_resp.get_data(as_text=True)
        self.assertIn("CLASSIFICATION: UNSAFE", det_html)
        self.assertIn("Current Fingerprint", det_html)

        # Alerts generated for rogue AP and can be acknowledged
        alerts_html = self.client.get("/alerts").get_data(as_text=True)
        self.assertIn("ee:dd:cc:11:22:33", alerts_html)
        from src.db_manager import get_alerts
        alerts_list = get_alerts(db_path=self.db_path)
        self.assertGreaterEqual(len(alerts_list), 1)
        ack_resp = self.client.post(
            f"/api/alerts/{alerts_list[0]['id']}/ack",
            json={"acknowledged": True}
        )
        self.assertEqual(ack_resp.status_code, 200)
        self.assertTrue(ack_resp.get_json()["success"])

        # History persistence check across a brand-new Flask app instance
        from app import create_app
        app2 = create_app(
            db_path=self.db_path,
            history_path=self.hist_path,
            observations_path=self.obs_path,
            reports_dir=self.reports_dir
        )
        client2 = app2.test_client()
        hist_html = client2.get("/history").get_data(as_text=True)
        self.assertIn("NewGuestNet", hist_html)
        scan_det = client2.get(f"/history/scan/{scan_id}")
        self.assertEqual(scan_det.status_code, 200)

        # Report exports (CSV, Printable HTML, History CSV)
        csv_resp = self.client.get(f"/reports/export/csv/{scan_id}")
        self.assertEqual(csv_resp.status_code, 200)
        self.assertIn("ee:dd:cc:11:22:33", csv_resp.get_data(as_text=True))

        html_rep = self.client.get(f"/reports/export/html/{scan_id}")
        self.assertEqual(html_rep.status_code, 200)
        self.assertIn("Evil Twin Wi-Fi Attack Detection System", html_rep.get_data(as_text=True))

        hist_csv_resp = self.client.get("/reports/export/history-csv")
        self.assertEqual(hist_csv_resp.status_code, 200)
        self.assertIn("NewGuestNet", hist_csv_resp.get_data(as_text=True))
        self.assertTrue(any(f.endswith(".csv") for f in os.listdir(self.reports_dir)))
        self.assertTrue(any(f.endswith(".html") for f in os.listdir(self.reports_dir)))

    def test_web_03_failed_scan_and_settings_and_manual_trust(self):
        failed_payload = {"success": False, "error": "WLAN AutoConfig service stopped.", "networks": []}
        with mock.patch("app.scan_wifi_detailed", return_value=failed_payload):
            with mock.patch("app.get_active_wifi_interface", return_value={"State": "disconnected"}):
                resp = self.client.post("/api/scan")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertIn("WLAN AutoConfig", data["error"])

        # Update settings
        post_set = self.client.post(
            "/settings",
            data={
                "action": "save_settings",
                "scan_timeout": "15",
                "suspicious_threshold": "30",
                "high_risk_threshold": "65",
                "auto_save_observations": "on"
            },
            follow_redirects=True
        )
        self.assertEqual(post_set.status_code, 200)
        self.assertIn("Settings saved successfully", post_set.get_data(as_text=True))

        # Manual trust & reversible untrust endpoints
        trust_resp = self.client.post(
            "/api/network/trust",
            json={"ssid": "TestWiFi", "bssid": "00:14:22:01:23:45"}
        )
        self.assertEqual(trust_resp.status_code, 200)
        self.assertTrue(trust_resp.get_json()["success"])

        untrust_resp = self.client.post(
            "/api/network/untrust",
            json={"ssid": "TestWiFi", "bssid": "00:14:22:01:23:45"}
        )
        self.assertEqual(untrust_resp.status_code, 200)
        self.assertTrue(untrust_resp.get_json()["success"])

    def test_web_04_unverified_network_labels_and_desktop_software_launcher(self):
        """Verifies exact user-facing labels and desktop software launcher helpers/icon."""
        self.assertEqual(STATUS_KNOWN_CONSISTENT, "SAFE")
        self.assertEqual(STATUS_NEW_UNVERIFIED, "UNVERIFIED NETWORK BUT SAFE")
        self.assertEqual(STATUS_SUSPICIOUS, "UNVERIFIED NETWORK AND UNSAFE")
        self.assertEqual(STATUS_HIGH_RISK, "UNSAFE")

        scanner_html = self.client.get("/scanner").get_data(as_text=True)
        self.assertIn("UNVERIFIED NETWORK BUT SAFE", scanner_html)
        self.assertIn("UNVERIFIED NETWORK AND UNSAFE", scanner_html)

        import importlib.util
        launcher_path = os.path.join(BASE_DIR, "EvilTwinDetector.pyw")
        spec = importlib.util.spec_from_file_location("EvilTwinDetector", launcher_path)
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)

        tmp_ico = os.path.join(self.temp_dir.name, "test_icon.ico")
        out_ico = launcher.ensure_app_icon(tmp_ico)
        self.assertTrue(os.path.exists(out_ico))
        self.assertGreater(os.path.getsize(out_ico), 200)
        self.assertFalse(launcher.is_server_alive("http://127.0.0.1:59999/api/dashboard", timeout=0.2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
