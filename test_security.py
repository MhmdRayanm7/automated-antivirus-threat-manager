import tempfile
import unittest
from pathlib import Path

from scanning_engine import ScanningEngine, SystemCompromisedError
from security_threats import RansomwareVirus, SpywareVirus


class TestThreatClasses(unittest.TestCase):
    """
    Tests threat classes.
    in: None
    out: test results
    """

    def test_valid_danger_score_update(self):
        """
        in: None
        out: None
        """
        threat = RansomwareVirus("locker.exe", 500, 40, "C:/Windows/System32")

        threat.danger_score = 60

        self.assertEqual(threat.danger_score, 60)

    def test_invalid_danger_score_raises_value_error(self):
        """
        in: None
        out: None
        """
        threat = RansomwareVirus("locker.exe", 500, 40, "C:/Windows/System32")

        with self.assertRaises(ValueError):
            threat.danger_score = 150

    def test_empty_filename_raises_value_error(self):
        """
        in: None
        out: None
        """
        with self.assertRaises(ValueError):
            RansomwareVirus("", 500, 40, "C:/Windows/System32")

    def test_private_danger_score_is_protected(self):
        """
        in: None
        out: None
        """
        threat = RansomwareVirus("locker.exe", 500, 40, "C:/Windows/System32")

        # This creates a new outside attribute, but does not change the private score.
        threat.__danger_score = 99

        self.assertEqual(threat.danger_score, 40)

    def test_ransomware_system32_risk(self):
        """
        in: None
        out: None
        """
        threat = RansomwareVirus("locker.exe", 500, 40, "C:/Windows/System32")

        risk = threat.assess_risk_level()

        self.assertAlmostEqual(risk, 100.0)

    def test_spyware_password_network_risk(self):
        """
        in: None
        out: None
        """
        threat = SpywareVirus("keylogger.exe", 300, 50, "passwords", True)

        risk = threat.assess_risk_level()

        self.assertAlmostEqual(risk, 170.0)


class TestScanningEngine(unittest.TestCase):
    """
    Tests scanning engine.
    in: None
    out: test results
    """

    def test_engine_scan_returns_total_risk(self):
        """
        in: None
        out: None
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "test_report.txt"
            engine = ScanningEngine(500, report_path)

            engine.add_threat(RansomwareVirus("locker.exe", 500, 40, "C:/Windows/System32"))
            engine.add_threat(SpywareVirus("keylogger.exe", 300, 50, "passwords", True))

            total_risk = engine.scan()

            self.assertAlmostEqual(total_risk, 270.0)
            self.assertEqual(len(engine.signatures), 2)
            self.assertEqual(len(engine.scan_results), 2)

    def test_engine_raises_system_compromised_error(self):
        """
        in: None
        out: None
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "test_report.txt"
            engine = ScanningEngine(100, report_path)

            engine.add_threat(SpywareVirus("keylogger.exe", 300, 50, "passwords", True))

            with self.assertRaises(SystemCompromisedError):
                engine.scan()

    def test_engine_writes_backup_report(self):
        """
        in: None
        out: None
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "test_report.txt"
            engine = ScanningEngine(500, report_path)

            engine.add_threat(RansomwareVirus("locker.exe", 500, 40, "C:/Windows/System32"))
            engine.scan()

            self.assertTrue(report_path.exists())
            self.assertIn("Backup Threat Report", report_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()