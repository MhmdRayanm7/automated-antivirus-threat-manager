import unittest

from security_threats import RansomwareVirus, SpywareVirus
from scanning_engine import ScanningEngine, SystemCompromisedError


class TestThreatClasses(unittest.TestCase):
    """
    Tests threat classes.
    in: None
    out: test results
    """

    def test_danger_score_valid_update(self):
        """
        in: None
        out: None
        """
        threat = RansomwareVirus("locker.exe", 500, 40, "C:/Windows/System32")

        threat.danger_score = 60

        self.assertEqual(threat.danger_score, 60)

    def test_danger_score_out_of_range_raises_value_error(self):
        """
        in: None
        out: None
        """
        threat = RansomwareVirus("locker.exe", 500, 40, "C:/Windows/System32")

        with self.assertRaises(ValueError):
            threat.danger_score = 150

    def test_private_danger_score_cannot_be_changed_directly(self):
        """
        in: None
        out: None
        """
        threat = RansomwareVirus("locker.exe", 500, 40, "C:/Windows/System32")

        threat.__danger_score = 99

        self.assertEqual(threat.danger_score, 40)

    def test_ransomware_risk_for_system32(self):
        """
        in: None
        out: None
        """
        threat = RansomwareVirus("locker.exe", 500, 40, "C:/Windows/System32")

        risk = threat.assess_risk_level()

        self.assertEqual(risk, 100)

    def test_spyware_risk_with_passwords_and_network(self):
        """
        in: None
        out: None
        """
        threat = SpywareVirus("keylogger.exe", 300, 50, "passwords", True)

        risk = threat.assess_risk_level()

        self.assertAlmostEqual(risk, 170)


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
        engine = ScanningEngine(500)

        engine.add_threat(RansomwareVirus("locker.exe", 500, 40, "C:/Windows/System32"))
        engine.add_threat(SpywareVirus("keylogger.exe", 300, 50, "passwords", True))

        total_risk = engine.scan()

        self.assertAlmostEqual(total_risk, 270)

    def test_engine_raises_system_compromised_error(self):
        """
        in: None
        out: None
        """
        engine = ScanningEngine(100)

        engine.add_threat(SpywareVirus("keylogger.exe", 300, 50, "passwords", True))

        with self.assertRaises(SystemCompromisedError):
            engine.scan()


if __name__ == "__main__":
    unittest.main()