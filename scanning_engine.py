from pathlib import Path

from security_threats import Threat


class SystemCompromisedError(Exception):
    """
    Custom error for critical system risk.
    in: message
    out: exception object
    """

    pass


class ScanningEngine:
    """
    Antivirus scanning engine.
    in: risk_limit, report_file
    out: scanning engine object
    """

    def __init__(self, risk_limit: float = 250, report_file: str = "backup_report.txt"):
        """
        in: risk_limit, report_file
        out: None
        """
        if risk_limit <= 0:
            raise ValueError("Risk limit must be greater than zero.")

        self.risk_limit = float(risk_limit)
        self.report_file = Path(report_file)

        self.threats = []
        self.signatures = []
        self.scan_results = []
        self.total_risk = 0.0

    def add_threat(self, threat: Threat):
        """
        in: threat
        out: None
        """
        if not isinstance(threat, Threat):
            raise TypeError("Only Threat objects can be added.")

        self.threats.append(threat)

    def scan(self) -> float:
        """
        in: None
        out: total risk
        """
        self.total_risk = 0.0
        self.signatures = []
        self.scan_results = []

        try:
            for threat in self.threats:
                risk = threat.assess_risk_level()
                signature = threat.generate_signature()

                self.total_risk += risk
                self.signatures.append(signature)

                # Save clean scan data for reports and charts.
                self.scan_results.append({
                    "type": threat.__class__.__name__,
                    "filename": threat.filename,
                    "file_size_kb": threat.file_size_kb,
                    "risk": risk,
                    "signature": signature
                })

            if self.total_risk > self.risk_limit:
                raise SystemCompromisedError("System risk limit passed.")

        except SystemCompromisedError:
            raise

        else:
            return self.total_risk

        finally:
            self.write_backup_report()

    def write_backup_report(self):
        """
        in: None
        out: None
        """
        with self.report_file.open("w", encoding="utf-8") as file:
            file.write("Backup Threat Report\n")
            file.write("====================\n")
            file.write(f"Risk limit: {self.risk_limit}\n")
            file.write(f"Total threats: {len(self.threats)}\n")
            file.write(f"Total risk: {self.total_risk}\n\n")

            file.write("Threat signatures:\n")
            for signature in self.signatures:
                file.write(f"- {signature}\n")