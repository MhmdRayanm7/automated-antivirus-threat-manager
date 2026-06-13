from security_threats import Threat


class SystemCompromisedError(Exception):
    """
    System security error.
    in: error message
    out: exception object
    """

    pass


class ScanningEngine:
    """
    Antivirus scanning engine.
    in: risk_limit
    out: ScanningEngine object
    """

    def __init__(self, risk_limit=250):
        """
        in: risk_limit
        out: None
        """
        self.risk_limit = risk_limit
        self.threats = []
        self.signatures = []
        self.total_risk = 0

    def add_threat(self, threat):
        """
        in: threat
        out: None
        """
        if not isinstance(threat, Threat):
            raise TypeError("Only Threat objects can be added.")

        self.threats.append(threat)

    def scan(self):
        """
        in: None
        out: total risk
        """
        self.total_risk = 0
        self.signatures = []

        try:
            for threat in self.threats:
                risk = threat.assess_risk_level()
                signature = threat.generate_signature()

                self.total_risk += risk
                self.signatures.append(signature)

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
        with open("backup_report.txt", "w") as file:
            file.write("Backup Threat Report\n")
            file.write(f"Total threats: {len(self.threats)}\n")
            file.write(f"Total risk: {self.total_risk}\n")

            for signature in self.signatures:
                file.write(f"{signature}\n")