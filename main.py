from security_threats import RansomwareVirus, SpywareVirus
from scanning_engine import ScanningEngine, SystemCompromisedError


def create_sample_threats():
    """
    in: None
    out: list of threats
    """
    threats = [
        RansomwareVirus("locker.exe", 500, 40, "C:/Windows/System32"),
        RansomwareVirus("photo_encryptor.exe", 250, 25, "C:/Users/Pictures"),
        SpywareVirus("keylogger.exe", 300, 50, "passwords", True),
        SpywareVirus("cookie_reader.exe", 150, 30, "browser cookies", True)
    ]

    return threats


def run_scan():
    """
    in: None
    out: None
    """
    engine = ScanningEngine(500)
    threats = create_sample_threats()

    for threat in threats:
        engine.add_threat(threat)

    try:
        total_risk = engine.scan()
        print("Scan finished successfully.")
        print(f"Total risk: {total_risk}")

    except SystemCompromisedError as error:
        print("Critical scan warning.")
        print(error)

    print("Generated signatures:")
    for signature in engine.signatures:
        print(signature)


if __name__ == "__main__":
    run_scan()