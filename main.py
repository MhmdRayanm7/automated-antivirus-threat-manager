import matplotlib.pyplot as plt

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


def show_threat_chart(threats):
    """
    in: threats
    out: None
    """
    plt.figure(figsize=(10, 5))

    plt.subplot(1, 2, 1)

    used_labels = []

    for threat in threats:
        risk = threat.assess_risk_level()

        if isinstance(threat, RansomwareVirus):
            label = "Ransomware"
            marker = "x"
        else:
            label = "Spyware"
            marker = "^"

        if label not in used_labels:
            plt.scatter(threat.file_size_kb, risk, marker=marker, label=label)
            used_labels.append(label)
        else:
            plt.scatter(threat.file_size_kb, risk, marker=marker)

    plt.title("Threat Risk by File Size")
    plt.xlabel("File Size KB")
    plt.ylabel("Risk Score")
    plt.grid(True)
    plt.legend()

    plt.subplot(1, 2, 2)

    ransomware_count = 0
    spyware_count = 0

    for threat in threats:
        if isinstance(threat, RansomwareVirus):
            ransomware_count += 1
        elif isinstance(threat, SpywareVirus):
            spyware_count += 1

    plt.bar(["Ransomware", "Spyware"], [ransomware_count, spyware_count], color=["red", "blue"])
    plt.title("Threat Types")
    plt.xlabel("Malware Family")
    plt.ylabel("Count")

    plt.tight_layout()
    plt.savefig("threat_report.png")
    plt.show()


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

    show_threat_chart(threats)


if __name__ == "__main__":
    run_scan()