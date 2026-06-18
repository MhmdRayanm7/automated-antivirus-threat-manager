import matplotlib.pyplot as plt

from security_threats import RansomwareVirus, SpywareVirus
from scanning_engine import ScanningEngine, SystemCompromisedError


def create_sample_threats():
    """
    in: None
    out: list of threats
    """
    return [
        RansomwareVirus("locker.exe", 500, 40, "C:/Windows/System32"),
        RansomwareVirus("photo_encryptor.exe", 250, 25, "C:/Users/Pictures"),
        SpywareVirus("keylogger.exe", 300, 50, "passwords", True),
        SpywareVirus("cookie_reader.exe", 150, 30, "browser cookies", True)
    ]


def print_scan_summary(engine):
    """
    in: engine
    out: None
    """
    print("Generated signatures:")

    for signature in engine.signatures:
        print(f"- {signature}")

    print("\nScan details:")

    for result in engine.scan_results:
        print(
            f"- {result['type']} | "
            f"{result['filename']} | "
            f"{result['file_size_kb']} KB | "
            f"risk={result['risk']}"
        )


def show_threat_chart(scan_results):
    """
    in: scan_results
    out: None
    """
    plt.figure(figsize=(10, 5))

    plt.subplot(1, 2, 1)

    for result in scan_results:
        marker = "x"

        if result["type"] == "SpywareVirus":
            marker = "^"

        plt.scatter(
            result["file_size_kb"],
            result["risk"],
            marker=marker,
            label=result["type"]
        )

    plt.title("Risk by File Size")
    plt.xlabel("File Size KB")
    plt.ylabel("Risk Score")
    plt.grid(True)

    plt.subplot(1, 2, 2)

    type_counts = {}

    for result in scan_results:
        threat_type = result["type"]
        type_counts[threat_type] = type_counts.get(threat_type, 0) + 1

    plt.bar(type_counts.keys(), type_counts.values())
    plt.title("Threat Type Count")
    plt.xlabel("Threat Type")
    plt.ylabel("Count")

    plt.tight_layout()
    plt.savefig("threat_report.png")
    plt.show()


def run_scan():
    """
    in: None
    out: None
    """
    engine = ScanningEngine(risk_limit=500)
    threats = create_sample_threats()

    for threat in threats:
        engine.add_threat(threat)

    try:
        total_risk = engine.scan()
        print("Scan finished successfully.")
        print(f"Total risk: {total_risk}\n")

    except SystemCompromisedError as error:
        print("Critical scan warning.")
        print(error)
        print()

    print_scan_summary(engine)
    show_threat_chart(engine.scan_results)


if __name__ == "__main__":
    run_scan()