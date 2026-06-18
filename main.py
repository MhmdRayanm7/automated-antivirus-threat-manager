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

    type_markers = {"RansomwareVirus": "x", "SpywareVirus": "^"}
    plotted_types = set()

    for result in scan_results:
        threat_type = result["type"]
        marker = type_markers.get(threat_type, "o")
        label = threat_type if threat_type not in plotted_types else None
        plotted_types.add(threat_type)

        plt.scatter(
            result["file_size_kb"],
            result["risk"],
            marker=marker,
            label=label
        )

    plt.title("Risk by File Size")
    plt.xlabel("File Size KB")
    plt.ylabel("Risk Score")
    plt.grid(True)
    plt.legend()

    plt.subplot(1, 2, 2)

    type_counts = {}

    for result in scan_results:
        threat_type = result["type"]
        type_counts[threat_type] = type_counts.get(threat_type, 0) + 1

    threat_types = list(type_counts.keys())
    type_colors = {"RansomwareVirus": "#e74c3c", "SpywareVirus": "#3498db"}
    bar_colors = [type_colors.get(threat_type, "#95a5a6") for threat_type in threat_types]

    plt.bar(threat_types, type_counts.values(), color=bar_colors)
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