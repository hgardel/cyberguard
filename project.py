import re
from collections import Counter


LOG_PATTERN = re.compile(
    r"(?P<date>\S+)\s+"
    r"(?P<time>\S+)\s+"
    r"(?P<event>SUCCESS_LOGIN|FAILED_LOGIN)\s+"
    r"user=(?P<user>\S+)\s+"
    r"ip=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def _valid_ipv4(ip):
    parts = ip.split(".")
    return len(parts) == 4 and all(
        part.isdigit()
        and not (len(part) > 1 and part.startswith("0"))
        and 0 <= int(part) <= 255
        for part in parts
    )


def parse_log(line):
    """Parse one supported security log entry."""
    match = LOG_PATTERN.fullmatch(line.strip())
    if match is None:
        return None

    data = match.groupdict()
    if not _valid_ipv4(data["ip"]):
        return None

    return data


def count_failed_logins(logs):
    """Count failed login attempts for each IP address."""
    return Counter(
        log["ip"]
        for log in logs
        if log and log["event"] == "FAILED_LOGIN"
    )


def detect_brute_force(logs, threshold=3):
    """Return IP addresses with at least threshold failed attempts."""
    counts = count_failed_logins(logs)
    return [ip for ip, attempts in counts.items() if attempts >= threshold]


def get_severity(attempts):
    """Classify failed-login activity by severity."""
    if attempts >= 5:
        return "HIGH"
    if attempts >= 3:
        return "MEDIUM"
    return "LOW"


def generate_report(logs):
    """Build the security report for parsed log entries."""
    valid_logs = [log for log in logs if log]
    successful = sum(log["event"] == "SUCCESS_LOGIN" for log in valid_logs)
    failed = sum(log["event"] == "FAILED_LOGIN" for log in valid_logs)
    counts = count_failed_logins(valid_logs)
    suspicious = detect_brute_force(valid_logs)

    lines = [
        "",
        "===== CYBERGUARD SECURITY REPORT =====",
        f"Total events: {len(valid_logs)}",
        f"Successful logins: {successful}",
        f"Failed logins: {failed}",
        "",
        "Suspicious IP addresses:",
    ]

    if suspicious:
        for ip in suspicious:
            attempts = counts[ip]
            lines.append(
                f"- {ip}: {attempts} failed attempts [{get_severity(attempts)}]"
            )
    else:
        lines.append("No suspicious activity detected.")

    lines.append("=======================================")
    lines.append("")
    return "\n".join(lines)


def main():
    print("CyberGuard - Security Log Analyzer")
    print("Enter security logs one per line.")
    print("Type 'DONE' when finished.\n")

    logs = []
    while True:
        line = input("Log: ")
        if line.upper() == "DONE":
            break

        parsed = parse_log(line)
        if parsed is None:
            print("Invalid log format.")
            continue
        logs.append(parsed)

    if not logs:
        print("\nNo valid logs were provided.")
        return

    print(generate_report(logs))


if __name__ == "__main__":
    main()
