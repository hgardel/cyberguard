import re
from collections import Counter


def parse_log(line):
    """Parse a security log line and return its information."""

    # The program accepts only the two login events used by CyberGuard.
    pattern = (
        r"(?P<date>\S+)\s+"
        r"(?P<time>\S+)\s+"
        r"(?P<event>SUCCESS_LOGIN|FAILED_LOGIN)\s+"
        r"user=(?P<user>\S+)\s+"
        r"ip=(?P<ip>\S+)"
    )

    match = re.search(pattern, line)

    # Return None when the input does not match the expected format.
    if not match:
        return None

    return match.groupdict()


def count_failed_logins(logs):
    """Count failed login attempts for each IP address."""

    failed_ips = []

    for log in logs:
        # Only failed login events are relevant to this analysis.
        if log and log["event"] == "FAILED_LOGIN":
            failed_ips.append(log["ip"])

    # Counter groups the IP addresses and counts their occurrences.
    return Counter(failed_ips)


def detect_brute_force(logs, threshold=3):
    """Return IP addresses with suspicious numbers of failed logins."""

    failed_logins = count_failed_logins(logs)

    suspicious_ips = []

    for ip, attempts in failed_logins.items():
        # Three or more failed attempts are treated as suspicious.
        if attempts >= threshold:
            suspicious_ips.append(ip)

    return suspicious_ips


def get_severity(attempts):
    """Return a severity level based on failed login attempts."""

    if attempts >= 5:
        return "HIGH"

    if attempts >= 3:
        return "MEDIUM"

    return "LOW"


def generate_report(logs):
    """Generate a security report from parsed log entries."""

    # Ignore invalid entries in case this function receives them.
    valid_logs = [log for log in logs if log]

    successful_logins = 0
    failed_logins = 0

    for log in valid_logs:
        if log["event"] == "SUCCESS_LOGIN":
            successful_logins += 1

        elif log["event"] == "FAILED_LOGIN":
            failed_logins += 1

    failed_by_ip = count_failed_logins(valid_logs)
    suspicious_ips = detect_brute_force(valid_logs)

    report = "\n===== CYBERGUARD SECURITY REPORT =====\n"
    report += f"Total events: {len(valid_logs)}\n"
    report += f"Successful logins: {successful_logins}\n"
    report += f"Failed logins: {failed_logins}\n"

    report += "\nSuspicious IP addresses:\n"

    if suspicious_ips:
        for ip in suspicious_ips:
            attempts = failed_by_ip[ip]
            severity = get_severity(attempts)

            report += (
                f"- {ip}: {attempts} failed attempts "
                f"[{severity}]\n"
            )
    else:
        report += "No suspicious activity detected.\n"

    report += "=======================================\n"

    return report


def main():
    """Run the CyberGuard security log analyzer."""

    print("CyberGuard - Security Log Analyzer")
    print("Enter security logs one per line.")
    print("Type 'DONE' when finished.\n")

    logs = []

    while True:
        line = input("Log: ")

        if line.upper() == "DONE":
            break

        parsed_log = parse_log(line)

        if parsed_log is None:
            print("Invalid log format.")
            continue

        logs.append(parsed_log)

    if not logs:
        print("\nNo valid logs were provided.")
        return

    print(generate_report(logs))


if __name__ == "__main__":
    main()