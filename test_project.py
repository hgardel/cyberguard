from project import (
    count_failed_logins,
    detect_brute_force,
    generate_report,
    get_severity,
    parse_log,
)


def test_parse_log():
    line = "2026-09-19 10:15:22 FAILED_LOGIN user=admin ip=192.168.1.10"
    result = parse_log(line)

    assert result["date"] == "2026-09-19"
    assert result["time"] == "10:15:22"
    assert result["event"] == "FAILED_LOGIN"
    assert result["user"] == "admin"
    assert result["ip"] == "192.168.1.10"


def test_invalid_log():
    assert parse_log("this is not a valid security log") is None


def test_invalid_event():
    line = "2026-09-19 10:15:22 UNKNOWN_EVENT user=admin ip=192.168.1.10"
    assert parse_log(line) is None


def test_invalid_ip_and_trailing_text():
    invalid_ips = (
        "999.1.1.1",
        "192.168.001.1",
        "192.168.1.256",
    )
    for ip in invalid_ips:
        line = f"2026-09-19 10:15:22 FAILED_LOGIN user=admin ip={ip}"
        assert parse_log(line) is None

    line = "2026-09-19 10:15:22 FAILED_LOGIN user=admin ip=192.168.1.10 junk"
    assert parse_log(line) is None


def test_count_failed_logins():
    logs = [
        {"event": "FAILED_LOGIN", "ip": "192.168.1.10"},
        {"event": "FAILED_LOGIN", "ip": "192.168.1.10"},
        {"event": "SUCCESS_LOGIN", "ip": "192.168.1.20"},
    ]
    result = count_failed_logins(logs)
    assert result["192.168.1.10"] == 2
    assert result["192.168.1.20"] == 0


def test_detect_brute_force():
    logs = [
        {"event": "FAILED_LOGIN", "ip": "10.0.0.1"},
        {"event": "FAILED_LOGIN", "ip": "10.0.0.1"},
        {"event": "FAILED_LOGIN", "ip": "10.0.0.1"},
        {"event": "SUCCESS_LOGIN", "ip": "10.0.0.2"},
    ]
    result = detect_brute_force(logs)
    assert "10.0.0.1" in result
    assert "10.0.0.2" not in result


def test_threshold():
    logs = [
        {"event": "FAILED_LOGIN", "ip": "10.0.0.1"},
        {"event": "FAILED_LOGIN", "ip": "10.0.0.1"},
        {"event": "FAILED_LOGIN", "ip": "10.0.0.1"},
    ]
    assert "10.0.0.1" in detect_brute_force(logs)


def test_get_severity():
    assert get_severity(1) == "LOW"
    assert get_severity(2) == "LOW"
    assert get_severity(3) == "MEDIUM"
    assert get_severity(4) == "MEDIUM"
    assert get_severity(5) == "HIGH"
    assert get_severity(10) == "HIGH"


def test_generate_report():
    logs = [
        {"event": "FAILED_LOGIN", "ip": "192.168.1.10"},
        {"event": "FAILED_LOGIN", "ip": "192.168.1.10"},
        {"event": "FAILED_LOGIN", "ip": "192.168.1.10"},
        {"event": "SUCCESS_LOGIN", "ip": "192.168.1.20"},
    ]
    report = generate_report(logs)
    assert "Total events: 4" in report
    assert "Successful logins: 1" in report
    assert "Failed logins: 3" in report
    assert "192.168.1.10" in report
    assert "3 failed attempts" in report
    assert "[MEDIUM]" in report


def test_high_severity_report():
    logs = [
        {"event": "FAILED_LOGIN", "ip": "10.0.0.5"},
        {"event": "FAILED_LOGIN", "ip": "10.0.0.5"},
        {"event": "FAILED_LOGIN", "ip": "10.0.0.5"},
        {"event": "FAILED_LOGIN", "ip": "10.0.0.5"},
        {"event": "FAILED_LOGIN", "ip": "10.0.0.5"},
    ]
    report = generate_report(logs)
    assert "10.0.0.5" in report
    assert "5 failed attempts" in report
    assert "[HIGH]" in report
