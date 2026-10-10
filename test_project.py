from project import (
    parse_log,
    count_failed_logins,
    detect_brute_force,
    get_severity,
    generate_report,
)


def test_parse_log():
    """Test parsing of a valid security log."""

    line = (
        "2026-09-19 10:15:22 "
        "FAILED_LOGIN user=admin ip=192.168.1.10"
    )

    result = parse_log(line)

    assert result["date"] == "2026-09-19"
    assert result["time"] == "10:15:22"
    assert result["event"] == "FAILED_LOGIN"
    assert result["user"] == "admin"
    assert result["ip"] == "192.168.1.10"


def test_invalid_log():
    """Test that an invalid log returns None."""

    result = parse_log("this is not a valid security log")

    assert result is None


def test_invalid_event():
    """Test that unsupported events are rejected."""

    line = (
        "2026-09-19 10:15:22 "
        "UNKNOWN_EVENT user=admin ip=192.168.1.10"
    )

    result = parse_log(line)

    assert result is None


def test_count_failed_logins():
    """Test counting failed login attempts by IP."""

    logs = [
        {
            "event": "FAILED_LOGIN",
            "ip": "192.168.1.10"
        },
        {
            "event": "FAILED_LOGIN",
            "ip": "192.168.1.10"
        },
        {
            "event": "SUCCESS_LOGIN",
            "ip": "192.168.1.20"
        }
    ]

    result = count_failed_logins(logs)

    assert result["192.168.1.10"] == 2
    assert result["192.168.1.20"] == 0


def test_detect_brute_force():
    """Test detection of an IP reaching the suspicious threshold."""

    logs = [
        {
            "event": "FAILED_LOGIN",
            "ip": "10.0.0.1"
        },
        {
            "event": "FAILED_LOGIN",
            "ip": "10.0.0.1"
        },
        {
            "event": "FAILED_LOGIN",
            "ip": "10.0.0.1"
        },
        {
            "event": "SUCCESS_LOGIN",
            "ip": "10.0.0.2"
        }
    ]

    result = detect_brute_force(logs)

    assert "10.0.0.1" in result
    assert "10.0.0.2" not in result


def test_threshold():
    """Test that exactly three failed attempts are suspicious."""

    logs = [
        {
            "event": "FAILED_LOGIN",
            "ip": "10.0.0.1"
        },
        {
            "event": "FAILED_LOGIN",
            "ip": "10.0.0.1"
        },
        {
            "event": "FAILED_LOGIN",
            "ip": "10.0.0.1"
        }
    ]

    result = detect_brute_force(logs)

    assert "10.0.0.1" in result


def test_severity():
    """Test severity levels based on failed attempts."""

    assert get_severity(1) == "LOW"
    assert get_severity(2) == "LOW"
    assert get_severity(3) == "MEDIUM"
    assert get_severity(4) == "MEDIUM"
    assert get_severity(5) == "HIGH"
    assert get_severity(10) == "HIGH"


def test_generate_report():
    """Test the generated security report."""

    logs = [
        {
            "event": "FAILED_LOGIN",
            "ip": "192.168.1.10"
        },
        {
            "event": "FAILED_LOGIN",
            "ip": "192.168.1.10"
        },
        {
            "event": "FAILED_LOGIN",
            "ip": "192.168.1.10"
        },
        {
            "event": "SUCCESS_LOGIN",
            "ip": "192.168.1.20"
        }
    ]

    report = generate_report(logs)

    assert "Total events: 4" in report
    assert "Successful logins: 1" in report
    assert "Failed logins: 3" in report
    assert "192.168.1.10" in report
    assert "3 failed attempts" in report
    assert "[MEDIUM]" in report


def test_high_severity_report():
    """Test that five or more attempts produce HIGH severity."""

    logs = [
        {
            "event": "FAILED_LOGIN",
            "ip": "10.0.0.5"
        },
        {
            "event": "FAILED_LOGIN",
            "ip": "10.0.0.5"
        },
        {
            "event": "FAILED_LOGIN",
            "ip": "10.0.0.5"
        },
        {
            "event": "FAILED_LOGIN",
            "ip": "10.0.0.5"
        },
        {
            "event": "FAILED_LOGIN",
            "ip": "10.0.0.5"
        }
    ]

    report = generate_report(logs)

    assert "10.0.0.5" in report
    assert "5 failed attempts" in report
    assert "[HIGH]" in report