# CyberGuard


#### Description:

CyberGuard is a command-line security log analyzer written in Python. It accepts authentication events entered by the user, validates each line, counts successful and failed login attempts, identifies IP addresses with repeated failed logins, assigns a simplified severity level, and prints a report. The project demonstrates text parsing, input validation, aggregation, functions, and automated testing. It is an educational exercise, not a production SIEM.

## Features

CyberGuard supports `FAILED_LOGIN` and `SUCCESS_LOGIN` events. Each accepted record contains a date, time, username, and IPv4 address. The program rejects malformed records, unsupported event names, invalid IPv4 octets, leading-zero octets, and extra text after a valid record. Valid events are collected until the user enters `DONE`, after which a summary is printed.

Failed login attempts are grouped by source IP. An address is reported as suspicious after three or more failed attempts. Severity labels are `LOW` for zero to two failures, `MEDIUM` for three or four, and `HIGH` for five or more. These labels are simple project-specific heuristics, not proof that an account or computer has been compromised.

## Input Format

Enter one record per line in this format:

```text
2026-09-19 10:15:22 FAILED_LOGIN user=admin ip=192.168.1.10
```

The supported event names are `FAILED_LOGIN` and `SUCCESS_LOGIN`. Type `DONE` when all records have been entered. Invalid lines are rejected and excluded from the report.

## Requirements

The application uses Python's standard library. Python 3 is required. `pytest` is needed only for the automated tests and can be installed with `python -m pip install pytest`.

## Installation and Usage

Clone or download the repository and enter the `CyberGuard` directory. A virtual environment is recommended:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python project.py
```

Run the automated tests with:

```bash
pytest
```

## Project Files

- `project.py` contains the command-line interface, parsing, IPv4 validation, counting, brute-force threshold, severity classification, and report generation.
- `test_project.py` tests valid and invalid input, unsupported events, IP validation, trailing text, failure counts, threshold detection, severity levels, and report output.
- `requirements.txt` lists the test dependency.
- `DESIGN.md` explains the architecture, validation rules, design decisions, and limitations.
- `.gitignore` excludes local Python caches and virtual-environment artifacts from version control.

## Design Choices

Parsing and analysis are split into functions so each behavior can be tested without interactive input. `parse_log()` uses a full-line regular expression, then validates the numeric range of each IPv4 octet. `count_failed_logins()` aggregates only failed events, while `detect_brute_force()` applies a configurable threshold. `get_severity()` keeps classification independent from report formatting. `generate_report()` returns a string instead of printing directly, making its output straightforward to assert in tests.

The accepted input format is intentionally narrow so validation is predictable and ambiguous lines are rejected. This also makes the program easier to extend with additional event types or reporting rules in a future version.

## Limitations

CyberGuard analyzes only records manually supplied during a session. It does not collect system logs, monitor network traffic, block connections, persist history, query threat intelligence, or determine whether an event was actually malicious. The thresholds are simplified rules and would need tuning and supporting context before real-world use. Date and time fields are kept as strings rather than validated as real calendar values, and usernames are not checked against real accounts.

