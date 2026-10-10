# CyberGuard

CyberGuard is a command-line security log analyzer written in Python.

The program analyzes authentication logs, counts successful and failed login attempts, identifies IP addresses with multiple failed login attempts, and assigns a simple severity level to potentially suspicious activity.

CyberGuard was developed as a Python programming project to demonstrate concepts such as functions, regular expressions, loops, conditionals, lists, dictionaries, modules, automated testing, and basic security log analysis.

## Features

CyberGuard can:

* Parse authentication log entries
* Identify successful and failed login attempts
* Count failed login attempts by IP address
* Detect IP addresses with three or more failed login attempts
* Assign a severity level based on the number of failed attempts
* Generate a security report
* Handle invalid log entries
* Run automated tests using pytest

The severity system used by CyberGuard is:

* `LOW`: fewer than 3 failed attempts
* `MEDIUM`: 3 or 4 failed attempts
* `HIGH`: 5 or more failed attempts

These levels are simplified rules created for this project. A suspicious IP address is not necessarily a malicious or compromised system.

## Log Format

CyberGuard expects log entries in the following format:

```text
2026-09-19 10:15:22 FAILED_LOGIN user=admin ip=192.168.1.10
```

The supported events are:

* `FAILED_LOGIN`
* `SUCCESS_LOGIN`

Each entry contains:

* Date
* Time
* Event type
* Username
* IP address

The user can enter multiple log entries and type `DONE` when finished.

## Requirements

CyberGuard requires:

* Python 3
* pytest for running the automated tests

The main program only uses Python's standard library. No additional packages are required to run `project.py`.

## Installation

Clone or download the project and enter its directory.

A virtual environment can be created with:

```bash
python -m venv .venv
```

Activate it on Linux:

```bash
source .venv/bin/activate
```

Install pytest:

```bash
python -m pip install pytest
```

## Running CyberGuard

Run the program with:

```bash
python project.py
```

Enter security logs one per line.

Example:

```text
2026-09-19 10:15:22 FAILED_LOGIN user=admin ip=192.168.1.10
2026-09-19 10:16:01 FAILED_LOGIN user=admin ip=192.168.1.10
2026-09-19 10:16:43 FAILED_LOGIN user=admin ip=192.168.1.10
2026-09-19 10:17:10 SUCCESS_LOGIN user=huendell ip=192.168.1.20
DONE
```

CyberGuard produces a report similar to:

```text
===== CYBERGUARD SECURITY REPORT =====
Total events: 4
Successful logins: 1
Failed logins: 3

Suspicious IP addresses:
- 192.168.1.10: 3 failed attempts [MEDIUM]
=======================================
```

## Running the Tests

The project includes automated tests in `test_project.py`.

Run them with:

```bash
pytest
```

The test suite verifies:

* Valid log parsing
* Invalid log handling
* Unsupported event handling
* Failed login counting
* Brute-force detection
* Detection thresholds
* Severity classification
* Security report generation

## Project Structure

```text
cyberguard/
├── .gitignore
├── project.py
├── test_project.py
├── README.md
└── DESIGN.md
```

### `project.py`

Contains the main program and the functions responsible for parsing logs, analyzing failed login attempts, detecting suspicious activity, assigning severity levels, and generating the final report.

### `test_project.py`

Contains the automated tests for the functions implemented in `project.py`.

### `DESIGN.md`

Describes the technical design of CyberGuard and explains the main implementation decisions.

## Limitations

CyberGuard is an educational project and uses a simplified approach to security log analysis.

It does not:

* Monitor a live system
* Collect real authentication logs automatically
* Perform network monitoring
* Block IP addresses
* Confirm that an IP address belongs to an attacker
* Replace a SIEM or other security monitoring platform

The three-attempt threshold and severity levels are simple rules used to demonstrate how authentication data can be analyzed programmatically.
