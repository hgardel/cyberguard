# CyberGuard Design

## Overview

CyberGuard is a command-line security log analyzer written in Python.

The program receives authentication log entries from the user, parses the information contained in each entry, analyzes failed login attempts, identifies potentially suspicious IP addresses, assigns severity levels, and generates a security report.

The project was designed to keep the implementation simple while demonstrating practical Python programming concepts in a cybersecurity-related context.

## Program Structure

CyberGuard is organized into several functions, each responsible for a specific part of the analysis.

### `parse_log()`

The `parse_log()` function receives a log entry as a string.

It uses a regular expression to extract:

* Date
* Time
* Event type
* Username
* IP address

The regular expression only accepts the two event types supported by CyberGuard:

```text
SUCCESS_LOGIN
FAILED_LOGIN
```

If the input does not match the expected format, the function returns `None`.

This separates input parsing from the rest of the program and makes the parser independently testable.

## Counting Failed Logins

The `count_failed_logins()` function analyzes the parsed logs and counts failed login attempts for each IP address.

The function stores the IP addresses associated with failed login events and uses Python's `Counter` class from the `collections` module to count how many times each IP appears.

For example:

```text
192.168.1.10
192.168.1.10
192.168.1.20
```

produces counts equivalent to:

```text
192.168.1.10 → 2
192.168.1.20 → 1
```

This allows the program to analyze authentication activity by IP address without manually maintaining a counting dictionary.

## Suspicious Activity Detection

The `detect_brute_force()` function identifies IP addresses with a suspicious number of failed login attempts.

The default threshold is three failed attempts.

```text
3 or more failed attempts → suspicious
```

This is a simplified rule for the project. It does not prove that an attack occurred.

The function accepts the threshold as an argument, which allows the detection rule to be changed without modifying the function's internal logic.

## Severity Classification

The `get_severity()` function assigns a severity level based on the number of failed login attempts.

The rules are:

```text
0-2 attempts → LOW
3-4 attempts → MEDIUM
5+ attempts  → HIGH
```

The severity levels are simplified classifications created specifically for CyberGuard.

They are intended to demonstrate conditional logic and provide additional information in the generated report.

## Report Generation

The `generate_report()` function creates the final security report.

It calculates:

* Total valid events
* Successful login attempts
* Failed login attempts
* Suspicious IP addresses
* Number of failed attempts for each suspicious IP
* Severity level for each suspicious IP

The function returns the report as a string instead of printing it directly.

This design makes the function easier to test because the tests can inspect the returned text.

## Main Program

The `main()` function provides the command-line interface.

It performs the following steps:

1. Displays instructions to the user.
2. Creates an empty list for valid logs.
3. Receives log entries using `input()`.
4. Stops when the user enters `DONE`.
5. Sends each entry to `parse_log()`.
6. Rejects invalid entries.
7. Stores valid parsed logs.
8. Generates the final report.
9. Displays the report to the user.

The actual analysis is handled by separate functions rather than placing all logic inside `main()`.

This keeps the program organized and makes individual components easier to test.

## Data Flow

The program follows this general data flow:

```text
User Input
    |
    v
parse_log()
    |
    v
Parsed Log Dictionary
    |
    v
List of Logs
    |
    +----------------------+
    |                      |
    v                      v
count_failed_logins()   generate_report()
    |                      |
    v                      v
Failed IP Counts       Security Report
    |
    v
detect_brute_force()
    |
    v
Suspicious IPs
    |
    v
get_severity()
```

## Input Validation

CyberGuard validates the basic structure of each log entry through the regular expression used by `parse_log()`.

Unsupported events and incorrectly formatted entries return `None`.

The `main()` function checks for this result and informs the user when the input is invalid instead of adding it to the list of logs.

This prevents malformed entries from being included in the final analysis.

## Testing

The project includes automated tests in `test_project.py`.

The tests cover:

* Valid log parsing
* Invalid log parsing
* Unsupported event handling
* Failed login counting
* Brute-force detection
* Detection thresholds
* Severity classification
* Security report generation

The project currently contains nine automated tests.

They can be executed with:

```bash
pytest
```

All tests should pass before the project is considered ready for submission.

## Design Decisions

### Regular Expressions

A regular expression was chosen for log parsing because the input follows a predictable text structure.

It allows the program to extract multiple fields from a single string without manually splitting every part of the input.

### `Counter`

The `Counter` class was chosen because the main analysis requires counting how many failed login attempts belong to each IP address.

This provides a simple and readable solution using Python's standard library.

### Separate Functions

The project separates parsing, counting, detection, severity classification, and report generation into different functions.

This makes the program easier to understand, test, and modify.

### Returning Data Instead of Printing

Functions such as `parse_log()` and `generate_report()` return their results instead of printing them directly.

This allows the functions to be tested independently and keeps input/output responsibilities primarily inside `main()`.

## Limitations

CyberGuard intentionally uses a simplified model of authentication monitoring.

It does not collect real system logs, monitor network traffic, block suspicious IP addresses, or determine whether an event was actually malicious.

The threshold and severity rules are not intended to represent a universal security standard.

A production security monitoring system would require additional context, such as timestamps, authentication sources, account behavior, network information, historical activity, and other detection rules.

## Conclusion

CyberGuard demonstrates how Python can be used to process structured text data and identify potentially suspicious authentication activity.

The project combines regular expressions, collections, functions, conditional logic, loops, input handling, and automated testing into a small command-line security analysis tool.
