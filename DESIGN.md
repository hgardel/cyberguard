# CyberGuard Design

## Overview

CyberGuard is a command-line security log analyzer. It parses authentication events, aggregates failed logins by IP address, detects repeated failures, assigns a severity label, and builds a text report.

## Program Structure

### `parse_log()`

Uses a regular expression with `fullmatch()` to require exactly the documented line structure. Only `SUCCESS_LOGIN` and `FAILED_LOGIN` events are accepted. The IPv4 validator requires four decimal octets in the range 0 through 255 and rejects multi-digit octets with leading zeros. Trailing text is rejected. Date/time values are retained as strings; the parser does not perform full calendar validation.

### `count_failed_logins()`

Uses `collections.Counter` to count events with the `FAILED_LOGIN` event type by IP address. Successful logins do not increase the count.

### `detect_brute_force()`

Returns IP addresses whose failed-login count reaches a supplied threshold. The default threshold is three attempts.

### `get_severity()`

Maps counts to project-specific categories: `LOW` for zero to two attempts, `MEDIUM` for three or four, and `HIGH` for five or more attempts.

### `generate_report()`

Builds and returns the full report as a string. Returning data instead of printing inside this function allows tests to inspect output independently from the interactive interface.

### `main()`

Reads one event per line, rejects malformed entries with a short message, stops at `DONE`, and prints the report for valid entries.

## Design Decisions

Each main operation is a separate function. This keeps parsing, counting, threshold logic, classification, report formatting, and interaction independently understandable and testable. The input format is intentionally narrow, which makes validation predictable and reduces ambiguity.

## Testing

`test_project.py` tests valid parsing, malformed input, unsupported events, invalid IPv4 octets, trailing text, failed-login counts, threshold detection, severity classification, and report generation. The tests do not need a real system log or network connection.

## Limitations

CyberGuard uses static, user-provided input and simple thresholds. It does not ingest live logs, monitor network traffic, correlate events from multiple systems, persist history, block addresses, validate accounts, or prove malicious intent. The date and time fields are not checked against the calendar. This is an educational prototype, not a production SIEM or incident-response system.
