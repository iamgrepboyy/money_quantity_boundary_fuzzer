# Money Quantity Boundary Fuzzer

A Burp Suite extension for probing boundary values on monetary, quantity, discount, and currency parameters. It helps identify cases where a server accepts out-of-range values and returns a successful response, which may indicate weak validation or business logic issues.

## Features

- Detects likely money/quantity fields in URL, form/body, and JSON parameters
- Tests boundary payloads for:
  - currency codes
  - quantities
  - discounts
  - amounts and totals
- Supports manual replay from a request context menu and a results tab
- Adds scanner insertion points for in-scope GET/HEAD requests by default
- Allows optional state-changing scanner probes for POST/PUT/PATCH/DELETE when explicitly enabled

## Prerequisites

- Burp Suite Professional or Community with Jython support
- Python 2.7-compatible Jython environment (the extension uses legacy Burp Jython APIs)

## Installation

1. Open Burp Suite.
2. Go to Extender > Extensions.
3. Click Add.
4. Select the extension type as Python.
5. Choose `money_quantity_boundary_fuzzer.py`.
6. The extension will load and add a "Money Fuzzer" tab.

## Usage

### Manual testing

1. In Burp, capture or select a request.
2. Right-click in the request editor and choose:
   - `Analyze money/quantity fields in request`
3. The extension will detect candidate parameters and populate the "Money Fuzzer" tab.
4. Select one or more detected fields.
5. Click `Run selected probes`.
6. Review the results table and the details panel for accepted payloads.

### Scanner integration

- By default, automated scanner checks are limited to in-scope GET/HEAD requests.
- You can enable state-changing scanner probes under the extension UI if you explicitly want POST/PUT/PATCH/DELETE probing in a safe test environment.

## Safety notes

- This tool can replay requests with values such as `-1`, `0`, `1000000`, or large numeric values.
- Some requests may change application state if the target accepts them.
- Only run this against in-scope, authorized test targets.
- Confirm with business-state verification before treating a successful status as a real vulnerability.

## Notes

This extension is intended for security validation and test environments. The definition of "accepted" is heuristic: the tool flags a successful response without common validation text as a candidate for manual verification.
