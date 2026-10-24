# Group 6 — Tool Output Provenance & Injection Risk Analyzer

## Project Overview

The Tool Output Provenance & Injection Risk Analyzer is a passive-only proof of concept developed for CYSE-587 / SYST-687 Deliverable 2.

The tool analyzes structured JSON and JSONL tool-call logs from the ADOP testbed to identify potentially suspicious activity, including prompt-injection-like language, suspicious Git arguments, and path traversal patterns.

It produces risk alerts with supporting evidence and recommendations for human review. It does not modify ADOP, block tool execution, or prove that an attack occurred.

## Features

- Reads JSON and JSONL log files.
- Examines tool names, arguments, target resources, and available event metadata.
- Identifies heuristic indicators of suspicious activity.
- Assigns risk levels and heuristic scores.
- Provides evidence and candidate links between events that share a task ID.
- Produces JSON-formatted analysis results.

## Requirements

- Python 3
- No third-party Python packages are required, assuming the analyzer uses only Python's standard library.

## Setup

1. Clone or download this repository.
2. Open a terminal in the project directory.
3. Confirm Python 3 is installed:

   ```bash
   python3 --version
   ```

4. Ensure `analyzer.py` and the input log file are in the current directory, or provide the correct path to the log file.

## How to Run

Analyze the clean sample:

```bash
python3 analyzer.py "session-01(clean).jsonl"
```

Analyze the poisoned sample:

```bash
python3 analyzer.py poisoned-file.jsonl
```

Analyze the mock data:

```bash
python3 analyzer.py mock_adop_logs.json
```

To save the analysis output to a JSON file:

```bash
python3 analyzer.py poisoned-file.jsonl --output results.json
```

The output includes the number of records analyzed, the number of alerts, risk levels, findings, supporting evidence, and limitations.

## Initial Test Results

The following results were observed during initial testing:

| Input | Records Analyzed | Alerts |
|---|---:|---:|
| `session-01.jsonl` | 10 | 0 |
| `poisoned-file.jsonl` | 12 | 2 |
| `mock_adop_logs.json` | 3 | 2 |

These results demonstrate that the prototype runs against the listed inputs and identifies suspicious patterns in the poisoned and mock samples. They do not establish complete detection coverage or production readiness.

## Limitations

- Detection is heuristic and may produce false positives or miss suspicious activity.
- Risk scores are indicators, not probabilities.
- Shared task IDs suggest a possible relationship but do not prove causation.
- Detection depends on the fields available in the input logs.
- The prototype is passive-only: it does not modify ADOP or block tool calls.
- Results require human review.

## Project Scope

This implementation is an initial proof of concept for Deliverable 2. Future work may include improved event correlation, evaluation across additional clean and poisoned scenarios, and refinement of risk scoring.

## Course

CYSE-587 — Cybersecurity Systems Engineering  
George Mason University  
Fall 2026
