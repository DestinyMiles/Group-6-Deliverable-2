
import json
import re
import argparse
from pathlib import Path
from collections import defaultdict

# Group 6: Tool Output Provenance & Injection Risk Analyzer

INJECTION_PHRASES = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "ignore the system prompt",
    "reveal secrets",
    "exfiltrate",
    "send credentials",
    "upload the contents",
    "execute the following",
]

TRAVERSAL_PATTERN = re.compile(
    r"(?:^|[/\\])\.\.(?:[/\\]|$)|\.\.[/\\]"
)

OUTPUT_PATTERN = re.compile(
    r"(?:^|\s)--output(?:=|\s)|(?:^|\s)>\s*\S",
    re.IGNORECASE,
)

SOURCE_TOOL_NAMES = ("fetch", "browser", "web", "search", "retrieve")


def load_logs(file_path):
    """Load JSON arrays, JSON objects, or JSON Lines files."""
    text = Path(file_path).read_text(encoding="utf-8")

    try:
        data = json.loads(text)

        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]

        if isinstance(data, dict):
            for key in ("events", "records", "logs", "data"):
                if isinstance(data.get(key), list):
                    return [
                        item for item in data[key]
                        if isinstance(item, dict)
                    ]
            return [data]

        raise ValueError("JSON must contain an object or list.")

    except json.JSONDecodeError:
        records = []

        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: {error.msg}"
                ) from error

            if isinstance(record, dict):
                records.append(record)

        return records


def flatten_record(value, prefix=""):
    """Make nested log fields searchable."""
    fields = []

    if isinstance(value, dict):
        for key, item in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            fields.extend(flatten_record(item, name))

    elif isinstance(value, list):
        for index, item in enumerate(value):
            fields.extend(
                flatten_record(item, f"{prefix}[{index}]")
            )

    elif value is not None:
        fields.append((prefix, str(value)))

    return fields


def get_value(record, *keys):
    """Return the first available field from a log record."""
    for key in keys:
        value = record.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return None


def get_identity(record, index):
    return {
        "record_index": index,
        "event_id": get_value(
            record, "event_id", "id", "record_id", "request_id"
        ),
        "task_id": get_value(
            record, "task_id", "session_id",
            "trace_id", "conversation_id"
        ),
        "timestamp": get_value(
            record, "timestamp", "time", "created_at"
        ),
        "tool_name": get_value(
            record, "tool_name", "tool", "name", "method"
        ) or "unknown",
        "result_status": get_value(
            record, "result_status", "status"
        ),
    }


def analyze_record(record, index):
    """Flag suspicious patterns and preserve supporting evidence."""
    fields = flatten_record(record)
    searchable_text = "\n".join(
        f"{name}: {value}" for name, value in fields
    )
    text_lower = searchable_text.lower()

    tool_name = (
        get_value(record, "tool_name", "tool", "name", "method")
        or "unknown"
    ).lower()

    findings = []
    score = 0

    # Check path-like fields for parent-directory traversal.
    for field_name, value in fields:
        path_field = any(
            word in field_name.lower()
            for word in (
                "path", "pathspec", "target_resource",
                "filename", "directory"
            )
        )

        if path_field and TRAVERSAL_PATTERN.search(value):
            findings.append({
                "category": "path_traversal_pattern",
                "evidence": (
                    f"{field_name} contains a parent-directory "
                    f"traversal pattern: {value[:180]}"
                ),
            })
            score += 45

    # Check for potentially unsafe output arguments.
    tool_related = any(
        word in tool_name
        for word in ("git", "file", "filesystem", "shell", "exec")
    )

    if tool_related and OUTPUT_PATTERN.search(searchable_text):
        findings.append({
            "category": "suspicious_tool_argument",
            "evidence": (
                "A command/output-redirection-style argument "
                "appears in a tool-related record."
            ),
        })
        score += 25

    # Look for possible prompt-injection language.
    matched_phrases = [
        phrase for phrase in INJECTION_PHRASES
        if phrase in text_lower
    ]

    if matched_phrases:
        findings.append({
            "category": "prompt_injection_like_text",
            "evidence": (
                "Possible instruction-override language: "
                + ", ".join(matched_phrases[:3])
            ),
        })
        score += 20

    if not findings:
        return None

    score = min(score, 100)

    if score >= 60:
        risk = "HIGH"
    elif score >= 35:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        **get_identity(record, index),
        "risk": risk,
        "heuristic_score": score,
        "findings": findings,
        "review_recommendation": (
            "Human review recommended; verify the source event, "
            "tool arguments, and intended target."
        ),
        "raw_evidence": record,
    }


def correlate_events(records, alerts):
    """Group events using IDs when available; do not infer causation."""
    events_by_task = defaultdict(list)

    for index, record in enumerate(records):
        task_id = get_value(
            record, "task_id", "session_id",
            "trace_id", "conversation_id"
        )

        if task_id:
            events_by_task[task_id].append((index, record))

    for alert in alerts:
        task_id = alert.get("task_id")

        if not task_id:
            alert["correlation"] = {
                "status": "insufficient_identifiers",
                "note": "No task/session ID is available for grouping.",
            }
            continue

        related_events = events_by_task[task_id]

        possible_sources = [
            get_identity(record, index)
            for index, record in related_events
            if any(
                name in (
                    get_value(
                        record, "tool_name", "tool", "name", "method"
                    ) or ""
                ).lower()
                for name in SOURCE_TOOL_NAMES
            )
        ]

        if possible_sources:
            status = "same_task_source_event_found"
            note = (
                "A source-like event shares this task ID. "
                "This is a candidate relationship, not proof of causation."
            )
        elif len(related_events) > 1:
            status = "same_task_only"
            note = (
                "Events share a task ID, but no source event "
                "could be identified from the available fields."
            )
        else:
            status = "single_record"
            note = "No related records were found for this task ID."

        alert["correlation"] = {
            "status": status,
            "related_record_count": len(related_events),
            "possible_source_events": possible_sources,
            "note": note,
        }


def analyze_logs(records):
    alerts = []

    for index, record in enumerate(records):
        alert = analyze_record(record, index)

        if alert:
            alerts.append(alert)

    correlate_events(records, alerts)

    return {
        "tool_name": (
            "Group 6 Tool Output Provenance "
            "& Injection Risk Analyzer"
        ),
        "version": "0.1",
        "analysis_mode": "passive_only",
        "records_analyzed": len(records),
        "alerts_found": len(alerts),
        "alerts": alerts,
        "limitations": [
            "Scores are heuristic indicators, not probabilities.",
            "A suspicious pattern is not proof of an attack.",
            "Shared task IDs do not prove causation.",
            "Detection depends on the fields present in the logs.",
            "This prototype does not modify ADOP or block actions.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Passively analyze structured tool logs."
    )
    parser.add_argument(
        "input",
        help="Path to the input JSON or JSONL log file"
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional path for the JSON results"
    )
    args = parser.parse_args()

    try:
        records = load_logs(args.input)
        report = analyze_logs(records)
        output = json.dumps(report, indent=2)

        if args.output:
            Path(args.output).write_text(
                output + "\n", encoding="utf-8"
            )
            print(f"Records analyzed: {len(records)}")
            print(f"Alerts found: {report['alerts_found']}")
            print(f"Results saved to: {args.output}")
        else:
            print(output)

    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
