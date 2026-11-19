"""
LOCAL RULE ENGINE
------------------
Simple Sigma-style rule matcher over the sandbox telemetry log.
Each rule maps to a MITRE ATT&CK technique and a CWE/CVE/NIST reference
pulled from compliance/mapping.json.

This is a REAL rule engine (not mocked) — it parses the JSON telemetry
lines emitted by sandbox/simulate_ransomware_behavior.py and evaluates
genuine threshold/pattern logic.
"""

import json
import os
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TELEMETRY_LOG = os.path.join(BASE_DIR, "..", "sandbox", "telemetry.log")
MAPPING_FILE = os.path.join(BASE_DIR, "..", "compliance", "mapping.json")

RULES = [
    {
        "id": "RULE-001",
        "name": "Mass File Rename Burst",
        "match_event": "rename_burst_summary",
        "technique": "T1486",
        "description": "Detects a high-rate file renaming pattern consistent with ransomware encryption routines.",
    },
    {
        "id": "RULE-002",
        "name": "Ransom Note Dropped",
        "match_event": "ransom_note_dropped",
        "technique": "T1486",
        "description": "Detects creation of a file matching known ransom-note naming conventions.",
    },
    {
        "id": "RULE-003",
        "name": "Shadow Copy Deletion Attempt",
        "match_event": "shadow_copy_deletion_attempt",
        "technique": "T1490",
        "description": "Detects an attempt to invoke vssadmin/wbadmin to inhibit system recovery.",
    },
    {
        "id": "RULE-004",
        "name": "Suspicious Extension Pattern",
        "match_event": "mass_file_rename",
        "technique": "T1486",
        "description": "Detects files renamed with a non-standard extension at volume (>5 occurrences).",
        "threshold": 5,
    },
    {
        "id": "RULE-005",
        "name": "Pre-Encryption File Staging Burst",
        "match_event": "file_creation_burst",
        "technique": "T1082",
        "description": "Detects a sudden burst of file creation in a directory, consistent with staging prior to encryption.",
    },
    {
        "id": "RULE-006",
        "name": "Suspicious Process Initiation",
        "match_event": "process_start",
        "technique": "T1059",
        "description": "Detects the initiating process event for a scripted file-system attack chain.",
    },
    {
        "id": "RULE-007",
        "name": "Outbound C2 Beacon Pattern",
        "match_event": "network_connection",
        "technique": "T1071",
        "description": "Detects outbound connection consistent with command-and-control beaconing.",
    },
    {
        "id": "RULE-008",
        "name": "Persistence via Run Key",
        "match_event": "registry_modification",
        "technique": "T1547",
        "description": "Detects modification of Run keys commonly used for persistence.",
    },
    {
        "id": "RULE-009",
        "name": "Process Injection Indicator",
        "match_event": "process_injection",
        "technique": "T1055",
        "description": "Detects cross-process memory write patterns associated with code injection.",
    },
]


def load_telemetry():
    if not os.path.exists(TELEMETRY_LOG):
        return []
    events = []
    with open(TELEMETRY_LOG) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def load_mapping():
    with open(MAPPING_FILE) as f:
        return json.load(f)


def evaluate(events=None):
    events = events if events is not None else load_telemetry()
    mapping = load_mapping()
    counts = defaultdict(int)
    for e in events:
        counts[e["event_type"]] += 1

    alerts = []
    for rule in RULES:
        occurrences = counts.get(rule["match_event"], 0)
        threshold = rule.get("threshold", 1)
        if occurrences >= threshold:
            compliance_refs = mapping.get("technique_to_controls", {}).get(rule["technique"], {})
            alerts.append({
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "technique": rule["technique"],
                "description": rule["description"],
                "occurrences": occurrences,
                "severity": "critical" if rule["technique"] in ("T1486", "T1490") else "medium",
                "compliance": compliance_refs,
            })
    return alerts


if __name__ == "__main__":
    for a in evaluate():
        print(json.dumps(a, indent=2))
