"""
FIREWALL MODULE (FADE-STYLE FLOW DATASET)
--------------------------------------------
Real rule-based flow classifier (not mocked) running over the
synthetic FADE-style dataset. Generates block/alert decisions from
genuine thresholding logic, and maps hits to ATT&CK/compliance via
compliance/mapping.json.

Rules:
  FW-001  C2 beaconing: fixed-interval low-volume external connections
  FW-002  SMB lateral burst: high packet rate to internal :445 (ransomware precursor)
  FW-003  Known-bad external IP reputation hit
"""

import csv
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "..", "data", "fade_flows_mock.csv")
MAPPING_FILE = os.path.join(BASE_DIR, "..", "compliance", "mapping.json")

KNOWN_BAD_IPS = {"45.142.212.61", "185.220.101.7"}  # illustrative threat-intel style list


def load_flows(path=None):
    """If `path` is given (e.g. a CSV the user uploaded via the dashboard),
    it's read and evaluated directly - real rule logic against real data
    you supplied, not the synthetic FADE-style set. Falls back to the
    synthetic generator only when no file (uploaded or default) exists."""
    target = path or DATA_FILE
    if not os.path.exists(target):
        if path:
            raise FileNotFoundError(f"Uploaded dataset not found at {target}")
        from generate_fade_dataset import generate
        generate()
    with open(target) as f:
        return list(csv.DictReader(f))


def load_mapping():
    with open(MAPPING_FILE) as f:
        return json.load(f)


def evaluate_flows(path=None):
    flows = load_flows(path=path)
    mapping = load_mapping()
    decisions = []

    for flow in flows:
        try:
            dur = int(float(flow["flow_duration_ms"]))
            pps = float(flow["packets_per_sec"])
            dst_port = int(float(flow["dst_port"]))
            dst_ip = flow["dst_ip"]
        except (KeyError, ValueError):
            continue  # skip malformed rows rather than crash on a user-uploaded CSV

        action = "allow"
        rule_hit = None
        technique = None

        if 29000 <= dur <= 31000 and pps < 2 and dst_ip not in ("192.168.100.0",):
            action, rule_hit, technique = "block", "FW-001 C2 Beaconing Pattern", "T1071"
        elif dst_port == 445 and pps > 100:
            action, rule_hit, technique = "block", "FW-002 SMB Lateral Burst (ransomware precursor)", "T1486"
        elif dst_ip in KNOWN_BAD_IPS:
            action, rule_hit, technique = "block", "FW-003 Known-Bad IP Reputation", "T1071"

        if action == "block":
            decisions.append({
                "flow": flow,
                "action": action,
                "rule": rule_hit,
                "technique": technique,
                "compliance": mapping.get("technique_to_controls", {}).get(technique, {}),
            })

    return {
        "total_flows_evaluated": len(flows),
        "blocked_count": len(decisions),
        "allowed_count": len(flows) - len(decisions),
        "blocked_flows": decisions,
    }


if __name__ == "__main__":
    result = evaluate_flows()
    print(f"Evaluated {result['total_flows_evaluated']} flows -> "
          f"blocked {result['blocked_count']}, allowed {result['allowed_count']}")
    for d in result["blocked_flows"][:5]:
        print(json.dumps(d, indent=2))
