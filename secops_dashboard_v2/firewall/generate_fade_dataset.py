"""
MOCK FADE-STYLE DATASET GENERATOR
------------------------------------
No real FADE dataset file was available in this environment, so this
script GENERATES a synthetic flow-based dataset using the schema
documented in compliance/mapping.json -> firewall_fade_dataset.

Clearly marked as synthetic. Replace generate() with a real file loader
(pandas.read_csv on your actual FADE export) when you have the source.
"""

import csv
import ipaddress
import os
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(BASE_DIR, "..", "data", "fade_flows_mock.csv")

SCHEMA = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flow_duration_ms", "packets_per_sec", "bytes_per_sec", "label"]

INTERNAL_NET = ipaddress.ip_network("192.168.100.0/24")
EXTERNAL_IPS = ["45.142.212.61", "185.220.101.7", "91.242.217.32", "103.98.63.15", "8.8.8.8", "1.1.1.1"]


def _rand_internal_ip():
    return str(random.choice(list(INTERNAL_NET.hosts())[:200]))


def generate(n_benign=2200, n_malicious=450, seed=42):
    random.seed(seed)
    rows = []

    for _ in range(n_benign):
        rows.append({
            "src_ip": _rand_internal_ip(),
            "dst_ip": random.choice(EXTERNAL_IPS[-2:] + [_rand_internal_ip()]),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([443, 80, 53, 22, 445, 3389, 5985]),
            "protocol": random.choice(["TCP", "UDP"]),
            "flow_duration_ms": random.randint(50, 4000),
            "packets_per_sec": round(random.uniform(1, 40), 2),
            "bytes_per_sec": round(random.uniform(200, 50000), 2),
            "label": "benign",
        })

    # Malicious: C2 beaconing pattern (T1071) - low packet rate, fixed interval, external IP
    for _ in range(int(n_malicious * 0.5)):
        rows.append({
            "src_ip": _rand_internal_ip(),
            "dst_ip": random.choice(EXTERNAL_IPS[:4]),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([443, 8080, 4444, 8443]),
            "protocol": "TCP",
            "flow_duration_ms": random.randint(29500, 30500),  # suspiciously regular beacon interval
            "packets_per_sec": round(random.uniform(0.2, 1.5), 2),
            "bytes_per_sec": round(random.uniform(300, 1200), 2),
            "label": "malicious_c2_beacon",
        })

    # Malicious: ransomware lateral SMB burst (T1486 precursor) - high packet rate, internal, port 445
    for _ in range(n_malicious - int(n_malicious * 0.5)):
        rows.append({
            "src_ip": _rand_internal_ip(),
            "dst_ip": _rand_internal_ip(),
            "src_port": random.randint(1024, 65535),
            "dst_port": 445,
            "protocol": "TCP",
            "flow_duration_ms": random.randint(10, 300),
            "packets_per_sec": round(random.uniform(150, 900), 2),
            "bytes_per_sec": round(random.uniform(80000, 900000), 2),
            "label": "malicious_smb_lateral_burst",
        })

    random.shuffle(rows)
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    with open(OUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SCHEMA)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[FADE] Generated {len(rows)} flow records -> {OUT_FILE}")
    return OUT_FILE


if __name__ == "__main__":
    generate()
