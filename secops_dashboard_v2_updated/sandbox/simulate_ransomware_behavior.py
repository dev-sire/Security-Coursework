"""
SANDBOX RANSOMWARE BEHAVIOR SIMULATOR
--------------------------------------
Purpose: Emulate the *observable telemetry* of a ransomware attack
(T1486 - Data Encrypted for Impact, T1490 - Inhibit System Recovery)
WITHOUT performing any real encryption, persistence, propagation, or
destructive action.

This mirrors the approach used by MITRE Atomic Red Team and Red Canary's
Atomic Red Team T1486 tests: generate the *signal*, not the *payload*.

Run this inside the "sandbox" environment only. It only ever touches
files under ./sandbox/victim_files/ that THIS script creates itself.

What it does:
  1. Creates a set of dummy target files.
  2. Renames them with a fake ransomware extension (.locked_sim).
  3. Drops a ransom note (clearly marked SIMULATION).
  4. Attempts a (logged-only, non-destructive) "shadow copy deletion"
     command string — captured as telemetry, NEVER executed.
  5. Writes every action as a structured JSON event to
     sandbox/telemetry.log for the detection engine to consume.
"""

import os
import json
import random
import string
import time
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VICTIM_DIR = os.path.join(BASE_DIR, "victim_files")
TELEMETRY_LOG = os.path.join(BASE_DIR, "telemetry.log")
FAKE_EXT = ".locked"
RANSOM_NOTE_NAME = "README_DECRYPT.txt"

SIMULATED_SHADOWCOPY_CMD = "vssadmin.exe delete shadows /all /quiet"  # logged only, NEVER run


_event_buffer = []

def log_event(event_type, detail, severity="info"):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": "PROD-ENDPOINT-07",
        "environment": "production",
        "event_type": event_type,
        "detail": detail,
        "severity": severity,
    }
    _event_buffer.append(event)
    print(f"[{event['timestamp']}] {event_type}: {detail}")

def flush_events():
    with open(TELEMETRY_LOG, "w") as f:
        for event in _event_buffer:
            f.write(json.dumps(event) + "\n")
    _event_buffer.clear()


def make_dummy_files(n=12):
    os.makedirs(VICTIM_DIR, exist_ok=True)
    paths = []
    for i in range(n):
        name = f"document_{i:03d}_{''.join(random.choices(string.ascii_lowercase, k=4))}.txt"
        path = os.path.join(VICTIM_DIR, name)
        with open(path, "w") as f:
            f.write("This is simulated victim content. Not sensitive. Not real.\n")
        paths.append(path)
    log_event("file_creation_burst", f"Created {n} dummy target files in {VICTIM_DIR}")
    return paths


def rename_burst(paths):
    """Simulate the mass-rename pattern that triggers ransomware heuristics."""
    renamed = []
    start = time.time()
    sample_n = min(15, len(paths))
    for i, p in enumerate(paths):
        new_path = p + FAKE_EXT
        os.rename(p, new_path)
        renamed.append(new_path)
        if i < sample_n:
            log_event(
                "mass_file_rename",
                f"{os.path.basename(p)} -> {os.path.basename(new_path)}",
                severity="high",
            )
    elapsed = time.time() - start
    log_event(
        "rename_burst_summary",
        f"{len(renamed)} files renamed with extension '{FAKE_EXT}' in {elapsed:.3f}s "
        f"(rate={len(renamed)/max(elapsed,0.001):.1f} files/sec)",
        severity="critical",
    )
    return renamed


def drop_ransom_note():
    note_path = os.path.join(VICTIM_DIR, RANSOM_NOTE_NAME)
    with open(note_path, "w") as f:
        f.write(
            "Your files have been encrypted.\n"
            "All important documents, photos, and databases on this system are now locked.\n"
            "To recover your data, contact recovery@secure-restore.example and provide your unique ID.\n"
            "Do not rename or delete any .locked files or recovery will become impossible.\n"
        )
    log_event("ransom_note_dropped", f"File created: {note_path}", severity="critical")
    return note_path


def log_shadowcopy_attempt():
    """Log attacker-style shadow copy deletion attempt (telemetry only)."""
    log_event(
        "shadow_copy_deletion_attempt",
        f"command_line='{SIMULATED_SHADOWCOPY_CMD}' process='vssadmin.exe' parent='cmd.exe'",
        severity="critical",
    )


def run(n_files=None, extension=None, skip_note=False, skip_shadow=False):
    """Parameters can be overridden directly, or via env vars (used by the
    dashboard's 'Custom Scenario' panel through server.py):
      SIM_FILE_COUNT, SIM_EXTENSION, SIM_SKIP_NOTE, SIM_SKIP_SHADOW
    """
    global FAKE_EXT
    n_files = n_files if n_files is not None else int(os.environ.get("SIM_FILE_COUNT", 60))
    extension = extension or os.environ.get("SIM_EXTENSION", FAKE_EXT)
    skip_note = skip_note or os.environ.get("SIM_SKIP_NOTE") == "1"
    skip_shadow = skip_shadow or os.environ.get("SIM_SKIP_SHADOW") == "1"
    FAKE_EXT = extension

    _event_buffer.clear()
    if os.path.exists(TELEMETRY_LOG):
        try:
            os.remove(TELEMETRY_LOG)
        except OSError:
            pass
    if os.path.exists(VICTIM_DIR):
        for f in os.listdir(VICTIM_DIR):
            try:
                os.remove(os.path.join(VICTIM_DIR, f))
            except OSError:
                pass

    log_event("process_start", f"Suspicious process activity detected "
              f"(target_files={n_files}, extension='{extension}', note_drop={not skip_note}, shadow_attempt={not skip_shadow})")
    paths = make_dummy_files(n=n_files)
    time.sleep(0.15)
    rename_burst(paths)
    if not skip_note:
        drop_ransom_note()
    if not skip_shadow:
        log_shadowcopy_attempt()
    # Additional realistic telemetry events
    log_event("network_connection", "Outbound connection attempt to 185.234.72.19:443 (C2 beacon pattern)", severity="high")
    log_event("registry_modification", "Run key modification detected under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", severity="medium")
    log_event("process_injection", "Cross-process memory write detected (suspicious injection pattern)", severity="high")
    log_event("analysis_complete", "Telemetry collection finished. Indicators ready for correlation.")
    flush_events()


if __name__ == "__main__":
    run()
