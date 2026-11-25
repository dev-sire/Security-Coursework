"""
server.py
-----------
Zero-dependency local server (stdlib only - http.server) that:
  1. Serves the dashboard/ folder as static files (so feed.json loads via fetch()).
  2. Exposes POST /api/run -> re-runs the full pipeline synchronously and
     returns the fresh feed.json, so the dashboard's "Run Live Detection"
     button gives a genuinely live result, not a canned replay.
  3. Exposes POST /api/config -> saves a Gemini API key to config.json so
     you can set it from the dashboard UI instead of an environment
     variable (both work; config.json takes precedence if present).
  4. Exposes GET /api/config -> reports whether a key is currently set
     (never returns the key value itself, to the UI or otherwise).

Run: python3 server.py [port] [host]   (defaults: 8000, 127.0.0.1)
Then open http://localhost:8000
"""

import json
import os
import subprocess
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOADED_CSV = os.path.join(DATA_DIR, "fade_flows_uploaded.csv")


def run_pipeline_subprocess(env_overrides=None):
    env = os.environ.copy()
    if env_overrides:
        env.update({k: str(v) for k, v in env_overrides.items()})
    result = subprocess.run(
        [sys.executable, os.path.join(BASE_DIR, "run_pipeline.py")],
        capture_output=True, text=True, cwd=BASE_DIR, timeout=120, env=env,
    )
    return result.returncode, result.stdout, result.stderr


sys.path.insert(0, os.path.join(BASE_DIR, "telemetry"))
sys.path.insert(0, os.path.join(BASE_DIR, "detection"))
LIVE_OUT = os.path.join(DASHBOARD_DIR, "live_telemetry.json")


def analyze_snapshot(snap):
    import windows_rules
    result = windows_rules.evaluate(snap)
    out = {"snapshot_meta": {k: snap.get(k) for k in ("collected_at", "host", "os", "is_admin", "source", "supported", "error")},
           "analysis": result, "raw": snap.get("modules", {})}
    with open(LIVE_OUT, "w") as f:
        json.dump(out, f)
    return out


def evaluate_uploaded_firewall_csv():
    """Runs the REAL firewall rule engine against whatever CSV the user
    uploaded, instead of the synthetic FADE-style dataset."""
    sys.path.insert(0, os.path.join(BASE_DIR, "firewall"))
    import importlib
    import fade_firewall
    importlib.reload(fade_firewall)
    return fade_firewall.evaluate_flows(path=UPLOADED_CSV)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DASHBOARD_DIR, **kwargs)

    def log_message(self, fmt, *args):
        print(f"[server] {self.address_string()} - {fmt % args}")

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/telemetry/capabilities":
            import windows_collector as wc
            self._send_json({"windows": wc.IS_WIN, "is_admin": wc.is_admin(), "modules": wc.ALL_MODULES})
            return
        if self.path == "/api/config":
            key_set = False
            if os.path.exists(CONFIG_FILE):
                try:
                    with open(CONFIG_FILE) as f:
                        key_set = bool(json.load(f).get("gemini_api_key"))
                except Exception:
                    key_set = False
            key_set = key_set or bool(os.environ.get("GEMINI_API_KEY"))
            self._send_json({"gemini_key_configured": key_set})
            return
        if self.path == "/api/live-log":
            # Stream current telemetry + ransomware operation status for live UI
            tel_path = os.path.join(BASE_DIR, "sandbox", "telemetry.log")
            events = []
            if os.path.exists(tel_path):
                try:
                    with open(tel_path) as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                events.append(json.loads(line))
                except Exception:
                    pass
            victim_dir = os.path.join(BASE_DIR, "sandbox", "victim_files")
            locked = []
            note_present = False
            if os.path.isdir(victim_dir):
                for name in sorted(os.listdir(victim_dir)):
                    if name.endswith(".locked") or name.endswith(".locked_sim"):
                        locked.append(name)
                    if name.startswith("README_DECRYPT"):
                        note_present = True
            status_path = os.path.join(BASE_DIR, "sandbox", "ransomware_status.json")
            status = {"state": "idle", "message": "No active operation"}
            if os.path.exists(status_path):
                try:
                    with open(status_path) as f:
                        status = json.load(f)
                except Exception:
                    pass
            self._send_json({
                "events": events[-80:],
                "encrypted_files": locked,
                "encrypted_count": len(locked),
                "ransom_note_present": note_present,
                "target_folder": victim_dir,
                "status": status,
            })
            return
        super().do_GET()

    def do_POST(self):
        if self.path == "/api/run":
            print("[server] Live run requested - executing run_pipeline.py ...")
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            try:
                params = json.loads(body.decode("utf-8")) if body else {}
            except Exception:
                params = {}
            env_overrides = {}
            if "file_count" in params:
                env_overrides["SIM_FILE_COUNT"] = params["file_count"]
            if "extension" in params and params["extension"]:
                env_overrides["SIM_EXTENSION"] = params["extension"]
            if params.get("skip_note"):
                env_overrides["SIM_SKIP_NOTE"] = "1"
            if params.get("skip_shadow"):
                env_overrides["SIM_SKIP_SHADOW"] = "1"

            code, out, err = run_pipeline_subprocess(env_overrides)
            feed_path = os.path.join(DASHBOARD_DIR, "feed.json")
            feed = None
            if os.path.exists(feed_path):
                with open(feed_path) as f:
                    feed = json.load(f)
            self._send_json({
                "success": code == 0,
                "returncode": code,
                "stdout_tail": out[-4000:],
                "stderr_tail": err[-2000:] if err else "",
                "feed": feed,
            })
            return

        if self.path in ("/api/telemetry/run", "/api/telemetry/upload"):
            length = int(self.headers.get("Content-Length", 0))
            try:
                params = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                if self.path == "/api/telemetry/upload":
                    snap = params.get("snapshot") or params
                    if "modules" not in snap:
                        raise ValueError("not a windows_collector snapshot (missing 'modules')")
                    snap["source"] = "uploaded_snapshot"
                else:
                    import windows_collector as wc
                    paths = [p.strip() for p in (params.get("scan_paths") or "").splitlines() if p.strip()]
                    snap = wc.collect(params.get("modules"), {"scan_paths": paths or None,
                                      "max_depth": params.get("max_depth", 4), "max_files": params.get("max_files", 20000)})
                    if not snap.get("supported"):
                        self._send_json({"success": False, "error": snap["error"], "snapshot_meta": snap}, 200); return
                self._send_json({"success": True, **analyze_snapshot(snap)})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, 400)
            return

        if self.path == "/api/firewall-upload":
            print("[server] CSV upload received - evaluating REAL firewall rules against it ...")
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            try:
                payload = json.loads(body.decode("utf-8"))
                csv_text = payload.get("csv_text", "")
            except Exception:
                csv_text = body.decode("utf-8", errors="ignore")

            if not csv_text.strip():
                self._send_json({"success": False, "error": "empty CSV"}, status=400)
                return

            os.makedirs(DATA_DIR, exist_ok=True)
            with open(UPLOADED_CSV, "w", newline="") as f:
                f.write(csv_text)

            try:
                result = evaluate_uploaded_firewall_csv()
                self._send_json({"success": True, "firewall_result": result})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if self.path == "/api/config":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                payload = {}
            api_key = payload.get("gemini_api_key", "").strip()
            if api_key:
                with open(CONFIG_FILE, "w") as f:
                    json.dump({"gemini_api_key": api_key}, f)
                self._send_json({"saved": True})
            else:
                self._send_json({"saved": False, "error": "empty key"}, status=400)
            return

        if self.path == "/api/ransomware/execute":
            print("[server] Ransomware payload execution requested ...")
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            try:
                params = json.loads(body.decode("utf-8")) if body else {}
            except Exception:
                params = {}
            file_count = int(params.get("file_count", 60))
            extension = params.get("extension") or ".locked"
            status_path = os.path.join(BASE_DIR, "sandbox", "ransomware_status.json")
            victim_dir = os.path.join(BASE_DIR, "sandbox", "victim_files")
            from datetime import datetime, timezone
            started = datetime.now(timezone.utc).isoformat()
            with open(status_path, "w") as f:
                json.dump({
                    "state": "running",
                    "message": f"Encrypting files in {victim_dir}",
                    "started_at": started,
                    "target_folder": victim_dir,
                }, f)
            env_overrides = {
                "SIM_FILE_COUNT": str(file_count),
                "SIM_EXTENSION": extension,
            }
            # Run full pipeline so detections also fire
            code, out, err = run_pipeline_subprocess(env_overrides)
            locked = []
            if os.path.isdir(victim_dir):
                locked = sorted([n for n in os.listdir(victim_dir) if n.endswith(extension) or n.endswith(".locked") or n.endswith(".locked_sim")])
            note_present = any(n.startswith("README_DECRYPT") for n in os.listdir(victim_dir)) if os.path.isdir(victim_dir) else False
            finished = datetime.now(timezone.utc).isoformat()
            result_status = {
                "state": "completed" if code == 0 else "failed",
                "message": (
                    f"Ransomware payload completed. {len(locked)} files encrypted in target folder. "
                    f"Ransom note {'deployed' if note_present else 'not found'}. Shadow-copy wipe attempted."
                ),
                "started_at": started,
                "finished_at": finished,
                "target_folder": victim_dir,
                "encrypted_count": len(locked),
                "encrypted_files": locked[:40],
                "ransom_note_present": note_present,
                "extension": extension,
            }
            with open(status_path, "w") as f:
                json.dump(result_status, f)
            feed_path = os.path.join(DASHBOARD_DIR, "feed.json")
            feed = None
            if os.path.exists(feed_path):
                with open(feed_path) as f:
                    feed = json.load(f)
            self._send_json({
                "success": code == 0,
                "returncode": code,
                "status": result_status,
                "stdout_tail": out[-3000:],
                "feed": feed,
            })
            return

        self._send_json({"error": "unknown endpoint"}, status=404)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"  # localhost only: endpoints expose host telemetry
    os.makedirs(DASHBOARD_DIR, exist_ok=True)
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Serving dashboard on http://{host}:{port}")
    print("POST /api/telemetry/run | /api/telemetry/upload -> live Windows telemetry")
    print("POST /api/run     -> re-run full pipeline live")
    print("GET/POST /api/config -> check/set Gemini API key")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()
