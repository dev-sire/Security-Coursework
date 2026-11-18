"""
WINDOWS LIVE TELEMETRY COLLECTOR  (read-only DFIR triage)
Collects: processes, scheduled tasks, TCP connections, shadow-copy state,
autorun (Run key) entries, Defender status, and ransomware-style file
extensions / ransom-note filenames (names + metadata only; file CONTENTS are never read).
Nothing is modified, deleted, executed or sent anywhere. Stdlib only.
Run standalone on a Windows host:  python windows_collector.py --out snapshot.json
Some modules (shadow copies, some tasks) need an elevated shell; failures are reported per-module.
"""
import argparse, json, os, platform, socket, subprocess, sys, time
from datetime import datetime, timezone

ALL_MODULES = ["processes", "tasks", "network", "shadow", "autoruns", "defender", "files"]
DEFAULT_MODULES = ALL_MODULES[:]
RANSOM_EXT = {".locked", ".locked_sim", ".encrypted", ".enc", ".crypt", ".crypted", ".crypto", ".lockbit",
              ".ryk", ".wncry", ".wnry", ".conti", ".akira", ".blackcat", ".royal", ".basta", ".medusalocker",
              ".djvu", ".stop", ".petya", ".cerber", ".zepto", ".locky", ".hive", ".play", ".rhysida"}
NOTE_HINTS = ("decrypt", "how_to_recover", "how_to_restore", "restore_my_files", "readme_to_recover",
              "recover_files", "your_files", "ransom", "read_me_now")
IS_WIN = os.name == "nt"


def is_admin():
    if not IS_WIN:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ps_json(script, timeout=60):
    """Run a READ-ONLY PowerShell snippet that emits JSON; return list of dicts."""
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
           "$ErrorActionPreference='Stop'; " + script]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[:400] or f"powershell exit {r.returncode}")
    out = r.stdout.strip()
    if not out:
        return []
    data = json.loads(out)
    return data if isinstance(data, list) else [data]


def c_processes(_o):
    rows = ps_json("@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,"
                   "CommandLine,@{n='Created';e={if($_.CreationDate){$_.CreationDate.ToString('o')}}}) "
                   "| ConvertTo-Json -Compress -Depth 3", 90)
    names = {r["ProcessId"]: r.get("Name") for r in rows}
    for r in rows:
        r["ParentName"] = names.get(r.get("ParentProcessId"))
    return rows


def c_tasks(_o):
    return ps_json("@(Get-ScheduledTask | ForEach-Object { [pscustomobject]@{Name=$_.TaskName;Path=$_.TaskPath;"
                   "State=[string]$_.State;Author=[string]$_.Author;RunAs=[string]$_.Principal.UserId;"
                   "Actions=((@($_.Actions | ForEach-Object { ($_.Execute + ' ' + $_.Arguments).Trim() })) -join ' | ')} }) "
                   "| ConvertTo-Json -Compress -Depth 3", 90)


def c_network(_o):
    rows = ps_json("@(Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,"
                   "@{n='State';e={[string]$_.State}},OwningProcess) | ConvertTo-Json -Compress -Depth 3", 60)
    return rows


def c_shadow(_o):
    return ps_json("@(Get-CimInstance Win32_ShadowCopy | Select-Object ID,VolumeName,"
                   "@{n='Installed';e={if($_.InstallDate){$_.InstallDate.ToString('o')}}}) "
                   "| ConvertTo-Json -Compress -Depth 3", 45)


def c_autoruns(_o):
    return ps_json(
        "$k=@('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',"
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce');"
        "@($k | ForEach-Object { $p=$_; $i=Get-ItemProperty -Path $p -ErrorAction SilentlyContinue; if($i){ "
        "$i.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "
        "[pscustomobject]@{Key=$p;Name=$_.Name;Value=[string]$_.Value} } } }) | ConvertTo-Json -Compress -Depth 3", 30)


def c_defender(_o):
    return ps_json("@(Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,"
                   "BehaviorMonitorEnabled,IoavProtectionEnabled,TamperProtectionEnabled,"
                   "@{n='SignaturesUpdated';e={$_.AntivirusSignatureLastUpdated.ToString('o')}}) "
                   "| ConvertTo-Json -Compress", 30)


def c_files(o):
    """Filename/metadata scan only. Bounded by depth and file count."""
    roots = o.get("scan_paths") or [os.path.join(os.path.expanduser("~"), d) for d in ("Documents", "Desktop", "Downloads")]
    max_files, max_depth = int(o.get("max_files", 20000)), int(o.get("max_depth", 4))
    hits, scanned, skipped = [], 0, []
    deadline = time.time() + int(o.get("scan_timeout", 45))
    for root in roots:
        root = os.path.expandvars(root)
        if not os.path.isdir(root):
            skipped.append(root); continue
        base_depth = root.rstrip("\\/").count(os.sep)
        for dp, dns, fns in os.walk(root, onerror=lambda e: None):
            if dp.count(os.sep) - base_depth >= max_depth:
                dns[:] = []
            for fn in fns:
                scanned += 1
                low = fn.lower()
                ext = os.path.splitext(low)[1]
                kind = "ransom_extension" if ext in RANSOM_EXT else ("ransom_note_name" if any(h in low for h in NOTE_HINTS) and ext in (".txt", ".html", ".hta", ".md") else None)
                if kind:
                    full = os.path.join(dp, fn)
                    try:
                        st = os.stat(full)
                        hits.append({"path": full, "kind": kind, "ext": ext, "size": st.st_size,
                                     "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()})
                    except OSError:
                        pass
                if scanned >= max_files or time.time() > deadline:
                    return {"hits": hits, "scanned": scanned, "roots": roots, "skipped_roots": skipped, "truncated": True}
    return {"hits": hits, "scanned": scanned, "roots": roots, "skipped_roots": skipped, "truncated": False}


COLLECTORS = {"processes": c_processes, "tasks": c_tasks, "network": c_network, "shadow": c_shadow,
              "autoruns": c_autoruns, "defender": c_defender, "files": c_files}


def collect(modules=None, options=None):
    modules, options = modules or DEFAULT_MODULES, options or {}
    snap = {"schema": "vip.winsnap.v1", "collected_at": datetime.now(timezone.utc).isoformat(),
            "host": socket.gethostname(), "os": platform.platform(), "is_admin": is_admin(),
            "source": "live_collection", "modules": {}}
    if not IS_WIN:
        snap["supported"] = False
        snap["error"] = "Live collection requires Windows. Run windows_collector.py on a Windows host and upload the snapshot."
        return snap
    snap["supported"] = True
    for m in modules:
        if m not in COLLECTORS:
            continue
        t0 = time.time()
        try:
            data = COLLECTORS[m](options)
            snap["modules"][m] = {"status": "ok", "data": data, "seconds": round(time.time() - t0, 2)}
        except Exception as e:
            snap["modules"][m] = {"status": "error", "error": str(e)[:400], "data": [] if m != "files" else {"hits": [], "scanned": 0},
                                  "seconds": round(time.time() - t0, 2)}
    return snap


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="windows_snapshot.json")
    ap.add_argument("--modules", default=",".join(DEFAULT_MODULES))
    ap.add_argument("--scan-path", action="append", help="folder for the extension scan (repeatable)")
    ap.add_argument("--max-depth", type=int, default=4)
    a = ap.parse_args()
    s = collect(a.modules.split(","), {"scan_paths": a.scan_path, "max_depth": a.max_depth})
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=2)
    print(f"Wrote {a.out} (admin={s['is_admin']}, supported={s.get('supported')})")
    for m, r in s["modules"].items():
        print(f"  {m:10s} {r['status']:6s} {r.get('error','')}")
