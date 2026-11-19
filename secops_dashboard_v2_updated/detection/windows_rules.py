"""
WINDOWS LIVE-TELEMETRY RULES (real logic over a real snapshot from telemetry/windows_collector.py)
Every finding carries its evidence (the exact row that matched) so an analyst can verify it.
Heuristics, not verdicts: legitimate software trips some of these -- findings are triage leads.
"""
import ipaddress, json, os, re
BASE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE, "..", "compliance", "mapping.json")) as _f:
    MAP = json.load(_f).get("technique_to_controls", {})

USER_WRITABLE = re.compile(r"\\(users\\[^\\]+\\(appdata|downloads|desktop)|temp|windows\\temp|programdata|users\\public)\\", re.I)
SHADOW_DEL = re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.*recoveryenabled\s+no|wbadmin\s+delete\s+(catalog|backup)|resize\s+shadowstorage|Remove-CimInstance.*Win32_ShadowCopy", re.I)
LOLBIN = [
    (re.compile(r"powershell.*\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.I), "PowerShell encoded command", "T1059"),
    (re.compile(r"powershell.*(downloadstring|downloadfile|iex\s*\(|invoke-expression|-w(indowstyle)?\s+hidden)", re.I), "PowerShell download/hidden/IEX", "T1059"),
    (re.compile(r"certutil.*(-urlcache|-decode|-encode)", re.I), "certutil used for download/decode", "T1218"),
    (re.compile(r"(mshta|regsvr32|rundll32)(\.exe)?.*(https?://|javascript:|scrobj)", re.I), "Script/DLL proxy execution with remote or script payload", "T1218"),
    (re.compile(r"bitsadmin.*/transfer", re.I), "bitsadmin transfer", "T1218"),
]
BROWSERISH = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "teams.exe", "onedrive.exe", "outlook.exe", "slack.exe", "zoom.exe", "svchost.exe", "code.exe", "spotify.exe", "discord.exe"}
COMMON_PORTS = {80, 443, 53, 8080, 8443, 993, 995, 587, 465, 143, 110, 5228, 5222}
SEV_W = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}


def _priv(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
        return a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast
    except Exception:
        return True


def _mod(snap, name):
    m = snap.get("modules", {}).get(name, {})
    return m.get("data") if m.get("status") == "ok" else None


def _f(rid, name, tech, sev, desc, evidence, module):
    return {"rule_id": rid, "rule_name": name, "technique": tech, "severity": sev, "description": desc,
            "evidence": evidence, "module": module, "compliance": MAP.get(tech, {})}


def evaluate(snap):
    F = []
    procs = _mod(snap, "processes") or []
    pid_name = {p.get("ProcessId"): (p.get("Name") or "").lower() for p in procs}
    for p in procs:
        cl, path, nm = p.get("CommandLine") or "", p.get("ExecutablePath") or "", (p.get("Name") or "")
        ev = {"pid": p.get("ProcessId"), "name": nm, "parent": p.get("ParentName"), "path": path, "cmd": cl[:300]}
        if SHADOW_DEL.search(cl):
            F.append(_f("WIN-001", "Recovery inhibition command line", "T1490", "critical", "A running process carries a shadow-copy/backup deletion command.", ev, "processes"))
        for rx, label, tech in LOLBIN:
            if rx.search(cl):
                F.append(_f("WIN-002", label, tech, "high", "Living-off-the-land binary with a suspicious argument pattern.", ev, "processes")); break
        if path and USER_WRITABLE.search(path) and nm.lower() not in ("onedrive.exe", "teams.exe", "code.exe", "discord.exe", "slack.exe", "spotify.exe"):
            F.append(_f("WIN-003", "Process running from user-writable path", "T1036", "medium", "Executable lives in Temp/AppData/Downloads/ProgramData/Public -- common for droppers, also for per-user apps.", ev, "processes"))
        if nm.lower() in ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe") and (p.get("ParentName") or "").lower() in ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "acrord32.exe"):
            F.append(_f("WIN-004", "Script interpreter spawned by Office/PDF app", "T1059", "high", "Classic macro/document-borne execution chain.", ev, "processes"))

    for t in _mod(snap, "tasks") or []:
        act = t.get("Actions") or ""
        if not act: continue
        ev = {k: t.get(k) for k in ("Name", "Path", "State", "Author", "RunAs")}; ev["actions"] = act[:300]
        non_ms = not (t.get("Path") or "").lower().startswith("\\microsoft\\")
        bad = USER_WRITABLE.search(act) or any(rx.search("powershell " + act) for rx, _, _ in LOLBIN[:2]) or SHADOW_DEL.search(act)
        if non_ms and bad:
            F.append(_f("WIN-005", "Scheduled task runs from risky path/command", "T1053", "high", "Non-Microsoft task whose action is a user-writable path, encoded/hidden PowerShell or recovery-inhibition command.", ev, "tasks"))

    conns = _mod(snap, "network") or []
    for c in conns:
        pn = pid_name.get(c.get("OwningProcess"), "?")
        ev = {"process": pn, "pid": c.get("OwningProcess"), "local": f'{c.get("LocalAddress")}:{c.get("LocalPort")}', "remote": f'{c.get("RemoteAddress")}:{c.get("RemotePort")}', "state": c.get("State")}
        st = str(c.get("State"))
        if st in ("Established",) and not _priv(c.get("RemoteAddress") or "") and c.get("RemotePort") not in COMMON_PORTS and pn not in BROWSERISH:
            F.append(_f("WIN-006", "Outbound connection on unusual port", "T1071", "medium", "Established external connection from a non-browser process on a non-standard port.", ev, "network"))
        if st == "Listen" and c.get("LocalPort") in (445, 3389, 5985, 5986, 23, 21) and c.get("LocalAddress") in ("0.0.0.0", "::"):
            F.append(_f("WIN-007", "Remote-service port listening on all interfaces", "T1021", "medium", "SMB/RDP/WinRM/Telnet/FTP bound to every interface -- confirm it is intended and firewalled.", ev, "network"))

    sh = _mod(snap, "shadow")
    if sh is not None and len(sh) == 0:
        F.append(_f("WIN-008", "No shadow copies present", "T1490", "medium", "Zero VSS snapshots. Normal on many clients, but also the post-state of recovery inhibition; compare with expected backup policy.", {"shadow_copy_count": 0}, "shadow"))

    for a in _mod(snap, "autoruns") or []:
        if USER_WRITABLE.search(a.get("Value") or "") or any(rx.search("powershell " + (a.get("Value") or "")) for rx, _, _ in LOLBIN[:2]):
            F.append(_f("WIN-009", "Autorun entry points to risky location/command", "T1547", "medium", "Run/RunOnce value launches from a user-writable path or encoded/hidden PowerShell.", a, "autoruns"))

    d = _mod(snap, "defender")
    if d:
        row = d[0]
        off = [k for k in ("RealTimeProtectionEnabled", "AntivirusEnabled", "BehaviorMonitorEnabled", "TamperProtectionEnabled") if row.get(k) is False]
        if off:
            F.append(_f("WIN-010", "Defender protection disabled", "T1562", "high", "One or more Microsoft Defender protections report disabled: " + ", ".join(off), row, "defender"))

    fm = snap.get("modules", {}).get("files", {})
    if fm.get("status") == "ok":
        hits = fm["data"].get("hits", [])
        exts = [h for h in hits if h["kind"] == "ransom_extension"]; notes = [h for h in hits if h["kind"] == "ransom_note_name"]
        if exts:
            F.append(_f("WIN-011", "Ransomware-style file extensions found", "T1486", "critical" if len(exts) >= 5 else "high", f"{len(exts)} file(s) carry known ransomware extensions.", {"count": len(exts), "samples": exts[:10]}, "files"))
        if notes:
            F.append(_f("WIN-012", "Ransom-note-like filenames found", "T1486", "high", f"{len(notes)} file(s) named like ransom notes.", {"count": len(notes), "samples": notes[:10]}, "files"))

    score = min(100, sum(SEV_W[f["severity"]] for f in F))
    sev_counts = {s: sum(1 for f in F if f["severity"] == s) for s in ("critical", "high", "medium", "low")}
    mods = {m: {"status": r.get("status"), "error": r.get("error"), "count": (len(r["data"]) if isinstance(r.get("data"), list) else len((r.get("data") or {}).get("hits", []))), "seconds": r.get("seconds")} for m, r in snap.get("modules", {}).items()}
    return {"findings": F, "risk_score": score, "severity_counts": sev_counts, "module_status": mods}
