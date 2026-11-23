"""CARNAGE SENTINEL v1.1 — detection layer.

Session-aware process/window/connection enumeration. Everything that touches
Win32 lives here so the GUI stays a rendering concern.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import os
import re
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:  # pragma: no cover
    import sys
    sys.exit("psutil missing: pip install psutil")

HOME = Path(os.environ.get("LOCALAPPDATA", "")) / "hermes" / "sentinel"
HOME.mkdir(parents=True, exist_ok=True)

# ── process families worth hunting ─────────────────────────────────────────
SHELLS = {
    "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cmd.exe", "conhost.exe",
    "wt.exe", "windowsterminal.exe", "openconsole.exe",
}
INTERPRETERS = {
    "python.exe", "pythonw.exe", "python3.exe", "py.exe", "pyshell.exe",
    "node.exe", "npx.exe", "bun.exe", "deno.exe", "ruby.exe", "perl.exe", "php.exe",
    "java.exe", "javaw.exe", "dotnet.exe", "mono.exe",
}
POSIX = {
    "bash.exe", "sh.exe", "ssh.exe", "git.exe", "git-bash.exe", "msys2.exe",
    "mintty.exe", "wsl.exe", "wslhost.exe", "wslrelay.exe", "wslservice.exe",
    "wslg.exe", "vmmemwsl.exe",
}
SCRIPTHOSTS = {"cscript.exe", "wscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe"}
RUNTIMES = {"docker.exe", "docker-compose.exe", "ollama.exe", "llama-server.exe", "com.docker.backend.exe"}
MEDIA = {"ffmpeg.exe", "ffprobe.exe", "obs64.exe", "vlc.exe"}
REMOTE = {"teamviewer.exe", "rustdesk.exe", "anydesk.exe", "vncserver.exe", "winvnc.exe", "mstsc.exe"}

HUNTED = SHELLS | INTERPRETERS | POSIX | SCRIPTHOSTS | RUNTIMES | MEDIA | REMOTE

FAMILY = {}
for _name in HUNTED:
    if _name in SHELLS:
        FAMILY[_name] = "shell"
    elif _name in INTERPRETERS:
        FAMILY[_name] = "interp"
    elif _name in POSIX:
        FAMILY[_name] = "posix"
    elif _name in SCRIPTHOSTS:
        FAMILY[_name] = "scripthost"
    elif _name in RUNTIMES:
        FAMILY[_name] = "runtime"
    elif _name in MEDIA:
        FAMILY[_name] = "media"
    else:
        FAMILY[_name] = "remote"

# ── command-line patterns that raise the threat score ──────────────────────
SUSPICIOUS = [
    (re.compile(r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I), 60, "encoded PowerShell command"),
    (re.compile(r"-e\s+[A-Za-z0-9+/=]{40,}", re.I), 45, "possible base64 arg"),
    (re.compile(r"-nop\b|-noprofile\b", re.I), 12, "no profile"),
    (re.compile(r"-w(indowstyle)?\s+hidden", re.I), 50, "hidden window style"),
    (re.compile(r"-exec(utionpolicy)?\s+bypass", re.I), 25, "policy bypass"),
    (re.compile(r"downloadstring|downloadfile|invoke-webrequest|iwr\b|curl\s+http|wget\s+http", re.I), 40, "remote payload fetch"),
    (re.compile(r"frombase64string|base64\s*-d|\[convert\]::", re.I), 40, "decode operation"),
    (re.compile(r"iex\b|invoke-expression", re.I), 45, "dynamic execution"),
    (re.compile(r"-c\s+\S+\s*;|powershell.*powershell", re.I), 30, "nested shell"),
    (re.compile(r"\bnetsh\b.*(firewall|advfirewall).*(disable|add rule)", re.I), 55, "firewall tampering"),
    (re.compile(r"vssadmin.*delete.*shadows|wbadmin.*delete", re.I), 65, "shadow copy deletion"),
    (re.compile(r"bcdedit.*(recoveryenabled|bootstatuspolicy)", re.I), 50, "boot config change"),
    (re.compile(r"schtasks.*\/create|sc\s+create|new-service", re.I), 35, "persistence"),
    (re.compile(r"reg\s+add.*\\run|currentversion\\\\run", re.I), 45, "run-key persistence"),
    (re.compile(r"mimikatz|sekurlsa|lsass\.dmp|procdump.*lsass", re.I), 80, "credential access"),
    (re.compile(r"nc\s+-e|ncat\s+-e|socat.*exec|/bin/sh\s+-i", re.I), 70, "reverse shell"),
    (re.compile(r"-ep\s+bypass|-exec\s+bypass", re.I), 25, "execution policy"),
    (re.compile(r"\btemp\\|\\appdata\\local\\temp|/tmp/", re.I), 15, "temp-directory execution"),
]

LOLBINS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "cscript.exe", "wscript.exe"}

# ── Win32 bindings ─────────────────────────────────────────────────────────
user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)

EnumWindowsProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

_WINSTA_ALL_ACCESS = 0x37F
_DESKTOP_ALL_ACCESS = 0x01FF
_UOI_NAME = 2

GW_OWNER = 4
GW_CHILD = 5


class WTS_SESSION_INFO(ctypes.Structure):
    _fields_ = [
        ("SessionId", wt.DWORD),
        ("pWinStationName", wt.LPWSTR),
        ("State", wt.DWORD),
    ]


def my_session() -> int:
    sid = wt.DWORD()
    kernel32.ProcessIdToSessionId(kernel32.GetCurrentProcessId(), ctypes.byref(sid))
    return sid.value


def process_session(pid: int) -> int:
    sid = wt.DWORD()
    if kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid)):
        return sid.value
    return -1


def list_sessions() -> list[tuple[int, str, int]]:
    """(session_id, station_name, state). 0=Services, 1=Console."""
    p_si = ctypes.POINTER(WTS_SESSION_INFO)()
    count = wt.DWORD()
    if not wtsapi32.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(p_si), ctypes.byref(count)):
        return []
    out = []
    try:
        for i in range(count.value):
            s = p_si[i]
            out.append((int(s.SessionId), s.pWinStationName or "", int(s.State)))
    finally:
        wtsapi32.WTSFreeMemory(p_si)
    return out


def _enumerate_desktop(hdesk) -> dict[int, list[dict]]:
    """Enumerate windows on one desktop handle."""
    found: dict[int, list[dict]] = defaultdict(list)

    def cb(hwnd, _lp):
        pid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not pid.value:
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        title = ""
        if length:
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value
        cls = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, cls, 256)
        found[pid.value].append({
            "hwnd": int(hwnd),
            "title": title,
            "class": cls.value,
            "visible": bool(user32.IsWindowVisible(hwnd)),
            "owner": bool(user32.GetWindow(hwnd, GW_OWNER)),
            "child": bool(user32.GetWindow(hwnd, GW_CHILD)),
        })
        return True

    try:
        user32.EnumWindows(EnumWindowsProc(cb), 0)
    except OSError:
        pass
    return found


def _desktop_windows_for_session(session_id: int) -> dict[int, list[dict]]:
    """Windows on another logon session's default desktop.

    Requires SeTcbPrivilege to switch window stations properly; without it the
    attempt fails cleanly and the caller falls back to MainWindowHandle data.
    """
    ws_name = f"WinSta0"
    hws = user32.OpenWindowStationW(ws_name, False, _WINSTA_ALL_ACCESS)
    if not hws:
        return {}
    try:
        user32.SetProcessWindowStation(hws)
        hd = user32.OpenDesktopW("Default", 0, False, _DESKTOP_ALL_ACCESS)
        if not hd:
            return {}
        try:
            user32.SetThreadDesktop(hd)
            return _enumerate_desktop(hd)
        finally:
            user32.CloseDesktop(hd)
    finally:
        user32.CloseWindowStation(hws)


def collect_windows() -> dict[int, list[dict]]:
    """Best-effort window map. Local desktop first, then other sessions."""
    mine = my_session()
    merged = dict(_enumerate_desktop(None))
    for sid, name, _state in list_sessions():
        if sid == mine or sid <= 0:
            continue
        try:
            other = _desktop_windows_for_session(sid)
        except OSError:
            other = {}
        for pid, wins in other.items():
            merged.setdefault(pid, []).extend(wins)
    return merged


def window_state(wins: list[dict]) -> str:
    """Classify window absence — the core signal."""
    if not wins:
        return "NO-WINDOW"
    visible = [w for w in wins if w["visible"]]
    if visible:
        titled = [w for w in visible if w["title"].strip()]
        if titled:
            return "VISIBLE"
        return "VISIBLE-UNTITLED"
    # Owns windows, all hidden
    if any(w["title"].strip() for w in wins):
        return "HIDDEN"
    return "HIDDEN-UNTITLED"


def threat_score(name: str, cmdline: str, win: str, conns: list, age: float) -> tuple[int, list[str]]:
    """Heuristic risk score 0-100 with human reasons."""
    score = 0
    reasons: list[str] = []
    low = (name or "").lower()

    if win in ("NO-WINDOW", "HIDDEN", "HIDDEN-UNTITLED"):
        score += 15
        reasons.append("no visible window")

    for pat, weight, label in SUSPICIOUS:
        if pat.search(cmdline or ""):
            score += weight
            reasons.append(label)

    if low in LOLBINS and cmdline:
        score += 20
        reasons.append("LOLBin execution")

    remote_conns = [c for c in conns if c[0] and c[2] == "ESTABLISHED"]
    if remote_conns:
        score += 10 + min(len(remote_conns) * 5, 25)
        reasons.append(f"{len(remote_conns)} live remote connection(s)")

    listening = [c for c in conns if c[2] == "LISTEN"]
    if listening and low in HUNTED:
        score += 8
        reasons.append(f"listening on {len(listening)} port(s)")

    if age > 604800:
        score += 5
        reasons.append("alive >7 days")

    if not cmdline and low in HUNTED:
        score += 12
        reasons.append("cmdline unreadable")

    return min(score, 100), reasons


_PS_SNAPSHOT = r"""
$ErrorActionPreference='SilentlyContinue'
$procs = Get-CimInstance Win32_Process
$win = @{}
$cpu = @{}
Get-Process | ForEach-Object {
  if ($_.MainWindowHandle -ne 0) { $win[[int]$_.Id] = $_.MainWindowTitle }
  $cpu[[int]$_.Id] = if ($null -ne $_.CPU) { [double]$_.CPU } else { 0 }
}
$rows = foreach ($p in $procs) {
  [PSCustomObject]@{
    pid     = [int]$p.ProcessId
    ppid    = [int]$p.ParentProcessId
    name    = [string]$p.Name
    cmdline = [string]$p.CommandLine
    ctime   = if ($p.CreationDate) { ([datetime]$p.CreationDate).ToUniversalTime().Subtract([datetime]'1970-01-01').TotalSeconds } else { 0 }
    rss     = [int64]$p.WorkingSetSize
    priv    = [int64]$p.PrivatePageCount
    threads = [int]$p.ThreadCount
    handles = [int]$p.HandleCount
    vtitle  = [string]$win[[int]$p.ProcessId]
    cputime = if ($null -ne $cpu[[int]$p.ProcessId]) { [double]$cpu[[int]$p.ProcessId] } else { 0 }
  }
}
$rows | ConvertTo-Json -Compress -Depth 3
"""


_SNAP_CACHE: dict[str, float] = {"mtime": 0.0}

_CPU_PREV: dict[int, tuple[float, float]] = {}
_LAST_WALL: list[float] = [0.0]


def bulk_processes() -> list[dict]:
    """One PowerShell sweep for every process in every session."""
    ps1 = HOME / "_snap.ps1"
    try:
        ps1.write_text(_PS_SNAPSHOT, encoding="utf-8")
        _SNAP_CACHE["mtime"] = ps1.stat().st_mtime
    except OSError:
        pass
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1)],
            capture_output=True, text=True, timeout=90,
            creationflags=0x08000000,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    raw = (out.stdout or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def bulk_conns() -> dict[int, list[tuple[str, int, str, int]]]:
    grouped: dict[int, list[tuple[str, int, str, int]]] = defaultdict(list)
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.pid is None:
                continue
            if c.raddr:
                grouped[c.pid].append((c.raddr.ip, c.raddr.port, c.status,
                                       c.laddr.port if c.laddr else 0))
            elif c.status == "LISTEN" and c.laddr:
                grouped[c.pid].append(("", c.laddr.port, "LISTEN", c.laddr.port))
    except (psutil.AccessDenied, OSError):
        pass
    return grouped


def _owner_of(pid: int) -> str:
    """Owner via psutil — a single cheap handle query, unlike WMI's GetOwner round-trip."""
    try:
        return psutil.Process(pid).username() or ""
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return ""


def snapshot() -> list[dict]:
    """Complete enriched snapshot. Returns rows sorted by threat score desc."""
    conns_by_pid = bulk_conns()
    raw = bulk_processes()
    wins_by_pid = collect_windows()

    now = time.time()
    prev_wall = _LAST_WALL[0]
    dt = max(now - prev_wall, 0.001) if prev_wall else 0.0
    mine = my_session()

    rows: list[dict] = []
    for r in raw:
        try:
            name = (r.get("name") or "").lower()
            if name not in HUNTED:
                continue
            pid = int(r.get("pid") or 0)
            if not pid:
                continue

            ctime = float(r.get("ctime") or 0.0)
            age = now - ctime if ctime else 0.0
            cmdline = (r.get("cmdline") or "").strip()
            wins = wins_by_pid.get(pid, [])
            cmd_wins = wins or ([{"title": r.get("vtitle"), "visible": True,
                                  "class": "", "hwnd": 0, "owner": False, "child": False}]
                                if (r.get("vtitle") or "").strip() else [])
            state = window_state(cmd_wins)
            conns = conns_by_pid.get(pid, [])

            cputime = float(r.get("cputime") or 0.0)
            prev = _CPU_PREV.get(pid)
            if prev and dt > 0 and pid in _CPU_PREV:
                d_cpu = max(cputime - prev[0], 0.0)
                cpu_pct = min(100.0 * d_cpu / dt, 400.0)
            else:
                cpu_pct = 0.0
            _CPU_PREV[pid] = (cputime, now)

            score, reasons = threat_score(name, cmdline, state, conns, age)

            owner = _owner_of(pid)

            rows.append({
                "pid": pid,
                "ppid": int(r.get("ppid") or 0),
                "name": r.get("name") or "?",
                "user": owner,
                "cmdline": cmdline,
                "age": age,
                "rss": int(r.get("rss") or 0),
                "priv": int(r.get("priv") or 0),
                "threads": int(r.get("threads") or 0),
                "handles": int(r.get("handles") or 0),
                "conns": conns,
                "win": state,
                "wtitle": " | ".join(w["title"] for w in cmd_wins if w.get("title", "").strip())[:160],
                "wcount": len(wins),
                "wclasses": sorted({w.get("class", "") for w in wins if w.get("class")})[:6],
                "family": FAMILY.get(name, "other"),
                "session": process_session(pid),
                "cross_session": process_session(pid) != mine,
                "cpu": cpu_pct,
                "threat": score,
                "reasons": reasons,
            })
        except (KeyError, TypeError, ValueError):
            continue

    _LAST_WALL[0] = now
    rows.sort(key=lambda r: (-r["threat"], r["win"] != "NO-WINDOW", -r["age"]))
    return rows


def cwd_of(pid: int) -> str:
    try:
        return psutil.Process(pid).cwd()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return "(denied)"


def parent_chain(pid: int, limit: int = 12) -> list[str]:
    out: list[str] = []
    try:
        cur = psutil.Process(pid).ppid()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return out
    for _ in range(limit):
        if not cur:
            break
        try:
            p = psutil.Process(cur)
            out.append(f"{p.pid:>7}  {p.name():<24} {' '.join(p.cmdline())[:110]}")
            cur = p.ppid()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            out.append(f"{cur:>7}  (gone or denied)")
            break
    return out
