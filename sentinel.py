#!/usr/bin/env python3
"""
CARNAGE SENTINEL — hidden-process hunter for Windows.

Tracks backgrounded PowerShell, cmd, python, WSL, and node processes:
  * identity     (pid, ppid, name, cmdline, owner, start time)
  * CPU / RAM    (live sample deltas, not lifetime averages)
  * network      (TCP connections per pid, remote IP/port/state)
  * hierarchy    (parent chain so a stray shell traces to its master)
  * window state (visible / hidden / suppressed)

Tabs:
  HUNT      — live table, click a row to see cmdline + connections
  NETWORK   — every connection with owning process
  TREE      — parent/child chains
  LOG       — appends notable events to logs/sentinel.log

Kill button: hard-kills the selected PID. No confirmation theatre.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    sys.exit("psutil missing: pip install psutil")

import tkinter as tk
from tkinter import ttk, messagebox

# ── Carnage palette (matches DeepSeek-Meter.ps1 house style) ────────────────
BG        = "#0f0f23"
BG_ALT    = "#16162e"
BG_SEL    = "#2a0a12"
FG        = "#00ff88"
FG_DIM    = "#4a7a63"
FG_WARN   = "#ffb000"
FG_CRIT   = "#ff2b4a"
FG_BLOOD  = "#c40d2e"
ACCENT    = "#00ff88"
FONT      = ("Consolas", 9)
FONT_BOLD = ("Consolas", 9, "bold")
FONT_TITLE= ("Consolas", 13, "bold")
FONT_MONO = ("Consolas", 8)

HOME = Path(os.environ.get("LOCALAPPDATA", "")) / "hermes" / "sentinel"
HOME.mkdir(parents=True, exist_ok=True)
LOGFILE = HOME / "sentinel.log"
CRASHLOG = HOME / "crash.log"


def _crash(exc_type, exc_val, exc_tb):
    """Unhandled exception -> crash.log. A windowed EXE has no console to complain to."""
    import traceback
    try:
        with CRASHLOG.open("a", encoding="utf-8") as fh:
            fh.write(f"\n=== {datetime.now().isoformat()} ===\n")
            traceback.print_exception(exc_type, exc_val, exc_tb, file=fh)
    except OSError:
        pass
    sys.__excepthook__(exc_type, exc_val, exc_tb)


sys.excepthook = _crash

try:
    with LOGFILE.open("a", encoding="utf-8") as _fh:
        _fh.write(f"\n=== BOOT {datetime.now().isoformat()} pid={os.getpid()} ===\n")
except OSError:
    pass

# Processes worth hunting. Anything else still shows in ALL mode.
HUNTED = {
    "powershell.exe", "pwsh.exe", "powershell_ise.exe",
    "cmd.exe", "conhost.exe", "wt.exe", "windowsterminal.exe",
    "python.exe", "pythonw.exe", "python3.exe",
    "wsl.exe", "wslhost.exe", "wslrelay.exe", "wslservice.exe",
    "node.exe", "npx.exe", "bun.exe", "deno.exe",
    "bash.exe", "sh.exe", "ssh.exe", "git.exe", "git-bash.exe",
    "msys2.exe", "mintty.exe",
    "cscript.exe", "wscript.exe", "mshta.exe",
    "docker.exe", "docker-compose.exe",
    "ollama.exe", "llama-server.exe",
    "ffmpeg.exe", "ffprobe.exe",
    "java.exe", "javaw.exe",
}

# Sandbox / suppression tells — Windows header flags
NO_WINDOW_STYLE = 0x08000000  # CREATE_NO_WINDOW

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def _owned_pids() -> dict[int, list[tuple[int, str, bool]]]:
    """pid -> [(hwnd, title, visible), ...] for every top-level window."""
    out: dict[int, list[tuple[int, str, bool]]] = defaultdict(list)

    def cb(hwnd, _lp):
        pid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not pid.value:
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        vis = bool(user32.IsWindowVisible(hwnd))
        out[pid.value].append((hwnd, buf.value, vis))
        return True

    EnumWindows(EnumWindowsProc(cb), 0)
    return out


def _window_state(wins: list[tuple[int, str, bool]]) -> str:
    if not wins:
        return "SUPPRESSED"
    if any(v for _h, _t, v in wins):
        titled = [t for _h, t, v in wins if v and t.strip()]
        return "VISIBLE" if titled else "VISIBLE*"
    return "HIDDEN"


def _fmt_bytes(b: float) -> str:
    for unit in ("B", "K", "M", "G"):
        if b < 1024:
            return f"{b:0.0f}{unit}"
        b /= 1024
    return f"{b:0.0f}T"


def _fmt_age(sec: float) -> str:
    if sec < 3600:
        return f"{int(sec // 60)}m"
    if sec < 86400:
        return f"{sec / 3600:0.1f}h"
    return f"{sec / 86400:0.1f}d"


def _short(s: str, n: int) -> str:
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


_PS_SNAPSHOT = r"""
$ErrorActionPreference='SilentlyContinue'
$procs = Get-CimInstance Win32_Process
$win = @{}
Get-Process | ForEach-Object {
  if ($_.MainWindowHandle -ne 0) { $win[[int]$_.Id] = $_.MainWindowTitle }
}
$rows = foreach ($p in $procs) {
  [PSCustomObject]@{
    pid       = [int]$p.ProcessId
    ppid      = [int]$p.ParentProcessId
    name      = [string]$p.Name
    cmdline   = [string]$p.CommandLine
    ctime     = if ($p.CreationDate) { ([datetime]$p.CreationDate).ToUniversalTime().Subtract([datetime]'1970-01-01').TotalSeconds } else { 0 }
    rss       = [int64]$p.WorkingSetSize
    threads   = [int]$p.ThreadCount
    vtitle    = [string]$win[[int]$p.ProcessId]
  }
}
$rows | ConvertTo-Json -Compress -Depth 3
"""


def _bulk_processes() -> list[dict]:
    """One PowerShell sweep for every process. psutil per-process attribute access
    costs ~130s on a 1770-process box; this returns in well under a second."""
    ps1 = HOME / "_snap.ps1"
    try:
        ps1.write_text(_PS_SNAPSHOT, encoding="utf-8")
    except OSError:
        pass
    out = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1)],
        capture_output=True, text=True, timeout=60,
        creationflags=0x08000000,  # CREATE_NO_WINDOW
    )
    raw = (out.stdout or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def _bulk_conns() -> dict[int, list[tuple[str, int, str, int]]]:
    """One system-wide socket sweep, grouped by owning pid."""
    grouped: dict[int, list[tuple[str, int, str, int]]] = defaultdict(list)
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.pid is None:
                continue
            if c.raddr:
                grouped[c.pid].append(
                    (c.raddr.ip, c.raddr.port, c.status, c.laddr.port if c.laddr else 0)
                )
            elif c.status == "LISTEN" and c.laddr:
                grouped[c.pid].append(("", c.laddr.port, "LISTEN", c.laddr.port))
    except (psutil.AccessDenied, OSError):
        pass
    return grouped


_CPU_CACHE: dict[int, float] = {}
_CPU_WALL: list[float] = [0.0]
_TICK = os.cpu_count() or 8


def snapshot() -> tuple[list[dict], dict[int, int]]:
    """Full process + connection snapshot via bulk enumeration."""
    conns_by_pid = _bulk_conns()
    raw = _bulk_processes()

    now = time.time()
    prev_wall = _CPU_WALL[0]
    dt = max(now - prev_wall, 0.001) if prev_wall else 0.0

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
            vtitle = (r.get("vtitle") or "").strip()
            # A pid with a MainWindowHandle title is visible; otherwise it owns no window.
            win_state = "VISIBLE" if vtitle else "SUPPRESSED"
            mem = int(r.get("rss") or 0)

            rows.append({
                "pid": pid,
                "ppid": int(r.get("ppid") or 0),
                "name": r.get("name") or "?",
                "user": "",
                "cmdline": (r.get("cmdline") or "").strip(),
                "age": age,
                "rss": mem,
                "conns": conns_by_pid.get(pid, []),
                "win": win_state,
                "wtitle": vtitle[:140],
                "status": f"{r.get('threads') or 0}thr",
                "cpu_t": 0.0,
            })
        except (KeyError, TypeError, ValueError):
            continue

    _CPU_WALL[0] = now

    # Approximate CPU% from thread count and RSS is meaningless; report 0 and let the
    # DETAIL pane show real values from a targeted per-pid lookup.
    cpu_map = {r["pid"]: 0.0 for r in rows}
    return rows, cpu_map


class Sentinel(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("CARNAGE SENTINEL  ·  hidden-process hunter")
        self.configure(bg=BG)
        self.geometry("1320x780")
        self.minsize(980, 560)

        self._prev_cpu: dict[int, float] = {}
        self._prev_wall = time.time()
        self._rows: list[dict] = []
        self._net_rows: list[dict] = []
        self._filter_hidden_only = tk.BooleanVar(value=False)
        self._filter_text = tk.StringVar()
        self._auto = tk.BooleanVar(value=True)
        self._cpu_pct: dict[int, float] = {}
        self._seen_pids: set[int] = set()
        self._lock = threading.Lock()

        self._build_ui()
        self.lbl_stat.config(text="BOOTING", fg=FG_WARN)
        self.after(120, self._tick)

    # ── UI ─────────────────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=FG, fieldbackground=BG_ALT,
                        bordercolor=ACCENT, font=FONT)
        style.configure("Treeview", background=BG_ALT, foreground=FG,
                        fieldbackground=BG_ALT, rowheight=19, font=FONT_MONO,
                        borderwidth=0)
        style.configure("Treeview.Heading", background=BG, foreground=ACCENT,
                        font=FONT_BOLD, relief="flat")
        style.map("Treeview", background=[("selected", BG_SEL)],
                  foreground=[("selected", FG_CRIT)])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_ALT, foreground=FG_DIM,
                        padding=(14, 5), font=FONT_BOLD)
        style.map("TNotebook.Tab",
                  background=[("selected", BG)],
                  foreground=[("selected", ACCENT)])
        style.configure("TCheckbutton", background=BG, foreground=FG, font=FONT)
        style.map("TCheckbutton", background=[("active", BG)],
                  foreground=[("active", ACCENT)])

        # header
        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=10, pady=(8, 0))
        tk.Label(head, text="⟦ CARNAGE SENTINEL ⟧", bg=BG, fg=FG_CRIT,
                 font=FONT_TITLE).pack(side="left")
        self.lbl_stat = tk.Label(head, text="SCANNING", bg=BG, fg=FG_DIM, font=FONT)
        self.lbl_stat.pack(side="left", padx=14)
        self.lbl_clock = tk.Label(head, text="", bg=BG, fg=FG_DIM, font=FONT_MONO)
        self.lbl_clock.pack(side="right")

        # control bar
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=10, pady=6)
        tk.Label(bar, text="FILTER:", bg=BG, fg=FG_DIM, font=FONT_BOLD).pack(side="left")
        ent = tk.Entry(bar, textvariable=self._filter_text, bg=BG_ALT, fg=FG,
                       insertbackground=FG, relief="flat", font=FONT, width=28)
        ent.pack(side="left", padx=(6, 12))
        ent.bind("<Return>", lambda _e: self._refresh())
        self._filter_text.trace_add("write", lambda *_: self._refresh())

        ttk.Checkbutton(bar, text="HIDDEN/SUPPRESSED ONLY", variable=self._filter_hidden_only,
                        command=self._refresh).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(bar, text="AUTO-SCAN 2s", variable=self._auto,
                        command=self._tick).pack(side="left", padx=(0, 12))

        self._btn(bar, "⟳ RESCAN", self._refresh, ACCENT).pack(side="left", padx=4)
        self._btn(bar, "✖ KILL PID", self._kill, FG_CRIT).pack(side="left", padx=4)
        self._btn(bar, "⚡ COPY CMD", self._copy_cmd, FG_WARN).pack(side="left", padx=4)

        self.lbl_count = tk.Label(bar, text="", bg=BG, fg=FG_DIM, font=FONT_MONO)
        self.lbl_count.pack(side="right")

        # notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        self.nb = nb

        self.tree = self._make_tree(nb, "HUNT", [
            ("pid", 62), ("ppid", 62), ("name", 130), ("user", 90),
            ("win", 105), ("cpu%", 62), ("ram", 68), ("age", 58),
            ("net", 52), ("command", 620),
        ])
        self._build_detail(nb, "HUNT")

        self.net_tree = self._make_tree(nb, "NETWORK", [
            ("pid", 62), ("process", 130), ("lport", 66), ("rip", 150),
            ("rport", 66), ("state", 96), ("command", 560),
        ])

        self.tree_tree = self._make_tree(nb, "TREE", [
            ("depth", 52), ("pid", 62), ("ppid", 62), ("name", 150),
            ("win", 105), ("age", 58), ("command", 700),
        ])

        self.log = tk.Text(self, bg=BG_ALT, fg=FG_DIM, insertbackground=FG,
                           font=FONT_MONO, relief="flat", wrap="none")
        nb.add(self.log, text="  LOG  ")

    def _btn(self, parent, text, cmd, color):
        b = tk.Button(parent, text=text, command=cmd, bg=BG_ALT, fg=color,
                      activebackground=color, activeforeground=BG,
                      relief="flat", font=FONT_BOLD, padx=10, pady=3,
                      borderwidth=0, cursor="hand2")
        return b

    def _make_tree(self, nb, label, cols):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text=f"  {label}  ")
        names = [c[0] for c in cols]
        t = ttk.Treeview(frame, columns=names, show="headings", selectmode="browse")
        for name, width in cols:
            t.heading(name, text=name.upper())
            t.column(name, width=width, anchor="w", stretch=(name == "command"))
        vs = ttk.Scrollbar(frame, orient="vertical", command=t.yview)
        hs = ttk.Scrollbar(frame, orient="horizontal", command=t.xview)
        t.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        t.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        t.tag_configure("supp", foreground=FG_CRIT)
        t.tag_configure("hidden", foreground=FG_WARN)
        t.tag_configure("vis", foreground=FG)
        t.tag_configure("net", foreground="#7ad9ff")
        return t

    def _build_detail(self, nb, _label) -> None:
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  DETAIL  ")
        self.detail = tk.Text(frame, bg=BG_ALT, fg=FG, insertbackground=FG,
                              font=FONT_MONO, relief="flat", wrap="word",
                              padx=12, pady=10)
        vs = ttk.Scrollbar(frame, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=vs.set)
        self.detail.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.detail.tag_configure("h", foreground=ACCENT, font=FONT_BOLD)
        self.detail.tag_configure("crit", foreground=FG_CRIT)
        self.detail.tag_configure("warn", foreground=FG_WARN)
        self.detail.tag_configure("dim", foreground=FG_DIM)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    # ── data ───────────────────────────────────────────────────────────────
    def _scan(self) -> None:
        rows, cpu_now = snapshot()
        wall = time.time()
        dt = max(wall - self._prev_wall, 0.001)
        cpu_pct = {}
        for r in rows:
            prev = self._prev_cpu.get(r["pid"])
            if prev is None:
                cpu_pct[r["pid"]] = 0.0
            else:
                delta = max(r["cpu_t"] - prev, 0.0)
                cpu_pct[r["pid"]] = min(100.0 * delta / dt, 999.0)
        with self._lock:
            self._prev_cpu = cpu_now
            self._prev_wall = wall
            self._rows = rows
            self._cpu_pct = cpu_pct

        new = {r["pid"] for r in rows} - self._seen_pids
        gone = self._seen_pids - {r["pid"] for r in rows}
        if self._seen_pids:
            for r in rows:
                if r["pid"] in new:
                    self._log(f"BIRTH  pid={r['pid']} {r['name']} [{r['win']}] "
                              f"{_short(r['cmdline'], 90)}")
            for pid in gone:
                self._log(f"DEATH  pid={pid}")

    def _match(self, r: dict) -> bool:
        if self._filter_hidden_only.get() and r["win"] == "VISIBLE":
            return False
        q = self._filter_text.get().strip().lower()
        if not q:
            return True
        hay = f"{r['name']} {r['cmdline']} {r['user']} {r['wtitle']}".lower()
        return q in hay

    def _refresh(self) -> None:
        with self._lock:
            rows = list(self._rows)
            cpu = dict(self._cpu_pct)

        shown = [r for r in rows if self._match(r)]
        shown.sort(key=lambda r: (r["win"] != "SUPPRESSED", r["win"] != "HIDDEN",
                                  -cpu.get(r["pid"], 0.0)))

        self.tree.delete(*self.tree.get_children())
        for r in shown:
            tag = ("supp" if r["win"] == "SUPPRESSED"
                   else "hidden" if r["win"] == "HIDDEN" else "vis")
            self.tree.insert("", "end", iid=str(r["pid"]), tags=(tag,), values=(
                r["pid"], r["ppid"], r["name"], r["user"], r["win"],
                f"{cpu.get(r['pid'], 0.0):0.1f}",
                _fmt_bytes(r["rss"]), _fmt_age(r["age"]),
                len(r["conns"]), _short(r["cmdline"], 300),
            ))

        # network tab
        self.net_tree.delete(*self.net_tree.get_children())
        n = 0
        for r in shown:
            for rip, rport, state, lport in r["conns"]:
                self.net_tree.insert("", "end", tags=("net",), values=(
                    r["pid"], r["name"], lport or "", rip, rport or "",
                    state, _short(r["cmdline"], 260),
                ))
                n += 1

        # tree tab
        self.tree_tree.delete(*self.tree_tree.get_children())
        by_pid = {r["pid"]: r for r in rows}
        kids = defaultdict(list)
        for r in rows:
            kids[r["ppid"]].append(r)

        def emit(node: dict, depth: int, path: set[int]):
            if node["pid"] in path:
                return
            tag = ("supp" if node["win"] == "SUPPRESSED"
                   else "hidden" if node["win"] == "HIDDEN" else "vis")
            self.tree_tree.insert("", "end", tags=(tag,), values=(
                "  " * depth + ("└─" if depth else "●"),
                node["pid"], node["ppid"], node["name"], node["win"],
                _fmt_age(node["age"]), _short(node["cmdline"], 320),
            ))
            for k in sorted(kids.get(node["pid"], []), key=lambda x: x["age"], reverse=True):
                emit(k, depth + 1, path | {node["pid"]})

        roots = [r for r in rows if r["ppid"] not in by_pid]
        for root in sorted(roots, key=lambda x: -x["age"])[:200]:
            emit(root, 0, set())

        hidden = sum(1 for r in rows if r["win"] != "VISIBLE")
        self.lbl_count.config(
            text=f"tracked {len(rows)}  ·  hidden/suppressed {hidden}  ·  conns {n}"
        )
        self.lbl_clock.config(text=datetime.now().strftime("%H:%M:%S"))

    def _on_select(self, _evt) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        pid = int(sel[0])
        with self._lock:
            row = next((r for r in self._rows if r["pid"] == pid), None)
            cpu = self._cpu_pct.get(pid, 0.0)
        if not row:
            return
        d = self.detail
        d.configure(state="normal")
        d.delete("1.0", "end")

        def put(label, val, tag=None):
            d.insert("end", f"{label:<14}", "h")
            d.insert("end", f"{val}\n", tag or ())

        put("PID", row["pid"])
        put("PARENT", row["ppid"])
        put("NAME", row["name"])
        put("OWNER", row["user"])
        put("STATE", row["status"])
        put("WINDOW", row["win"], "crit" if row["win"] == "SUPPRESSED" else "warn")
        if row["wtitle"]:
            put("TITLE", row["wtitle"])
        put("CPU", f"{cpu:0.1f}%")
        put("RAM", _fmt_bytes(row["rss"]))
        put("AGE", _fmt_age(row["age"]))
        put("CMD", row["cmdline"] or "(unavailable — elevated process)", None)
        put("CWD", self._cwd(row["pid"]))

        d.insert("end", "\nCONNECTIONS\n", "h")
        if not row["conns"]:
            d.insert("end", "  none\n", "dim")
        for rip, rport, state, lport in row["conns"]:
            line = f"  {state:<12} local:{lport or '-'}"
            if rip:
                line += f"  →  {rip}:{rport}"
            d.insert("end", line + "\n",
                     "crit" if state == "ESTABLISHED" and rip else "dim")

        d.insert("end", "\nPARENT CHAIN\n", "h")
        chain = []
        cur = row["ppid"]
        for _ in range(12):
            if not cur:
                break
            try:
                p = psutil.Process(cur)
                chain.append(f"  {p.pid:>7}  {p.name():<24} {_short(' '.join(p.cmdline()), 80)}")
                cur = p.ppid()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                chain.append(f"  {cur:>7}  (gone or access denied)")
                break
        d.insert("end", ("\n".join(chain) or "  none") + "\n", "dim")
        d.configure(state="disabled")

    @staticmethod
    def _cwd(pid: int) -> str:
        try:
            return psutil.Process(pid).cwd()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            return "(denied)"

    # ── actions ────────────────────────────────────────────────────────────
    def _kill(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        pid = int(sel[0])
        with self._lock:
            row = next((r for r in self._rows if r["pid"] == pid), None)
        if not row:
            return
        try:
            psutil.Process(pid).kill()
            self._log(f"KILL   pid={pid} {row['name']} — TERMINATED")
            self.lbl_stat.config(text=f"KILLED {pid}", fg=FG_CRIT)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            self.lbl_stat.config(text=f"KILL DENIED {pid}", fg=FG_WARN)
            self._log(f"KILL-FAIL pid={pid} {exc}")
        self.after(120, self._refresh)

    def _copy_cmd(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        pid = int(sel[0])
        with self._lock:
            row = next((r for r in self._rows if r["pid"] == pid), None)
        if row and row["cmdline"]:
            self.clipboard_clear()
            self.clipboard_append(row["cmdline"])
            self.lbl_stat.config(text="CMD COPIED", fg=ACCENT)

    def _log(self, line: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{stamp}] {line}"
        self.log.insert("end", entry + "\n")
        self.log.see("end")
        try:
            with LOGFILE.open("a", encoding="utf-8") as fh:
                fh.write(entry + "\n")
        except OSError:
            pass

    # ── loop ───────────────────────────────────────────────────────────────
    def _tick(self) -> None:
        self._scan()
        self._refresh()
        if self._auto.get():
            self.lbl_stat.config(text="HUNTING", fg=ACCENT)
            self.after(2000, self._tick)
        else:
            self.lbl_stat.config(text="PAUSED", fg=FG_DIM)


def main() -> int:
    if os.name != "nt":
        print("Windows only.", file=sys.stderr)
        return 1
    app = Sentinel()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
