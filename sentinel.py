#!/usr/bin/env python3
"""CARNAGE SENTINEL v1.1 — hidden-process, window and connection hunter.

New in v1.1 over v1.0:
  * session-aware enumeration (Sessions 0/1 exposed as a column, cross-session flagged)
  * 8-state window classifier instead of VISIBLE/SUPPRESSED (NO-WINDOW, HIDDEN,
    HIDDEN-UNTITLED, VISIBLE-UNTITLED, ...) with window class capture
  * heuristic threat score 0-100 with printed reasons
  * command-line pattern detection (encoded payloads, policy bypass, reverse shells,
    persistence, credential access)
  * per-process CPU from a real delta table, not a stub
  * structured JSONL event log + filterable list-viewer with timestamps and pids
  * connection-diff events: fires once when a socket appears, not every sweep

Tabs: HUNT · NETWORK · TREE · LOG · DETAIL
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import tkinter as tk
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from tkinter import ttk, filedialog

sys.path.insert(0, str(Path(__file__).resolve().parent))

import carnage_detect as detect
import carnage_log as clog

# ── palette ────────────────────────────────────────────────────────────────
BG       = "#0f0f23"
BG_ALT   = "#16162e"
BG_SEL   = "#2a0a12"
FG       = "#00ff88"
FG_DIM   = "#4a7a63"
FG_WARN  = "#ffb000"
FG_CRIT  = "#ff2b4a"
FG_BLOOD = "#c40d2e"
FG_WHITE = "#d8f5e8"
FG_CYAN  = "#7ad9ff"
ACCENT   = "#00ff88"
FONT       = ("Consolas", 9)
FONT_BOLD  = ("Consolas", 9, "bold")
FONT_TITLE = ("Consolas", 13, "bold")
FONT_MONO  = ("Consolas", 8)

CRASH = clog.HOME / "crash.log"


def _crash(exc_type, exc_val, exc_tb):
    import traceback
    try:
        with CRASH.open("a", encoding="utf-8") as fh:
            fh.write(f"\n=== {datetime.now().isoformat()} ===\n")
            traceback.print_exception(exc_type, exc_val, exc_tb, file=fh)
    except OSError:
        pass
    sys.__excepthook__(exc_type, exc_val, exc_tb)


sys.excepthook = _crash

WIN_TAG = {
    "NO-WINDOW": "supp",
    "HIDDEN": "hidden",
    "HIDDEN-UNTITLED": "hidden",
    "VISIBLE-UNTITLED": "warn",
    "VISIBLE": "vis",
}

KIND_COLORS = {
    "BIRTH": FG,
    "DEATH": FG_DIM,
    "ESCALATE": FG_CRIT,
    "CONNECT": FG_CYAN,
    "KILL": FG_BLOOD,
    "KILL-FAIL": FG_WARN,
    "BOOT": ACCENT,
    "NOTE": FG_DIM,
}


def fmt_bytes(b: float) -> str:
    for unit in ("B", "K", "M", "G"):
        if b < 1024:
            return f"{b:0.0f}{unit}"
        b /= 1024
    return f"{b:0.0f}T"


def fmt_age(sec: float) -> str:
    if sec < 3600:
        return f"{int(sec // 60)}m"
    if sec < 86400:
        return f"{sec / 3600:0.1f}h"
    return f"{sec / 86400:0.1f}d"


def short(s: str, n: int) -> str:
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


class Sentinel(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("CARNAGE SENTINEL v1.1  ·  hidden process / window / connection hunter")
        self.configure(bg=BG)
        self.geometry("1440x840")
        self.minsize(1080, 620)

        self._rows: list[dict] = []
        self._lock = threading.Lock()
        self._seen: dict[int, dict] = {}
        self._seen_conns: dict[int, set] = {}
        self._alerted: dict[int, int] = {}
        self._events: list[dict] = []
        self._filter_text = tk.StringVar()
        self._filter_hidden = tk.BooleanVar(value=False)
        self._filter_min_threat = tk.IntVar(value=0)
        self._auto = tk.BooleanVar(value=True)
        self._scanning = False
        self._last_scan_s = 0.0

        clog.record("BOOT", "sentinel v1.1 started",
                    pid=os.getpid(), name="CarnageSentinel",
                    session=detect.my_session(),
                    detail=f"enumerating from session {detect.my_session()}")

        self._build_ui()
        self._load_log()
        self.after(100, self._tick)

    # ── UI construction ────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=BG, foreground=FG, fieldbackground=BG_ALT, font=FONT)
        st.configure("Treeview", background=BG_ALT, foreground=FG, fieldbackground=BG_ALT,
                     rowheight=19, font=FONT_MONO, borderwidth=0)
        st.configure("Treeview.Heading", background=BG, foreground=ACCENT,
                     font=FONT_BOLD, relief="flat")
        st.map("Treeview", background=[("selected", BG_SEL)],
               foreground=[("selected", FG_CRIT)])
        st.configure("TNotebook", background=BG, borderwidth=0)
        st.configure("TNotebook.Tab", background=BG_ALT, foreground=FG_DIM,
                     padding=(14, 5), font=FONT_BOLD)
        st.map("TNotebook.Tab", background=[("selected", BG)],
               foreground=[("selected", ACCENT)])
        st.configure("TCheckbutton", background=BG, foreground=FG, font=FONT)
        st.map("TCheckbutton", background=[("active", BG)],
               foreground=[("active", ACCENT)])
        st.configure("TScale", background=BG, troughcolor=BG_ALT)

        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=10, pady=(8, 0))
        tk.Label(head, text="⟦ CARNAGE SENTINEL ⟧", bg=BG, fg=FG_CRIT,
                 font=FONT_TITLE).pack(side="left")
        self.lbl_stat = tk.Label(head, text="BOOTING", bg=BG, fg=FG_WARN, font=FONT)
        self.lbl_stat.pack(side="left", padx=14)
        self.lbl_session = tk.Label(head, text=f"session {detect.my_session()}",
                                    bg=BG, fg=FG_DIM, font=FONT_MONO)
        self.lbl_session.pack(side="right", padx=(0, 10))
        self.lbl_clock = tk.Label(head, text="", bg=BG, fg=FG_DIM, font=FONT_MONO)
        self.lbl_clock.pack(side="right", padx=10)

        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=10, pady=6)
        tk.Label(bar, text="FILTER", bg=BG, fg=FG_DIM, font=FONT_BOLD).pack(side="left")
        ent = tk.Entry(bar, textvariable=self._filter_text, bg=BG_ALT, fg=FG,
                       insertbackground=FG, relief="flat", font=FONT, width=26)
        ent.pack(side="left", padx=(6, 10))
        self._filter_text.trace_add("write", lambda *_: self._on_filter())

        ttk.Checkbutton(bar, text="HIDDEN ONLY", variable=self._filter_hidden,
                        command=self._refresh).pack(side="left", padx=(0, 8))

        tk.Label(bar, text="MIN THREAT", bg=BG, fg=FG_DIM, font=FONT_BOLD).pack(side="left", padx=(4, 0))
        self._threat_lbl = tk.Label(bar, text="0", bg=BG, fg=FG_CRIT, font=FONT_BOLD, width=3)
        self._threat_lbl.pack(side="left")
        sc = ttk.Scale(bar, from_=0, to=100, orient="horizontal", length=110,
                       command=self._on_threat)
        sc.set(0)
        sc.pack(side="left", padx=4)

        ttk.Checkbutton(bar, text="AUTO 2s", variable=self._auto,
                        command=self._tick).pack(side="left", padx=8)

        self._btn(bar, "⟳ RESCAN", self._force_scan, ACCENT).pack(side="left", padx=3)
        self._btn(bar, "✖ KILL", self._kill, FG_CRIT).pack(side="left", padx=3)
        self._btn(bar, "⧉ CMD", self._copy_cmd, FG_WARN).pack(side="left", padx=3)
        self._btn(bar, "⇩ EXPORT", self._export, FG_CYAN).pack(side="left", padx=3)

        self.lbl_count = tk.Label(bar, text="", bg=BG, fg=FG_DIM, font=FONT_MONO)
        self.lbl_count.pack(side="right")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(0, 6))

        self.tree = self._mk_tree("HUNT", [
            ("threat", 54), ("pid", 62), ("sess", 44), ("name", 128),
            ("family", 68), ("win", 118), ("cpu", 50), ("ram", 62),
            ("age", 52), ("conns", 50), ("user", 122), ("command", 540),
        ])
        self.net_tree = self._mk_tree("NETWORK", [
            ("threat", 54), ("pid", 62), ("process", 120), ("sess", 44),
            ("lport", 62), ("remote", 148), ("rport", 62), ("state", 92),
            ("command", 520),
        ])
        self.tree_tree = self._mk_tree("TREE", [
            ("depth", 56), ("pid", 62), ("ppid", 62), ("name", 140),
            ("win", 118), ("sess", 44), ("threat", 54), ("command", 640),
        ])
        self._build_log_tab()
        self._build_detail_tab()

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def _on_threat(self, val) -> None:
        v = int(float(val))
        self._threat_lbl.config(text=str(v))
        self._filter_min_threat.set(v)
        self._refresh()

    def _on_filter(self) -> None:
        self._refresh()
        self._render_log()

    def _btn(self, parent, text, cmd, color):
        return tk.Button(parent, text=text, command=cmd, bg=BG_ALT, fg=color,
                         activebackground=color, activeforeground=BG, relief="flat",
                         font=FONT_BOLD, padx=9, pady=3, borderwidth=0, cursor="hand2")

    def _mk_tree(self, label, cols):
        frame = tk.Frame(self.nb, bg=BG)
        self.nb.add(frame, text=f"  {label}  ")
        return self._tree_in(frame, cols)

    def _tree_in(self, frame, cols):
        names = [c[0] for c in cols]
        t = ttk.Treeview(frame, columns=names, show="headings", selectmode="browse")
        for name, width in cols:
            t.heading(name, text=name.upper())
            t.column(name, width=width, anchor="w",
                     stretch=(name in ("command", "remote", "message", "detail")))
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
        t.tag_configure("warn", foreground=FG_WARN)
        t.tag_configure("net", foreground=FG_CYAN)
        for kind, color in KIND_COLORS.items():
            t.tag_configure(kind, foreground=color)
        return t

    def _build_log_tab(self) -> None:
        frame = tk.Frame(self.nb, bg=BG)
        self.nb.add(frame, text="  LOG  ")

        ctl = tk.Frame(frame, bg=BG)
        ctl.pack(fill="x", pady=(4, 2))
        tk.Label(ctl, text="KIND", bg=BG, fg=FG_DIM, font=FONT_BOLD).pack(side="left")
        self._log_kinds = {}
        for kind in clog.KINDS:
            v = tk.BooleanVar(value=True)
            self._log_kinds[kind] = v
            ttk.Checkbutton(ctl, text=kind, variable=v,
                            command=self._render_log).pack(side="left", padx=(4, 0))
        self._btn(ctl, "⟳ RELOAD", self._load_log, ACCENT).pack(side="right", padx=3)
        self._btn(ctl, "⇩ SAVE", self._save_log, FG_CYAN).pack(side="right", padx=3)

        wrap = tk.Frame(frame, bg=BG)
        wrap.pack(fill="both", expand=True)
        self._log_tree = self._tree_in(wrap, [
            ("ts", 78), ("kind", 92), ("pid", 62), ("name", 132), ("win", 112),
            ("sess", 44), ("threat", 54), ("message", 280), ("detail", 400),
        ])

    def _build_detail_tab(self) -> None:
        frame = tk.Frame(self.nb, bg=BG)
        self.nb.add(frame, text="  DETAIL  ")
        self.detail = tk.Text(frame, bg=BG_ALT, fg=FG, insertbackground=FG,
                              font=FONT_MONO, relief="flat", wrap="word",
                              padx=12, pady=10)
        vs = ttk.Scrollbar(frame, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=vs.set)
        self.detail.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        for tag, color in (("h", ACCENT), ("crit", FG_CRIT), ("warn", FG_WARN),
                           ("dim", FG_DIM), ("cyan", FG_CYAN), ("white", FG_WHITE)):
            self.detail.tag_configure(tag, foreground=color,
                                      font=FONT_BOLD if tag == "h" else FONT_MONO)

    # ── scanning ───────────────────────────────────────────────────────────
    def _force_scan(self) -> None:
        if self._scanning:
            return
        self._scan()
        self._refresh()

    def _scan(self) -> None:
        self._scanning = True
        t0 = time.time()
        try:
            rows = detect.snapshot()
        finally:
            self._last_scan_s = time.time() - t0
            self._scanning = False

        with self._lock:
            prev_pids = set(self._seen)
            prev_conn_sets = dict(self._seen_conns)
            self._rows = rows

        cur_pids = {r["pid"] for r in rows}

        for r in rows:
            if r["pid"] not in prev_pids and prev_pids:
                clog.record("BIRTH", f"process appeared: {r['name']}",
                            pid=r["pid"], ppid=r["ppid"], name=r["name"],
                            win=r["win"], session=r["session"],
                            threat=r["threat"], cmdline=r["cmdline"])

        for pid in prev_pids - cur_pids:
            old = self._seen.get(pid, {})
            clog.record("DEATH", f"process gone: {old.get('name', '?')}",
                        pid=pid, name=old.get("name", ""), win=old.get("win", ""),
                        session=old.get("session"))

        for r in rows:
            prev_t = self._alerted.get(r["pid"])
            if (prev_t is None or r["threat"] >= prev_t + 15) and r["threat"] >= 40:
                self._alerted[r["pid"]] = r["threat"]
                clog.record(
                    "ESCALATE",
                    f"threat {r['threat']}: {', '.join(r['reasons'][:4]) or 'pattern match'}",
                    pid=r["pid"], name=r["name"], win=r["win"], session=r["session"],
                    threat=r["threat"], cmdline=r["cmdline"],
                    detail="; ".join(r["reasons"]),
                )

            sig = {(c[0], c[1], c[2]) for c in r["conns"]}
            if sig:
                before = prev_conn_sets.get(r["pid"], set())
                fresh = sig - before
                if fresh and prev_conn_sets:
                    conn_list = [c for c in r["conns"] if (c[0], c[1], c[2]) in fresh]
                    clog.record("CONNECT", f"{len(fresh)} new connection(s)",
                                pid=r["pid"], name=r["name"], win=r["win"],
                                session=r["session"], threat=r["threat"],
                                conns=conn_list, cmdline=r["cmdline"])
            self._seen_conns[r["pid"]] = sig

        with self._lock:
            self._seen = {r["pid"]: r for r in rows}

        self._events = clog.read_events(4000)

    # ── rendering ──────────────────────────────────────────────────────────
    def _match(self, r: dict) -> bool:
        if self._filter_hidden.get() and r["win"] == "VISIBLE":
            return False
        if r["threat"] < self._filter_min_threat.get():
            return False
        q = self._filter_text.get().strip().lower()
        if not q:
            return True
        hay = f"{r['name']} {r['cmdline']} {r['user']} {r['wtitle']} {r['win']} {r['family']}".lower()
        return q in hay

    def _refresh(self) -> None:
        try:
            if not self.winfo_exists():
                return
        except tk.TclError:
            return
        with self._lock:
            rows = list(self._rows)
        shown = [r for r in rows if self._match(r)]

        self.tree.delete(*self.tree.get_children())
        for r in shown:
            self.tree.insert("", "end", iid=str(r["pid"]),
                             tags=(WIN_TAG.get(r["win"], "vis"),), values=(
                                 r["threat"], r["pid"], r["session"], r["name"],
                                 r["family"], r["win"], f"{r['cpu']:0.1f}",
                                 fmt_bytes(r["rss"]), fmt_age(r["age"]),
                                 len(r["conns"]),
                                 (r["user"] or "").split("\\")[-1][:18],
                                 short(r["cmdline"], 260),
                             ))

        self.net_tree.delete(*self.net_tree.get_children())
        n = 0
        for r in shown:
            for rip, rport, state, lport in r["conns"]:
                self.net_tree.insert("", "end", tags=("net",), values=(
                    r["threat"], r["pid"], r["name"], r["session"], lport or "",
                    rip or "-", rport or "", state, short(r["cmdline"], 220),
                ))
                n += 1

        self.tree_tree.delete(*self.tree_tree.get_children())
        kids = defaultdict(list)
        by_pid = {r["pid"]: r for r in rows}
        for r in rows:
            kids[r["ppid"]].append(r)

        def emit(node, depth, path):
            if node["pid"] in path or depth > 8:
                return
            self.tree_tree.insert("", "end", tags=(WIN_TAG.get(node["win"], "vis"),), values=(
                "  " * depth + ("└─" if depth else "●"), node["pid"], node["ppid"],
                node["name"], node["win"], node["session"], node["threat"],
                short(node["cmdline"], 300),
            ))
            for k in sorted(kids.get(node["pid"], []), key=lambda x: x["age"], reverse=True):
                emit(k, depth + 1, path | {node["pid"]})

        roots = [r for r in rows if r["ppid"] not in by_pid]
        for root in sorted(roots, key=lambda x: -x["age"])[:250]:
            emit(root, 0, set())

        hidden = sum(1 for r in rows if r["win"].startswith(("NO-WINDOW", "HIDDEN")))
        hot = sum(1 for r in rows if r["threat"] >= 40)
        self.lbl_count.config(
            text=f"rows {len(shown)}/{len(rows)}  ·  hidden {hidden}  ·  threat≥40 {hot}  ·  conns {n}  ·  scan {self._last_scan_s:0.2f}s")
        self.lbl_clock.config(text=datetime.now().strftime("%H:%M:%S"))
        self._render_log()

    def _on_select(self, _evt=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        pid = int(sel[0])
        with self._lock:
            row = next((r for r in self._rows if r["pid"] == pid), None)
        if not row:
            return

        d = self.detail
        d.configure(state="normal")
        d.delete("1.0", "end")

        def put(label, val, tag="white"):
            d.insert("end", f"{label:<16}", "h")
            d.insert("end", f"{val}\n", tag)

        put("PID / PPID", f"{row['pid']}  ←  {row['ppid']}")
        put("NAME", row["name"])
        put("FAMILY", row["family"])
        sess_note = f"{row['session']}"
        if row["cross_session"]:
            sess_note += "   (cross-session: window enumeration limited)"
        put("SESSION", sess_note, "warn" if row["cross_session"] else "white")
        put("OWNER", row["user"] or "(unknown)")
        put("WINDOW", row["win"], "crit" if row["win"].startswith(("NO-WINDOW", "HIDDEN")) else "warn")
        if row["wtitle"]:
            put("TITLE", row["wtitle"])
        if row["wclasses"]:
            put("CLASSES", ", ".join(row["wclasses"]))
        put("HANDLES", row["handles"])
        put("THREADS", row["threads"])
        put("CPU", f"{row['cpu']:0.1f}%")
        put("RAM", f"{fmt_bytes(row['rss'])}  (private {fmt_bytes(row['priv'])})")
        put("AGE", fmt_age(row["age"]))
        put("THREAT", f"{row['threat']}/100",
            "crit" if row["threat"] >= 60 else "warn" if row["threat"] >= 30 else "white")

        if row["reasons"]:
            d.insert("end", "\nWHY THE SCORE\n", "h")
            for reason in row["reasons"]:
                d.insert("end", f"  ▸ {reason}\n",
                         "crit" if row["threat"] >= 60 else "warn")

        d.insert("end", "\nCOMMAND LINE\n", "h")
        d.insert("end", (row["cmdline"] or "  (unavailable — elevated or protected process)") + "\n", "dim")

        d.insert("end", "\nWORKING DIRECTORY\n", "h")
        d.insert("end", f"  {detect.cwd_of(row['pid'])}\n", "dim")

        d.insert("end", "\nCONNECTIONS\n", "h")
        if not row["conns"]:
            d.insert("end", "  none\n", "dim")
        for rip, rport, state, lport in row["conns"]:
            line = f"  {state:<13} local:{lport or '-':<6}"
            if rip:
                line += f"  →  {rip}:{rport}"
            d.insert("end", line + "\n",
                     "crit" if state == "ESTABLISHED" and rip else "dim")

        d.insert("end", "\nPARENT CHAIN\n", "h")
        chain = detect.parent_chain(row["pid"])
        d.insert("end", ("\n".join("  " + c for c in chain) or "  none") + "\n", "dim")

        events = [e for e in self._events if e.get("pid") == pid][-15:]
        if events:
            d.insert("end", "\nRECENT EVENTS\n", "h")
            for e in events:
                d.insert("end", f"  {e.get('ts_short', '')}  {e.get('kind', ''):<10} {e.get('message', '')}\n", "dim")

        d.configure(state="disabled")
        self.nb.select(4)

    # ── log tab ────────────────────────────────────────────────────────────
    def _load_log(self) -> None:
        self._events = clog.read_events(4000)
        self._render_log()

    def _render_log(self) -> None:
        active = {k for k, v in self._log_kinds.items() if v.get()}
        q = self._filter_text.get().strip().lower()
        self._log_tree.delete(*self._log_tree.get_children())
        for e in reversed(self._events):
            kind = e.get("kind", "NOTE")
            if kind not in active:
                continue
            if q:
                hay = f"{e.get('name', '')} {e.get('message', '')} {e.get('cmdline', '')}".lower()
                if q not in hay:
                    continue
            self._log_tree.insert("", "end", tags=(kind,), values=(
                e.get("ts_short", ""), kind, e.get("pid") or "",
                e.get("name", ""), e.get("win", ""), e.get("session") or "",
                e.get("threat") or "", e.get("message", ""),
                short(e.get("detail", ""), 300),
            ))

    def _save_log(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".jsonl",
            initialfile=f"sentinel-events-{datetime.now():%Y%m%d-%H%M%S}.jsonl",
            filetypes=[("JSON Lines", "*.jsonl"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                for e in self._events:
                    fh.write(json.dumps(e, ensure_ascii=False) + "\n")
            self.lbl_stat.config(text=f"SAVED {len(self._events)} events", fg=ACCENT)
        except OSError as exc:
            self.lbl_stat.config(text="SAVE FAILED", fg=FG_CRIT)
            clog.record("NOTE", f"log export failed: {exc}")

    def _export(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=f"sentinel-snapshot-{datetime.now():%Y%m%d-%H%M%S}.json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        with self._lock:
            rows = list(self._rows)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, indent=1, default=str)
            self.lbl_stat.config(text=f"EXPORTED {len(rows)}", fg=ACCENT)
        except OSError as exc:
            self.lbl_stat.config(text="EXPORT FAILED", fg=FG_CRIT)
            clog.record("NOTE", f"snapshot export failed: {exc}")

    # ── actions ────────────────────────────────────────────────────────────
    def _kill(self) -> None:
        sel = self.tree.selection()
        if not sel:
            self.lbl_stat.config(text="NO SELECTION", fg=FG_WARN)
            return
        pid = int(sel[0])
        with self._lock:
            row = next((r for r in self._rows if r["pid"] == pid), None)
        if not row:
            return
        try:
            import psutil
            psutil.Process(pid).kill()
            clog.record("KILL", f"terminated {row['name']}", pid=pid, name=row["name"],
                        win=row["win"], session=row["session"], threat=row["threat"],
                        cmdline=row["cmdline"])
            self.lbl_stat.config(text=f"KILLED {pid}", fg=FG_BLOOD)
        except Exception as exc:
            clog.record("KILL-FAIL", f"kill denied: {exc}", pid=pid, name=row["name"],
                        win=row["win"], session=row["session"])
            self.lbl_stat.config(text=f"KILL DENIED {pid}", fg=FG_WARN)
        self._events = clog.read_events(4000)
        self.after(150, self._force_scan)

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

    # ── loop ───────────────────────────────────────────────────────────────
    def _tick(self) -> None:
        try:
            if not self.winfo_exists():
                return
        except tk.TclError:
            return
        if self._auto.get():
            self._scan()
            self._refresh()
            self.lbl_stat.config(text="HUNTING", fg=ACCENT)
            self.after(2000, self._tick)
        else:
            self.lbl_stat.config(text="PAUSED", fg=FG_DIM)
            self.after(500, self._tick)


def main() -> int:
    if os.name != "nt":
        print("Windows only.", file=sys.stderr)
        return 1
    app = Sentinel()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
