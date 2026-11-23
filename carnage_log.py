"""CARNAGE SENTINEL v1.1 — event log with structured records and on-disk persistence.

Every event is a dict, written as one JSON line plus a human line. The GUI reads
the JSONL so the viewer can filter and sort without re-parsing prose.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from threading import Lock

HOME = Path.home() / "AppData" / "Local" / "hermes" / "sentinel"
HOME.mkdir(parents=True, exist_ok=True)

JSONL = HOME / "events.jsonl"
HUMAN = HOME / "sentinel.log"
MAX_JSONL_BYTES = 8 * 1024 * 1024

_lock = Lock()

KINDS = ("BIRTH", "DEATH", "ESCALATE", "CONNECT", "KILL", "KILL-FAIL", "BOOT", "NOTE")


def _rotate() -> None:
    """Keep the JSONL bounded. Rename to .1 when it grows past the cap."""
    try:
        if JSONL.exists() and JSONL.stat().st_size > MAX_JSONL_BYTES:
            backup = JSONL.with_suffix(".jsonl.1")
            if backup.exists():
                backup.unlink()
            JSONL.rename(backup)
    except OSError:
        pass


def record(
    kind: str,
    message: str,
    *,
    pid: int | None = None,
    name: str = "",
    ppid: int | None = None,
    win: str = "",
    session: int | None = None,
    threat: int | None = None,
    conns: list | None = None,
    cmdline: str = "",
    detail: str = "",
) -> dict:
    """Append one structured event. Returns the record so the caller can mirror it."""
    now = datetime.now()
    rec = {
        "ts": now.isoformat(timespec="seconds"),
        "ts_short": now.strftime("%H:%M:%S"),
        "epoch": now.timestamp(),
        "kind": kind,
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "win": win,
        "session": session,
        "threat": threat,
        "conns": len(conns) if conns is not None else None,
        "cmdline": cmdline,
        "message": message,
        "detail": detail,
    }
    line = ""
    if kind == "CONNECT" and conns:
        parts = []
        for rip, rport, state, lport in conns[:4]:
            if rip:
                parts.append(f"{state} {rip}:{rport}")
            else:
                parts.append(f"LISTEN :{lport}")
        line = " | ".join(parts)
        if len(conns) > 4:
            line += f" +{len(conns) - 4} more"
    elif cmdline:
        line = " ".join(cmdline.split())[:160]

    with _lock:
        _rotate()
        try:
            with JSONL.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass
        try:
            human = f"[{rec['ts_short']}] {kind:<10}"
            if pid:
                human += f" pid={pid:<7}"
            if name:
                human += f" {name:<20}"
            if win:
                human += f" {win:<16}"
            if session is not None:
                human += f" s{session}"
            if threat is not None:
                human += f" t{threat}"
            human += f" | {message}"
            if line:
                human += f" -- {line}"
            with HUMAN.open("a", encoding="utf-8") as fh:
                fh.write(human + "\n")
        except OSError:
            pass
    return rec


def read_events(limit: int = 4000) -> list[dict]:
    """Load recent events, newest last. Tolerates a truncated final line."""
    if not JSONL.exists():
        return []
    out: list[dict] = []
    try:
        with JSONL.open("r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    out.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return out[-limit:]


def tail_text(lines: int = 500) -> str:
    if not HUMAN.exists():
        return ""
    try:
        with HUMAN.open("r", encoding="utf-8", errors="replace") as fh:
            data = fh.readlines()
    except OSError:
        return ""
    return "".join(data[-lines:])


def rotate_now() -> None:
    with _lock:
        _rotate()
