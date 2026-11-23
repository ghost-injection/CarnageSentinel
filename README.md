# CARNAGE SENTINEL

A native Windows process hunter that answers one question the Task Manager cannot: **which of these things has no window, and why?**

Every process family that runs code, holds sockets, or hides gets enumerated. Each one is resolved against the window manager, scored against a set of command-line patterns, and printed with the evidence attached. A process with no window is either a service doing its job or something that was deliberately concealed. Sentinel does not decide which. It shows you the command line, the session, the sockets, the parent chain — and lets you kill it.

Version 1.1. Windows 11, Python 3.12, ships as a single 12 MB binary.

---

## What changed in v1.1

**Session awareness.** v1.0 enumerated windows from whatever window station the process happened to run in. This machine has two logon sessions — `0 (Services)` and `1 (Console)` — and a tool running in Session 0 sees none of Session 1's windows. v1.0 reported 758 processes as `SUPPRESSED` when in truth most of them were just in the other session. v1.1 maps every process to its session id via `ProcessIdToSessionId`, prints it as a column, and flags cross-session rows explicitly so a `NO-WINDOW` verdict inside your own session reads differently from one across the boundary.

**Eight window states instead of two.** `NO-WINDOW` (owns no window at all), `HIDDEN` (owns windows, all invisible, at least one titled), `HIDDEN-UNTITLED` (owns invisible untitled windows — the message-only pump shape), `VISIBLE-UNTITLED` (visible but nameless), `VISIBLE`. Window class names are captured too, which is how you tell a `ConsoleWindowClass` from a `PyInstallerOnefileHiddenWindow`.

**Threat scoring.** Every process gets 0–100 and a list of the reasons behind it. No opaque numbers: the DETAIL pane prints each contributing factor.

**Command-line pattern detection.** Nineteen patterns across encoded payloads, execution-policy bypass, remote fetch, dynamic invocation, reverse shells, firewall tampering, shadow-copy deletion, persistence via `schtasks`/`sc`/run-keys, credential access (`mimikatz`, `lsass` dumps), and temp-directory execution.

**Real CPU.** v1.0 reported `0.0` because bulk PowerShell could not supply per-process CPU time. v1.1 pulls `$_.CPU` from `Get-Process` and keeps a delta table between sweeps, so the figure is real utilization since the last scan, not lifetime average.

**Structured event log with a viewer.** Events are written as JSON Lines with a timestamp, kind, pid, ppid, name, window state, session, threat score, and command line. The LOG tab reads them back into a sortable list you can filter by kind and by the global filter box.

**Connection diffing.** A `CONNECT` event fires the first time a socket appears on a process, not on every sweep. Otherwise a single listening daemon would generate 43,200 log lines a day.

---

## What it tracks

**shell** — `powershell.exe`, `pwsh.exe`, `powershell_ise.exe`, `cmd.exe`, `conhost.exe`, `wt.exe`, `windowsterminal.exe`, `openconsole.exe`

**interp** — `python.exe`, `pythonw.exe`, `python3.exe`, `py.exe`, `pyshell.exe`, `node.exe`, `npx.exe`, `bun.exe`, `deno.exe`, `ruby.exe`, `perl.exe`, `php.exe`, `java.exe`, `javaw.exe`, `dotnet.exe`, `mono.exe`

**posix** — `bash.exe`, `sh.exe`, `ssh.exe`, `git.exe`, `git-bash.exe`, `msys2.exe`, `mintty.exe`, `wsl.exe`, `wslhost.exe`, `wslrelay.exe`, `wslservice.exe`, `wslg.exe`, `vmmemwsl.exe`

**scripthost** — `cscript.exe`, `wscript.exe`, `mshta.exe`, `regsvr32.exe`, `rundll32.exe`. These five run code with no compiler and no signature, which is why they carry a flat +20 when they appear with arguments.

**runtime** — `docker.exe`, `docker-compose.exe`, `ollama.exe`, `llama-server.exe`, `com.docker.backend.exe`

**media** — `ffmpeg.exe`, `ffprobe.exe`, `obs64.exe`, `vlc.exe`

**remote** — `teamviewer.exe`, `rustdesk.exe`, `anydesk.exe`, `vncserver.exe`, `winvnc.exe`, `mstsc.exe`

Everything else is out of scope by design. A 1,963-process machine is noise; the 880 that match this list are the ones with hands.

---

## The threat score, in full

| Signal | Weight |
|---|---|
| No visible window | +15 |
| Encoded PowerShell command (`-enc` + base64) | +60 |
| Credential access patterns | +80 |
| Reverse shell patterns (`nc -e`, `socat exec`, `/bin/sh -i`) | +70 |
| Shadow copy / backup deletion | +65 |
| Firewall tampering | +55 |
| Hidden window style (`-WindowStyle Hidden`) | +50 |
| Boot configuration change | +50 |
| Dynamic execution (`iex`, `Invoke-Expression`) | +45 |
| Run-key persistence | +45 |
| Base64 decode operation | +40 |
| Remote payload fetch (`DownloadString`, `iwr`, `curl http`) | +40 |
| Persistence (`schtasks /create`, `sc create`) | +40 |
| LOLBin executed with arguments | +20 |
| Nested shell | +30 |
| Execution-policy bypass | +25 |
| `-NoProfile` | +12 |
| Cmdline unreadable on a hunted family | +12 |
| Live remote connection(s) | +10, +5 each, cap +25 |
| Listening socket | +8 |
| Alive longer than a week | +5 |
| Temp-directory execution | +15 |

Scores cap at 100. The grade is a triage aid, not a verdict — a build server will produce `-NoProfile` shells all day and every one of them is legitimate.

---

## Tabs

**HUNT** — one row per process, sorted by threat descending. Columns: threat, pid, session, name, family, window state, CPU%, RAM, age, connection count, owner, command line. Rows are colour-coded: red for `NO-WINDOW`, amber for `HIDDEN`, green for `VISIBLE`.

**NETWORK** — flattens every tracked process into one row per socket. Remote address and port for established connections, local port for listeners, with the owning process and command line on every line.

**TREE** — parent/child hierarchy with cycle detection and a depth ceiling of eight. Roots render with a filled bullet; descendants use box-drawing indents. This is where an orphaned `conhost.exe` under a dead `cmd.exe` shows its shape.

**LOG** — the event viewer. Eight columns: timestamp, kind, pid, name, window state, session, threat, message, detail. Filter by kind with the checkboxes, or by text with the global filter box, which matches name, message, and command line.

**DETAIL** — everything known about the selected process, in order: identity, session (with a cross-session warning when applicable), owner, window state and classes, handles, threads, CPU, RAM and private bytes, age, threat score with the full reason list, command line, working directory, every socket, the twelve-level parent chain, and the last fifteen log events that touched that pid.

---

## Event kinds

**BOOT** — process start, with the session the tool is enumerating from.
**BIRTH** — a tracked process appeared. Carries the full command line.
**DEATH** — a tracked process disappeared.
**ESCALATE** — a process crossed threat 40, or climbed 15 points above its previous score.
**CONNECT** — a new socket signature appeared on a process.
**KILL** — a process was terminated from the UI.
**KILL-FAIL** — a kill was denied, usually by an OS access boundary.
**NOTE** — anything else worth recording.

---

## Files it writes

`%LOCALAPPDATA%\hermes\sentinel\events.jsonl` — the structured event log, one JSON object per line. Rotates to `events.jsonl.1` at 8 MB.

`%LOCALAPPDATA%\hermes\sentinel\sentinel.log` — the same events as fixed-width human text, for tailing and grepping.

`%LOCALAPPDATA%\hermes\sentinel\crash.log` — unhandled exception traces. A `--windowed` PyInstaller build has no console, so without this a crash is completely silent.

`%LOCALAPPDATA%\hermes\sentinel\_snap.ps1` — the generated PowerShell sweep, rewritten on every snapshot call.

---

## Controls

**FILTER** — substring match against name, command line, owner, window title, window state, and family. Applies to both HUNT and LOG.

**HIDDEN ONLY** — hides anything with a visible window.

**MIN THREAT** — slider from 0 to 100. At 40 you see only processes that matched at least one real pattern.

**AUTO 2s** — the refresh loop. Toggle off to pause; the tick keeps running but stops scanning so you can read without the table reshuffling.

**⟳ RESCAN** — one immediate sweep.

**✖ KILL** — hard-kills the selected pid. No confirmation. Denied kills report `KILL DENIED` and log a `KILL-FAIL` event instead of failing quietly.

**⧉ CMD** — copies the selected command line to the clipboard.

**⇩ EXPORT** — dumps the current snapshot to JSON with every field, for offline analysis.

The LOG tab also has **⇩ SAVE**, which writes the visible event set to a JSONL file.

---

## Why the enumeration is fast

The first build called `psutil.process_iter()` with per-process attribute access and took **229 seconds** for one snapshot. A window that freezes for four minutes on open is indistinguishable from a crash. Profiling isolated the cost: `create_time()` alone was **132 seconds** across 1,773 processes, because psutil resolves creation time per-process through the registry.

v1.1 does one `Get-CimInstance Win32_Process` sweep plus one `Get-Process` for window handles and CPU, both inside a single PowerShell invocation. Socket data comes from one system-wide `psutil.net_connections()` — 1,135 sockets in 0.02 seconds — grouped by owning pid. Owner names come from `psutil.Process.username()`, a cheap handle query.

`GetOwner` was tried first and rejected: as a WMI method it requires `Invoke-CimMethod` per process, and on 1,963 processes that is a 90-second sweep that also silently produced zero rows when the method was accessed as a property instead.

**Snapshot time: 229s → 2.6s across 880 tracked rows.**

---

## Build from source

```
pip install pyinstaller psutil
pyinstaller --noconfirm --clean --onefile --windowed \
  --name "CarnageSentinel" --version-file version_info.txt \
  --hidden-import psutil --distpath dist --workpath build --specpath . sentinel.py
```

`--hidden-import psutil` is load-bearing: PyInstaller's dependency scan does not follow psutil's runtime C-extension loading and will produce a binary that dies on first import without it.

Source layout: `sentinel.py` (GUI), `carnage_detect.py` (enumeration, window mapping, scoring), `carnage_log.py` (event records and rotation).

---

## Known limits

**Cross-session window enumeration is best-effort.** Reading another logon session's desktop requires `SeTcbPrivilege` and a window-station switch that usually fails without SYSTEM. Cross-session processes therefore report `NO-WINDOW` even when they own windows in the other session — which is exactly why the session column exists. Read `NO-WINDOW` as definitive only for your own session.

**Elevated and protected processes yield no command line.** That is an OS boundary. Sentinel does not attempt to escalate.

**Window state comes from the window manager's view**, so a process with a visible child but no top-level window of its own can read as hidden. Class names in DETAIL disambiguate.

**The threat score is heuristics.** Legitimate automation trips it regularly. It ranks triage order; it does not establish intent.

---

## License

MIT.
