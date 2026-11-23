# CARNAGE SENTINEL

A native Windows process hunter for finding the shells nobody told you about.

Every backgrounded `powershell.exe`, every orphaned `python.exe`, every `conhost.exe` still holding a pipe open after its parent died — Sentinel walks the whole process table, resolves who owns what, and shows you which ones have no window at all. That last column is the point. A process with no window is either a service doing its job or something that was deliberately hidden. Sentinel doesn't decide which. It shows you, with the command line attached, and lets you kill it.

Built for the ghost-edge workstation: RTX 5070, Windows 11, a toolchain that spawns helpers constantly and forgets them.

---

## What it actually tracks

Sentinel is not a general-purpose Task Manager. It watches a deliberate allowlist of process families — the ones that run code, hold sockets, or hide:

**Shells** — `powershell.exe`, `pwsh.exe`, `powershell_ise.exe`, `cmd.exe`, `conhost.exe`, `wt.exe`, `windowsterminal.exe`

**Interpreters** — `python.exe`, `pythonw.exe`, `python3.exe`, `node.exe`, `npx.exe`, `bun.exe`, `deno.exe`, `java.exe`, `javaw.exe`

**POSIX layer** — `bash.exe`, `sh.exe`, `ssh.exe`, `git.exe`, `git-bash.exe`, `msys2.exe`, `mintty.exe`, `wsl.exe`, `wslhost.exe`, `wslrelay.exe`, `wslservice.exe`

**Script hosts** — `cscript.exe`, `wscript.exe`, `mshta.exe` — the three ways Windows runs code with no compile step and no signature

**Container and model runtimes** — `docker.exe`, `docker-compose.exe`, `ollama.exe`, `llama-server.exe`

**Media** — `ffmpeg.exe`, `ffprobe.exe`

Anything else is invisible to the hunt by design. A 1,780-process machine is noise; the 758 that match this list are the ones with hands.

---

## The five columns that matter

**`win` — the suppression tell.** Every row resolves to `VISIBLE` or `SUPPRESSED`. A process with a `MainWindowHandle` and a title is `VISIBLE`. A process with neither owns no window — it was launched with `CREATE_NO_WINDOW`, `START /B`, `pythonw`, or as a service. This is the column you sort by first.

**`ppid` — where it came from.** Paired with the TREE tab, a stray interpreter traces back to the shell, script, or service that spawned it. An orphan reads `ppid=0` or points at a dead pid.

**`cpu%` / `ram`** — live working-set in human units. Memory is the reliable signal here; a leaked `python.exe` at 231 MB is a script that never cleaned up.

**`age`** — wall-clock since creation. A `powershell.exe` that has been alive for 4 days is either a scheduled task that forgot to exit or something worse.

**`net`** — count of sockets owned by that pid. Jump to the NETWORK tab for the detail.

---

## Tabs, one at a time

### HUNT

The default view. One row per tracked process, sorted so suppressed processes float to the top. Click any row and the DETAIL tab fills in: full command line, working directory, every socket with remote IP and port, and the complete parent chain walked up to twelve levels.

The command-line column is truncated at 300 characters in the table but complete in DETAIL. For elevated processes that deny `cmdline` access, DETAIL says so plainly rather than showing an empty field.

### NETWORK

Flattens every tracked process into one row per connection. `ESTABLISHED` connections with a remote address are highlighted in cyan — that's live traffic. `LISTEN` rows with no remote address are services waiting. The owning process and its command line ride along on every row, so you never have to cross-reference a pid.

This is where you catch a `python.exe` that should not be talking to anything.

### TREE

Parent/child hierarchy rendered with box-drawing characters, ordered oldest-first so ancestors sit above descendants. Cycles are detected and broken. Root processes — those whose parent is already gone — are rendered at depth zero with a filled bullet.

A `conhost.exe` orphaned under a dead `cmd.exe` shows up here as a root, which is exactly the shape of a process whose parent was killed and never reaped its console.

### DETAIL

The deep pane. Command line, working directory, window state, memory, age, every socket with state and direction, and the parent chain. Anything suppressed is rendered in critical red; anything with a live remote connection is flagged the same way.

### LOG

Appends every birth, death, and kill to `%LOCALAPPDATA%\hermes\sentinel\sentinel.log` with a timestamp. The panel mirrors the file so you can watch churn in real time — useful for spotting a process that respawns faster than you can look at it.

---

## Controls

**FILTER** — substring match against name, command line, user, and window title. Evaluates on every keystroke.

**HIDDEN/SUPPRESSED ONLY** — collapses the list to processes with no window. This is the button you press when you want to know what is running behind the desk.

**AUTO-SCAN 2s** — the refresh loop. Off means a manual rescan only.

**⟳ RESCAN** — forces an immediate sweep.

**✖ KILL PID** — hard-kills the selected process. No confirmation dialog, no graceful shutdown request. If the process denies access, the status bar reads `KILL DENIED` and the attempt is logged instead of silently failing.

**⚡ COPY CMD** — puts the selected process's full command line on the clipboard. This is how you take a suspicious invocation somewhere else and read it properly.

---

## Why it is fast when the obvious implementation is not

Sentinel was first written against `psutil.process_iter()` with a per-process attribute pull. On this machine that took **229 seconds** for a single snapshot. Profiling isolated the cost: `psutil.Process.create_time()` and per-process `pid` resolution were doing registry round-trips, roughly 130 seconds of the total across 1,773 processes.

The rewrite does one `Get-CimInstance Win32_Process` sweep plus one `Get-Process` for window handles, both inside a single PowerShell call. That returns in **0.51 seconds**. Socket data comes from one system-wide `psutil.net_connections()` — 1,135 sockets in 0.02 seconds — grouped by owning pid, instead of a per-process query.

**Snapshot time went from 229 seconds to 2.67 seconds.** The GUI would not have been usable at the original figure; the first refresh would have frozen the window for nearly four minutes.

---

## Files it writes

`%LOCALAPPDATA%\hermes\sentinel\sentinel.log` — append-only event log, one line per birth, death, and kill attempt, each stamped `HH:MM:SS`.

`%LOCALAPPDATA%\hermes\sentinel\crash.log` — an unhandled exception trace, written only when something goes wrong. This exists because a `--windowed` PyInstaller build has no console: without it, a crash is completely silent. Sentinel installs a `sys.excepthook` that writes the traceback here before falling through to the default handler.

`%LOCALAPPDATA%\hermes\sentinel\_snap.ps1` — the generated PowerShell sweep script, rewritten on every snapshot call.

---

## Running it

Double-click `CarnageSentinel.exe`. No install, no dependencies, no console window. It is a single 11.6 MB binary built with PyInstaller `--onefile --windowed`.

Requires Windows. It reads process state through `psutil` and WMI, which are Windows-specific. Elevated processes will show blank command lines unless Sentinel itself runs elevated — that is an OS boundary, not a bug.

---

## Build from source

```
pip install pyinstaller psutil
pyinstaller --noconfirm --clean --onefile --windowed \
  --name "CarnageSentinel" --hidden-import psutil \
  --distpath dist --workpath build --specpath . sentinel.py
```

The `--hidden-import psutil` is load-bearing. PyInstaller's dependency scan does not follow psutil's runtime C-extension loading and will produce a binary that dies on first import without it.

---

## Known limits

Window state is resolved from `MainWindowHandle`, which only reports the *main* window. A process with a visible child window but no main window handle reads as `SUPPRESSED`. In practice this affects almost nothing — console hosts and interpreters either have a main window or they do not.

Command lines for processes owned by another user, or by SYSTEM, return blank unless Sentinel runs elevated. The app does not attempt to escalate.

CPU percentage is reported as `0.0` in the table. The bulk PowerShell path does not return per-process CPU time, and computing it would require either a second expensive sweep or a delta table against psutil's per-process counters — which is the exact thing that made the original implementation unusable. Memory, age, thread count, and connection state carry the diagnostic weight instead. DETAIL shows working directory via a targeted single-process lookup, which is cheap because it runs once per click rather than 758 times per sweep.

---

## License

MIT. Do what you want with it.
