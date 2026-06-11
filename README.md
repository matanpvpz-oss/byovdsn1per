# BYOVDsn1per

A scanner for Bring-Your-Own-Vulnerable-Driver work. Walks PE headers without IDA. Walks dispatchers with it.

Built on `idalib`, the headless Python bindings shipped with IDA Pro Essential 9.x. The `--quick` mode skips IDA entirely if all you need is hashes, signing, HVCI flags, and a CVE fingerprint match.

## What it does

Three pieces.

**Crawl.** Walk known Windows driver paths (or every logical drive) and copy unique kernel drivers to one folder. Resumes from a checkpoint if you Ctrl+C halfway through. Output lands in `%APPDATA%\BYOVDsn1per\crawler\`.

**Analyze.** Per driver: dispatcher walk (legacy MJ14, recursive, WDF stub-inferred, minifilter, static-WDF), per-IOCTL primitive classification, gate detection (PID checks, magic cookies, trust-DB, string compares), HVCI flag verdict, Authenticode chain, Rich Header, PDB info, TLS callbacks, exports.

**Match.** A 30-entry CVE database. Fingerprinting only, no exploitation. Tiers: CONFIRMED via sha256_exact, HIGH via signer + IOCTL overlap, MEDIUM, LOW, with polluted device-type filtering so a `0x0022` driver doesn't trigger five unrelated CVEs.

Also: `--diff` for side-by-side comparison of two drivers, `--strings` with regex-tagged URLs/IPv4/registry/PDB/SDDL, and `--yara-rule` to emit a YARA detection rule per driver.

## Install

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

Copies the script to `%LOCALAPPDATA%\Programs\BYOVDsn1per\` and adds it to your user PATH. No admin needed. Open a new terminal and `byovdsn1per --version` should print v2.15.

After install, run `byovdsn1per --doctor` to confirm Python, idalib, pefile, the Windows signing tools, **and the user PATH entry** are all in place. It also shows where the default crawl output dir resolves on your machine.

### Repair without re-running the installer

Two commands rebuild a broken or partial install without touching `install.ps1`:

- `byovdsn1per --doctor --fix` — maximum repair. Redeploys every install artifact that's missing or stale (main script, `.cmd` launcher, lowercase alias, README), **adds the install dir to your user PATH** (Windows, via `HKCU\Environment` + a settings broadcast), pip-installs `pefile` if it's missing, creates the crawler/results dirs, and prunes stale `__pycache__` and dead sha256-cache entries. Idempotent; safe to re-run.
- `byovdsn1per --update` (alias `--upgrade`) — the same full repair, focused on the install: redeploy stale/missing artifacts, ensure the PATH entry, pre-create the crawler dir, and install `pefile`. This is `install.ps1` minus the admin-y bits, runnable from a plain shell.

Both report a per-item checklist and exit non-zero if anything couldn't be repaired (e.g. a permission-denied copy, or `pip` blocked by your network policy).

Uninstall: `.\install.ps1 -Uninstall`.

If you'd rather not install, the script runs in place. Call `python BYOVDsn1per.py`, or use `BYOVDsn1per.cmd` from the repo folder. The launcher tries `python` first, then `py -3`.

## Requirements

Python 3.10 or newer.

For full IOCTL-dispatcher analysis you need IDA Pro Essential 9.3+ with the `idapro` Python package installed. The signing/HVCI path calls Windows-only tools: PowerShell's `Get-AuthenticodeSignature` and `signtool /kp`. The PE-info pipeline is pure-stdlib and works anywhere Python runs.

### What works without IDA

These run silently on a no-IDA box:

| Mode | Notes |
|---|---|
| `--quick DRIVER` | HVCI + signing + PE info + imports |
| `--hvci-only`, `--sign-verify`, `--hashes-only`, `--imports-only` | single-fact lookups |
| `--cve-list` | print the matcher database |
| `--crawl`, `--deepcrawl`, `--restart` | filesystem walk + PE-header check, no disassembly |
| `--list`, `--list-default-roots` | inspect crawler contents / show crawl roots |
| `--doctor` | reports whether idalib was found, lists IDA-free modes |
| `--sweep --quick`, `--diff --quick a b` | the `--quick` modifier skips IDA in those modes too |
| `--strings`, `--yara-rule`, `--poc` | per-driver modifiers; they work whenever the underlying scan does |

### What needs IDA

These will block with a friendly error if idalib is missing, exit code 2:

```
error: full scan (default mode) needs idalib (IDA Pro 9.x Essential+ Python bindings)
       reason: ModuleNotFoundError: No module named 'idapro'
       install: pip install idapro    (from your IDA install directory)
       or:      add --quick to skip IDA-based dispatcher analysis
       see also: byovdsn1per --doctor
```

| Mode | Why |
|---|---|
| `DRIVER` (default full scan) | dispatcher walk needs IDA |
| `--deep DRIVER` | per-IOCTL primitive classification |
| `--sweep DIR` (no `--quick`) | per-driver full scan in a loop |
| `--diff a b` (no `--quick`) | per-driver full scan |
| `--decompile DRIVER --ea ADDR` | hexrays-decompile, no `--quick` fallback |

Run `byovdsn1per --doctor` for an explicit yes/no on this machine.

## Where do crawl results go?

`%APPDATA%\BYOVDsn1per\crawler\` by default. Same place every time, regardless of where you ran the command from.

Each driver lands as `<stem>_<sha256[0:8]>.sys`. Two metadata files live in the same folder:

- `.scanned_paths.txt` lists directories the crawler has finished. Both `--crawl` and `--deepcrawl` consult this before walking, so resuming after a Ctrl+C costs nothing.
- `.sha256_cache.txt` caches driver hashes. Subsequent runs skip rehashing files already in the folder.

Override with `--crawl-out`:

```bash
byovdsn1per --crawl --crawl-out D:\my_drivers
```

Wipe the checkpoint and start fresh with `--restart`. Alone, `--restart` implies `--deepcrawl`.

## Quick start

If you skipped the installer, replace `byovdsn1per` with `python BYOVDsn1per.py`.

Single driver:

```bash
byovdsn1per driver.sys                  # default full scan
byovdsn1per --quick driver.sys          # no IDA needed
byovdsn1per --deep driver.sys           # per-IOCTL primitive classification
byovdsn1per --all driver.sys            # --deep + --poc + --strings + --yara-rule + --verify-load
```

`--all` is the kitchen-sink mode. Equivalent to listing those five flags by hand.

### Short flags

Every common long flag has a one-letter alias, and single-letter flags bundle:

```bash
byovdsn1per -a driver.sys               # --all
byovdsn1per -Qz driver.sys              # --quick --offline-mode
byovdsn1per -s -F perfect -P            # --sweep --filter perfect --poc
byovdsn1per -cw                         # --crawl --deepcrawl
```

| | | | |
|---|---|---|---|
| `-a` all | `-Q` quick | `-d` deep | `-s` sweep |
| `-D` diff | `-C` decompile | `-e` ea | `-c` crawl |
| `-w` deepcrawl | `-r` restart | `-p` crawl-path | `-o` crawl-out |
| `-L` crawl-limit | `-t` doctor | `-f` fix | `-u` update/upgrade |
| `-l` list | `-H` hvci-only | `-g` sign-verify | `-X` hashes-only |
| `-P` poc | `-S` strings | `-y` yara-rule | `-b` burnt-check |
| `-E` explain | `-m` max-strings | `-z` offline-mode | `-O` output |
| `-q` quiet | `-vv` verbose | `-j` jobs | `-F` filter |
| `-n` no-patterns | `-V` version | | |

Run `byovdsn1per --help` for the authoritative list.

CVE matcher:

```bash
byovdsn1per --poc driver.sys
byovdsn1per --cve-list
```

Inspect what you've already harvested:

```bash
byovdsn1per --list                        # count, total size, top-10 by size
byovdsn1per --doctor                      # verify install + show resolved paths
```

Strings, YARA, diff:

```bash
byovdsn1per --strings --yara-rule driver.sys
byovdsn1per --yara-rule --yara-out rule.yar driver.sys
byovdsn1per --diff a.sys b.sys
```

Sweep a folder. With no argument, `--sweep` analyses the `--crawl` output dir (`%APPDATA%\BYOVDsn1per\crawler\`):

```bash
byovdsn1per --sweep                       # the crawler output dir
byovdsn1per --sweep D:\my_drivers          # any folder you like
byovdsn1per --sweep --filter perfect       # only PERFECT/STRONG tier
byovdsn1per --sweep --all                  # full enrichment: --deep --poc --strings --yara-rule --verify-load
```

Sweep auto-saves a JSON of all per-driver results to `%APPDATA%\BYOVDsn1per\sweep_<timestamp>.json`. Ctrl+C is safe — partial results are flushed every 10 drivers and again on exit (via an `atexit` handler). The summary tells you exactly where the file landed.

## Crawl

```bash
byovdsn1per --crawl
byovdsn1per --deepcrawl
byovdsn1per --restart
byovdsn1per --crawl --crawl-path D:\extracted_drivers
byovdsn1per --crawl --crawl-out my_harvest --crawl-limit 100
byovdsn1per --list-default-roots
```

The driver filter requires three things, in order:

1. NATIVE subsystem PE (the only subsystem the kernel loads)
2. AddressOfEntryPoint != 0 (i.e. there's an entry function, which for `.sys` files is `DriverEntry`)
3. At least one import from a known kernel-mode module (ntoskrnl.exe, hal.dll, fltmgr.sys, ndis.sys, wdf01000.sys, ksecdd.sys, etc.)

That third check is what separates "real kernel driver" from "happens to be PE32+ NATIVE with an entry point". Things like `cmd.exe` renamed to `.sys` get rejected. WDF helpers and minifilter assist DLLs (e.g. `ksapi64_del.sys`) still pass because they import from wdf01000.sys or fltmgr.sys.

## End-to-end

```bash
byovdsn1per --crawl                       # 1. discover. Results land in %APPDATA%\BYOVDsn1per\crawler\
byovdsn1per --sweep --poc                 # 2. analyze + match CVEs (uses the crawler dir by default)
byovdsn1per --sweep --filter perfect      # 3. only show PERFECT / STRONG tier
```

## Output formats

```
--output table       (default, ANSI-colored)
--output json
--output markdown
--quiet              one line per driver
--verbose            full IOCTL list, all sections, all imports
```

## Scoring

Each driver gets 0–100, mapped to a tier:

```
PERFECT      90+   HVCI loadable, production cert, open dispatcher, rich primitive surface
STRONG       70+   most of those
INTERESTING  50+   some signals
WEAK         30+   partial relevance
SKIP         < 30  anti-cheat archetype penalty, etc.
```

Score gets capped by HVCI status. No FORCE_INTEGRITY: cap 80. No GuardCF or has init-WX: cap 60. Full HVCI pass: uncapped.

The scoring mixes primitive count, gate count, archetype tags, and DACL signal so the verdict isn't reducible to one number.

## Speed

The CPU-strain knob is `--jobs`/`-j` (default `0` = auto = core count, capped at 8; `-j 1` forces serial). Auto deliberately does **not** oversubscribe: both parallel phases have a CPU-heavy component — SHA-256 in the crawl, and one PowerShell process per worker in a `--quick` sweep — so spawning several workers per core just pins every core (and floods the box with PowerShell processes) for little wall-clock gain. Matching the core count keeps the cores busy without the thrash. Bump `-j` higher only if you know your workload is pure wait.

Per-file hashing feeds each digest the whole in-memory buffer in one pass rather than re-slicing it into 64 KB copies per digest. The compression cost is the same, but it drops the per-chunk allocations and releases the GIL across each pass, so a worker blocked on PowerShell can run while another hashes. Digests are identical.

- **Crawl** fans out the per-file read + SHA-256 (the per-`.sys` hot path). Dedup, copy, and checkpoint bookkeeping stay on the main thread, so results — including which copy wins a hash collision — are identical to a serial run.
- **Sweep** fans out per-driver analysis for `--quick` and `--patterns-only`, where the dominant cost is the `Get-AuthenticodeSignature` PowerShell subprocess. On a signing-bound sweep this scales close to linearly with worker count.

Detection is unchanged: every driver runs the exact same analysis function whether the sweep is serial or parallel; only the iteration strategy differs, and the final ordering is still by score.

A **full IDA sweep stays single-threaded** regardless of `-j`. `idalib` holds global, single-database process state and is not thread-safe, so parallelizing it in-process would corrupt analysis. Use `--quick` (or per-driver subprocesses of your own) if you need the disassembly path to scale across cores.

## A few implementation notes

It's a single-file scanner, about 4000 lines, pure stdlib for everything except idalib. Each driver gets analyzed in a copy under `%TEMP%` so cross-driver state doesn't leak.

The dispatcher walker handles `cmp+jz`, `cmp+jnz` with fall-through handler (MSVC switch optimization, used by Avast aswSP), `cmp+setcc`, `cmp+cmovcc` (branchless materialization), biased switches (`add reg, IMM; cmp reg, MAX`), and the two-register `mov reg, IMM; cmp r2, reg; jcc` pattern. The look-ahead accepts both halves of each pair: `jz` and `jnz`, `setz` and `setnz`, `cmovz` and `cmovnz`. ZF is ZF either way.

The MS-reserved device-type filter (`0x003C..0x7FFF`) catches phantom emissions. Without it, drivers like cpu-z report 2 extra "IOCTLs" that are really ASCII string constants. `0x5f534750` looks like an IOCTL until you notice the bytes spell out "PG_S_".

CVE matching maintains a polluted-device-type set computed from the database at import time. Types appearing in 3+ entries are treated as non-evidence in isolation. `0x0022` shows up in 5 CVE entries, so a `0x0022` driver matching all of them on device type alone tells you nothing. You need signer or IOCTL overlap to escape LOW confidence.

## What this isn't

A way to load drivers. A way to exploit them. A way to detect them at runtime. It's just analysis.

HVCI status from PE flags tells you whether the kernel signing policy will accept the driver. It doesn't tell you whether Defender's vulnerable-driver blocklist or your machine's local Code Integrity policy will allow it to actually load. Check those separately.

The scoring is heuristic. A STRONG verdict means "worth looking at by hand," not "exploitable today." Do the manual work.

## License

Public domain.
