# BYOVDsn1per

IDA-powered BYOVD (Bring Your Own Vulnerable Driver) specimen scanner. Headless analysis via the `idalib` Python bindings shipped with IDA Pro 9.x.

Identifies kernel drivers that load on modern Windows and exposes weaponizable primitives — IOCTL dispatchers, exposed kernel APIs, missing HVCI gates, weak access checks, and matches against a 30-entry database of documented vulnerable-driver CVEs.

## What it does

- **Crawl**: walk known Windows driver paths (System32\drivers, DriverStore, Program Files, vendor dirs) or the entire PC, dedupe by SHA256, resume from a checkpoint file
- **Quick triage** (no IDA): HVCI flags, Authenticode signing, PE imports, hashes, version info, Rich Header
- **Full scan**: IOCTL dispatcher walk (legacy MJ14, recursive, WDF stub-inferred, minifilter, static-WDF), per-IOCTL primitive classification, gate detection (PID checks, magic cookies, trust-DB, string compares)
- **CVE matcher**: safe fingerprint-only matching against 30 documented BYOVD CVEs (no exploitation, just identification — CONFIRMED via SHA256, HIGH via signer + IOCTL overlap, etc.)
- **YARA rule emission**: compilable detection rule per driver using `hash` + `pe` YARA modules
- **String extraction**: ASCII + UTF-16LE with regex-tagged URLs / IPv4 / registry keys / file paths / PDB / GUIDs / device paths / SDDL
- **Driver diff**: side-by-side comparison of two drivers (hashes, signing, PE info, IOCTL surface, verdict)

## Requirements

- Python 3.10+
- IDA Pro Essential 9.3+ with the `idapro` Python package installed (for non-`--quick` modes)
- Windows for full functionality (PowerShell for Authenticode, `signtool` for kernel signing policy verification)

`--quick`, `--crawl`, `--diff` work on any OS; `--deep`, `--sweep`, dispatcher analysis require IDA.

## Install

Run from PowerShell (no admin required):

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

This copies the scanner to `%LOCALAPPDATA%\Programs\BYOVDsn1per\` and adds it to your user PATH. Open a **new** terminal and you can type `byovdsn1per` from anywhere.

To uninstall:

```powershell
.\install.ps1 -Uninstall
```

If you'd rather not install, the script runs in place too — see "Quick start" below.

## Where do crawl results go?

By default, `--crawl` and `--deepcrawl` write to:

```
%USERPROFILE%\BYOVDsn1per\crawler\
```

This is the same location regardless of where you launched the command from. Each driver is copied as `<original-stem>_<sha256[0:8]>.sys`, and two metadata files live alongside the harvest:

- `.scanned_paths.txt` — directories already processed (resumable checkpoint)
- `.sha256_cache.txt` — hash-of-each-file cache (skip re-hashing on re-runs)

Override the location with `--crawl-out DIR`:

```bash
byovdsn1per --crawl --crawl-out D:\my_drivers
```

## Quick start

After running `install.ps1`, just type `byovdsn1per` from any terminal. If you skipped the installer, replace `byovdsn1per` with `python BYOVDsn1per.py` (or use `BYOVDsn1per.cmd` from the repo dir).

```bash
# Single driver, full analysis
byovdsn1per driver.sys

# Quick triage (no IDA dependency)
byovdsn1per --quick driver.sys

# Deep mode with per-IOCTL primitive classification
byovdsn1per --deep driver.sys

# CVE matcher (SAFE - no exploitation)
byovdsn1per --poc driver.sys
byovdsn1per --cve-list

# Strings + YARA rule
byovdsn1per --strings --yara-rule driver.sys
byovdsn1per --yara-rule --yara-out rule.yar driver.sys

# Compare two drivers
byovdsn1per --diff a.sys b.sys

# Bulk sweep a directory
byovdsn1per --sweep drivers/ --filter perfect
```

## Crawl mode

Discover kernel drivers on the system. Output goes to `%USERPROFILE%\BYOVDsn1per\crawler\` by default (see "Where do crawl results go?" above).

```bash
# 33 default known driver paths (System32\drivers, DriverStore, Program Files, vendor dirs)
byovdsn1per --crawl

# Every logical drive (A:..Z:) — entire PC
byovdsn1per --deepcrawl

# Wipe the .scanned_paths.txt checkpoint + fresh deepcrawl
byovdsn1per --restart

# Custom paths
byovdsn1per --crawl --crawl-path D:\extracted_drivers
byovdsn1per --crawl --crawl-out my_harvest/ --crawl-limit 100

# Show what --crawl walks by default
byovdsn1per --list-default-roots
```

Crawl filter is intentionally minimal — checks for `subsystem == NATIVE` and `AddressOfEntryPoint != 0` (has DriverEntry). Deduplicates by SHA256 using a `.sha256_cache.txt` so re-runs are instant. Resumable via per-directory checkpoint.

## End-to-end pipeline

```bash
byovdsn1per --crawl                                  # 1. discover
byovdsn1per --sweep %USERPROFILE%\BYOVDsn1per\crawler --poc       # 2. analyze + match CVEs
byovdsn1per --sweep %USERPROFILE%\BYOVDsn1per\crawler --filter perfect  # 3. focus on top-tier
```

## Output modes

```bash
--output table      # default human-readable
--output json
--output markdown
--quiet             # one-line verdict per driver
--verbose           # full IOCTL list, all sections, all imports
```

## Scoring

Each driver gets a score 0-100 mapped to a tier:

- **PERFECT** (90+): HVCI loadable + production cert + open dispatcher + multiple primitives
- **STRONG** (70+): HVCI loadable + at least one of: production cert, weak gates, rich primitive surface
- **INTERESTING** (50+): partial signals
- **WEAK** (30+): some BYOVD relevance
- **SKIP**: below threshold (anti-cheat, archetype penalty, etc.)

Score caps apply by HVCI status (no-FI=80, no-GCF/WX=60, full HVCI=100).

## Architecture notes

- Single-file scanner (~4500 lines). All extractors are pure-stdlib (no external PE parsing libs).
- `idalib` is invoked in a copied-to-tempdir database to keep cross-driver state isolated.
- Dispatcher walker supports MSVC switch lowering patterns: cmp+jz, cmp+jnz (fall-through handler), cmp+setcc, cmp+cmovcc, biased switches (`add reg, IMM; cmp reg, MAX`), `mov reg, IMM; cmp r2, reg; jcc` two-register patterns.
- Burnt-cert thumbprint blacklist (LeYao, WDKTestCert, brazilian impersonating campaign, etc.) for fast filtering.
- Polluted-device-type CVE matcher gating: types appearing in 3+ CVE entries (`0x22, 0x9C40, 0xA040, 0xC350`) are non-evidence in isolation.

## Caveats

- IDA Pro is commercial software; the `idapro` Python package requires a valid license.
- This is a research tool. The scoring is heuristic — manual analysis is required before claiming a driver is exploitable.
- The CVE matcher is **fingerprinting-only**. It identifies known-vulnerable drivers but does NOT exploit them.
- HVCI status reflects PE flags only. Whether a driver actually loads on a given host depends on hot-patch state, Windows Code Integrity policy, and Defender Vulnerable Driver Blocklist version.

## License

Public domain.
