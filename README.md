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

## Quick start

```bash
# Single driver, full analysis
python BYOVDsn1per.py driver.sys

# Quick triage (no IDA dependency)
python BYOVDsn1per.py --quick driver.sys

# Deep mode with per-IOCTL primitive classification
python BYOVDsn1per.py --deep driver.sys

# CVE matcher (SAFE - no exploitation)
python BYOVDsn1per.py --poc driver.sys
python BYOVDsn1per.py --cve-list

# Strings + YARA rule
python BYOVDsn1per.py --strings --yara-rule driver.sys
python BYOVDsn1per.py --yara-rule --yara-out rule.yar driver.sys

# Compare two drivers
python BYOVDsn1per.py --diff a.sys b.sys

# Bulk sweep a directory
python BYOVDsn1per.py --sweep drivers/ --filter perfect
```

## Crawl mode

Discover kernel drivers on the system:

```bash
# 33 default known driver paths (System32\drivers, DriverStore, Program Files, vendor dirs)
python BYOVDsn1per.py --crawl

# Every logical drive (A:..Z:) — entire PC
python BYOVDsn1per.py --deepcrawl

# Wipe the .scanned_paths.txt checkpoint + fresh deepcrawl
python BYOVDsn1per.py --restart

# Custom paths
python BYOVDsn1per.py --crawl --crawl-path D:\extracted_drivers
python BYOVDsn1per.py --crawl --crawl-out my_harvest/ --crawl-limit 100

# Show what --crawl walks by default
python BYOVDsn1per.py --list-default-roots
```

Crawl filter is intentionally minimal — checks for `subsystem == NATIVE` and `AddressOfEntryPoint != 0` (has DriverEntry). Deduplicates by SHA256 using a `.sha256_cache.txt` so re-runs are instant. Resumable via per-directory checkpoint.

## End-to-end pipeline

```bash
python BYOVDsn1per.py --crawl                       # 1. discover
python BYOVDsn1per.py --sweep crawler/ --poc        # 2. analyze + match CVEs
python BYOVDsn1per.py --sweep crawler/ --filter perfect  # 3. focus on top-tier
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
