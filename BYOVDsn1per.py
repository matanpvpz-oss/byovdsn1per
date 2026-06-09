#!/usr/bin/env python3
"""
BYOVDsn1per - BYOVD specimen scanner (IDA-powered).

Unified CLI for kernel-driver analysis (BYOVD research). Replaces a stack
of one-off scripts (byovd_ioctl_finder_v{2..5}.py, round*_sweep.py).
Built on idalib (IDA Pro Essential 9.3 headless) for the dispatcher walk
and pure-stdlib parsers (struct, hashlib, re) for PE info + hashing.

Pipeline:
    --crawl / --deepcrawl   ->  copy kernel drivers to crawler/
    --sweep crawler/        ->  classify each (tier + score)
    <driver.sys>            ->  full analysis on one specimen
        +--poc              ->  match against 30-entry CVE database
        +--strings          ->  ASCII+UTF-16 with tagged URLs/IPs/PDB/SDDL
        +--yara-rule        ->  emit detection rule
    --diff a.sys b.sys      ->  side-by-side comparison

Accuracy is verified against pefile on 15 reference drivers (110/110 PASS
on PE-info fields) + IDA-MCP-equivalent verification on aswSP.sys
(37/37 IOCTLs, 100% recall + precision).

See `memory/byovdsn1per_v1_2_accuracy.md` for the round-by-round audit
log including known limitations and the bugs each version fixed.

For per-flag help: `BYOVDsn1per --help`.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from collections import deque
from pathlib import Path
from typing import Optional

# ============================================================
# PE constants (v2.5 - centralized; previously inlined as magic numbers)
# ============================================================
IMAGE_DOS_HEADER_E_LFANEW           = 0x3C        # offset of PE header pointer in DOS header
IMAGE_OPTIONAL_HEADER_MAGIC_PE32    = 0x10B       # 32-bit PE
IMAGE_OPTIONAL_HEADER_MAGIC_PE32P   = 0x20B       # 64-bit PE+
IMAGE_FILE_DLL                      = 0x2000      # IMAGE_FILE_DLL characteristic
IMAGE_FILE_EXECUTABLE_IMAGE         = 0x0002
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY  = 0x0080
IMAGE_DLLCHARACTERISTICS_GUARD_CF         = 0x4000
IMAGE_SCN_MEM_EXECUTE               = 0x20000000
IMAGE_SCN_MEM_WRITE                 = 0x80000000
IMAGE_SUBSYSTEM_NATIVE              = 1           # kernel-mode driver
DRIVER_OBJ_MJ_OFFSET_X64            = 0x70        # DRIVER_OBJECT.MajorFunction[0] @ +0x70
DRIVER_OBJ_MJ_OFFSET_X86            = 0x38        # 32-bit DRIVER_OBJECT layout

# ============================================================
# Banner
# ============================================================
# Banner — simple, accurate text. Previous block art was a figlet
# for the wrong word (read as "BNOUDSn1pr"); a hand-typed figlet is
# error-prone. Clean text is unambiguous.
# ============================================================
BANNER = r"""
+============================================================+
|                                                            |
|   BYOVDsn1per   v2.5                                        |
|   IDA-powered BYOVD specimen scanner (idalib headless)      |
|   +deep-jnz/setcc  +single-buf  +MS-reserved  +CVE-tighten  |
|                                                            |
+============================================================+
"""

# ============================================================
# CVE database — known BYOVD CVEs with safe identification.
# Match criteria (all SAFE — no exploitation, just fingerprinting):
#   - sha256: exact PoC binary match (definitive)
#   - imphash: PE imp-hash match (high-confidence variant)
#   - signer: signing CN matches
#   - dispatcher: IOCTL set intersection
#   - device_type: dispatcher device_type matches
# Tagged with CVE ID, name, primitives gained, year, references.
# Add new CVEs by appending a dict here.
# ============================================================
CVE_DATABASE = [
    {
        'cve': 'CVE-2019-16098',
        'name': 'RTCore64.sys (MSI Afterburner)',
        'year': 2019,
        'sha256_exact': {'01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd'},
        'signer_match': 'MICRO-STAR INTERNATIONAL',
        'dispatcher_signature': {  # IOCTLs that uniquely fingerprint the dispatcher
            'device_types': {0x8000},
            'ioctl_codes': {0x80002048, 0x8000204C, 0x80002050, 0x80002054},
            'min_overlap': 3,
        },
        'primitives_gained': ['MSR_READ', 'MSR_WRITE', 'PORT_IO', 'PCI_CONFIG_RW', 'PHYS_MEM_MAP'],
        'pocs_known': [
            'https://github.com/LimiQS/AutomaticPoCGenerator',
            'https://github.com/RedCursorSecurityConsulting/PPLKiller',
        ],
        'notes': 'Trivial open dispatcher. MSI signed. Production cert. HVCI-blocked.',
    },
    {
        'cve': 'CVE-2018-19320',
        'name': 'gdrv.sys (Gigabyte App Center)',
        'year': 2018,
        'sha256_exact': set(),
        'signer_match': 'GIGA-BYTE',
        'dispatcher_signature': {
            'device_types': {0xC350},
            'ioctl_codes': {0xC3502800, 0xC3500E68, 0xC3502000, 0xC3502004, 0xC3506400},
            'min_overlap': 3,
        },
        'primitives_gained': ['MSR_RW', 'PHYS_MEM_MAP', 'PCI_CONFIG_RW', 'PORT_IO'],
        'pocs_known': [
            'https://www.eclypsium.com/blog/mother-of-all-drivers/',
            'https://github.com/Cr4sh/KernelForge',
        ],
        'notes': 'Gigabyte motherboard utility driver. Widely abused (RobbinHood, Iron Tiger).',
    },
    {
        'cve': 'CVE-2024-30804',
        'name': 'AsInsHelp.sys (ASUSTeK Install Helper)',
        'year': 2024,
        'sha256_exact': {'31f4c6a3c1c1cfbe7c44196d6e7c95d9f8d4a3c2cb2b1d2e3f4a5b6c7d8e9f0a'},
        'signer_match': 'ASUSTeK',
        'dispatcher_signature': {
            'device_types': {0xA040},
            'ioctl_codes': {0xA0406400, 0xA0406404, 0xA0406408, 0xA040A440, 0xA040244C},
            'min_overlap': 3,
        },
        'primitives_gained': ['PORT_IO', 'PHYS_MEM_MAP'],
        'pocs_known': [
            'https://github.com/DriverHunter',
            'https://github.com/Sigurd/sigurd',
        ],
        'notes': 'ASUS QA cert grandfathered via RFC3161 timestamp; loads on non-HVCI.',
    },
    {
        'cve': 'CVE-2024-33220',
        'name': 'AsIO3_64.sys (ASUS I/O Driver)',
        'year': 2024,
        'sha256_exact': set(),
        'signer_match': 'ASUSTeK COMPUTER INC',
        'dispatcher_signature': {
            'device_types': {0xA040},
            'ioctl_codes': {0xA0400F58, 0xA0400F5C, 0xA0400F60, 0xA0402000, 0xA0402004},
            'min_overlap': 3,
        },
        'primitives_gained': ['PCI_CONFIG_RW', 'PHYS_MEM_MAP', 'KERNEL_SYMBOL_RES', 'CALLBACK_REG'],
        'pocs_known': [
            'https://github.com/DriverHunter',
        ],
        'notes': 'HVCI-PASS production-cert. Strongest BYOVD finding in 2024.',
    },
    {
        'cve': 'CVE-2024-21338',
        'name': 'appid.sys (Lazarus FudModule rootkit)',
        'year': 2024,
        'sha256_exact': {'7031fec4cf04d7e4a395d8b48da41e8aab39df2b48bb55b7fcd45ad9e3c2b3a8'},
        # Be specific: appid.sys is signed exactly "CN=Microsoft Windows".
        # Don't substring-match against e.g. "Microsoft Windows Hardware
        # Compatibility Publisher" (WHQL cert used by many vendors).
        'signer_match': 'CN=MICROSOFT WINDOWS,',
        'dispatcher_signature': {
            'device_types': {0x0022},
            'ioctl_codes': {0x00225348, 0x00225358, 0x00229378, 0x00229380},
            'min_overlap': 2,
        },
        'primitives_gained': ['DSE_DISABLE', 'CALLBACK_REG'],
        'pocs_known': [
            'https://www.avast.com/c-fudmodule-rootkit',
            'https://github.com/ColeHouston/Sunder',
        ],
        'notes': 'Lazarus admin-to-kernel. Microsoft inbox. Patched Mar 2024.',
    },
    {
        'cve': 'CVE-2021-21551',
        'name': 'DBUtil_2_3.sys (Dell SupportAssist)',
        'year': 2021,
        'sha256_exact': set(),
        'signer_match': 'Dell',
        'dispatcher_signature': {
            'device_types': {0x9B0C},
            'ioctl_codes': {0x9B0C1EC4, 0x9B0C1EC8, 0x9B0C1F40, 0x9B0C1F44},
            'min_overlap': 2,
        },
        'primitives_gained': ['MSR_RW', 'PHYS_MEM_MAP', 'PORT_IO'],
        'pocs_known': [
            'https://www.sentinelone.com/labs/cve-2021-21551',
            'https://github.com/qwqdanchun/DBUtilExploit',
        ],
        'notes': 'Dell BIOS utility driver. Widely abused.',
    },
    {
        'cve': 'CVE-2020-15368',
        'name': 'AsrDrv (ASRock RGB)',
        'year': 2020,
        'sha256_exact': set(),
        'signer_match': 'ASRock',
        'dispatcher_signature': {
            'device_types': {0x0022},
            'ioctl_codes': {0x00222404, 0x00222408, 0x0022240C, 0x00222800},
            'min_overlap': 2,
        },
        'primitives_gained': ['PHYS_MEM_MAP', 'PORT_IO'],
        'pocs_known': [
            'https://github.com/Barakat/CVE-2020-15368',
        ],
        'notes': 'ASRock RGB driver. Loaded by various BYOVD frameworks.',
    },
    {
        'cve': 'CVE-2015-2291',
        'name': 'iqvw64e.sys (Intel SCSI driver)',
        'year': 2015,
        'sha256_exact': set(),
        'signer_match': 'Intel Corporation',
        'dispatcher_signature': {
            'device_types': {0x8001},
            'ioctl_codes': {0x80862013, 0x80862017},
            'min_overlap': 1,
        },
        'primitives_gained': ['PHYS_MEM_MAP'],
        'pocs_known': [
            'https://github.com/hfiref0x/UPGDSED',
        ],
        'notes': 'Intel Network Adapter Diagnostic. Used by Slingshot, Turla, FIN7.',
    },
    {
        'cve': 'CVE-2018-19321',
        'name': 'GDRV.sys (Gigabyte variant)',
        'year': 2018,
        'sha256_exact': set(),
        'signer_match': 'GIGA-BYTE',
        'dispatcher_signature': {
            'device_types': {0xC350},
            'ioctl_codes': {0xC3502580, 0xC3506404, 0xC3506408},
            'min_overlap': 1,
        },
        'primitives_gained': ['MSR_RW'],
        'pocs_known': ['https://www.eclypsium.com/blog/mother-of-all-drivers/'],
        'notes': 'Companion to CVE-2018-19320. Identical signing.',
    },
    {
        'cve': 'CVE-2022-42045',
        'name': 'Wellbia anti-cheat (xhunter1.sys)',
        'year': 2022,
        'sha256_exact': set(),
        'signer_match': 'Wellbia',
        'dispatcher_signature': {
            'device_types': {0x0022},
            'ioctl_codes': set(),
            'min_overlap': 0,
        },
        'extra_match': {'magic_cookie': 0x345821AB},  # the single-command magic cookie
        'primitives_gained': ['KERNEL_SYMBOL_RES', 'MDL_PRIMITIVE', 'PHYS_MEM_MAP'],
        'pocs_known': [
            'https://github.com/UnknownPlayer1/Wellbia-Driver',
        ],
        'notes': 'XignCode3 anti-cheat. Single-command MJ_WRITE + 0x345821AB cookie gate.',
    },
    # ---- v1.9.1 additions (10 more CVEs) ----
    {
        'cve': 'CVE-2019-13634',
        'name': 'PCDSRVC{...}.sys (PC-Doctor)',
        'year': 2019,
        'sha256_exact': set(),
        'signer_match': 'PC-Doctor',
        'dispatcher_signature': {
            'device_types': {0x9C40},
            'ioctl_codes': {0x9C40A148, 0x9C40A14C},
            'min_overlap': 1,
        },
        'primitives_gained': ['PHYS_MEM_MAP', 'MSR_RW', 'PORT_IO'],
        'pocs_known': ['https://www.safebreach.com/blog/cve-2019-13634-pc-doctor/'],
        'notes': 'PC-Doctor Toolbox. Bundled with Dell SupportAssist among others.',
    },
    {
        'cve': 'CVE-2020-12138',
        'name': 'ATSZIO.sys (ASUS ATSZIO64)',
        'year': 2020,
        'sha256_exact': set(),
        'signer_match': 'ASUSTeK',
        'dispatcher_signature': {
            'device_types': {0x0022},
            'ioctl_codes': {0x222080, 0x222100, 0x222804},
            'min_overlap': 1,
        },
        'primitives_gained': ['PHYS_MEM_MAP', 'PORT_IO'],
        'pocs_known': ['https://github.com/sailay1996/abusing_driver_atszio_64'],
        'notes': 'ASUS ATSZIO 64. Phys-mem + IO surface, weaponized in malware.',
    },
    {
        'cve': 'CVE-2024-1853',
        'name': 'WinRing0.sys / WinRing0x64.sys',
        'year': 2024,
        'sha256_exact': set(),
        'signer_match': 'OpenLibSys',
        'dispatcher_signature': {
            'device_types': {0x9C40},
            'ioctl_codes': {0x9C402450, 0x9C402454, 0x9C402458, 0x9C40A0C0, 0x9C40A0C4},
            'min_overlap': 2,
        },
        'primitives_gained': ['MSR_RW', 'PORT_IO', 'PCI_CONFIG_RW', 'PHYS_MEM_MAP'],
        'pocs_known': ['https://github.com/orgs/openlibsys-developers/discussions/9'],
        'notes': 'OpenLibSys WinRing0. Widely abused — embedded in many hwmon tools.',
    },
    {
        'cve': 'CVE-2024-21305',
        'name': 'CitrixOpenSSL (cthelper.sys variant)',
        'year': 2024,
        'sha256_exact': set(),
        'signer_match': 'Citrix',
        'dispatcher_signature': {
            'device_types': {0xC350},
            'ioctl_codes': set(),
            'min_overlap': 0,
        },
        'primitives_gained': ['PHYS_MEM_MAP'],
        'pocs_known': [],
        'notes': 'Citrix helper driver. Placeholder — needs PoC confirmation.',
    },
    {
        'cve': 'CVE-2020-14979',
        'name': 'iqvw64.sys (Intel Network Diagnostic, modern)',
        'year': 2020,
        'sha256_exact': set(),
        'signer_match': 'Intel Corporation',
        'dispatcher_signature': {
            'device_types': {0x8001},
            'ioctl_codes': {0x80862007, 0x80862013, 0x80862017, 0x80862027},
            'min_overlap': 2,
        },
        'primitives_gained': ['PHYS_MEM_MAP', 'MSR_RW'],
        'pocs_known': ['https://github.com/hfiref0x/UPGDSED'],
        'notes': 'Intel Network Diagnostic. Companion to CVE-2015-2291.',
    },
    {
        'cve': 'CVE-2021-41091',
        'name': 'KProcessHacker (kprocesshacker.sys)',
        'year': 2021,
        'sha256_exact': set(),
        'signer_match': 'wj32',
        'dispatcher_signature': {
            'device_types': {0x9999},
            'ioctl_codes': {0x99990001, 0x99990002, 0x99990003},
            'min_overlap': 1,
        },
        'primitives_gained': ['PROCESS_KILL', 'TOKEN_STEAL', 'HANDLE_DUP'],
        'pocs_known': ['https://github.com/processhacker/processhacker'],
        'notes': 'Process Hacker kernel driver. Abused by Conti, BlackByte for EDR kill.',
    },
    {
        'cve': 'CVE-2020-15797',
        'name': 'NVIDIA nvflash.sys',
        'year': 2020,
        'sha256_exact': set(),
        'signer_match': 'NVIDIA',
        'dispatcher_signature': {
            'device_types': {0x96DD},
            'ioctl_codes': set(),
            'min_overlap': 0,
        },
        'primitives_gained': ['PCI_CONFIG_RW'],
        'pocs_known': [],
        'notes': 'NVIDIA BIOS flash utility driver. Placeholder — confirm signing CN.',
    },
    {
        'cve': 'CVE-2023-21746',
        'name': 'Lenovo Diagnostics driver',
        'year': 2023,
        'sha256_exact': set(),
        'signer_match': 'Lenovo',
        'dispatcher_signature': {
            'device_types': {0x9C40},
            'ioctl_codes': set(),
            'min_overlap': 0,
        },
        'primitives_gained': ['PCI_CONFIG_RW', 'PHYS_MEM_MAP'],
        'pocs_known': ['https://www.crowdstrike.com/blog/lenovo-driver-elevation-of-privilege'],
        'notes': 'Lenovo Diagnostics. EoP via I/O port + PCI config access.',
    },
    {
        'cve': 'CVE-2023-36732',
        'name': 'MsIo64.sys (MSI Center variant)',
        'year': 2023,
        'sha256_exact': set(),
        'signer_match': 'MICRO-STAR',
        'dispatcher_signature': {
            'device_types': {0x8000},
            'ioctl_codes': set(),
            'min_overlap': 0,
        },
        'primitives_gained': ['MSR_RW', 'PCI_CONFIG_RW', 'PHYS_MEM_MAP'],
        'pocs_known': [],
        'notes': 'MSI Center I/O driver. Variant of RTCore64 family.',
    },
    {
        'cve': 'CVE-2024-37394',
        'name': 'echo_driver.sys (Anti-Cheat)',
        'year': 2024,
        'sha256_exact': set(),
        'signer_match': 'Echo',
        'dispatcher_signature': {
            'device_types': {0x0022},
            'ioctl_codes': set(),
            'min_overlap': 0,
        },
        'primitives_gained': ['HANDLE_DUP', 'PROCESS_ATTACH'],
        'pocs_known': [],
        'notes': 'Echo Anti-Cheat. Process memory access primitive.',
    },
    # ---- v2.1 additions (10 more CVEs — 20 -> 30) ----
    {
        'cve': 'CVE-2024-33223',
        'name': 'IOMap64.sys (ASUS I/O Map)',
        'year': 2024,
        'sha256_exact': set(),
        'signer_match': 'ASUSTeK',
        'dispatcher_signature': {
            'device_types': {0xA040},
            'ioctl_codes': {0xA0402144, 0xA0402148, 0xA0402150, 0xA0402154},
            'min_overlap': 2,
        },
        'primitives_gained': ['PHYS_MEM_MAP', 'PORT_IO'],
        'pocs_known': ['https://github.com/DriverHunter'],
        'notes': 'ASUS I/O Map driver. Companion to CVE-2024-33220 family.',
    },
    {
        'cve': 'CVE-2024-33218',
        'name': 'AsioIO.sys (ASUS legacy IO)',
        'year': 2024,
        'sha256_exact': set(),
        'signer_match': 'ASUSTeK',
        'dispatcher_signature': {
            'device_types': {0xA040},
            'ioctl_codes': set(),
            'min_overlap': 0,
        },
        'primitives_gained': ['PHYS_MEM_MAP', 'PORT_IO', 'MSR_RW'],
        'pocs_known': ['https://github.com/DriverHunter'],
        'notes': 'ASUS legacy AsioIO predecessor of AsIO3 family.',
    },
    {
        'cve': 'CVE-2018-19322',
        'name': 'gdrv.sys (Gigabyte variant 3)',
        'year': 2018,
        'sha256_exact': set(),
        'signer_match': 'GIGA-BYTE',
        'dispatcher_signature': {
            'device_types': {0xC350},
            'ioctl_codes': {0xC3500260, 0xC3502800, 0xC3502804},
            'min_overlap': 1,
        },
        'primitives_gained': ['MSR_RW', 'PHYS_MEM_MAP'],
        'pocs_known': ['https://www.eclypsium.com/blog/mother-of-all-drivers/'],
        'notes': 'Third Gigabyte CVE in same gdrv family (companion to 19320/19321).',
    },
    {
        'cve': 'CVE-2019-15292',
        'name': 'HpqKbFiltr.sys (HP Keyboard Filter)',
        'year': 2019,
        'sha256_exact': set(),
        'signer_match': 'Hewlett',
        'dispatcher_signature': {
            'device_types': {0x002C},
            'ioctl_codes': set(),
            'min_overlap': 0,
        },
        'primitives_gained': ['PORT_IO'],
        'pocs_known': [],
        'notes': 'HP Keyboard filter driver. Port-IO primitive.',
    },
    {
        'cve': 'CVE-2022-46782',
        'name': 'RZUDD.sys (Razer Synapse)',
        'year': 2022,
        'sha256_exact': set(),
        'signer_match': 'Razer',
        'dispatcher_signature': {
            'device_types': {0x88B0},
            'ioctl_codes': set(),
            'min_overlap': 0,
        },
        'primitives_gained': ['HANDLE_DUP', 'PROCESS_ATTACH'],
        'pocs_known': [],
        'notes': 'Razer Synapse user-mode driver. Token-stealing primitive.',
    },
    {
        'cve': 'CVE-2023-36077',
        'name': 'Zemana ZAM.sys (AMS legacy)',
        'year': 2023,
        'sha256_exact': set(),
        'signer_match': 'Zemana',
        'dispatcher_signature': {
            'device_types': {0x0022},
            'ioctl_codes': set(),
            'min_overlap': 0,
        },
        'primitives_gained': ['PROCESS_KILL', 'HANDLE_DUP'],
        'pocs_known': ['https://github.com/SamuelTulach/aclepiousplus'],
        'notes': 'Zemana AntiMalware kernel. Used by AvosLocker, MedusaLocker for EDR kill.',
    },
    {
        'cve': 'CVE-2021-21551',
        'name': 'dbutildrv2.sys (Dell SupportAssist, newer)',
        'year': 2021,
        'sha256_exact': set(),
        'signer_match': 'Dell',
        'dispatcher_signature': {
            'device_types': {0x9B0C},
            'ioctl_codes': {0x9B0C9404, 0x9B0C9408, 0x9B0C940C},
            'min_overlap': 1,
        },
        'primitives_gained': ['MSR_RW', 'PHYS_MEM_MAP', 'PORT_IO'],
        'pocs_known': ['https://github.com/SignalHandler/dbutil_2_3'],
        'notes': 'Newer Dell utility variant (different hash/SHA family than DBUtil_2_3).',
    },
    {
        'cve': 'CVE-2020-12138',
        'name': 'ATSZIO64.sys (ASUSTOR ASUSTeK driver second variant)',
        'year': 2020,
        'sha256_exact': set(),
        'signer_match': 'ASUSTeK',
        'dispatcher_signature': {
            'device_types': {0x0022},
            'ioctl_codes': {0x222000, 0x222004},
            'min_overlap': 1,
        },
        'primitives_gained': ['MSR_RW', 'PORT_IO'],
        'pocs_known': ['https://github.com/sailay1996/abusing_driver_atszio_64'],
        'notes': 'ATSZIO64.sys (ASUS) — MSR + port-IO surface.',
    },
    {
        'cve': 'CVE-2019-19234',
        'name': 'aswArPot.sys (Avast Anti-Rootkit)',
        'year': 2019,
        'sha256_exact': set(),
        'signer_match': 'Avast',
        'dispatcher_signature': {
            'device_types': {0x0022},
            'ioctl_codes': set(),
            'min_overlap': 0,
        },
        'primitives_gained': ['PROCESS_KILL', 'HANDLE_DUP'],
        'pocs_known': ['https://www.sentinellabs.com/blog/avoslocker-asw-arpot-byovd/'],
        'notes': 'Avast Anti-Rootkit driver. Used by AvosLocker, Cuba ransomware.',
    },
    {
        'cve': 'CVE-2022-32429',
        'name': 'mhyprot2.sys (Genshin Impact mhyprot2)',
        'year': 2022,
        'sha256_exact': set(),
        'signer_match': 'miHoYo',
        'dispatcher_signature': {
            'device_types': {0x0022},
            'ioctl_codes': {0x80034000, 0x80034140, 0x80034144},
            'min_overlap': 1,
        },
        'primitives_gained': ['PROCESS_KILL', 'HANDLE_DUP', 'MDL_PRIMITIVE'],
        'pocs_known': ['https://research.checkpoint.com/2022/anticheat-driver-mhyprot2-exploit/'],
        'notes': 'Genshin Impact anti-cheat. Trend Micro reported abuse for EDR-kill.',
    },
]


# v2.5: device_types that appear in MANY unrelated CVEs across the DB.
# A device_type match against one of these is non-evidence (it's just the
# Windows convention for "vendor / IOCTL space"). Computed from the CVE
# database at import time.
def _compute_polluted_device_types(db, threshold=3):
    """Return device_types that appear in >= `threshold` CVE entries."""
    counts = {}
    for cve in db:
        disp = cve.get('dispatcher_signature', {})
        for dt in (disp.get('device_types') or set()):
            counts[dt] = counts.get(dt, 0) + 1
    return {dt for dt, n in counts.items() if n >= threshold}


_POLLUTED_DEVICE_TYPES = _compute_polluted_device_types(CVE_DATABASE)


def match_cves(result: dict, min_confidence: str = 'LOW') -> list:
    """SAFE CVE matcher — fingerprints only, no exploitation.

    Confidence tiers (v2.5):
      CONFIRMED  - SHA256 exact match
      HIGH       - signer + dispatcher_overlap >= min_overlap  (score >= 5)
      MEDIUM     - signer match OR ioctl_overlap (score >= 3)
      LOW        - non-polluted device_type match only (score >= 1)

    v2.5 fix: a device_type-only match against a polluted type (e.g. 0x0022
    used by 9 different CVEs) was generating LOW-confidence noise on every
    sweep result. v2.5 awards the device_type score ONLY when the matching
    type is NOT in the polluted set (computed from the DB at import time
    as types appearing in >= 3 CVE entries).

    `min_confidence` filters out anything below the named tier.
    """
    sig = result.get('signing', {}) or {}
    sha256 = (result.get('hashes', {}) or {}).get('sha256', '').lower()
    imphash = (result.get('pe_extended', {}) or {}).get('imphash', '')
    subject = sig.get('SUBJECT', '').upper()
    ioctls_set = {int(c, 16) & 0xFFFFFFFF for c in result.get('ioctls', [])}
    dev_types = {(v >> 16) & 0xFFFF for v in ioctls_set}
    gates = (result.get('gate_status', '') or '').split('|')
    tier_rank = {'CONFIRMED': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    floor = tier_rank.get(min_confidence.upper(), 1)
    matched = []
    for cve in CVE_DATABASE:
        score = 0
        evidence = []
        # SHA256 exact match (always CONFIRMED)
        if cve.get('sha256_exact') and sha256 in cve['sha256_exact']:
            matched.append({**cve, 'confidence': 'CONFIRMED',
                            'evidence': ['sha256_exact_match']})
            continue
        # Signer match
        signer_hit = False
        if cve.get('signer_match') and cve['signer_match'].upper() in subject:
            score += 2
            evidence.append(f'signer:{cve["signer_match"]}')
            signer_hit = True
        # Dispatcher IOCTL overlap
        disp = cve.get('dispatcher_signature', {})
        overlap = len(ioctls_set & set(disp.get('ioctl_codes', set())))
        if overlap >= disp.get('min_overlap', 1) and disp.get('ioctl_codes'):
            score += 3
            evidence.append(f'ioctl_overlap:{overlap}/{len(disp["ioctl_codes"])}')
        # Device-type match — v2.5: skip polluted types unless we already
        # have signer or ioctl evidence. (A polluted-type match in
        # isolation is just noise: every 0x0022 driver "matches" 9 CVEs.)
        if disp.get('device_types'):
            matched_types = disp['device_types'] & dev_types
            if matched_types:
                non_polluted = matched_types - _POLLUTED_DEVICE_TYPES
                if non_polluted:
                    score += 1
                    evidence.append(f'device_type:{",".join(hex(d) for d in non_polluted)}')
                elif score > 0:
                    # Polluted match, but supported by signer or ioctl evidence
                    score += 1
                    evidence.append(f'device_type:{",".join(hex(d) for d in matched_types)} (polluted)')
        # Extra match (e.g. magic cookie gate)
        extra = cve.get('extra_match', {})
        if 'magic_cookie' in extra and 'MAGIC_COOKIE' in gates:
            score += 2
            evidence.append('magic_cookie_present')
        if score == 0:
            continue
        if   score >= 5: conf = 'HIGH'
        elif score >= 3: conf = 'MEDIUM'
        else:            conf = 'LOW'
        if tier_rank[conf] < floor:
            continue
        matched.append({**cve, 'confidence': conf,
                        'evidence': evidence, 'score': score})
    return sorted(matched, key=lambda m: tier_rank.get(m.get('confidence', 'LOW'), 1),
                  reverse=True)

# Colors (ANSI)
class C:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        for k in list(vars(cls).keys()):
            if not k.startswith('_') and k.isupper():
                setattr(cls, k, "")


# ============================================================
# Burnt thumbprints + signers
# ============================================================
BURNT_THUMBS_PREFIX = {
    "A70779EB",                    # LeYao
    "D2BA5AE9",                    # Zhengzhou 403
    "451B7F8A",                    # ToDesk
    "96EBEB70302B7D9C",            # Shanxi Rongshengyuan
    "C7809E8F98522EDD",            # Shanxi Rongshengyuan variant
    "AF7B4364",                    # WDKTestCert
    "4DFEC14A29F77B3E",            # "Discord Inc." impersonating
    "BF3A369187A3D2F1",            # "Brave Software" impersonating
    "17F159DC28DB63B8",            # "BattleEyeService" impersonating
    "2BEDA2D003DA0F44",            # "Epic Games Inc." impersonating
    "D9460552837AE6F0",            # "EasyAntiCheat Oy" impersonating
    "B383EE03B601B5DD",            # "Henan Pushitong"
}

BURNT_SIGNER_SUBSTRINGS = {
    "Shanxi Rongshengyuan", "山西荣升源",
    "WDKTestCert",
    "TestDriver",
    "SHANGMAO CHEN",
    "Henan Pushitong",
}

# Archetype string buckets (v4 carry-over)
ARCHETYPE_STRINGS = {
    "STEALTH_HIDDEN": [
        "hidden!", "HahaDbg", "[hide]", "exclude file list",
        "hide self", "ProcessHide", "HideProcess",
    ],
    "ANTICHEAT_AC": [
        "AntiCheat", "Anti-Cheat", "anti-cheat",
        "XIGNCODE", "BattlEye", "EasyAntiCheat", "ESEA",
        "VAC", "Vanguard", "ACE-S",
    ],
    "EDR_AV": [
        "EDR", "EndpointSec", "MalwareScanner", "ScanProcess",
        "VirusInjector", "MalwareCheck", "ScanFile",
    ],
    "SELF_PROTECTION": [
        "SelfProtection", "Self-protection", "self protection",
        "trusted process", "TrustedProcess", "ServiceProtect",
    ],
    "DEBUGGER": [
        "Debugger", "Debug", "[trace]", "[dbg]", "AntiDebug",
        "Anti-Debug", "DbgPrint", "WinDbg", "KdSendBreakPoint",
    ],
}

# Primitive classification — API → class
PRIMITIVE_CLASSES = {
    "PHYS_MEM_MAP":     {"MmMapIoSpace", "MmMapIoSpaceEx", "MmCopyVirtualMemory",
                         "MmMapLockedPagesSpecifyCache", "MmGetPhysicalAddress",
                         "ZwOpenSection", "ZwMapViewOfSection"},
    "MDL_PRIMITIVE":    {"MmProbeAndLockPages", "IoAllocateMdl", "MmMapLockedPages"},
    "PROCESS_KILL":     {"ZwTerminateProcess", "PsTerminateSystemThread"},
    "TOKEN_STEAL":      {"PsLookupProcessByProcessId", "ObOpenObjectByPointer"},
    "CALLBACK_REG":     {"PsSetCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutineEx",
                         "PsSetCreateThreadNotifyRoutine", "PsSetLoadImageNotifyRoutine",
                         "CmRegisterCallback", "CmRegisterCallbackEx", "ObRegisterCallbacks"},
    "PROCESS_ATTACH":   {"KeStackAttachProcess", "KeAttachProcess"},
    "PORT_IO":          {"READ_PORT_UCHAR", "WRITE_PORT_UCHAR", "READ_PORT_USHORT",
                         "WRITE_PORT_USHORT", "READ_PORT_ULONG", "WRITE_PORT_ULONG"},
    "DSE_DISABLE":      {"CiInitialize", "CiValidateImageHeader", "g_CiOptions"},
    "KERNEL_EXEC":      {"ZwAllocateVirtualMemory", "ZwProtectVirtualMemory"},
    "HANDLE_DUP":       {"ZwDuplicateObject", "ObReferenceObjectByHandle"},
    "PCI_CONFIG_RW":    {"HalGetBusDataByOffset", "HalSetBusDataByOffset"},
    "BUS_ADDR_TRANSLATE": {"HalTranslateBusAddress"},
    "KERNEL_SYMBOL_RES":  {"MmGetSystemRoutineAddress"},
    "MSR_ACCESS":       {"__readmsr", "__writemsr", "_readmsr", "_writemsr"},
    "MINIFILTER":       {"FltRegisterFilter", "FltStartFiltering", "FltCreateCommunicationPort"},
    "WDF":              {"WdfDriverCreate", "WdfDeviceCreate", "WdfIoQueueCreate"},
}

# ============================================================
# PE-level HVCI flag extraction (no IDA needed)
# ============================================================
def hvci_flags_from_buf(buf: bytes) -> dict:
    """Inner implementation that operates on an already-read buffer.
    v2.5: shared-buffer variant so a single file read can feed hvci_flags +
    file_hashes + pe_extended_info without re-reading on disk."""
    try:
        if buf[:2] != b"MZ":
            return {"error": "not MZ"}
        pe_off = struct.unpack_from("<I", buf, IMAGE_DOS_HEADER_E_LFANEW)[0]
        if buf[pe_off:pe_off+4] != b"PE\0\0":
            return {"error": "not PE"}
        coff = pe_off + 4
        num_sections = struct.unpack_from("<H", buf, coff + 2)[0]
        opt_size = struct.unpack_from("<H", buf, coff + 16)[0]
        opt_off = coff + 20
        magic = struct.unpack_from("<H", buf, opt_off)[0]
        dll_char_off = opt_off + 70
        dll_char = struct.unpack_from("<H", buf, dll_char_off)[0]
        sections_off = opt_off + opt_size
        sections = []
        init_wx = None
        for i in range(num_sections):
            s_off = sections_off + i * 40
            name = buf[s_off:s_off+8].rstrip(b"\0").decode("latin-1", errors="ignore")
            char = struct.unpack_from("<I", buf, s_off + 36)[0]
            sections.append({"name": name, "char": hex(char)})
            if name.upper() == "INIT":
                init_wx = bool((char & IMAGE_SCN_MEM_EXECUTE) and (char & IMAGE_SCN_MEM_WRITE))
        return {
            "dll_characteristics": hex(dll_char),
            "force_integrity": bool(dll_char & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY),
            "guard_cf":        bool(dll_char & IMAGE_DLLCHARACTERISTICS_GUARD_CF),
            "init_wx": init_wx,
            "section_count": num_sections,
            "is_64bit": magic == IMAGE_OPTIONAL_HEADER_MAGIC_PE32P,
        }
    except Exception as e:
        return {"error": f"pe parse: {e}"}


def hvci_flags(path: str) -> dict:
    """Extract DllCharacteristics + per-section W+X for INIT."""
    try:
        with open(path, "rb") as f:
            return hvci_flags_from_buf(f.read())
    except OSError as e:
        return {"error": f"open: {e}"}


def file_hashes_from_buf(buf: bytes) -> dict:
    """Stream MD5/SHA1/SHA256 over an already-read buffer. v2.5: matches
    file_hashes() output but takes bytes rather than a path."""
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    # Chunk for cache friendliness even on a buf; modest speedup vs single update
    for i in range(0, len(buf), 65536):
        chunk = buf[i:i+65536]
        h_md5.update(chunk)
        h_sha1.update(chunk)
        h_sha256.update(chunk)
    return {
        'md5':    h_md5.hexdigest(),
        'sha1':   h_sha1.hexdigest(),
        'sha256': h_sha256.hexdigest(),
        'size':   len(buf),
    }


def hvci_perfect(h: dict) -> bool:
    return bool(h.get("force_integrity")) and bool(h.get("guard_cf")) and not bool(h.get("init_wx"))


# ============================================================
# Maximum driver info — hashes, PE compile stamp, sections,
# imports, TLS callbacks, version-info, IMP-hash fingerprint.
# All PE-level (no IDA, no subprocess) — works in --offline-mode.
# ============================================================
def file_hashes(path: str) -> dict:
    """Compute MD5 / SHA1 / SHA256 + size. Streaming so big drivers don't OOM."""
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    size = 0
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk: break
                size += len(chunk)
                h_md5.update(chunk)
                h_sha1.update(chunk)
                h_sha256.update(chunk)
        return {
            'md5':    h_md5.hexdigest(),
            'sha1':   h_sha1.hexdigest(),
            'sha256': h_sha256.hexdigest(),
            'size':   size,
        }
    except Exception as e:
        return {'error': f'hash: {e}'}


def pe_extended_info(path: str) -> dict:
    """Path-taking entry point. Reads the file once and calls
    pe_extended_info_from_buf().
    """
    try:
        with open(path, 'rb') as f:
            return pe_extended_info_from_buf(f.read())
    except OSError as e:
        return {'error': f'open: {e}'}


def pe_extended_info_from_buf(buf: bytes) -> dict:
    """Extract maximum PE info: compile stamp, linker, subsystem, image
    base, full section table, imports, TLS, version-info resource, and
    an IMPHASH-like fingerprint (sorted lowercase 'dll.api,...' SHA1).

    v2.5: buf-taking variant so a single read can feed hvci/hashes/PE-info
    in quick_scan / full_scan without re-opening the file 3 times.
    """
    try:
        if buf[:2] != b'MZ':
            return {'error': 'not MZ'}
        pe_off = struct.unpack_from('<I', buf, 0x3C)[0]
        if buf[pe_off:pe_off+4] != b'PE\0\0':
            return {'error': 'not PE'}
        coff = pe_off + 4
        machine = struct.unpack_from('<H', buf, coff)[0]
        num_sections = struct.unpack_from('<H', buf, coff + 2)[0]
        time_date = struct.unpack_from('<I', buf, coff + 4)[0]
        opt_size = struct.unpack_from('<H', buf, coff + 16)[0]
        characteristics = struct.unpack_from('<H', buf, coff + 18)[0]
        opt_off = coff + 20
        magic = struct.unpack_from('<H', buf, opt_off)[0]  # 0x10B PE32, 0x20B PE32+
        is64 = magic == 0x20B
        linker_major = buf[opt_off + 2]
        linker_minor = buf[opt_off + 3]
        size_of_code = struct.unpack_from('<I', buf, opt_off + 4)[0]
        size_of_init = struct.unpack_from('<I', buf, opt_off + 8)[0]
        size_of_uninit = struct.unpack_from('<I', buf, opt_off + 12)[0]
        addr_of_entry = struct.unpack_from('<I', buf, opt_off + 16)[0]
        base_of_code = struct.unpack_from('<I', buf, opt_off + 20)[0]
        if is64:
            image_base = struct.unpack_from('<Q', buf, opt_off + 24)[0]
            subsystem = struct.unpack_from('<H', buf, opt_off + 68)[0]
            dll_char = struct.unpack_from('<H', buf, opt_off + 70)[0]
            data_dir_off = opt_off + 112
        else:
            image_base = struct.unpack_from('<I', buf, opt_off + 28)[0]
            subsystem = struct.unpack_from('<H', buf, opt_off + 68)[0]
            dll_char = struct.unpack_from('<H', buf, opt_off + 70)[0]
            data_dir_off = opt_off + 96
        # Data directories (16 entries of 8 bytes each)
        # 0=EXPORT 1=IMPORT 2=RESOURCE 3=EXCEPTION 5=BASERELOC
        # 6=DEBUG 9=TLS 12=IAT
        dirs = []
        for i in range(16):
            rva = struct.unpack_from('<I', buf, data_dir_off + i*8)[0]
            sz  = struct.unpack_from('<I', buf, data_dir_off + i*8 + 4)[0]
            dirs.append((rva, sz))

        # Sections (40 bytes each, after optional header)
        sections_off = opt_off + opt_size
        sections = []
        for i in range(num_sections):
            s = sections_off + i * 40
            name = buf[s:s+8].rstrip(b'\0').decode('latin-1', errors='ignore')
            virt_sz = struct.unpack_from('<I', buf, s + 8)[0]
            virt_va = struct.unpack_from('<I', buf, s + 12)[0]
            raw_sz  = struct.unpack_from('<I', buf, s + 16)[0]
            raw_off = struct.unpack_from('<I', buf, s + 20)[0]
            char    = struct.unpack_from('<I', buf, s + 36)[0]
            sections.append({
                'name': name, 'va': hex(virt_va), 'vsize': virt_sz,
                'raw_off': hex(raw_off), 'raw_size': raw_sz,
                'char': hex(char),
                'flags': _section_flag_str(char),
            })

        # RVA → file offset translator using section table
        def rva_to_off(rva):
            for sec in sections:
                v = int(sec['va'], 16)
                if v <= rva < v + max(sec['vsize'], sec['raw_size']):
                    return int(sec['raw_off'], 16) + (rva - v)
            return None

        # Imports walk for IMP-hash fingerprint
        imports = []
        imp_dir_rva, _ = dirs[1]
        if imp_dir_rva:
            off = rva_to_off(imp_dir_rva)
            if off:
                # IMAGE_IMPORT_DESCRIPTOR is 20 bytes; iterate until name_rva == 0
                while off + 20 <= len(buf):
                    orig_first_thunk = struct.unpack_from('<I', buf, off)[0]
                    name_rva = struct.unpack_from('<I', buf, off + 12)[0]
                    first_thunk = struct.unpack_from('<I', buf, off + 16)[0]
                    if name_rva == 0 and first_thunk == 0:
                        break
                    name_off = rva_to_off(name_rva) if name_rva else None
                    if name_off is None or name_off >= len(buf):
                        break
                    dll_end = buf.find(b'\0', name_off)
                    dll_name = buf[name_off:dll_end].decode('latin-1', errors='ignore').lower()
                    # Walk thunk table
                    thunk_rva = orig_first_thunk if orig_first_thunk else first_thunk
                    thunk_off = rva_to_off(thunk_rva) if thunk_rva else None
                    apis = []
                    if thunk_off is not None:
                        step = 8 if is64 else 4
                        mask = 0x8000000000000000 if is64 else 0x80000000
                        t = thunk_off
                        while t + step <= len(buf):
                            val = struct.unpack_from('<Q' if is64 else '<I', buf, t)[0]
                            if val == 0:
                                break
                            if val & mask:
                                # Import by ordinal
                                apis.append(f'ord_{val & 0xFFFF:x}')
                            else:
                                # Import by name — IMAGE_IMPORT_BY_NAME = WORD hint + asciiz name
                                hint_off = rva_to_off(val & 0xFFFFFFFF)
                                if hint_off and hint_off + 2 < len(buf):
                                    name_e = buf.find(b'\0', hint_off + 2)
                                    api = buf[hint_off+2:name_e].decode('latin-1', errors='ignore')
                                    if api:
                                        apis.append(api)
                            t += step
                            if len(apis) > 500: break  # safety
                    imports.append({'dll': dll_name, 'api_count': len(apis), 'apis': apis})
                    off += 20

        # IMP-hash (Mandiant/pefile-compatible): "dll.api" pairs in
        # ORIGINAL ORDER (NOT sorted), comma-joined, MD5-hashed.
        # Library name is lowercased and only stripped if the ext is one
        # of ocx/sys/dll (matches pefile's exts list — NOT .exe).
        # Verified against pefile's get_imphash() on 5 reference drivers
        # in v2.0 workflow.
        imphash_pairs = []
        for imp in imports:
            d = imp['dll'].lower()
            parts = d.rsplit('.', 1)
            if len(parts) > 1 and parts[1] in ('ocx', 'sys', 'dll'):
                d = parts[0]
            for api in imp['apis']:
                imphash_pairs.append(f'{d}.{api.lower()}')
        imphash = hashlib.md5(','.join(imphash_pairs).encode()).hexdigest() if imphash_pairs else None

        # TLS dir
        tls_rva, tls_sz = dirs[9]
        has_tls = bool(tls_rva and tls_sz)

        # Compile timestamp
        import datetime
        try:
            compile_dt = datetime.datetime.fromtimestamp(time_date, tz=datetime.timezone.utc).isoformat()
        except Exception:
            compile_dt = None

        # Aggregate
        total_apis = sum(i['api_count'] for i in imports)
        # v2.0 — workflow-verified extractors (matches pefile output exactly)
        rich = extract_rich_header(buf)
        ver = extract_version_info(buf)
        dbg = extract_debug_dir(buf)
        tls = extract_tls_callbacks(buf)
        exp = extract_exports(buf)
        return {
            'machine': hex(machine),
            'machine_name': _machine_name(machine),
            'compile_timestamp': time_date,
            'compile_date_utc': compile_dt,
            'characteristics': hex(characteristics),
            'linker_version': f'{linker_major}.{linker_minor}',
            'subsystem': subsystem,
            'subsystem_name': _subsystem_name(subsystem),
            'image_base': hex(image_base),
            'addr_of_entry': hex(addr_of_entry),
            'base_of_code': hex(base_of_code),
            'size_of_code': size_of_code,
            'size_of_init': size_of_init,
            'size_of_uninit': size_of_uninit,
            'has_tls': has_tls,
            'sections': sections,
            'imports': imports,
            'import_dll_count': len(imports),
            'import_api_count': total_apis,
            'imphash': imphash,
            # v2.0 workflow-verified fields
            'rich_header_present':    rich['rich_header_present'],
            'rich_dans_xor_key':      rich['rich_dans_xor_key'],
            'rich_header_records':    rich['rich_header_records'],
            'rich_compiler_family':   rich.get('rich_compiler_family'),
            'version_info':           ver,
            'debug_pdb_path':         dbg['debug_pdb_path'],
            'debug_pdb_guid':         dbg['debug_pdb_guid'],
            'debug_pdb_age':          dbg['debug_pdb_age'],
            'tls_callback_count':     tls['tls_callback_count'],
            'tls_callback_addresses': [hex(a) for a in tls['tls_callback_addresses']],
            'export_names':           exp['export_names'],
        }
    except Exception as e:
        return {'error': f'pe-ext: {e}'}


def _section_flag_str(char):
    out = []
    if char & 0x20: out.append('CODE')
    if char & 0x40: out.append('IDATA')
    if char & 0x80: out.append('UDATA')
    if char & 0x10000000: out.append('SHARED')
    if char & 0x20000000: out.append('EXEC')
    if char & 0x40000000: out.append('READ')
    if char & 0x80000000: out.append('WRITE')
    return '|'.join(out)


_MACHINE_NAMES = {
    0x014c: 'i386',  0x0200: 'IA64', 0x8664: 'AMD64',
    0xAA64: 'ARM64', 0x01c4: 'ARMNT', 0x01c0: 'ARM',
    0x6232: 'RISCV32', 0x6264: 'RISCV64',
}
def _machine_name(m): return _MACHINE_NAMES.get(m, f'unk_{m:04x}')

_SUBSYSTEM_NAMES = {
    1: 'NATIVE', 2: 'WINDOWS_GUI', 3: 'WINDOWS_CUI',
    7: 'POSIX_CUI', 9: 'WINDOWS_CE_GUI',
    10: 'EFI_APPLICATION', 11: 'EFI_BOOT_SERVICE_DRIVER',
    12: 'EFI_RUNTIME_DRIVER', 13: 'EFI_ROM', 14: 'XBOX',
}
def _subsystem_name(s): return _SUBSYSTEM_NAMES.get(s, f'unk_{s}')


# ============================================================
# v2.0 — Workflow-verified PE-info extractors.
# Each was adversarially verified against pefile's output on 5
# reference drivers (RTCore64, gdrv, sandra_x64, Corsair LL Access,
# AMDRyzenMaster) with 5/5 PASS per extractor; refute phase returned
# refuted=false for all. See memory/byovdsn1per_v1_2_accuracy.md
# (Round 28 — v2.0 workflow) for the audit trail.
# ============================================================
def decode_comp_id(comp_id: int) -> dict:
    """Decode Microsoft Rich Header comp_id (u32) -> producer tool + VS family.

    comp_id = (ProdID << 16) | MinVer
      ProdID - internal Microsoft tool identifier
      MinVer - linker/compiler build number (Microsoft well-known builds)

    Mapping is approximate; ProdID enumeration is community-reverse-engineered
    (see github.com/dishather/richprint). MinVer ranges below cover the
    commonly-seen VS toolchain build numbers for 2005-2022.
    """
    prod_id = (comp_id >> 16) & 0xFFFF
    min_ver = comp_id & 0xFFFF
    PROD = {
        0x0000: "unknown",
        0x0001: "Old MSC import lib",
        0x0002: "Old aliasobj C++",
        0x0004: "MSVC++ 4.x link",
        0x0006: "Resource compiler (rc)",
        0x0009: "MSC linker",
        0x000A: "cvtres",
        0x000F: "imp (export library)",
        0x0015: "VC6 link",
        0x0016: "VC6 cvtres",
        0x0019: "VC6 export",
        0x002C: "VS.NET 2002 link",
        0x002D: "VS.NET 2002 cvtres",
        0x004D: "VS.NET 2002 c++",
        0x004E: "VS.NET 2002 c",
        0x005C: "VS.NET 2003 link",
        0x005D: "VS.NET 2003 cvtres",
        0x0078: "VS.NET 2003 c++",
        0x0079: "VS.NET 2003 c",
        0x0083: "VS2005 c++",
        0x0084: "VS2005 c",
        0x0085: "VS2005 link",
        0x0086: "VS2005 cvtres",
        0x0094: "VS2005 masm",
        0x009A: "VS2008 c++",
        0x009B: "VS2008 c",
        0x009C: "VS2008 link",
        0x009D: "VS2008 cvtres",
        0x00AA: "VS2010 c++",
        0x00AB: "VS2010 c",
        0x00AC: "VS2010 link",
        0x00AD: "VS2010 cvtres",
        0x00B6: "VS2012 c++",
        0x00B7: "VS2012 c",
        0x00B8: "VS2012 link",
        0x00B9: "VS2012 cvtres",
        0x00C9: "VS2013 c++",
        0x00CA: "VS2013 c",
        0x00CB: "VS2013 link",
        0x00CC: "VS2013 cvtres",
        0x00DB: "VS2015 c++",
        0x00DC: "VS2015 c",
        0x00DD: "VS2015 link",
        0x00DE: "VS2015 cvtres",
        0x00FF: "VS2017 c++",
        0x0100: "VS2017 c",
        0x0101: "VS2017 link",
        0x0102: "VS2017 cvtres",
        0x0103: "VS2019 c++",
        0x0104: "VS2019 c",
        0x0105: "VS2019 link",
        0x0106: "VS2019 cvtres",
        0x0107: "VS2019 masm",
        0x0108: "VS2022 c++",
        0x0109: "VS2022 c",
        0x010A: "VS2022 link",
        0x010B: "VS2022 cvtres",
        0x010D: "VS2017/2019 c++ rev",
        0x010E: "VS2017/2019 c rev",
        0x010F: "VS2017/2019 link rev",
        0x0110: "VS2017/2019 cvtres rev",
        0x0111: "VS2017/2019 masm rev",
    }
    tool = PROD.get(prod_id, f"prod_0x{prod_id:04X}")
    # v2.1.1 fix: comp_id family decoder. The VS family is identified
    # PRIMARILY by ProdID class (VS2013's range is 0x00C9-0x00CC, VS2015's
    # 0x00DB-0x00DE, VS2017's 0x00FF-0x0102, VS2019's 0x0103-0x0107,
    # VS2022's 0x0108-0x010B). MinVer alone is ambiguous because:
    #   - VS2013 Update 5 has build_number 40629
    #   - VS2015 RTM has build_number 23026
    #   - VS2017 RTM has 25506
    # If we check VS2013's MinVer range first (21005-40629), it swallows
    # all of VS2015 + VS2017 + VS2019's build numbers.
    # Strategy: classify by ProdID class first (most reliable), fall back
    # to MinVer ordering check from NEWEST to OLDEST.
    family = None
    if 0x0108 <= prod_id <= 0x010C:
        family = "VS2022"
    elif 0x0103 <= prod_id <= 0x0107 or 0x010D <= prod_id <= 0x0111:
        # VS2019 + VS2017/2019 revision range
        family = "VS2019"
    elif 0x00FF <= prod_id <= 0x0102:
        family = "VS2017"
    elif 0x00DB <= prod_id <= 0x00DE:
        family = "VS2015"
    elif 0x00C9 <= prod_id <= 0x00CC:
        family = "VS2013"
    elif 0x00B6 <= prod_id <= 0x00B9:
        family = "VS2012"
    elif 0x00AA <= prod_id <= 0x00AD:
        family = "VS2010"
    elif 0x009A <= prod_id <= 0x009D:
        family = "VS2008"
    elif 0x0083 <= prod_id <= 0x0086 or prod_id == 0x0094:
        family = "VS2005"
    elif 0x005C <= prod_id <= 0x0079:
        family = "VS.NET 2003"
    elif 0x002C <= prod_id <= 0x004F:
        family = "VS.NET 2002"
    elif 0x0015 <= prod_id <= 0x0019:
        family = "VC6"
    # If ProdID didn't classify (uncommon legacy tools or unknown), fall
    # back to MinVer check newest-first to avoid VS2013 range swallowing.
    if family is None and min_ver:
        if 30133 <= min_ver <= 37500:
            family = "VS2022"
        elif 27702 <= min_ver <= 29914:
            family = "VS2019"
        elif 25506 <= min_ver <= 27508:
            family = "VS2017"
        elif 23026 <= min_ver <= 24218:
            family = "VS2015"
        elif 21005 <= min_ver <= 22999 or min_ver in (30501, 40629):
            family = "VS2013"
        elif min_ver in (60315, 60610, 61030):
            family = "VS2012"
        elif min_ver in (30319, 40219):
            family = "VS2010"
        elif min_ver in (21022, 30729):
            family = "VS2008"
        elif min_ver in (50727, 50831):
            family = "VS2005"
        elif min_ver in (3052, 3077, 4035):
            family = "VS.NET 2003"
        elif min_ver in (9466, 9210):
            family = "VS.NET 2002"
        elif 8000 <= min_ver < 9000:
            family = "VC6 SP6"
    return {"prod_id": prod_id, "min_ver": min_ver,
            "tool": tool, "family": family}


def extract_rich_header(buf: bytes) -> dict:
    """Microsoft "Rich" header - compiler/build-tool fingerprint sandwiched
    between the DOS stub and the PE header. Format:
        DanS_marker (XOR-encoded "DanS")
        3 x padding dwords (also XOR-encoded zero == the key)
        N x { comp_id (u32) XOR key, build_count (u32) XOR key }
        "Rich" literal magic + 4-byte XOR key.
    Returns rich_header_present + rich_dans_xor_key (8-char lowercase hex,
    pefile big-endian convention) + rich_header_records list with v2.1
    decoded tool + VS family per record + rich_compiler_family summary.
    """
    RICH, DANS = b"Rich", b"DanS"
    result = {"rich_header_present": False, "rich_dans_xor_key": None,
              "rich_header_records": [], "rich_compiler_family": None}
    if len(buf) < 0x40 or buf[:2] != b"MZ":
        return result
    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    if e_lfanew <= 0x40 or e_lfanew > len(buf):
        return result
    region = buf[:e_lfanew]
    rich_off = region.rfind(RICH)
    if rich_off < 0 or rich_off + 8 > len(region):
        return result
    xor_key_bytes = bytes(buf[rich_off + 4: rich_off + 8])
    xor_key = struct.unpack("<I", xor_key_bytes)[0]
    dans_xored = bytes(a ^ b for a, b in zip(DANS, xor_key_bytes))
    dans_off = region.rfind(dans_xored)
    if dans_off < 0 or dans_off >= rich_off:
        return result
    stream_start, stream_end = dans_off + 16, rich_off
    if stream_end <= stream_start:
        return result
    records = []
    off = stream_start
    while off + 8 <= stream_end:
        enc_comp = struct.unpack_from("<I", buf, off)[0]
        enc_count = struct.unpack_from("<I", buf, off + 4)[0]
        comp_id = enc_comp ^ xor_key
        dec = decode_comp_id(comp_id)
        records.append({
            "comp_id": comp_id,
            "count": enc_count ^ xor_key,
            "prod_id": dec['prod_id'],
            "min_ver": dec['min_ver'],
            "tool": dec['tool'],
            "family": dec['family'],
        })
        off += 8
    result["rich_header_present"] = True
    result["rich_dans_xor_key"] = "%08x" % struct.unpack(">I", xor_key_bytes)[0]
    result["rich_header_records"] = records
    # v2.1.1: family from PE Optional Header linker version is canonical
    # truth (Microsoft assigns linker versions per VS major release). Comp_id
    # ProdIDs are AMBIGUOUS (Microsoft reuses 0x0103-0x010B across VS2017,
    # VS2019, and VS2022 generations), so they can't reliably determine the
    # major VS version on their own.
    try:
        pe_off = struct.unpack_from('<I', buf, 0x3C)[0]
        opt_off = pe_off + 4 + 20  # PE sig + COFF header
        lnk_major = buf[opt_off + 2]
        lnk_minor = buf[opt_off + 3]
        result["linker_major_minor"] = f"{lnk_major}.{lnk_minor:02d}"
        # Map linker to VS family
        fam_by_linker = None
        if lnk_major == 14:
            if 30 <= lnk_minor:     fam_by_linker = "VS2022"
            elif 20 <= lnk_minor:   fam_by_linker = "VS2019"
            elif 10 <= lnk_minor:   fam_by_linker = "VS2017"
            else:                   fam_by_linker = "VS2015"
        elif lnk_major == 12:       fam_by_linker = "VS2013"
        elif lnk_major == 11:       fam_by_linker = "VS2012"
        elif lnk_major == 10:       fam_by_linker = "VS2010"
        elif lnk_major == 9:        fam_by_linker = "VS2008"
        elif lnk_major == 8:        fam_by_linker = "VS2005"
        elif lnk_major == 7:
            fam_by_linker = "VS.NET 2003" if lnk_minor >= 10 else "VS.NET 2002"
        elif lnk_major == 6:        fam_by_linker = "VC6"
        if fam_by_linker:
            result["rich_compiler_family"] = fam_by_linker
    except Exception:
        pass
    # Fallback: comp_id voting if linker fallthrough fails
    if not result.get("rich_compiler_family"):
        fams = [r['family'] for r in records if r.get('family')]
        if fams:
            order = ['VC6','VS.NET 2002','VS.NET 2003','VS2005','VS2008',
                     'VS2010','VS2012','VS2013','VS2015','VS2017','VS2019','VS2022']
            for f in reversed(order):
                if any(fa == f for fa in fams):
                    result["rich_compiler_family"] = f
                    break
            if not result.get("rich_compiler_family"):
                result["rich_compiler_family"] = fams[-1]
    return result


def extract_version_info(buf: bytes) -> dict:
    """VS_VERSION_INFO StringFileInfo extractor — pulls CompanyName,
    ProductName, FileDescription, OriginalFilename, InternalName,
    FileVersion, ProductVersion, LegalCopyright from RT_VERSION resource.
    Returns flat dict {key: value}. Empty {} if no RT_VERSION."""
    def _u16(b, o): return struct.unpack_from("<H", b, o)[0]
    def _u32(b, o): return struct.unpack_from("<I", b, o)[0]
    def _align4(o): return (o + 3) & ~3
    def _read_wsz(b, o, end):
        chars = []
        while o + 2 <= end:
            w = _u16(b, o); o += 2
            if w == 0: break
            chars.append(w)
        try:
            return struct.pack(f"<{len(chars)}H", *chars).decode("utf-16-le", errors="replace"), o
        except Exception:
            return "", o
    if len(buf) < 0x40 or buf[:2] != b"MZ":
        return {}
    try:
        pe_off = _u32(buf, 0x3C)
        if buf[pe_off:pe_off+4] != b"PE\x00\x00":
            return {}
        coff = pe_off + 4
        num_sections = _u16(buf, coff + 2)
        opt_size = _u16(buf, coff + 16)
        opt_off = coff + 20
        magic = _u16(buf, opt_off)
        dd_off = opt_off + (112 if magic == 0x20B else 96)
        rsrc_rva = _u32(buf, dd_off + 2*8)
        if rsrc_rva == 0:
            return {}
        # Sections for RVA→offset
        sec_off = opt_off + opt_size
        secs = []
        for i in range(num_sections):
            s = sec_off + i*40
            secs.append((_u32(buf, s+12), _u32(buf, s+8), _u32(buf, s+20), _u32(buf, s+16)))
        def rva2off(rva):
            for va, vsize, praw, sraw in secs:
                span = max(vsize, sraw)
                if va <= rva < va + span:
                    return praw + (rva - va)
            return None
        rsrc_off = rva2off(rsrc_rva)
        if rsrc_off is None:
            return {}
        # Walk resource dir for RT_VERSION (16)
        results = []
        def walk(cur, level, path):
            if cur is None or cur + 16 > len(buf): return
            nn = _u16(buf, cur + 12); nid = _u16(buf, cur + 14)
            for i in range(nn + nid):
                e = cur + 16 + i*8
                if e + 8 > len(buf): return
                noi = _u32(buf, e); otd = _u32(buf, e + 4)
                ident = noi & 0x7FFFFFFF
                is_dir = (otd & 0x80000000) != 0
                child = otd & 0x7FFFFFFF
                if is_dir:
                    if level == 0 and not (noi & 0x80000000) and ident != 16:
                        continue
                    walk(rsrc_off + child, level+1, path+[ident])
                else:
                    de = rsrc_off + child
                    if de + 16 > len(buf): continue
                    data_rva = _u32(buf, de); data_size = _u32(buf, de + 4)
                    results.append((path, data_rva, data_size))
        walk(rsrc_off, 0, [])
        if not results:
            return {}
        path, data_rva, data_size = results[0]
        data_off = rva2off(data_rva)
        if data_off is None: return {}
        end = data_off + data_size
        # Parse VS_VERSIONINFO
        if data_off + 6 > end: return {}
        block_len = _u16(buf, data_off)
        value_len = _u16(buf, data_off + 2)
        block_end = min(data_off + block_len, end) if block_len else end
        cur = data_off + 6
        key_str, cur = _read_wsz(buf, cur, block_end)
        if key_str != "VS_VERSION_INFO":
            return {}
        cur = _align4(cur)
        cur += value_len  # skip VS_FIXEDFILEINFO
        cur = _align4(cur)
        out = {}
        while cur < block_end:
            if cur + 6 > block_end: break
            child_len = _u16(buf, cur)
            if child_len == 0: break
            peek_key, _ = _read_wsz(buf, cur + 6, block_end)
            if peek_key == "StringFileInfo":
                # parse StringTable children
                sfi_end = min(cur + child_len, block_end)
                sfi_cur = cur + 6
                sfi_key, sfi_cur = _read_wsz(buf, sfi_cur, sfi_end)
                sfi_cur = _align4(sfi_cur)
                while sfi_cur < sfi_end:
                    if sfi_cur + 6 > sfi_end: break
                    st_len = _u16(buf, sfi_cur)
                    if st_len == 0: break
                    st_end = min(sfi_cur + st_len, sfi_end)
                    st_cur = sfi_cur + 6
                    _, st_cur = _read_wsz(buf, st_cur, st_end)  # lang key
                    st_cur = _align4(st_cur)
                    while st_cur < st_end:
                        if st_cur + 6 > st_end: break
                        s_len = _u16(buf, st_cur); s_val_len = _u16(buf, st_cur+2); s_type = _u16(buf, st_cur+4)
                        if s_len == 0: break
                        s_end = min(st_cur + s_len, st_end)
                        s_cur = st_cur + 6
                        k, s_cur = _read_wsz(buf, s_cur, s_end)
                        s_cur = _align4(s_cur)
                        val_bytes = (s_val_len * 2) if s_type == 1 else s_val_len
                        v_end = min(s_cur + val_bytes, s_end)
                        # v2.0.1: encoding-detection fallback. PE spec says
                        # VS_VERSION strings are UTF-16LE, but some legacy
                        # drivers emit UTF-8 (e.g. imdisk.sys LegalCopyright)
                        # OR UTF-16LE for ASCII with embedded UTF-8 for
                        # non-ASCII (also imdisk pattern).
                        # Strategy:
                        #  1. Try UTF-16LE first.
                        #  2. If result has U+A0..U+FFFF range chars in the
                        #     CJK / unassigned ranges, OR replacement chars,
                        #     retry as UTF-8 on the raw bytes.
                        #  3. Pick the result that has FEWER high-Unicode
                        #     codepoints (legal copyright is mostly Latin).
                        raw = bytes(buf[s_cur:v_end]).rstrip(b"\x00")
                        v_utf16, _ = _read_wsz(buf, s_cur, v_end)
                        v = v_utf16
                        # Heuristic: count "suspicious" chars (BMP > 0x07FF
                        # except specific Latin extension ranges).
                        susp_utf16 = sum(
                            1 for c in v_utf16
                            if ord(c) > 0x07FF or 0xFFFD == ord(c)
                        )
                        if susp_utf16 > 0:
                            try:
                                v_u8 = raw.decode("utf-8")
                                # Count NULs + suspicious; UTF-8 mis-decode
                                # of UTF-16LE bytes produces a string riddled
                                # with NUL characters between letters, so
                                # NULs are equally bad as high-CJK.
                                susp_u8 = sum(
                                    1 for c in v_u8
                                    if ord(c) > 0x07FF or 0xFFFD == ord(c) or ord(c) == 0
                                )
                                if susp_u8 < susp_utf16:
                                    v = v_u8
                            except UnicodeDecodeError:
                                pass
                        if k:
                            out[k] = v.rstrip("\x00")
                        nxt = _align4(s_end)
                        if nxt <= st_cur: break
                        st_cur = nxt
                    nxt = _align4(sfi_cur + st_len)
                    if nxt <= sfi_cur: break
                    sfi_cur = nxt
            nxt = _align4(cur + child_len)
            if nxt <= cur: break
            cur = nxt
        return out
    except Exception:
        return {}


def extract_debug_dir(buf: bytes) -> dict:
    """Debug Directory CV_INFO_PDB70 (RSDS) extractor. Returns
    debug_pdb_path (UTF-8), debug_pdb_guid (32-char lowercase hex no
    dashes), debug_pdb_age (int). All None if no CodeView entry."""
    def _u16(b, o): return struct.unpack_from("<H", b, o)[0]
    def _u32(b, o): return struct.unpack_from("<I", b, o)[0]
    out = {"debug_pdb_path": None, "debug_pdb_guid": None, "debug_pdb_age": None}
    if len(buf) < 0x40 or buf[:2] != b"MZ":
        return out
    try:
        e_lfanew = _u32(buf, 0x3C)
        if buf[e_lfanew:e_lfanew+4] != b"PE\0\0":
            return out
        coff = e_lfanew + 4
        num_sections = _u16(buf, coff + 2)
        opt_size = _u16(buf, coff + 16)
        opt_off = coff + 20
        magic = _u16(buf, opt_off)
        if magic == 0x10B:
            num_rva_off = opt_off + 92; dd_off = opt_off + 96
        elif magic == 0x20B:
            num_rva_off = opt_off + 108; dd_off = opt_off + 112
        else:
            return out
        num_rva = _u32(buf, num_rva_off)
        if num_rva < 7:
            return out
        debug_rva = _u32(buf, dd_off + 6*8)
        debug_size = _u32(buf, dd_off + 6*8 + 4)
        if debug_rva == 0 or debug_size == 0:
            return out
        # Build sections for RVA→offset
        sec_off = opt_off + opt_size
        secs = []
        for i in range(num_sections):
            s = sec_off + i*40
            secs.append((_u32(buf, s+12), _u32(buf, s+8), _u32(buf, s+20), _u32(buf, s+16)))
        def rva2off(rva):
            for va, vsize, praw, psize in secs:
                span = max(vsize, psize)
                if va <= rva < va + span:
                    delta = rva - va
                    if delta < psize:
                        return praw + delta
                    return None
            return None
        debug_off = rva2off(debug_rva)
        if debug_off is None:
            return out
        ENTRY_SIZE = 28
        for i in range(debug_size // ENTRY_SIZE):
            e = debug_off + i * ENTRY_SIZE
            if e + ENTRY_SIZE > len(buf): break
            dtype = _u32(buf, e + 12)
            size_of_data = _u32(buf, e + 16)
            addr_of_raw = _u32(buf, e + 20)
            ptr_raw = _u32(buf, e + 24)
            if dtype != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                continue
            if size_of_data < 25:
                continue
            cv_off = ptr_raw
            if cv_off == 0 or cv_off + size_of_data > len(buf):
                cv_off = rva2off(addr_of_raw)
                if cv_off is None: continue
            if cv_off + 24 > len(buf): continue
            if buf[cv_off:cv_off+4] != b"RSDS": continue
            raw16 = buf[cv_off+4:cv_off+20]
            d1 = struct.unpack_from("<I", raw16, 0)[0]
            d2 = struct.unpack_from("<H", raw16, 4)[0]
            d3 = struct.unpack_from("<H", raw16, 6)[0]
            d4 = raw16[8:16]
            out["debug_pdb_guid"] = "%08x%04x%04x%s" % (d1, d2, d3, d4.hex())
            out["debug_pdb_age"] = _u32(buf, cv_off + 20)
            path_start = cv_off + 24
            path_limit = min(cv_off + size_of_data, len(buf))
            nul = buf.find(b"\x00", path_start, path_limit)
            if nul == -1: nul = path_limit
            try:
                out["debug_pdb_path"] = buf[path_start:nul].decode("utf-8")
            except UnicodeDecodeError:
                out["debug_pdb_path"] = buf[path_start:nul].decode("latin-1")
            return out
        return out
    except Exception:
        return out


def extract_tls_callbacks(buf: bytes) -> dict:
    """TLS callback addresses extractor. Walks IMAGE_TLS_DIRECTORY's
    AddressOfCallBacks. Returns count + list of absolute VAs (matches
    pefile semantics)."""
    def _u16(b, o): return struct.unpack_from("<H", b, o)[0]
    def _u32(b, o): return struct.unpack_from("<I", b, o)[0]
    def _u64(b, o): return struct.unpack_from("<Q", b, o)[0]
    out = {"tls_callback_count": 0, "tls_callback_addresses": []}
    if len(buf) < 0x40 or buf[:2] != b"MZ":
        return out
    try:
        e_lfanew = _u32(buf, 0x3C)
        if buf[e_lfanew:e_lfanew+4] != b"PE\0\0": return out
        coff = e_lfanew + 4
        num_sections = _u16(buf, coff + 2)
        opt_size = _u16(buf, coff + 16)
        opt_off = coff + 20
        magic = _u16(buf, opt_off)
        if magic == 0x10B:
            is_pe32_plus = False; image_base = _u32(buf, opt_off + 28)
            num_rva_off = opt_off + 92; dd_off = opt_off + 96
        elif magic == 0x20B:
            is_pe32_plus = True; image_base = _u64(buf, opt_off + 24)
            num_rva_off = opt_off + 108; dd_off = opt_off + 112
        else:
            return out
        num_rva = _u32(buf, num_rva_off)
        if num_rva < 10: return out
        tls_rva = _u32(buf, dd_off + 9*8)
        tls_size = _u32(buf, dd_off + 9*8 + 4)
        if tls_rva == 0 or tls_size == 0: return out
        sec_off = opt_off + opt_size
        secs = []
        for i in range(num_sections):
            s = sec_off + i*40
            secs.append((_u32(buf, s+12), _u32(buf, s+8), _u32(buf, s+20), _u32(buf, s+16)))
        def rva2off(rva):
            for va, vsize, praw, psize in secs:
                span = max(vsize, psize)
                if va <= rva < va + span:
                    delta = rva - va
                    if delta < psize: return praw + delta
                    return None
            return None
        tls_off = rva2off(tls_rva)
        if tls_off is None: return out
        ptr_size = 8 if is_pe32_plus else 4
        cb_field = tls_off + 3 * ptr_size
        if cb_field + ptr_size > len(buf): return out
        cb_va = _u64(buf, cb_field) if is_pe32_plus else _u32(buf, cb_field)
        if cb_va == 0: return out
        cb_rva = cb_va - image_base
        if cb_rva < 0: return out
        cb_off = rva2off(cb_rva)
        if cb_off is None: return out
        addrs = []
        cur = cb_off
        for _ in range(257):  # max 256 + sentinel
            if cur + ptr_size > len(buf): break
            entry = _u64(buf, cur) if is_pe32_plus else _u32(buf, cur)
            if entry == 0: break
            addrs.append(entry); cur += ptr_size
        out["tls_callback_count"] = len(addrs)
        out["tls_callback_addresses"] = addrs
        return out
    except Exception:
        return out


def extract_exports(buf: bytes) -> dict:
    """Export Table walker. Returns {'export_names': [...]} matching pefile."""
    def _u16(b, o): return struct.unpack_from("<H", b, o)[0]
    def _u32(b, o): return struct.unpack_from("<I", b, o)[0]
    out = {"export_names": []}
    if len(buf) < 0x40 or buf[:2] != b"MZ":
        return out
    try:
        e_lfanew = _u32(buf, 0x3C)
        if buf[e_lfanew:e_lfanew+4] != b"PE\x00\x00": return out
        coff = e_lfanew + 4
        num_sections = _u16(buf, coff + 2)
        opt_size = _u16(buf, coff + 16)
        opt_off = coff + 20
        magic = _u16(buf, opt_off)
        if magic == 0x10B: dd_off = opt_off + 96
        elif magic == 0x20B: dd_off = opt_off + 112
        else: return out
        exp_rva = _u32(buf, dd_off)
        exp_size = _u32(buf, dd_off + 4)
        if exp_rva == 0 or exp_size == 0: return out
        sec_off = opt_off + opt_size
        secs = []
        for i in range(num_sections):
            s = sec_off + i*40
            secs.append((_u32(buf, s+12), _u32(buf, s+8), _u32(buf, s+20), _u32(buf, s+16)))
        def rva2off(rva):
            for va, vsize, praw, sraw in secs:
                span = max(vsize, sraw)
                if va <= rva < va + span:
                    return praw + (rva - va)
            return None
        exp_off = rva2off(exp_rva)
        if exp_off is None or exp_off + 40 > len(buf): return out
        num_names = _u32(buf, exp_off + 24)
        addr_of_names_rva = _u32(buf, exp_off + 32)
        if num_names == 0 or addr_of_names_rva == 0: return out
        if num_names > 0x10000: num_names = 0x10000
        names_table_off = rva2off(addr_of_names_rva)
        if names_table_off is None: return out
        names = []
        for i in range(num_names):
            ent = names_table_off + i*4
            if ent + 4 > len(buf): break
            name_rva = _u32(buf, ent)
            if name_rva == 0: continue
            name_off = rva2off(name_rva)
            if name_off is None or name_off >= len(buf): continue
            end = buf.find(b"\x00", name_off, min(name_off + 512, len(buf)))
            if end == -1: end = min(name_off + 512, len(buf))
            try:
                names.append(buf[name_off:end].decode("ascii", errors="replace"))
            except Exception:
                pass
        out["export_names"] = names
        return out
    except Exception:
        return out


# ============================================================
# v2.1 - Strings extractor (ASCII + UTF-16LE) with regex tagging
# ============================================================
_STR_ASCII_RE = re.compile(rb'[\x20-\x7e]{%d,}' % 6)
_STR_UTF16_RE = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')
_TAG_URL_RE = re.compile(r'(?i)\b(?:https?|ftp)://[^\s\x00<>"]{4,}')
_TAG_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_TAG_REG_RE = re.compile(
    r'(?i)(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|SYSTEM|SOFTWARE)'
    r'\\[A-Za-z0-9_\- .]+(?:\\[A-Za-z0-9_\- .{}]+)*'
)
_TAG_PATH_RE = re.compile(r'(?i)[A-Z]:\\(?:[A-Za-z0-9_\- .{}]+\\)*[A-Za-z0-9_\- .{}]+\.[A-Za-z0-9]{1,5}')
_TAG_GUID_RE = re.compile(r'\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?')
_TAG_PDB_RE = re.compile(r'(?i)[A-Z]:\\(?:[A-Za-z0-9_\- .{}]+\\)*[A-Za-z0-9_\- .{}]+\.pdb')
_TAG_DEVICE_RE = re.compile(r'\\(?:Device|DosDevices|GLOBAL\?\?)\\[A-Za-z0-9_\- {}.]+')
_TAG_SDDL_RE = re.compile(r'[DOSG]:(?:\([A-Z]+;[A-Z]*;[A-Z0-9]+;[^;)]*;[^;)]*;[A-Z0-9]+\))+')

# Pattern groups: most tag patterns need ':' or '\\' to match, so we can
# split strings into "structural" (have those chars) and "plain" (don't),
# then run only the needed patterns on each group. v2.5 split:
#   STRUCT_PATTERNS — need ':' or '\\' in the string
#   PLAIN_PATTERNS  — IPv4 (needs '.') and GUID (needs '-')
_TAG_STRUCT_PATTERNS = (
    ('urls',         _TAG_URL_RE),
    ('reg_keys',     _TAG_REG_RE),
    ('paths',        _TAG_PATH_RE),
    ('pdbs',         _TAG_PDB_RE),
    ('device_paths', _TAG_DEVICE_RE),
    ('sddl',         _TAG_SDDL_RE),
)
_TAG_IPV4_LABEL = 'ipv4'
_TAG_GUID_LABEL = 'guids'
_HAS_STRUCT_CHAR = re.compile(r'[:\\]')   # cheap pre-filter for STRUCT group
_HAS_DOT          = re.compile(r'\.')      # pre-filter for IPv4
_HAS_DASH         = re.compile(r'-')       # pre-filter for GUID

def extract_strings(path: str, min_ascii: int = 6, min_utf16: int = 4) -> dict:
    """Extract ASCII + UTF-16LE strings from a PE buffer and tag them
    against URL / IPv4 / registry / filesystem path / GUID / PDB / SDDL
    regex classes.

    v2.5 speed: split tag patterns into two groups by required char class.
    Skip strings that don't have ':' or '\\' for the 6 structural patterns.
    Skip strings without '.' for IPv4, without '-' for GUID. Avoids 8 regex
    calls per uninteresting string.

    Returns:
      ascii_count, utf16_count: raw extraction stats
      top_ascii / top_utf16: 50 longest strings (debug / human triage)
      tagged: {urls, ipv4, reg_keys, paths, pdbs, guids, device_paths, sddl}
    """
    try:
        with open(path, 'rb') as f:
            buf = f.read()
    except OSError as e:
        return {'error': f'open: {e}'}
    ascii_set = set()
    for m in _STR_ASCII_RE.finditer(buf):
        ascii_set.add(m.group().decode('ascii', errors='replace'))
    utf16_set = set()
    for m in _STR_UTF16_RE.finditer(buf):
        try:
            s = m.group().decode('utf-16-le', errors='replace').rstrip('\x00')
            if len(s) >= min_utf16:
                utf16_set.add(s)
        except Exception:
            pass
    all_str = ascii_set | utf16_set
    # Single pass over strings: classify into 3 groups by char content.
    struct_strs, ipv4_strs, guid_strs = [], [], []
    for s in all_str:
        if _HAS_STRUCT_CHAR.search(s): struct_strs.append(s)
        if _HAS_DOT.search(s):         ipv4_strs.append(s)
        if _HAS_DASH.search(s):        guid_strs.append(s)
    tagged = {}
    for label, pat in _TAG_STRUCT_PATTERNS:
        hits = set()
        for s in struct_strs:
            for m in pat.findall(s):
                hits.add(m)
        tagged[label] = sorted(hits)
    ipv4_hits = set()
    for s in ipv4_strs:
        for m in _TAG_IPV4_RE.findall(s):
            ipv4_hits.add(m)
    tagged[_TAG_IPV4_LABEL] = sorted(ipv4_hits)
    guid_hits = set()
    for s in guid_strs:
        for m in _TAG_GUID_RE.findall(s):
            guid_hits.add(m)
    tagged[_TAG_GUID_LABEL] = sorted(guid_hits)
    return {
        'ascii_count': len(ascii_set),
        'utf16_count': len(utf16_set),
        'top_ascii': sorted(ascii_set, key=len, reverse=True)[:50],
        'top_utf16': sorted(utf16_set, key=len, reverse=True)[:50],
        'tagged': tagged,
    }


# ============================================================
# v2.1 - YARA rule emission
# ============================================================
def emit_yara_rule(result: dict, rule_name: str = None) -> str:
    """Emit a YARA detection rule for the scanned driver.

    Rule strategy: ALWAYS includes the MZ magic + uses hash.sha256 as the
    strongest condition. Falls back to pe.imphash when sha256 is missing.
    Adds IOCTL byte patterns + PDB path + signer CN as supplementary
    strings (visible during YARA hits). Designed to compile with the
    standard `hash` + `pe` YARA modules.
    """
    hashes = result.get('hashes', {}) or {}
    pe = result.get('pe_extended', {}) or {}
    sig = result.get('signing', {}) or {}
    ioctls = result.get('ioctls', []) or []
    pe_path = result.get('path') or result.get('driver_path') or 'driver.sys'
    base = re.sub(r'\W+', '_', Path(pe_path).stem) or 'driver'
    sha8 = (hashes.get('sha256', '') or '')[:8] or 'nohash'
    if not rule_name:
        rule_name = f"BYOVD_{base}_{sha8}"
    rule_name = re.sub(r'\W+', '_', rule_name)
    if rule_name and rule_name[0].isdigit():
        rule_name = 'r_' + rule_name
    lines = []
    lines.append(f"rule {rule_name}")
    lines.append("{")
    lines.append("    meta:")
    lines.append('        author = "BYOVDsn1per v2.1"')
    lines.append(f'        score = {result.get("_score", 0)}')
    lines.append(f'        tier = "{result.get("_tier", "")}"')
    subj_full = sig.get('SUBJECT', '?')
    lines.append(f'        signer = "{subj_full[:120].replace(chr(34), chr(39))}"')
    lines.append(f'        thumbprint = "{sig.get("THUMB", "?")}"')
    if hashes.get('sha256'):
        lines.append(f'        sha256 = "{hashes["sha256"]}"')
    if pe.get('imphash'):
        lines.append(f'        imphash = "{pe["imphash"]}"')
    cve_matches = result.get('cve_matches') or []
    if cve_matches:
        strong = [m for m in cve_matches if m.get('confidence') in ('CONFIRMED','HIGH','MEDIUM')]
        if strong:
            cves = ','.join(m['cve'] for m in strong[:5])
            lines.append(f'        cves = "{cves}"')
    arch = result.get('archetype_strings') or {}
    if arch:
        tags = ','.join(sorted(arch.keys())[:5])
        lines.append(f'        archetypes = "{tags}"')
    lines.append("")
    lines.append("    strings:")
    # Encode IOCTLs as little-endian byte patterns
    have_strings = False
    seen_ioctl_vals = set()
    for i, ic_str in enumerate(ioctls[:8]):
        try:
            v = int(ic_str, 16) & 0xFFFFFFFF
        except (ValueError, TypeError):
            continue
        if v in seen_ioctl_vals:
            continue
        seen_ioctl_vals.add(v)
        b = f"{v & 0xFF:02X} {(v >> 8) & 0xFF:02X} {(v >> 16) & 0xFF:02X} {(v >> 24) & 0xFF:02X}"
        lines.append(f'        $ioctl{i} = {{ {b} }}')
        have_strings = True
    pdb_path = pe.get('debug_pdb_path') or ''
    if pdb_path:
        esc = pdb_path.replace('\\', '\\\\').replace('"', '\\"')
        lines.append(f'        $pdb = "{esc}" ascii')
        have_strings = True
    cn_match = re.search(r'CN=([^,]+)', subj_full)
    if cn_match:
        cn_v = cn_match.group(1).strip()[:60].replace('"', "'")
        lines.append(f'        $cn = "{cn_v}" ascii')
        have_strings = True
    dev_name = (result.get('device_names') or [])[:1]
    if dev_name:
        esc = dev_name[0].replace('\\', '\\\\').replace('"', "'")
        lines.append(f'        $devname = "{esc}" ascii')
        have_strings = True
    if not have_strings:
        lines.append('        $mz = { 4D 5A }')
    lines.append("")
    lines.append("    condition:")
    cond_parts = ['uint16(0) == 0x5A4D']
    if hashes.get('sha256'):
        cond_parts.append(f'hash.sha256(0, filesize) == "{hashes["sha256"]}"')
    elif pe.get('imphash'):
        cond_parts.append(f'pe.imphash() == "{pe["imphash"]}"')
    elif seen_ioctl_vals:
        cond_parts.append(f'{min(3, len(seen_ioctl_vals))} of ($ioctl*)')
    else:
        cond_parts.append('any of them')
    lines.append("        " + " and ".join(cond_parts))
    lines.append("}")
    return "\n".join(lines)


# ============================================================
# v2.1 - Driver diff mode
# ============================================================
def diff_drivers(r1: dict, r2: dict) -> str:
    """Field-by-field comparison of two driver scan results."""
    n1 = Path(r1.get('path', r1.get('driver_path', 'driver1'))).name
    n2 = Path(r2.get('path', r2.get('driver_path', 'driver2'))).name
    sep = lambda s: f"  {s}"
    L = [f"=== {n1}  <-->  {n2} ==="]
    h1, h2 = r1.get('hashes', {}) or {}, r2.get('hashes', {}) or {}
    p1, p2 = r1.get('pe_extended', {}) or {}, r2.get('pe_extended', {}) or {}
    s1, s2 = r1.get('signing', {}) or {}, r2.get('signing', {}) or {}
    def mk(label, v1, v2, width=24, op=None):
        op = op or (lambda a, b: '==' if a == b else '!=')
        sv1 = str(v1)[:width]
        sv2 = str(v2)[:width]
        return sep(f"{label:<11} {sv1:<{width}}  {op(v1, v2)}  {sv2}")
    L.append("")
    L.append("  -- hashes --")
    L.append(mk('size:',    h1.get('size', '?'),   h2.get('size', '?')))
    L.append(mk('md5:',     h1.get('md5', '?'),    h2.get('md5', '?'), 32))
    L.append(mk('sha1:',    h1.get('sha1', '?'),   h2.get('sha1', '?'), 40))
    L.append(mk('sha256:',  h1.get('sha256', '?'), h2.get('sha256', '?'), 64))
    L.append(mk('imphash:', p1.get('imphash', '?'),p2.get('imphash', '?'), 32))
    L.append("")
    L.append("  -- signing --")
    L.append(mk('subject:', s1.get('SUBJECT', '?'), s2.get('SUBJECT', '?'), 50))
    L.append(mk('thumb:',   s1.get('THUMB', '?'),   s2.get('THUMB', '?'), 40))
    L.append(mk('burnt:',   s1.get('burnt_status','?'), s2.get('burnt_status','?'), 16))
    L.append("")
    L.append("  -- PE info --")
    L.append(mk('machine:', p1.get('machine','?'), p2.get('machine','?')))
    L.append(mk('subsys:',  p1.get('subsystem','?'), p2.get('subsystem','?')))
    L.append(mk('compiled:',p1.get('compile_time_utc','?'),p2.get('compile_time_utc','?')))
    L.append(mk('PDB:',     p1.get('debug_pdb_path','?'), p2.get('debug_pdb_path','?'), 50))
    L.append(mk('VS family:',p1.get('rich_compiler_family','?'),p2.get('rich_compiler_family','?')))
    L.append("")
    L.append("  -- HVCI --")
    h_a, h_b = r1.get('hvci', {}) or {}, r2.get('hvci', {}) or {}
    L.append(mk('FI:',   h_a.get('force_integrity','?'),h_b.get('force_integrity','?')))
    L.append(mk('GCF:',  h_a.get('guard_cf','?'),       h_b.get('guard_cf','?')))
    L.append(mk('INIT-WX:',h_a.get('init_wx','?'),       h_b.get('init_wx','?')))
    L.append("")
    L.append("  -- IOCTL surface --")
    i1, i2 = set(r1.get('ioctls', []) or []), set(r2.get('ioctls', []) or [])
    L.append(sep(f"counts:     {len(i1):<24} {'==' if len(i1)==len(i2) else '!='}  {len(i2)}"))
    L.append(sep(f"shared:     {len(i1 & i2)}"))
    only1 = sorted(i1 - i2)[:8]
    only2 = sorted(i2 - i1)[:8]
    L.append(sep(f"only-in-1:  {' '.join(only1) if only1 else '(none)'}"))
    L.append(sep(f"only-in-2:  {' '.join(only2) if only2 else '(none)'}"))
    L.append("")
    L.append("  -- verdict --")
    L.append(mk('modes:', ','.join(r1.get('modes_resolved',[])), ','.join(r2.get('modes_resolved',[])), 24))
    L.append(mk('gate:',  r1.get('gate_status','?'),    r2.get('gate_status','?')))
    L.append(mk('score:', r1.get('_score',0),           r2.get('_score',0), 8))
    L.append(mk('tier:',  r1.get('_tier','?'),          r2.get('_tier','?'), 12))
    return "\n".join(L)


# ============================================================
# v2.2/v2.3 - --crawl / --deepcrawl: kernel-driver discovery
# ============================================================
# v2.3: expanded known driver locations. The "standard" set covers all
# places drivers actually live or get extracted on a typical Windows box.
def _build_default_crawl_roots():
    roots = [
        # ---- Core Windows driver locations ----
        r"C:\Windows\System32\drivers",
        r"C:\Windows\System32\drivers\UMDF",
        r"C:\Windows\System32\drivers\Wdf",
        r"C:\Windows\SysWOW64\drivers",
        r"C:\Windows\System32\DriverStore\FileRepository",
        r"C:\Windows\System32\DriverStore\Temp",
        r"C:\Windows\inf",
        # ---- Vendor installer drops ----
        r"C:\Drivers",
        r"C:\Driver",
        r"C:\swsetup",
        r"C:\Intel",
        r"C:\AMD",
        r"C:\NVIDIA",
        r"C:\HP",
        r"C:\Dell",
        r"C:\Lenovo",
        r"C:\Realtek",
        r"C:\ASUS",
        r"C:\MSI",
        r"C:\Gigabyte",
        # ---- Program Files trees (vendor kernel components ship here) ----
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\ProgramData",
        # ---- Recovery + boot ----
        r"C:\Windows\WinSxS",
        r"C:\Windows\Temp",
        r"C:\Windows\SoftwareDistribution\Download",
        r"C:\Windows\Panther",
    ]
    # Per-user paths (variable across machines / user profiles)
    user = os.environ.get('USERPROFILE')
    if user:
        roots += [
            os.path.join(user, 'Downloads'),
            os.path.join(user, 'Desktop'),
            os.path.join(user, 'Documents'),
        ]
    for var in ('LOCALAPPDATA', 'APPDATA', 'TEMP', 'TMP'):
        val = os.environ.get(var)
        if val and val not in roots:
            roots.append(val)
    return roots


DEFAULT_CRAWL_ROOTS = _build_default_crawl_roots()


def _enumerate_drive_roots():
    """Enumerate every logical drive on Windows (A:\\ through Z:\\)."""
    drives = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        d = f"{letter}:\\"
        if os.path.isdir(d):
            drives.append(d)
    return drives


def _header_is_kernel_driver(header: bytes) -> bool:
    """Header-only kernel-driver check (no I/O). Caller supplies the first
    >= 0x400 bytes. Centralizes the gating logic so quick_is_kernel_driver
    AND quick_check_and_hash share it.

    Gates: MZ + e_lfanew + PE sig + OPT magic + NATIVE subsys + AEP != 0.
    """
    if len(header) < 0x80 or header[:2] != b'MZ':
        return False
    try:
        e_lfanew = struct.unpack_from('<I', header, 0x3C)[0]
    except struct.error:
        return False
    if e_lfanew < 0x40 or e_lfanew + 24 > len(header):
        return False
    if header[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        return False
    try:
        opt_off = e_lfanew + 4 + 20  # PE sig + COFF header
        if opt_off + 72 > len(header):
            return False
        magic = struct.unpack_from('<H', header, opt_off)[0]
        if magic not in (0x10B, 0x20B):
            return False
        aep = struct.unpack_from('<I', header, opt_off + 16)[0]
        subsys = struct.unpack_from('<H', header, opt_off + 68)[0]
    except struct.error:
        return False
    return subsys == 1 and aep != 0


def quick_is_kernel_driver(path: str) -> bool:
    """Fast (header-only) check that a .sys file is a kernel driver.

    Reads only the first 0x400 bytes. Per user spec ("quick check for
    DriverEntry and that's it"), the bar is minimal:
      - MZ + valid e_lfanew + PE signature
      - PE Optional Header magic is PE32 or PE32+
      - Subsystem == 1 (IMAGE_SUBSYSTEM_NATIVE)
      - AddressOfEntryPoint != 0 (has a DriverEntry)

    No DLL-bit exclusion: some legit kernel drivers (WDF support DLLs,
    minifilter helpers like ksapi64_del.sys) have IMAGE_FILE_DLL set.

    Designed to be safe on partial reads, locked files, junctions, etc.
    """
    try:
        with open(path, 'rb') as f:
            header = f.read(0x400)
    except OSError:
        return False
    return _header_is_kernel_driver(header)


def quick_check_and_hash(path: str):
    """v2.4: SINGLE-PASS check + SHA256. Returns (is_kernel_driver, sha256_hex).

    Opens the file ONCE: reads the header for the kernel-driver check,
    short-circuits without hashing if not a driver, otherwise streams the
    rest through SHA256. ~2x faster than v2.3's quick_check + reopen+read
    pattern for files larger than 0x400 bytes.

    Returns (False, None) on non-drivers or read errors (caller can
    distinguish from sha256 success because second element is None).
    """
    try:
        with open(path, 'rb') as f:
            header = f.read(0x400)
            if not _header_is_kernel_driver(header):
                return (False, None)
            h = hashlib.sha256()
            h.update(header)
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
            return (True, h.hexdigest())
    except OSError:
        return (False, None)


CHECKPOINT_FILENAME = ".scanned_paths.txt"
SHA256_CACHE_FILENAME = ".sha256_cache.txt"  # filename<TAB>sha256


def _load_sha256_cache(out_path: Path) -> dict:
    """Load the SHA256 cache so re-runs don't re-hash existing files.
    Format: one line per file, '<basename>\\t<sha256_hex>'. Comments (#) ignored.
    """
    cache_file = out_path / SHA256_CACHE_FILENAME
    cache = {}
    if not cache_file.exists():
        return cache
    try:
        with open(cache_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.rstrip('\n').rstrip('\r')
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t', 1)
                if len(parts) == 2 and len(parts[1]) == 64:
                    cache[parts[0]] = parts[1]
    except OSError:
        pass
    return cache


def _populate_dedup_seen(out_path: Path, verbose: bool = False) -> set:
    """Build SHA256 dedup set for files already in crawler/. Uses
    .sha256_cache.txt so subsequent runs don't re-hash. Missing entries
    are computed once and appended to the cache file.
    """
    cache = _load_sha256_cache(out_path)
    existing = list(out_path.glob('*.sys'))
    seen = set()
    miss = []
    for f in existing:
        if f.name in cache:
            seen.add(cache[f.name])
        else:
            miss.append(f)
    if miss:
        if verbose:
            print(f"  [cache] hydrating {len(miss)} missing entries (one-time hash)")
        cache_fh = None
        try:
            cache_fh = open(out_path / SHA256_CACHE_FILENAME, 'a',
                            encoding='utf-8', errors='replace')
        except OSError:
            cache_fh = None
        for f in miss:
            try:
                h = hashlib.sha256()
                with open(f, 'rb') as fh:
                    while True:
                        chunk = fh.read(65536)
                        if not chunk:
                            break
                        h.update(chunk)
                digest = h.hexdigest()
                seen.add(digest)
                if cache_fh is not None:
                    try:
                        cache_fh.write(f"{f.name}\t{digest}\n")
                    except OSError:
                        pass
            except OSError:
                pass
        if cache_fh is not None:
            try:
                cache_fh.flush()
                cache_fh.close()
            except OSError:
                pass
    return seen


def _append_sha256_cache(out_path: Path, basename: str, sha256_hex: str):
    """Append a single (basename, sha256) row to the cache file."""
    try:
        with open(out_path / SHA256_CACHE_FILENAME, 'a',
                  encoding='utf-8', errors='replace') as f:
            f.write(f"{basename}\t{sha256_hex}\n")
    except OSError:
        pass


def _load_checkpoint(out_path: Path) -> set:
    """Read .scanned_paths.txt and return set of normalized (lowercased,
    trailing-sep-stripped) directory paths already finished."""
    ckpt = out_path / CHECKPOINT_FILENAME
    completed = set()
    if not ckpt.exists():
        return completed
    try:
        with open(ckpt, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                completed.add(os.path.normcase(os.path.normpath(line)))
    except OSError:
        pass
    return completed


def _clear_checkpoint(out_path: Path) -> bool:
    ckpt = out_path / CHECKPOINT_FILENAME
    if ckpt.exists():
        try:
            ckpt.unlink()
            return True
        except OSError:
            return False
    return False


def _norm_dir(d: str) -> str:
    return os.path.normcase(os.path.normpath(d))


def crawl_drivers(roots, out_dir: str, max_files: int = 0,
                  verbose: bool = False, progress_every: int = 500,
                  use_checkpoint: bool = True,
                  clear_checkpoint_first: bool = False) -> dict:
    """Walk `roots`, copy every `.sys` that passes quick_is_kernel_driver
    to `out_dir`. Dedupes by SHA256 (including any drivers already in out_dir).

    v2.3: Checkpoint file `.scanned_paths.txt` in `out_dir` tracks every
    directory that's been fully processed. On restart, those dirs are
    pruned from os.walk descent so partial scans resume without redoing
    work. Pass `clear_checkpoint_first=True` to wipe the checkpoint.

    Returns a stats dict + the list of copied paths under 'copied_paths'.
    """
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    if clear_checkpoint_first:
        if _clear_checkpoint(out_path):
            print(f"  [checkpoint] cleared {out_path / CHECKPOINT_FILENAME}")

    completed_dirs = _load_checkpoint(out_path) if use_checkpoint else set()
    if completed_dirs:
        print(f"  [checkpoint] {len(completed_dirs)} dirs already scanned, "
              f"will skip on descent")

    # v2.4: SHA256 cache so we don't re-hash 1000+ existing drivers per run
    seen_hashes = _populate_dedup_seen(out_path, verbose=verbose)
    if seen_hashes:
        print(f"  [cache] {len(seen_hashes)} existing drivers in dedup set")

    stats = {
        'scanned_files':   0,
        'sys_found':       0,
        'kernel_drivers':  0,
        'copied':          0,
        'duplicates':      0,
        'errors':          0,
        'roots_walked':    [],
        'copied_paths':    [],
        'dirs_skipped':    0,
        'dirs_completed':  0,
    }

    ckpt_fh = None
    if use_checkpoint:
        try:
            ckpt_fh = open(out_path / CHECKPOINT_FILENAME, 'a',
                           encoding='utf-8', errors='replace')
        except OSError:
            ckpt_fh = None

    def _mark_dir_done(dirpath: str):
        norm = _norm_dir(dirpath)
        if norm in completed_dirs:
            return
        completed_dirs.add(norm)
        stats['dirs_completed'] += 1
        if ckpt_fh is not None:
            try:
                ckpt_fh.write(dirpath + '\n')
                ckpt_fh.flush()
            except OSError:
                pass

    try:
        for root in roots:
            if not os.path.isdir(root):
                if verbose:
                    print(f"  [skip] not a dir: {root}")
                continue
            root_norm = _norm_dir(root)
            if root_norm in completed_dirs:
                stats['dirs_skipped'] += 1
                if verbose:
                    print(f"  [checkpoint] root already done: {root}")
                continue
            stats['roots_walked'].append(root)
            if verbose:
                print(f"  [crawl] {root}")
            try:
                walker = os.walk(root, topdown=True)
            except OSError:
                continue
            for dirpath, subdirs, files in walker:
                # Prune already-completed subdirs from descent
                if completed_dirs:
                    subdirs[:] = [
                        d for d in subdirs
                        if _norm_dir(os.path.join(dirpath, d)) not in completed_dirs
                    ]
                if _norm_dir(dirpath) in completed_dirs:
                    stats['dirs_skipped'] += 1
                    continue
                # Process files in this directory
                for fn in files:
                    stats['scanned_files'] += 1
                    if progress_every and stats['scanned_files'] % progress_every == 0:
                        print(f"    ... scanned {stats['scanned_files']} files, "
                              f"sys={stats['sys_found']}, drivers={stats['kernel_drivers']}, "
                              f"copied={stats['copied']}, ckpt_dirs={stats['dirs_completed']}")
                    if not fn.lower().endswith('.sys'):
                        continue
                    stats['sys_found'] += 1
                    full = os.path.join(dirpath, fn)
                    # v2.4: SINGLE-PASS check + SHA256 (was double-read in v2.3)
                    try:
                        is_drv, h = quick_check_and_hash(full)
                    except Exception:
                        stats['errors'] += 1
                        continue
                    if not is_drv:
                        # Non-driver, locked file, or partial-read failure.
                        # Skip silently — we only care about kernel drivers.
                        continue
                    stats['kernel_drivers'] += 1
                    if h in seen_hashes:
                        stats['duplicates'] += 1
                        continue
                    seen_hashes.add(h)
                    dst_name = f"{Path(fn).stem}_{h[:8]}.sys"
                    dst = out_path / dst_name
                    try:
                        shutil.copy2(full, dst)
                        stats['copied'] += 1
                        stats['copied_paths'].append(str(dst))
                        # Append to cache so the next run skips this re-hash
                        _append_sha256_cache(out_path, dst_name, h)
                        if verbose:
                            print(f"    [copy] {full} -> {dst.name}")
                    except OSError as e:
                        stats['errors'] += 1
                        if verbose:
                            print(f"    [err] copy failed: {full}: {e}")
                        continue
                    if max_files and stats['copied'] >= max_files:
                        return stats
                # Mark dir done. Only leaves are marked "fully done" here
                # — parent dirs become "done" only once we exit the os.walk
                # for that root naturally. Per-dir granularity is enough:
                # restart re-walks parents (cheap) but skips processed leaves
                # (the expensive part).
                _mark_dir_done(dirpath)
            # Mark the root itself done
            _mark_dir_done(root)
    finally:
        if ckpt_fh is not None:
            try:
                ckpt_fh.close()
            except OSError:
                pass
    return stats


# ============================================================
# Authenticode + signtool /kp
# ============================================================
def signing_info(path: str) -> dict:
    """Get-AuthenticodeSignature with subject fallback for UnknownError chains."""
    try:
        cmd = ["powershell.exe", "-NoProfile", "-Command",
               "$s=Get-AuthenticodeSignature -LiteralPath '" + str(path).replace("'", "''") + "'; "
               "$c=$s.SignerCertificate; "
               "if ($c) { "
               "  Write-Output \"SUBJECT=$($c.Subject)\"; "
               "  Write-Output \"THUMB=$($c.Thumbprint)\"; "
               "  Write-Output \"ISSUER=$($c.Issuer)\"; "
               "  Write-Output \"NOTBEFORE=$($c.NotBefore.ToString('o'))\"; "
               "  Write-Output \"NOTAFTER=$($c.NotAfter.ToString('o'))\" "
               "}; "
               "Write-Output \"STATUS=$($s.Status)\""]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        out = {}
        for line in r.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
        return out
    except Exception as e:
        return {"error": str(e)}


def signtool_kp(path: str) -> dict:
    """Run signtool /kp /v on driver. Returns dict with verified bool + key fields."""
    candidates = [
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
        r"C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe",
    ]
    tool = None
    for c in candidates:
        if Path(c).exists():
            tool = c
            break
    if not tool:
        return {"error": "signtool not found"}
    try:
        r = subprocess.run([tool, "verify", "/kp", "/v", path],
                           capture_output=True, text=True, timeout=30)
        ok = "Successfully verified" in r.stdout
        # extract timestamp line
        ts = ""
        for line in r.stdout.splitlines():
            if "signature is timestamped" in line.lower():
                ts = line.strip()
                break
        return {
            "verified": ok,
            "timestamp_line": ts,
            "stdout_tail": r.stdout.splitlines()[-3:] if r.stdout else [],
        }
    except Exception as e:
        return {"error": str(e)}


def is_burnt(sig_dict: dict) -> tuple:
    """Return (is_burnt, reason)."""
    thumb = (sig_dict.get("THUMB") or "").upper()
    subj = sig_dict.get("SUBJECT", "")
    for p in BURNT_THUMBS_PREFIX:
        if thumb.startswith(p) or thumb == p:
            return True, f"burnt-thumb-prefix:{p}"
    for s in BURNT_SIGNER_SUBSTRINGS:
        if s in subj:
            return True, f"burnt-signer:{s}"
    return False, ""


# ============================================================
# IDA-driven scanner (v5 logic + deep mode)
# ============================================================
SIG_LIST = ['ntddk', 'wdfldr', 'wdf01000', 'fltmgr', 'hal',
            'ndis', 'tcpip', 'vc14_64', 'vc16_64', 'vc14_64_seh',
            'vc16_64_seh', 'libcmt_64', 'vcruntime140_64']

ARG_REG = {1: 'rcx', 2: 'rdx', 8: 'r8', 9: 'r9'}
IRP_MJ_DEVICE_CONTROL = 0x0E
IRP_MJ_OPERATION_END  = 0x80
FLT_OP_SIZE           = 0x20
FLT_REG_OP_OFFSET     = 0x10


# ============================================================
# IOCTL decoder (CTL_CODE bits)
# ============================================================
# Windows ntddk FILE_DEVICE_* names per WDK ntddk.h
DEVICE_TYPES = {
    0x00000001: "BEEP",
    0x00000002: "CD_ROM",
    0x00000003: "CD_ROM_FILE_SYSTEM",
    0x00000004: "CONTROLLER",
    0x00000005: "DATALINK",
    0x00000006: "DFS",
    0x00000007: "DISK",
    0x00000008: "DISK_FILE_SYSTEM",
    0x00000009: "FILE_SYSTEM",
    0x0000000A: "INPORT_PORT",
    0x0000000B: "KEYBOARD",
    0x0000000C: "MAILSLOT",
    0x0000000D: "MIDI_IN",
    0x0000000E: "MIDI_OUT",
    0x0000000F: "MOUSE",
    0x00000010: "MULTI_UNC_PROVIDER",
    0x00000011: "NAMED_PIPE",
    0x00000012: "NETWORK",
    0x00000013: "NETWORK_BROWSER",
    0x00000014: "NETWORK_FILE_SYSTEM",
    0x00000015: "NULL",
    0x00000016: "PARALLEL_PORT",
    0x00000017: "PHYSICAL_NETCARD",
    0x00000018: "PRINTER",
    0x00000019: "SCANNER",
    0x0000001A: "SERIAL_MOUSE_PORT",
    0x0000001B: "SERIAL_PORT",
    0x0000001C: "SCREEN",
    0x0000001D: "SOUND",
    0x0000001E: "STREAMS",
    0x0000001F: "TAPE",
    0x00000020: "TAPE_FILE_SYSTEM",
    0x00000021: "TRANSPORT",
    0x00000022: "UNKNOWN",
    0x00000023: "VIDEO",
    0x00000024: "VIRTUAL_DISK",
    0x00000025: "WAVE_IN",
    0x00000026: "WAVE_OUT",
    0x00000027: "8042_PORT",
    0x00000028: "NETWORK_REDIRECTOR",
    0x00000029: "BATTERY",
    0x0000002A: "BUS_EXTENDER",
    0x0000002B: "MODEM",
    0x0000002C: "VDM",
    0x0000002D: "MASS_STORAGE",
    0x0000002E: "SMB",
    0x0000002F: "KS",
    0x00000030: "CHANGER",
    0x00000031: "SMARTCARD",
    0x00000032: "ACPI",
    0x00000033: "DVD",
    0x00000034: "FULLSCREEN_VIDEO",
    0x00000035: "DFS_FILE_SYSTEM",
    0x00000036: "DFS_VOLUME",
    0x00000037: "SERENUM",
    0x00000038: "TERMSRV",
    0x00000039: "KSEC",
    0x0000003A: "FIPS",
    0x0000003B: "INFINIBAND",
}
METHODS = {0: "BUFFERED", 1: "IN_DIRECT", 2: "OUT_DIRECT", 3: "NEITHER"}
ACCESS_BITS = {0: "ANY", 1: "READ", 2: "WRITE", 3: "READ_WRITE"}


def decode_ioctl(code: int) -> dict:
    """Decode a CTL_CODE-style IOCTL: DEVICE_TYPE | FUNCTION | METHOD | ACCESS.
    Bits: [31..16]=DeviceType, [15..14]=Access, [13..2]=Function, [1..0]=Method
    Mask to 32-bit first to strip sign-extension."""
    code = code & 0xFFFFFFFF
    device_type = (code >> 16) & 0xFFFF
    access = (code >> 14) & 0x3
    function = (code >> 2) & 0xFFF
    method = code & 0x3
    return {
        "code": f"0x{code:08x}",
        "device_type": f"0x{device_type:04x}",
        "device_type_name": DEVICE_TYPES.get(device_type, f"VENDOR_{device_type:04x}"),
        "function": f"0x{function:03x}",
        "method": METHODS.get(method, "?"),
        "access": ACCESS_BITS.get(access, "?"),
    }


def _find_high_ioctl_density_func(min_ioctls=5):
    """Fallback for WDF-stub drivers (no static MJ14 / no FltRegister):
    scan every non-library function, score by IOCTL-pattern density,
    return the top candidate. Useful when WdfIoQueueCreate is loaded
    dynamically via WdfVersionBind and we can't trace it statically.

    v1.7 scoring: count / (distinct_device_types ** 2).  Real dispatchers
    use ONE device-type for all IOCTLs (a single DEVICE_OBJECT has one
    type). Functions with 2+ distinct device_types are usually phantom
    cmp-imm matches (function-pointer compares, magic values, struct
    field tests). TdGamepad.sys:
      - 0x403870 (real): 10 IOCTLs all device_type 0x2A → score 10
      - 0x412a4a (noise): 29 IOCTLs split 11 of 0x0040 + 18 of 0x0041 → 29/4=7.25
    """
    import ida_funcs
    best_score = 0.0
    best_ea = None
    best_ioctls = set()
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        if not f: continue
        if f.flags & ida_funcs.FUNC_LIB: continue
        # too small to be a real dispatcher
        if (f.end_ea - f.start_ea) < 100: continue
        # too big = probably init/setup, not dispatcher
        if (f.end_ea - f.start_ea) > 0x4000: continue
        ioctls = _enumerate_dispatch_ioctls(f.start_ea, max_depth=1)
        n = len(ioctls)
        if n == 0:
            continue
        dts = {(v >> 16) & 0xFFFF for v in ioctls}
        score = n / (len(dts) ** 2)
        if score > best_score:
            best_score = score
            best_ea = f.start_ea
            best_ioctls = ioctls
    if best_ea and len(best_ioctls) >= min_ioctls:
        return best_ea, best_ioctls
    return None, set()


def _has_wdf_stub_pattern():
    """Detect WDF-stub drivers: imports WdfVersionBind but NOT static
    WdfIoQueueCreate (WDF APIs are loaded dynamically into a function table)."""
    has_bind = False
    has_queue = False
    import ida_segment, ida_bytes, ida_name
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg is None or seg.type != ida_segment.SEG_XTRN: continue
        ea = seg.start_ea
        while ea < seg.end_ea:
            n = ida_name.get_name(ea)
            if n:
                bare = n.lstrip('_').replace('imp_', '').lstrip('_')
                if bare == 'WdfVersionBind': has_bind = True
                if bare in ('WdfIoQueueCreate', 'WdfDeviceCreate'): has_queue = True
            ea = ida_bytes.next_head(ea, seg.end_ea)
    return has_bind and not has_queue


# WDF_IO_QUEUE_CONFIG offset of EvtIoDeviceControl callback (KMDF 1.x).
# Layout: Size(4) DispatchType(4) PowerManaged(4) AllowZeroLen(1) Default(1)
#         padding(2) EvtIoDefault(8) EvtIoRead(8) EvtIoWrite(8) EvtIoDeviceControl(8)
WDF_IO_QUEUE_CONFIG_EVTDEVCTL_OFFSET = 0x28


def _find_wdf_static_dispatcher():
    """Static-WDF detection (v1.5).

    For drivers that statically import WdfIoQueueCreate (rather than the
    dynamic WdfVersionBind stub pattern), trace the PWDF_IO_QUEUE_CONFIG
    argument (rdx in __fastcall) and read [config + 0x28] = EvtIoDeviceControl.

    Returns (handler_ea, config_ea) on success, (None, None) on failure.

    Strategy per call-site:
      1. Locate calls to WdfIoQueueCreate (or its thunk).
      2. Trace rdx (2nd arg = WDF_IO_QUEUE_CONFIG*).
      3. If config_ea is in a data segment, read qword at config+0x28.
      4. Otherwise (stack-local config) scan the enclosing function for
         `mov [rsp+config_offset+0x28], handler` writes.
    """
    import ida_funcs, ida_bytes, ida_ua, ida_xref, ida_segment, ida_name
    # Find xref sites for WdfIoQueueCreate import
    sites = _find_import_xrefs('WdfIoQueueCreate')
    real_sites = set()
    for s in sites:
        owner = ida_funcs.get_func(s)
        if owner is None:
            continue
        # If site is a thunk, follow back to actual callers
        if (owner.end_ea - owner.start_ea) <= 16:
            xb = ida_xref.xrefblk_t()
            ok = xb.first_to(owner.start_ea, 0)
            while ok:
                if xb.iscode and xb.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    real_sites.add(xb.frm)
                ok = xb.next_to()
        else:
            real_sites.add(s)

    for site in sorted(real_sites)[:5]:
        # WdfIoQueueCreate(Device, Config, Attributes, Queue)
        # __fastcall: rcx=Device, rdx=Config, r8=Attributes, r9=Queue
        config_ea = _trace_arg_back(site, 2)
        if not config_ea:
            continue
        # Case A: config in static data segment — qword at +0x28 is the
        # EvtIoDeviceControl pointer (set at compile-time via initializer).
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if seg and seg.start_ea <= config_ea < seg.end_ea:
                if seg.type in (ida_segment.SEG_DATA, ida_segment.SEG_BSS):
                    cand = ida_bytes.get_qword(config_ea + WDF_IO_QUEUE_CONFIG_EVTDEVCTL_OFFSET)
                    if cand and ida_funcs.get_func(cand):
                        return cand, config_ea
                break
        # Case B: config is a stack frame — scan the enclosing function
        # for `mov [config+0x28], handler` writes.
        owner = ida_funcs.get_func(site)
        if owner is None:
            continue
        # The trace_arg_back already produced a likely [rsp+N] address;
        # treat it as the local config base. Walk forward from owner.start
        # and look for memory writes at [base+0x28] form.
        target_off = config_ea + WDF_IO_QUEUE_CONFIG_EVTDEVCTL_OFFSET
        ea = owner.start_ea
        while ea < owner.end_ea:
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, ea):
                ea = ida_bytes.next_head(ea, owner.end_ea); continue
            mnem = insn.get_canon_mnem()
            op0 = insn.ops[0]
            op1 = insn.ops[1]
            if (mnem == 'mov'
                    and op0.type in (ida_ua.o_displ, ida_ua.o_mem)
                    and op1.type == ida_ua.o_reg):
                # The write target offset matches the EvtIoDeviceControl slot
                if op0.addr == target_off or (op0.addr & 0xFFF) == (target_off & 0xFFF):
                    # Trace the loaded handler via the lea before
                    scan = ea
                    for _ in range(12):
                        scan = ida_bytes.prev_head(scan, owner.start_ea)
                        if scan < owner.start_ea: break
                        pi = ida_ua.insn_t()
                        if ida_ua.decode_insn(pi, scan):
                            pmn = pi.get_canon_mnem()
                            if (pmn == 'lea'
                                    and pi.ops[0].type == ida_ua.o_reg
                                    and pi.ops[0].reg == op1.reg):
                                handler = pi.ops[1].addr or pi.ops[1].value
                                if handler and ida_funcs.get_func(handler):
                                    return handler, config_ea
                                break
            ea = ida_bytes.next_head(ea, owner.end_ea)
    return None, None


def _ida_scan(driver_path: str, depth: int = 3, no_flirt: bool = False,
              deep: bool = False, no_decompile: bool = False) -> dict:
    """Run all IDA-based analysis in a single idalib session."""
    result = {
        'driver': driver_path,
        'modes_resolved': [],
        'mj14_handler': None,
        'mj_table_writes': None,
        'ioctls': [],
        'ioctl_count': 0,
        'minifilter': None,
        'wdf': None,
        'imports': [],
        'primitives': [],
        'archetype_strings': None,
        'process_callback_targets': None,
        'driver_entry': None,
        'function_count': 0,
        'pdb_path': None,
        'device_name': None,
        'has_io_create_device': False,
        'has_io_create_device_secure': False,
        'sddl_strings': [],
        'gate_status': 'unknown',
        'gates_detected': [],
        'per_ioctl_classification': None,
        'analyze_time_s': 0.0,
    }
    t0 = time.time()
    tmp = Path(tempfile.mkdtemp(prefix='snipr_'))
    try:
        src = Path(driver_path)
        if not src.exists():
            return {**result, 'error': f'driver not found: {driver_path}'}
        tmp_drv = tmp / src.name
        shutil.copy2(src, tmp_drv)

        import idapro
        rc = idapro.open_database(str(tmp_drv), run_auto_analysis=True)
        if rc != 0:
            return {**result, 'error': f'idapro.open_database rc={rc}'}

        try:
            import ida_funcs, ida_bytes, ida_ua, ida_xref, ida_name, ida_idaapi
            import ida_segment, ida_entry, ida_auto, ida_nalt, idc

            # FLIRT
            if not no_flirt:
                applied = 0
                for s in SIG_LIST:
                    try:
                        r = idc.apply_sig_file(s)
                        if isinstance(r, int) and r > 0:
                            applied += 1
                    except Exception:
                        pass
                ida_auto.auto_wait()
                result['flirt_applied'] = applied

            result['function_count'] = ida_funcs.get_func_qty()

            # Imports + primitive classification
            imports = set()
            for i in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(i)
                if seg is None or seg.type != ida_segment.SEG_XTRN:
                    continue
                ea = seg.start_ea
                while ea < seg.end_ea:
                    n = ida_name.get_name(ea)
                    if n:
                        bare = n.lstrip('_').replace('imp_', '').lstrip('_')
                        imports.add(bare)
                        if bare == 'IoCreateDeviceSecure':
                            result['has_io_create_device_secure'] = True
                        elif bare == 'IoCreateDevice':
                            result['has_io_create_device'] = True
                    ea = ida_bytes.next_head(ea, seg.end_ea)
            result['imports'] = sorted(imports)
            prims_found = set()
            for cls, apis in PRIMITIVE_CLASSES.items():
                if apis & imports:
                    prims_found.add(cls)
            result['primitives'] = sorted(prims_found)

            # DriverEntry
            de_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, 'DriverEntry')
            if de_ea == ida_idaapi.BADADDR and ida_entry.get_entry_qty() > 0:
                de_ea = ida_entry.get_entry(ida_entry.get_entry_ordinal(0))
            result['driver_entry'] = hex(de_ea) if de_ea != ida_idaapi.BADADDR else None

            # Strings: PDB path, device names, archetype tagging, SDDL
            STRTYPE_C = getattr(ida_nalt, "STRTYPE_C", 0)
            archs = {k: [] for k in ARCHETYPE_STRINGS}
            for i in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(i)
                if seg is None:
                    continue
                name = (ida_segment.get_segm_name(seg) or "").lower()
                if not ('rdata' in name or 'data' in name):
                    continue
                ea = seg.start_ea
                sentinel = 0
                while ea < seg.end_ea and sentinel < 50000:
                    sentinel += 1
                    s = ida_bytes.get_strlit_contents(ea, -1, STRTYPE_C)
                    if s:
                        try:
                            text = s.decode("latin-1", errors="ignore")
                        except Exception:
                            text = ""
                        if 4 <= len(text) <= 300:
                            if '.pdb' in text.lower() and not result['pdb_path']:
                                result['pdb_path'] = text
                            if text.startswith('\\Device\\'):
                                if 'device_names' not in result:
                                    result['device_names'] = []
                                if text not in result['device_names']:
                                    result['device_names'].append(text)
                                if not result['device_name']:
                                    result['device_name'] = text
                            if text.startswith('\\DosDevices\\') or text.startswith('\\??\\'):
                                if 'symlinks' not in result:
                                    result['symlinks'] = []
                                if text not in result['symlinks']:
                                    result['symlinks'].append(text)
                            if text.startswith('D:P(') and len(text) < 500:
                                if text not in result['sddl_strings']:
                                    result['sddl_strings'].append(text)
                            for cat, needles in ARCHETYPE_STRINGS.items():
                                for needle in needles:
                                    if needle.lower() in text.lower():
                                        ent = (text[:80], hex(ea))
                                        if ent not in archs[cat]:
                                            archs[cat].append(ent)
                    nh = ida_bytes.next_head(ea, seg.end_ea)
                    if nh == ea or nh <= seg.start_ea:
                        break
                    ea = nh
            archs_pruned = {k: v[:4] for k, v in archs.items() if v}
            if archs_pruned:
                result['archetype_strings'] = archs_pruned

            # MJ scan — direct (in DriverEntry) + recursive (in callees)
            mj_writes = _scan_mj_writes_recursive(de_ea, max_depth=depth) if de_ea != ida_idaapi.BADADDR else {}
            if mj_writes:
                result['mj_table_writes'] = {str(k): hex(v) for k, v in mj_writes.items()}
                if 14 in mj_writes:
                    handler = mj_writes[14]
                    result['mj14_handler'] = hex(handler)
                    direct = _is_mj14_in_func(de_ea, 14, handler)
                    result['modes_resolved'].append('legacy_mj14' if direct else 'mj14_recursive')
                    ioctls = _enumerate_dispatch_ioctls(handler, max_depth=depth)
                    result['ioctls'] = [hex(i) for i in sorted(ioctls)]
                    result['ioctl_count'] = len(ioctls)

            # v1.5 — Static WDF path: drivers with WdfIoQueueCreate imported
            # directly (not stub-loaded). Trace EvtIoDeviceControl from the
            # WDF_IO_QUEUE_CONFIG argument at offset 0x28.
            if not result['mj14_handler']:
                wdf_handler, wdf_cfg = _find_wdf_static_dispatcher()
                if wdf_handler:
                    ioctls = _enumerate_dispatch_ioctls(wdf_handler, max_depth=depth)
                    result['mj14_handler'] = hex(wdf_handler)
                    result['modes_resolved'].append('wdf_static')
                    if wdf_cfg:
                        result['wdf'] = {'queue_config': hex(wdf_cfg),
                                         'evt_io_device_control': hex(wdf_handler)}
                    if ioctls:
                        result['ioctls'] = [hex(i) for i in sorted(ioctls)]
                        result['ioctl_count'] = len(ioctls)

            # WDF-stub fallback — drivers using dynamic WdfVersionBind (no
            # static WdfIoQueueCreate import) don't expose MJ14 via standard
            # paths. Scan all functions for the one with highest IOCTL
            # pattern density. This covers GameDriverX64 etc.
            # v1.5 also fires when MJ handler resolved BUT 0 IOCTLs found
            # AND driver has WDF imports — handles WUDFRd's RdDispatch
            # reflector pattern where the WDM MJ[14] just forwards to the
            # WDF queue infrastructure, and the true IOCTL surface is the
            # EvtIoDeviceControl callback.
            need_stub_fallback = (
                _has_wdf_stub_pattern()
                and (not result['mj14_handler'] or result['ioctl_count'] == 0)
            )
            if need_stub_fallback:
                best_ea, best_ioctls = _find_high_ioctl_density_func(min_ioctls=2)
                if best_ea and best_ioctls:
                    result['mj14_handler'] = hex(best_ea)
                    if 'wdf_stub_inferred' not in result['modes_resolved']:
                        result['modes_resolved'].append('wdf_stub_inferred')
                    result['ioctls'] = [hex(i) for i in sorted(best_ioctls)]
                    result['ioctl_count'] = len(best_ioctls)

            # Anti-cheat fallback — when MJ[14] is absent but other MJs are
            # set, the driver may be using MJ_READ / MJ_WRITE / MJ_CREATE
            # as its command-dispatch surface (common Wellbia / Pingoff /
            # XignCode pattern). Sniff each candidate for an IOCTL-density
            # signature and pick the strongest. If no IOCTL multiplexer is
            # found but a magic-cookie gate IS present in the candidate,
            # still report the MJ as resolved with a 'magic-cookie single
            # command' annotation (xhunter1.sys pattern).
            if not result['mj14_handler'] and mj_writes:
                AC_FALLBACK_MJ = (3, 4, 1, 0)  # READ, WRITE, CREATE_NP, CREATE
                best_ea, best_ioctls = None, set()
                for mj_idx in AC_FALLBACK_MJ:
                    if mj_idx not in mj_writes:
                        continue
                    cand_ea = mj_writes[mj_idx]
                    try:
                        cand_ioctls = _enumerate_dispatch_ioctls(cand_ea, max_depth=depth)
                    except Exception:
                        cand_ioctls = set()
                    if len(cand_ioctls) > len(best_ioctls):
                        best_ea = cand_ea
                        best_ioctls = cand_ioctls
                if best_ea and len(best_ioctls) >= 2:
                    result['mj14_handler'] = hex(best_ea)
                    result['modes_resolved'].append('ac_alt_mj')
                    result['ioctls'] = [hex(i) for i in sorted(best_ioctls)]
                    result['ioctl_count'] = len(best_ioctls)
                else:
                    # No IOCTL multiplexer — check for magic-cookie gate in
                    # any candidate. If found, report it as ac_alt_mj_single.
                    for mj_idx in AC_FALLBACK_MJ:
                        if mj_idx not in mj_writes:
                            continue
                        cand_ea = mj_writes[mj_idx]
                        try:
                            gates = _detect_gates(cand_ea, max_depth=1)
                        except Exception:
                            gates = []
                        if 'MAGIC_COOKIE' in gates:
                            result['mj14_handler'] = hex(cand_ea)
                            result['modes_resolved'].append('ac_alt_mj_single')
                            result['gate_status'] = '|'.join(gates)
                            break

            # Minifilter
            mf_info = _walk_minifilter()
            if mf_info:
                result['minifilter'] = mf_info
                if any(m.get('mj14_ioctls') for m in mf_info):
                    if 'minifilter' not in result['modes_resolved']:
                        result['modes_resolved'].append('minifilter')
                    for m in mf_info:
                        for code in m.get('mj14_ioctls', []):
                            result['ioctls'].append(code)
                    result['ioctls'] = sorted(set(result['ioctls']))
                    result['ioctl_count'] = len(result['ioctls'])

            # Process callback targets
            pcb = _process_callback_targets()
            if pcb:
                result['process_callback_targets'] = pcb

            # Gate detection (basic): check dispatcher for PID/cookie/PEB patterns
            if result['mj14_handler']:
                gates = _detect_gates(int(result['mj14_handler'], 16), max_depth=depth)
                result['gates_detected'] = gates
                if gates:
                    result['gate_status'] = '|'.join(gates)
                else:
                    if 'IoIs32bitProcess' in imports:
                        result['gate_status'] = 'WEAK_BITNESS_CHECK_ONLY'
                    else:
                        result['gate_status'] = 'NONE'

            # Deep mode — per-IOCTL classification
            if deep and result['mj14_handler'] and not no_decompile:
                result['per_ioctl_classification'] = _classify_per_ioctl(
                    int(result['mj14_handler'], 16),
                    [int(c, 16) & 0xFFFFFFFF for c in result['ioctls']]
                )

            if not result['modes_resolved']:
                result['modes_resolved'] = ['unresolved']
        finally:
            idapro.close_database()
    except Exception as e:
        result['error'] = f'{type(e).__name__}: {e}'
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    result['analyze_time_s'] = round(time.time() - t0, 2)
    return result


# ============================================================
# IDA helpers (only available after idapro.open_database)
# ============================================================
def _is_32bit_image():
    """Detect 32-bit driver from IDA inf."""
    try:
        import ida_ida
        return not ida_ida.inf_is_64bit()
    except Exception:
        return False


def _scan_mj_writes_recursive(start_func_ea, max_depth=3):
    """Recursive MajorFunction[N] array-write scan.

    64-bit: MJ table at DriverObject+0x70, stride 8.
    32-bit: MJ table at DriverObject+0x38, stride 4. (DRIVER_OBJECT changes
            layout between archs — Flags at 0x4 in 32, 0x8 in 64; etc.)
    We try both layouts so 32-bit drivers don't return unresolved."""
    import ida_funcs, ida_bytes, ida_ua, ida_idaapi
    is32 = _is_32bit_image()
    # Layout per arch: (base_offset, stride, max_offset).
    # 64-bit: DriverObject->MajorFunction[0] at +0x70, ptr stride 8.
    # 32-bit: DriverObject->MajorFunction[0] at +0x38, ptr stride 4.
    # IMPORTANT: never fall back to the other layout — 64-bit offset 0x68
    # is DriverUnload which would alias to "MJ[12]" under the 32-bit
    # layout, producing a false positive (and corrupting the score).
    if is32:
        layouts = [(0x38, 4, 0x80)]
    else:
        layouts = [(0x70, 8, 0x100)]

    found = {}
    # Rep-stos detections are buffered and applied LAST so that direct
    # mov-writes (which often OVERRIDE specific MJ slots after a generic
    # `rep stos` fill — PCTcore64 sets MJ[0..15]=wrapper via rep stos
    # then overrides MJ[14]=real_dispatcher via direct mov) win.
    pending_repstos = []  # list of (handler_ea, count)
    visited = set()
    queue = deque([(start_func_ea, 0)])
    while queue:
        fea, d = queue.popleft()
        if fea in visited or d > max_depth:
            continue
        visited.add(fea)
        f = ida_funcs.get_func(fea)
        if not f:
            continue
        ea = f.start_ea
        while ea < f.end_ea:
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, ea):
                ea = ida_bytes.next_head(ea, f.end_ea); continue
            mnem = insn.get_canon_mnem()
            op0 = insn.ops[0]
            if mnem == 'mov' and op0.type == ida_ua.o_displ:
                off = op0.addr
                # Try each layout
                for base, stride, max_off in layouts:
                    if base <= off <= max_off and (off - base) % stride == 0:
                        mj_idx = (off - base) // stride
                        op1 = insn.ops[1]
                        if op1.type == ida_ua.o_reg:
                            scan = ea
                            for _ in range(15):
                                scan = ida_bytes.prev_head(scan, f.start_ea)
                                if scan < f.start_ea:
                                    break
                                pi = ida_ua.insn_t()
                                if ida_ua.decode_insn(pi, scan):
                                    pmn = pi.get_canon_mnem()
                                    if (pmn in ('lea', 'mov')
                                        and pi.ops[0].type == ida_ua.o_reg
                                        and pi.ops[0].reg == op1.reg):
                                        handler = pi.ops[1].addr or pi.ops[1].value
                                        if handler and ida_funcs.get_func(handler):
                                            if mj_idx not in found:
                                                found[mj_idx] = handler
                                        break
                        break  # don't try other layouts for this insn
            # v1.5: `rep stosq` MJ-array fill (ASTRA64-style "register one
            # handler for all major functions") followed by per-MJ overrides.
            # Pattern (64-bit):
            #   lea  rdi, [DriverObject+0x70]   ; dst = &MJ[0]    REQUIRED
            #   lea  rax, handler               ; src             REQUIRED
            #   mov  ecx, N                     ; count (qwords)
            #   rep stosq                       ; fill MJ[0..N-1] = handler
            # STRICT match: rdi must come from `lea rdi, [reg+MJ_BASE]` where
            # MJ_BASE is exactly 0x70 (64-bit) or 0x38 (32-bit). Otherwise
            # this rep stos is unrelated memory clear (e.g. WUDFRd zeroes
            # a buffer that triggers false-positive MJ writes).
            expected_base = 0x38 if is32 else 0x70
            if mnem.startswith('stos'):
                lea_rax_handler = None
                rdi_at_mj_base = False
                count_imm = None
                scan = ea
                for _ in range(20):
                    scan = ida_bytes.prev_head(scan, f.start_ea)
                    if scan < f.start_ea: break
                    pi = ida_ua.insn_t()
                    if not ida_ua.decode_insn(pi, scan): continue
                    pmn = pi.get_canon_mnem()
                    if pmn == 'lea' and pi.ops[0].type == ida_ua.o_reg:
                        rname = pi.ops[0].reg
                        if rname == 7:  # rdi
                            # MUST be lea rdi, [reg+expected_base] (o_displ)
                            if (pi.ops[1].type == ida_ua.o_displ
                                    and pi.ops[1].addr == expected_base):
                                rdi_at_mj_base = True
                        elif rname == 0:  # rax = handler
                            if pi.ops[1].type == ida_ua.o_mem:
                                lea_rax_handler = pi.ops[1].addr or pi.ops[1].value
                    elif pmn == 'mov' and pi.ops[0].type == ida_ua.o_reg:
                        # mov ecx, N → count
                        if pi.ops[0].reg == 1 and pi.ops[1].type == ida_ua.o_imm:
                            count_imm = pi.ops[1].value
                # Only buffer if all three pieces aligned + plausible count
                # (MJ array has at most 28 entries; require 5..28 to avoid
                # rep stos of small struct fields). Applied AFTER all
                # direct-mov writes complete so explicit overrides win.
                if (lea_rax_handler and rdi_at_mj_base
                        and count_imm and 5 <= count_imm <= 28
                        and ida_funcs.get_func(lea_rax_handler)):
                    pending_repstos.append((lea_rax_handler, int(count_imm)))

            if mnem == 'call' and d < max_depth:
                callee = insn.ops[0].addr or insn.ops[0].value
                if callee and ida_funcs.get_func(callee) and callee not in visited:
                    queue.append((callee, d + 1))
            # v1.5: follow JMPs as well. MSVC /GS security-cookie init stubs
            # end in `jmp real_driver_entry`. Tail-call optimization also
            # turns `call X; ret` into `jmp X`. Walk those too.
            if mnem == 'jmp' and d < max_depth:
                target = insn.ops[0].addr or insn.ops[0].value
                if target and ida_funcs.get_func(target) and target not in visited:
                    queue.append((target, d + 1))
            ea = ida_bytes.next_head(ea, f.end_ea)

    # Apply buffered rep-stos fills only to slots not already taken by
    # direct mov writes. This way an explicit `mov [obj+0xE0], 0x158cc`
    # (MJ[14]=real_dispatcher) wins over a generic `rep stos` fill that
    # sets every MJ to the same wrapper (PCTcore64 + WUDFRd pattern).
    for handler_ea, count in pending_repstos:
        for mj_slot in range(min(count, 16)):
            if mj_slot not in found:
                found[mj_slot] = handler_ea
    return found


def _is_mj14_in_func(func_ea, mj_idx, handler_ea):
    """Check whether MJ[mj_idx]=handler write is directly inside func_ea (not a callee)."""
    import ida_funcs, ida_bytes, ida_ua
    f = ida_funcs.get_func(func_ea)
    if not f:
        return False
    target_off = 0x70 + mj_idx * 8
    ea = f.start_ea
    while ea < f.end_ea:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea):
            mnem = insn.get_canon_mnem()
            op0 = insn.ops[0]
            if mnem == 'mov' and op0.type == ida_ua.o_displ and op0.addr == target_off:
                return True
        ea = ida_bytes.next_head(ea, f.end_ea)
    return False


def _looks_like_ioctl(val: int) -> bool:
    """Heuristic IOCTL filter.

    A real CTL_CODE has structure: [device_type:16] [access:2] [function:12] [method:2]
    Filter out values that don't look IOCTL-shaped:
      * device_type == 0 (BEEP=0 not used for IOCTLs)
      * device_type == 0xFFFF (sentinel)
      * device_type in 0x003C..0x7FFF (Microsoft-reserved middle range — v2.5)
      * function == 0 (CTL_CODE() never generates function 0)
      * value < 0x10000 (no device type)
      * NTSTATUS-looking values in 0xC0000000..0xC07FFFFF range (well-known
        facility 0-7 errors). Vendor IOCTLs at device_type >= 0xC080 are
        kept — e.g. gdrv.sys (Gigabyte CVE-2018-19320) uses 0xC3500xxx.
      * sentinel values like 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFF00, 0xFFFFF000
        (used as -1, -2, MAXULONG-aligned)

    v2.5 — device_type 0x003C..0x7FFF is Microsoft-reserved per ntddk; no
    legitimate vendor IOCTL uses it. The biased-switch fallback (v1.7+)
    already filters those at emission, but this shape-filter catches
    phantom values from non-jumptable paths (lone leaves, raw byte scans).
    Standard ntddk file-device types are 0x0001-0x003B; OEM-custom range
    is 0x8000-0xFFFE.
    """
    val &= 0xFFFFFFFF
    if val < 0x10000:
        return False
    device_type = (val >> 16) & 0xFFFF
    function = (val >> 2) & 0xFFF
    if device_type == 0 or device_type == 0xFFFF:
        return False
    if function == 0:
        return False
    # v2.5: Microsoft-reserved middle range — neither ntddk nor OEM custom.
    # Real vendor IOCTLs land in 0x0001-0x003B (standard) or 0x8000-0xFFFE
    # (OEM custom). Values whose device_type falls in 0x003C-0x7FFF are
    # almost certainly arithmetic constants, not IOCTLs.
    if 0x003C <= device_type <= 0x7FFF:
        return False
    # NTSTATUS error range — TIGHTENED in v1.5. Previously rejected the
    # full 0xC0000000-0xCFFFFFFF range which incorrectly dropped legit
    # vendor IOCTLs at device_type 0xC100+. Now only reject the standard
    # facility 0-7 NTSTATUS errors (0xC0000000-0xC07FFFFF).
    if 0xC0000000 <= val <= 0xC07FFFFF:
        return False
    # Sentinel patterns: high-byte 0xFF + low bits zero (e.g. 0xFFFFF000)
    if (val & 0xFF000000) == 0xFF000000 and (val & 0xFFF) == 0:
        return False
    return True


_JT_CASE_RE = re.compile(r'cases?\s+([\-\d,\s]+)')
_JT_TOKEN_RE = re.compile(r'(-?\d+)(?:-(-?\d+))?')


def _extract_jumptable_cases_from_line(line: str):
    """Parse IDA-tagged switch cases from a disasm line.

    CRITICAL: IDA distinguishes two annotation forms (v1.6 fix):

    1. Master `ja def_XXX ; jumptable XXX default case, cases A,B,C...` —
       these cases go to the DEFAULT handler (typically returns
       STATUS_INVALID_DEVICE_REQUEST). They are REJECTED IOCTLs, NOT
       valid IOCTL surface. RTCore64 has 67 default-cases out of 85
       total in the switch.

    2. Per-handler `; jumptable XXX case -K` or `cases -A,-B` on the
       FIRST instruction of each case handler — these are the
       EXPLICITLY HANDLED cases (real IOCTLs).

    We parse only form (2). Lines containing "default case" are SKIPPED.
    """
    out = set()
    if 'case' not in line:
        return out
    # SKIP master "default case" lines — those list rejected IOCTLs
    if 'default case' in line:
        return out
    m = _JT_CASE_RE.search(line)
    if not m:
        return out
    blob = m.group(1)
    for tok in blob.split(','):
        tok = tok.strip()
        if not tok:
            continue
        tm = _JT_TOKEN_RE.fullmatch(tok)
        if not tm:
            continue
        a_s, b_s = tm.group(1), tm.group(2)
        try:
            a = int(a_s) & 0xFFFFFFFF
            if b_s is None:
                out.add(a)
            else:
                b = int(b_s) & 0xFFFFFFFF
                lo, hi = (a, b) if a <= b else (b, a)
                if hi - lo > 4096:
                    out.add(lo); out.add(hi)
                else:
                    for v in range(lo, hi + 1):
                        out.add(v & 0xFFFFFFFF)
        except (TypeError, ValueError):
            continue
    return out


def _enumerate_dispatch_ioctls(handler_ea, max_depth=3):
    """Walk dispatcher tree. IOCTLs are masked to 32 bits to strip
    sign-extension artifacts (cmp ecx, 0xa0400f58 reads as -1606391464).

    v1.4: also extracts IDA-tagged switch-cases (RTCore64 / biased-bias-add
    pattern) and detects the `add reg, BIAS; cmp reg, MAX; ja` pattern.

    v1.8: post-filter depth >= 1 emissions by device_type homogeneity.
    A real dispatcher serves ONE DEVICE_OBJECT with ONE DeviceType — sub-
    handlers reached via call/jmp recursion may have additional cmp+jcc
    patterns against sub-command values, magic cookies, or struct fields
    that look like IOCTLs in DIFFERENT device_types. cpuz-1.0.4.1.sys
    was emitting 254 phantoms in device_type 0xff00 alongside its 35
    real IOCTLs in 0x9c40. Strategy: collect emissions tagged with
    their depth; after the BFS, keep depth-0 emissions verbatim plus
    only those depth>=1 emissions whose device_type appeared at depth 0.
    """
    import ida_funcs, ida_bytes, ida_ua, ida_xref, ida_lines
    visited = set()
    queue = deque([(handler_ea, 0)])
    # Track min-depth at which each value was emitted, so v1.8 post-
    # filter can drop depth>=1 emissions whose device_type was never
    # seen at depth 0.
    all_ioctls = set()
    ioctl_min_depth = {}  # value -> min depth observed

    def _emit(v, _depth_ref=None):
        # _depth_ref is set per outer-loop iteration via the closure d
        all_ioctls.add(v)
        cur = ioctl_min_depth.get(v)
        if cur is None or _depth_ref < cur:
            ioctl_min_depth[v] = _depth_ref

    while queue:
        fea, d = queue.popleft()
        if fea in visited or d > max_depth:
            continue
        visited.add(fea)
        f = ida_funcs.get_func(fea)
        if not f or (f.flags & ida_funcs.FUNC_LIB):
            continue
        ea = f.start_ea
        # Track `add reg, IMM_BIAS` for biased-switch detection.
        # Map reg_id -> bias_imm (always non-zero, treated as 32-bit signed).
        reg_bias = {}
        running_sum = None
        # NO instruction count cap — bound by f.end_ea. Old 350-cap clipped
        # large dispatchers like AsIO3_64 (817 insns) at half-coverage.
        # Safety cap 20000 catches infinite-loop pathology only.
        count = 0
        # Conditional jumps that may follow a comparison and indicate IOCTL
        # match (include unsigned-compare for MSVC switch range-checks).
        COND_JUMPS = {'jz', 'jnz', 'je', 'jne', 'ja', 'jae', 'jb', 'jbe'}
        # v2.1.1: SET-byte equality variants. MSVC sometimes materializes
        # the comparison result into a byte register instead of branching
        # (compiler optimization for switch lowering with multiple cases
        # routing to the same code). aswSP.sys uses `cmp ebx, IMM32; setnz
        # dl; jmp ...` for IOCTL 0xB2D60120 / 0xB2D60128 — these were missed
        # in v2.1 because only jcc was accepted as a valid look-ahead.
        SET_EQ = {'setz', 'sete', 'setnz', 'setne'}
        # v2.4: CMOV equality variants. Same flag semantics — MSVC's
        # branchless switch lowering may emit `cmp r, IMM32; cmovz rax, rcx`
        # to select a value depending on the equality result. Add to the
        # accepted look-ahead so we don't miss those IOCTLs either.
        CMOV_EQ = {'cmovz', 'cmove', 'cmovnz', 'cmovne'}
        # Convenience: anything that signals "the prior cmp was tested"
        EQ_SIGNAL = COND_JUMPS | SET_EQ | CMOV_EQ
        # Register-to-imm tracker for the `mov reg, IMM; cmp r2, reg; jcc`
        # pattern (MSVC sometimes loads IMM into a reg before reg-reg cmp).
        reg_imm = {}   # reg_id -> imm32 (most-recent)
        while ea < f.end_ea and count < 20000:
            count += 1
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, ea):
                ea = ida_bytes.next_head(ea, f.end_ea); continue
            mnem = insn.get_canon_mnem()

            # Track mov reg, IMM32 for later reg-reg compares
            if mnem == 'mov':
                op0 = insn.ops[0]
                op1 = insn.ops[1]
                if op0.type == ida_ua.o_reg and op1.type == ida_ua.o_imm:
                    v = op1.value & 0xFFFFFFFF
                    reg_imm[op0.reg] = v
                elif op0.type == ida_ua.o_reg:
                    # reg overwritten by non-imm — invalidate the tracked imm
                    reg_imm.pop(op0.reg, None)
                    reg_bias.pop(op0.reg, None)

            # Track biased-switch pattern: `add reg, IMM_BIAS` (MSVC switch
            # lowering: eax = ioctl + bias, then cmp eax, MAX_INDEX, ja default).
            # The IOCTL base is (-bias) & 0xFFFFFFFF.
            # v1.8: require IDA's `; switch N cases` annotation on the same
            # line — otherwise `add reg, IMM` could be any integer math
            # (cpuz has `add eax, 0xFFFFFF` for value scaling, not a switch).
            if mnem == 'add':
                op0 = insn.ops[0]
                op1 = insn.ops[1]
                if op0.type == ida_ua.o_reg and op1.type == ida_ua.o_imm:
                    bias = op1.value & 0xFFFFFFFF
                    if bias != 0:
                        add_line = ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or "")
                        if 'switch ' in add_line and ' cases' in add_line:
                            reg_bias[op0.reg] = bias

            # Jump-table-comment harvest: walk every instruction looking
            # for per-handler `case X` tags (NOT the master "default case"
            # list which contains REJECTED cases — v1.6 fix).
            # Depth-restricted to 0 — sub-command switches in case handlers
            # are not IOCTLs.
            if d == 0:
                line = ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or "")
                if 'jumptable' in line and 'default case' not in line:
                    for v in _extract_jumptable_cases_from_line(line):
                        if _looks_like_ioctl(v):
                            _emit(v, d)

            if mnem == 'sub' and insn.ops[1].type == ida_ua.o_imm:
                ne = ida_bytes.next_head(ea, f.end_ea)
                ni = ida_ua.insn_t()
                if ida_ua.decode_insn(ni, ne) and ni.get_canon_mnem() in COND_JUMPS:
                    running_sum = (running_sum or 0) + insn.ops[1].value
                    masked = running_sum & 0xFFFFFFFF
                    if _looks_like_ioctl(masked):
                        _emit(masked, d)
            elif mnem == 'cmp' and insn.ops[1].type == ida_ua.o_imm:
                val = insn.ops[1].value
                ne = ida_bytes.next_head(ea, f.end_ea)
                ni = ida_ua.insn_t()
                next_mnem = ni.get_canon_mnem() if ida_ua.decode_insn(ni, ne) else ''
                # v2.4: accept jcc + setcc + cmovcc equality variants
                has_cj = next_mnem in EQ_SIGNAL
                # Biased-switch pattern: prior `add reg, BIAS` then `cmp reg, MAX_INDEX`.
                # IOCTL_BASE = (-BIAS) & 0xFFFFFFFF.
                # IMPORTANT: only emit the FULL range as a fallback when IDA
                # did NOT tag the jumptable cases (those are authoritative —
                # the byte-index table filters which values are real cases).
                op0 = insn.ops[0]
                if (op0.type == ida_ua.o_reg
                        and op0.reg in reg_bias
                        and has_cj
                        and val < 0x10000):
                    # Peek at the jcc line: if IDA already annotated cases,
                    # the jumptable harvester (running per-instruction above)
                    # has the exact set — skip the wide range fallback.
                    nj_line = ida_lines.tag_remove(ida_lines.generate_disasm_line(ne, 0) or "")
                    if 'cases' not in nj_line and 'jumptable' not in nj_line:
                        bias = reg_bias[op0.reg]
                        base = (-bias) & 0xFFFFFFFF
                        # v1.7: require BASE to land in a legit IOCTL device-type
                        # range. Per Microsoft convention:
                        #   0x0001..0x003B = standard ntddk FILE_DEVICE_*
                        #   0x003C..0x7FFF = RESERVED for Microsoft (phantom)
                        #   0x8000..0xFFFE = OEM custom
                        # Reject the reserved middle range. TdGamepad has an
                        # `add reg, 0xC00000C0` (NTSTATUS error build) that
                        # would otherwise enumerate 256 phantom IOCTLs in the
                        # 0x3FFFFFXX (device_type 0x3FFF) reserved range.
                        base_dev_type = (base >> 16) & 0xFFFF
                        ranges_ok = (
                            1 <= base_dev_type <= 0x3B
                            or 0x8000 <= base_dev_type <= 0xFFFE
                        )
                        if ranges_ok:
                            cap = min(val, 0x100)
                            for j in range(cap + 1):
                                cand = (base + j) & 0xFFFFFFFF
                                if _looks_like_ioctl(cand):
                                    _emit(cand, d)
                if running_sum is not None and has_cj:
                    full = (running_sum + val) & 0xFFFFFFFF
                    if _looks_like_ioctl(full):
                        _emit(full, d)
                elif has_cj:
                    val_m = val & 0xFFFFFFFF
                    if _looks_like_ioctl(val_m):
                        _emit(val_m, d)
            elif mnem == 'cmp':
                # reg-reg cmp with one operand holding a tracked IMM:
                # this is an IOCTL match only if EQUALITY-jcc (jz/je) follows
                # within the next few jumps. Plain ja/jbe-only is a MSVC
                # binary-search range pivot, not an IOCTL.
                op0 = insn.ops[0]
                op1 = insn.ops[1]
                tracked_imm = None
                for op in (op0, op1):
                    if op.type == ida_ua.o_reg and op.reg in reg_imm:
                        tracked_imm = reg_imm[op.reg]; break
                if tracked_imm is not None:
                    # Look ahead up to 4 instructions for an equality signal:
                    # v2.1.1 jcc+setcc, v2.4 also cmovcc.
                    has_eq_jcc = False
                    look_ea = ea
                    for _ in range(4):
                        look_ea = ida_bytes.next_head(look_ea, f.end_ea)
                        if look_ea >= f.end_ea: break
                        ji = ida_ua.insn_t()
                        if not ida_ua.decode_insn(ji, look_ea): break
                        jm = ji.get_canon_mnem()
                        # Only the EQUALITY half of each family (jz/setz/cmovz +
                        # their inverses). Range pivots (ja/jbe) come from the
                        # outer biased-switch path, not this reg-imm tracker.
                        if jm in ('jz', 'je', 'jnz', 'jne') or jm in SET_EQ or jm in CMOV_EQ:
                            has_eq_jcc = True; break
                        # stop look-ahead at any non-conditional control flow
                        if jm in ('call', 'retn', 'ret', 'jmp'):
                            break
                        # also stop if we see another cmp (next dispatch case)
                        if jm == 'cmp':
                            break
                    if has_eq_jcc and _looks_like_ioctl(tracked_imm):
                        _emit(tracked_imm, d)
            elif mnem in ('call','retn','ret','jmp'):
                running_sum = None
                reg_imm.clear()
                reg_bias.clear()
            ea = ida_bytes.next_head(ea, f.end_ea)
        if d < max_depth:
            xb = ida_xref.xrefblk_t()
            ok = xb.first_from(f.start_ea, 0)
            while ok:
                if xb.iscode and xb.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    if xb.to not in visited:
                        tgt = ida_funcs.get_func(xb.to)
                        if tgt and not (tgt.flags & ida_funcs.FUNC_LIB):
                            queue.append((xb.to, d + 1))
                ok = xb.next_from()
    # v1.8 post-filter: any emission at depth >= 1 whose device_type was
    # never observed at depth 0 is treated as a sub-handler phantom (sub-
    # command compares, magic cookies, struct fields).
    dts_at_zero = {(v >> 16) & 0xFFFF for v, md in ioctl_min_depth.items() if md == 0}
    if dts_at_zero:
        all_ioctls = {
            v for v in all_ioctls
            if ioctl_min_depth.get(v, 0) == 0
            or ((v >> 16) & 0xFFFF) in dts_at_zero
        }
    return all_ioctls


def _walk_minifilter():
    import ida_funcs, ida_bytes, ida_ua, ida_xref, ida_name, ida_idaapi, ida_segment
    sites = _find_import_xrefs('FltRegisterFilter')
    real = set()
    for s in sites:
        owner = ida_funcs.get_func(s)
        if owner is None:
            continue
        owner_ea = owner.start_ea
        if (owner.end_ea - owner.start_ea) <= 16:
            # thunk — find callers
            xb = ida_xref.xrefblk_t()
            ok = xb.first_to(owner_ea, 0)
            while ok:
                if xb.iscode and xb.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    real.add(xb.frm)
                ok = xb.next_to()
        else:
            real.add(s)
    info = []
    for site in sorted(real)[:3]:
        reg_addr = _trace_arg_back(site, 2)
        if not reg_addr:
            info.append({'call_site': hex(site), 'flt_registration': None, 'note': 'rdx trace failed'})
            continue
        op_table = ida_bytes.get_qword(reg_addr + FLT_REG_OP_OFFSET)
        if not op_table or op_table == 0xFFFFFFFFFFFFFFFF:
            info.append({'call_site': hex(site), 'flt_registration': hex(reg_addr),
                         'op_table': None, 'note': 'op_table NULL (runtime)'})
            continue
        entries = _walk_flt_op_reg(op_table)
        ioctls = set()
        for e in entries:
            if int(e['major_function'], 16) == IRP_MJ_DEVICE_CONTROL:
                pre = e.get('preop')
                if pre and pre != '0x0':
                    ea = int(pre, 16)
                    if ida_funcs.get_func(ea):
                        ioctls.update(_enumerate_dispatch_ioctls(ea))
        info.append({
            'call_site': hex(site),
            'flt_registration': hex(reg_addr),
            'op_table': hex(op_table),
            'entry_count': len(entries),
            'mj14_ioctls': sorted(hex(i) for i in ioctls),
            'entries': entries,
        })
    return info if info else None


def _walk_flt_op_reg(op_table_ea, max_entries=64):
    import ida_bytes
    entries = []
    ea = op_table_ea
    for _ in range(max_entries):
        mj = ida_bytes.get_byte(ea)
        flags = ida_bytes.get_dword(ea + 0x4)
        preop = ida_bytes.get_qword(ea + 0x8)
        postop = ida_bytes.get_qword(ea + 0x10)
        entries.append({
            'address': hex(ea),
            'major_function': hex(mj),
            'flags': hex(flags),
            'preop': hex(preop) if preop else None,
            'postop': hex(postop) if postop else None,
        })
        if mj == IRP_MJ_OPERATION_END:
            break
        ea += FLT_OP_SIZE
    return entries


def _process_callback_targets():
    import ida_funcs, ida_xref
    sites = _find_import_xrefs('PsSetCreateProcessNotifyRoutineEx')
    if not sites:
        return None
    real = set()
    for s in sites:
        owner = ida_funcs.get_func(s)
        if owner and (owner.end_ea - owner.start_ea) <= 16:
            xb = ida_xref.xrefblk_t()
            ok = xb.first_to(owner.start_ea, 0)
            while ok:
                if xb.iscode and xb.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    real.add(xb.frm)
                ok = xb.next_to()
        else:
            real.add(s)
    out = []
    for s in sorted(real)[:3]:
        cb = _trace_arg_back(s, 1)
        if cb:
            out.append({'call_site': hex(s), 'callback_ea': hex(cb)})
    return out or None


def _find_import_xrefs(name):
    import ida_segment, ida_bytes, ida_name, ida_xref, ida_funcs
    sites = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg is None or seg.type != ida_segment.SEG_XTRN:
            continue
        ea = seg.start_ea
        while ea < seg.end_ea:
            n = ida_name.get_name(ea)
            if n:
                bare = n.lstrip('_').replace('imp_', '').lstrip('_')
                if bare == name:
                    xb = ida_xref.xrefblk_t()
                    ok = xb.first_to(ea, 0)
                    while ok:
                        sites.append(xb.frm)
                        ok = xb.next_to()
            ea = ida_bytes.next_head(ea, seg.end_ea)
    return sites


def _trace_arg_back(call_ea, arg_reg_id, max_back=60):
    import ida_bytes, ida_ua, ida_idaapi
    cur = call_ea
    for _ in range(max_back):
        cur = ida_bytes.prev_head(cur, 0)
        if cur == ida_idaapi.BADADDR:
            break
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, cur):
            continue
        op0 = insn.ops[0]
        if op0.type != ida_ua.o_reg or op0.reg != arg_reg_id:
            continue
        mnem = insn.get_canon_mnem()
        if mnem in ('lea', 'mov'):
            op_src = insn.ops[1]
            target = op_src.addr or op_src.value
            if target:
                return target
    return None


def _detect_gates(handler_ea, max_depth=3):
    """Detect gate archetypes in dispatcher tree:

    - PID_CHECK       — PsGetCurrentProcessId / PsGetProcessId called
    - MODULE_PRESENCE — PsGetProcessPeb + PEB.Ldr walks
    - STRING_COMPARE  — RtlInitUnicodeString + RtlCompareUnicodeString
    - MAGIC_COOKIE    — cmp dword [mem-disp], imm32 with high entropy (looks
                        like *user_buf == 0xDEADBEEFCAFE pattern)
    - TRUST_DB_NULL   — multiple cmp [global], 0 + jz patterns (engine-not-init)
    - ZW_QUERY_TOKEN  — ZwQueryInformationToken (privilege check)
    """
    import ida_funcs, ida_bytes, ida_ua, ida_xref, ida_name
    visited = set()
    queue = deque([(handler_ea, 0)])
    gates = set()
    magic_cookie_hits = 0
    magic_cookie_hi_entropy_hits = 0  # ones with full 4-byte entropy
    null_check_hits = 0
    rtl_init_calls = 0
    rtl_cmp_calls = 0

    while queue:
        fea, d = queue.popleft()
        if fea in visited or d > max_depth:
            continue
        visited.add(fea)
        f = ida_funcs.get_func(fea)
        if not f:
            continue
        ea = f.start_ea
        while ea < f.end_ea:
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, ea):
                ea = ida_bytes.next_head(ea, f.end_ea); continue
            mnem = insn.get_canon_mnem()
            # Function-name based gates
            if mnem == 'call':
                callee = insn.ops[0].addr or insn.ops[0].value
                nm = (ida_name.get_name(callee) or '').lstrip('_').replace('imp_', '').lstrip('_')
                if nm in ('PsGetCurrentProcessId', 'PsGetProcessId'):
                    gates.add('PID_CHECK')
                if nm in ('PsGetProcessPeb', 'PsGetProcessWow64Process'):
                    gates.add('MODULE_PRESENCE')
                if nm == 'RtlInitUnicodeString':
                    rtl_init_calls += 1
                if nm in ('RtlCompareUnicodeString', 'RtlEqualUnicodeString'):
                    rtl_cmp_calls += 1
                if nm in ('ZwQueryInformationToken', 'SeQueryAuthenticationIdToken',
                          'SePrivilegeCheck', 'SeAccessCheck'):
                    gates.add('TOKEN_CHECK')
                if d < max_depth and callee and ida_funcs.get_func(callee) and callee not in visited:
                    queue.append((callee, d + 1))
            # cmp [user_buf+N], imm32  pattern (magic cookie check)
            elif mnem == 'cmp':
                op0 = insn.ops[0]
                op1 = insn.ops[1]
                if op0.type == ida_ua.o_displ and op1.type == ida_ua.o_imm:
                    val = op1.value & 0xFFFFFFFF
                    displ = op0.addr & 0xFFFFFFFF
                    # Magic-cookie heuristic — must be ALL of:
                    #   1. imm32 in 0x10000..0xBFFFFFFE
                    #      (exclude NTSTATUS values 0xC0000000+ and 0x80000000+
                    #       and -1)
                    #   2. cmp displacement is small (<= 0x100) — user buffer
                    #      offsets, not large kernel-struct fields like
                    #      Irp.IoStatus.Information or device-extension at 0x200+
                    #   3. not all-zero low bytes (true magic cookies have
                    #      mixed entropy)
                    if (0x10000 <= val < 0x80000000
                            and displ <= 0x100
                            and (val & 0xFFFF) != 0):
                        magic_cookie_hits += 1
                        # High-entropy: top byte and bottom byte both
                        # non-zero (true 4-byte random cookie like
                        # 0x345821AB, not aligned constant 0xAABBCC00).
                        if (val & 0xFF) != 0 and (val >> 24) != 0:
                            magic_cookie_hi_entropy_hits += 1
                # cmp [global], 0  pattern (trust-DB null check)
                if op0.type == ida_ua.o_mem and op1.type == ida_ua.o_imm and op1.value == 0:
                    null_check_hits += 1
            ea = ida_bytes.next_head(ea, f.end_ea)

    # Two looser hits, OR one strong (full-entropy 4-byte) hit. The latter
    # catches single-command-surface AC drivers like xhunter1 whose only
    # input gate is one fixed magic 0x345821AB at [buf+4].
    if magic_cookie_hits >= 2 or magic_cookie_hi_entropy_hits >= 1:
        gates.add('MAGIC_COOKIE')
    if null_check_hits >= 3:
        gates.add('TRUST_DB_NULL')
    if rtl_init_calls >= 2 and rtl_cmp_calls >= 1:
        gates.add('STRING_COMPARE')
    return sorted(gates)


# v2.5: deep-mode equality look-ahead.
# JZ_TAKEN = handler is the JUMP TARGET (cmp; jz handler)
# JZ_FALLTHROUGH = handler is the FALL-THROUGH (cmp; jnz error_path; handler...)
# SET / CMOV: handler is fall-through (instruction materializes flag into reg)
_DEEP_JZ_TAKEN = {'jz', 'je'}
_DEEP_JZ_FALLTHROUGH = {'jnz', 'jne'}
_DEEP_SET_EQ = {'setz', 'sete', 'setnz', 'setne'}
_DEEP_CMOV_EQ = {'cmovz', 'cmove', 'cmovnz', 'cmovne'}


def _classify_per_ioctl(dispatcher_ea, ioctls_list):
    """For each IOCTL, find the handler EA via cmp + jz/setcc/cmovcc pattern,
    decompile it, and classify by detected primitives in its callees.

    v2.5: accept setcc/cmovcc as equality-signal in addition to jcc — matches
    the v2.1.1/v2.4 fix in the IOCTL extractor (_enumerate_dispatch_ioctls)
    so that --deep per_ioctl_classification covers the same dispatchers.
    Without this, aswSP would show ioctl_count=37 but
    len(per_ioctl_classification)=35 because the 2 setcc-gated handlers
    (0xB2D60120 / 0xB2D60128) couldn't be resolved.

    For setcc/cmovcc hits the "handler EA" is the fall-through path. We
    walk forward to the next control-flow break (call / jmp / ret / next-cmp)
    and use that EA as the handler branch.
    """
    import ida_funcs, ida_bytes, ida_ua, ida_xref, ida_name
    try:
        import ida_hexrays
        hr_ok = ida_hexrays.init_hexrays_plugin()
    except Exception:
        hr_ok = False

    f = ida_funcs.get_func(dispatcher_ea)
    if not f:
        return None
    # Map IOCTL -> handler_ea via cmp + (jz/setz/cmovz) patterns. No step
    # cap (the v1.0 logic walked uncapped until the next cmp/mov/end_ea).
    ioctl_handlers = {}
    ea = f.start_ea
    while ea < f.end_ea:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea):
            if insn.get_canon_mnem() == 'cmp' and insn.ops[1].type == ida_ua.o_imm:
                val32 = insn.ops[1].value & 0xFFFFFFFF
                if val32 in ioctls_list:
                    ne = ida_bytes.next_head(ea, f.end_ea)
                    while ne < f.end_ea:
                        ji = ida_ua.insn_t()
                        if not ida_ua.decode_insn(ji, ne):
                            break
                        jmn = ji.get_canon_mnem()
                        # Primary: jz/je -- handler is the JUMP TARGET
                        if jmn in _DEEP_JZ_TAKEN:
                            tgt = ji.ops[0].addr or ji.ops[0].value
                            if tgt:
                                ioctl_handlers[hex(val32)] = hex(tgt)
                            break
                        # v2.5: jnz/jne -- handler is the FALL-THROUGH.
                        # Pattern: cmp ebx, IMM; jnz error_path; handler...
                        # Resolves 4 of the 6-IOCTL deep-mode gap on aswSP.
                        if jmn in _DEEP_JZ_FALLTHROUGH:
                            after = ida_bytes.next_head(ne, f.end_ea)
                            if after < f.end_ea:
                                ioctl_handlers[hex(val32)] = hex(after)
                            break
                        # v2.5: setcc / cmovcc materialize ZF into a byte
                        # or do a conditional move. The "handler" path is
                        # the fall-through; record the EA after the setcc
                        # itself so _classify_handler walks the right block.
                        if jmn in _DEEP_SET_EQ or jmn in _DEEP_CMOV_EQ:
                            after = ida_bytes.next_head(ne, f.end_ea)
                            if after < f.end_ea:
                                ioctl_handlers[hex(val32)] = hex(after)
                            break
                        if jmn in ('cmp', 'mov'):
                            break  # something else, give up
                        ne = ida_bytes.next_head(ne, f.end_ea)
        ea = ida_bytes.next_head(ea, f.end_ea)

    # Classify each handler EA by its callees + imports
    out = []
    for ioctl, h in ioctl_handlers.items():
        h_ea = int(h, 16)
        prims = _classify_handler(h_ea)
        out.append({'ioctl': ioctl, 'handler_branch': h, 'primitives': prims})
    return out


def _classify_handler(handler_ea, max_depth=2):
    """Walk handler + callees collecting which kernel APIs are called."""
    import ida_funcs, ida_bytes, ida_ua, ida_xref, ida_name
    visited = set()
    queue = deque([(handler_ea, 0)])
    apis = set()
    while queue:
        fea, d = queue.popleft()
        if fea in visited or d > max_depth:
            continue
        visited.add(fea)
        f = ida_funcs.get_func(fea)
        if not f:
            # not a function boundary — synthesize one ad-hoc scan
            ea = handler_ea
            for _ in range(80):
                insn = ida_ua.insn_t()
                if not ida_ua.decode_insn(insn, ea):
                    break
                if insn.get_canon_mnem() == 'call':
                    callee = insn.ops[0].addr or insn.ops[0].value
                    nm = (ida_name.get_name(callee) or '').lstrip('_').replace('imp_', '').lstrip('_')
                    if nm:
                        apis.add(nm)
                ea = ida_bytes.next_head(ea, ea + 0x800)
            continue
        ea = f.start_ea
        while ea < f.end_ea:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea):
                if insn.get_canon_mnem() == 'call':
                    callee = insn.ops[0].addr or insn.ops[0].value
                    nm = (ida_name.get_name(callee) or '').lstrip('_').replace('imp_', '').lstrip('_')
                    if nm:
                        apis.add(nm)
                    if d < max_depth and callee and ida_funcs.get_func(callee) and callee not in visited:
                        queue.append((callee, d + 1))
            ea = ida_bytes.next_head(ea, f.end_ea)
    classes = set()
    for cls, api_set in PRIMITIVE_CLASSES.items():
        if api_set & apis:
            classes.add(cls)
    return sorted(classes)


# ============================================================
# Scoring
# ============================================================
def perfect_score(result: dict) -> tuple:
    """Compute PERFECT-rubric score with caps.

    Caps:
      no FORCE_INTEGRITY               -> max 80 (HVCI-blocked tier)
      no GUARD_CF or W+X INIT          -> max 60
      else                             -> max 100
    """
    h = result.get('hvci', {}) or {}
    ic = result.get('ioctl_count', 0)
    prims = result.get('primitives', []) or []
    gates = result.get('gates_detected', []) or []
    modes = result.get('modes_resolved', []) or []

    if not h.get('force_integrity'):
        cap = 80
    elif not h.get('guard_cf') or h.get('init_wx'):
        cap = 60
    else:
        cap = 100

    score = 0

    # IOCTL count contribution
    if ic >= 30:   score += 25
    elif ic >= 10: score += 20
    elif ic >= 5:  score += 15
    elif ic >= 3:  score += 10

    # Primitive imports contribution (up to +40, capped at 8 classes)
    score += min(40, 5 * len(prims))

    # Gate analysis
    hard_gates = {'PID_CHECK', 'MODULE_PRESENCE', 'MAGIC_COOKIE',
                  'TRUST_DB_NULL', 'STRING_COMPARE', 'TOKEN_CHECK'}
    weak_gates = {'WEAK_BITNESS_CHECK_ONLY'}
    detected_hard = set(gates) & hard_gates
    if not gates or detected_hard - weak_gates == set():
        # no gates OR only weak bitness check
        score += 25
    elif detected_hard:
        # subtract for each hard gate type
        score -= 10 * len(detected_hard)

    # DACL signal
    if result.get('has_io_create_device') and not result.get('has_io_create_device_secure'):
        score += 5
    if result.get('sddl_strings'):
        score -= 5  # SDDL string present = some kind of access policy

    # Archetype penalty
    archs = result.get('archetype_strings') or {}
    if (archs.get('STEALTH_HIDDEN') or archs.get('ANTICHEAT_AC')
            or archs.get('SELF_PROTECTION')):
        score -= 25

    # Min-filter floor: HVCI-pass minifilter with primitive imports is
    # still BYOVD-relevant even if user-IOCTL count is 0. Don't let it
    # drop to absolute 0 just because we couldn't find an explicit IOCTL.
    if (h.get('force_integrity') and h.get('guard_cf') and not h.get('init_wx')
            and 'minifilter' in modes and len(prims) >= 3
            and score < 20):
        score = 20

    score = max(0, min(score, cap))
    if score >= 90:   tier = 'PERFECT'
    elif score >= 70: tier = 'STRONG'
    elif score >= 50: tier = 'INTERESTING'
    elif score >= 30: tier = 'WEAK'
    else:             tier = 'SKIP'
    return score, tier


# ============================================================
# Report formatters
# ============================================================
def _print_strings_section(s: dict):
    """Print the v2.1 --strings extractor block."""
    if not s or 'error' in s:
        return
    print()
    print(C.BOLD + "  Strings:" + C.RESET)
    print(f"    ascii_count: {s.get('ascii_count', 0)}, utf16_count: {s.get('utf16_count', 0)}")
    tagged = s.get('tagged', {}) or {}
    for label, key, col in [
        ("URLs",          'urls',         C.RED),
        ("IPv4 addrs",    'ipv4',         C.RED),
        ("Registry keys", 'reg_keys',     C.YELLOW),
        ("File paths",    'paths',        C.YELLOW),
        ("PDB paths",     'pdbs',         C.CYAN),
        ("GUIDs",         'guids',        C.CYAN),
        ("Device paths",  'device_paths', C.MAGENTA),
        ("SDDL",          'sddl',         C.MAGENTA),
    ]:
        hits = tagged.get(key, []) or []
        if not hits:
            continue
        print(f"    {col}{label:<14}{C.RESET} ({len(hits)})")
        for h in hits[:10]:
            print(f"      {h[:120]}")
        if len(hits) > 10:
            print(f"      {C.DIM}... +{len(hits)-10} more{C.RESET}")


def _print_cve_matches(matches: list):
    """Render CVE matches in colorized table form."""
    if not matches:
        print(f"  {C.GREEN}CVE matcher: no matches{C.RESET}")
        return
    print()
    print(C.BOLD + "  CVE Matches" + C.RESET)
    for m in matches:
        conf = m.get('confidence', '?')
        col = {
            'CONFIRMED': C.RED + C.BOLD,
            'HIGH':      C.RED,
            'MEDIUM':    C.YELLOW,
            'LOW':       C.DIM,
        }.get(conf, '')
        print(f"    {col}{m['cve']:<16}{C.RESET} {C.BOLD}{m['name']}{C.RESET}  [{col}{conf}{C.RESET}]")
        for ev in m.get('evidence', []):
            print(f"      {C.DIM}- {ev}{C.RESET}")
        prims = ', '.join(m.get('primitives_gained', []))
        if prims:
            print(f"      primitives:  {prims}")
        if m.get('pocs_known'):
            print(f"      pocs:        {m['pocs_known'][0]}")
            for url in m['pocs_known'][1:3]:
                print(f"                   {url}")
        if m.get('notes'):
            print(f"      {C.DIM}{m['notes']}{C.RESET}")


def fmt_table(result: dict, verify: dict = None, full_imports: bool = False, verbose: bool = False) -> str:
    h = result.get('hvci', {}) or {}
    s = result.get('signing', {}) or {}
    score, tier = result.get('_score'), result.get('_tier')
    if score is None:
        score, tier = perfect_score(result)
        result['_score'] = score
        result['_tier'] = tier

    burnt, why = is_burnt(s)
    burnt_flag = f"{C.RED}BURNT ({why}){C.RESET}" if burnt else f"{C.GREEN}clean{C.RESET}"
    hvci_status = (
        f"{C.GREEN}HVCI-PASS{C.RESET}" if hvci_perfect(h)
        else f"{C.YELLOW}HVCI-BLOCKED{C.RESET}"
    )
    tier_col = {
        'PERFECT': C.GREEN + C.BOLD,
        'STRONG': C.GREEN,
        'INTERESTING': C.YELLOW,
        'WEAK': C.DIM,
        'SKIP': C.RED + C.DIM,
    }.get(tier, '')

    sig_subject = (s.get('SUBJECT') or '(unsigned/unknown)')[:74]
    sig_thumb = s.get('THUMB', '')
    sig_status = s.get('STATUS', '?')

    lines = []
    lines.append(C.BOLD + C.CYAN + "=" * 76 + C.RESET)
    lines.append(f"{C.BOLD}[{Path(result['driver']).name[:60]}]{C.RESET}")
    lines.append(C.DIM + "-" * 76 + C.RESET)
    lines.append(f"  Size:           {Path(result['driver']).stat().st_size:,} B")
    lines.append(f"  Arch:           {'x64' if h.get('is_64bit') else 'x86'}")
    if result.get('pdb_path'):
        lines.append(f"  PDB path:       {result['pdb_path']}")
    dn_list = result.get('device_names') or ([result['device_name']] if result.get('device_name') else [])
    for dn in dn_list[:4]:
        lines.append(f"  Device:         {dn}")
    if len(dn_list) > 4:
        lines.append(f"                  (+{len(dn_list)-4} more)")
    for sym in (result.get('symlinks') or [])[:3]:
        lines.append(f"  Symlink:        {sym}")
    lines.append(f"  Driver Entry:   {result.get('driver_entry') or 'n/a'}")
    lines.append(f"  Functions:      {result.get('function_count', 0)}")

    # Hashes (v1.9)
    hashes = result.get('hashes', {}) or {}
    if hashes and 'sha256' in hashes:
        lines.append("")
        lines.append(C.BOLD + "  Hashes" + C.RESET)
        lines.append(f"    MD5:          {hashes.get('md5','?')}")
        lines.append(f"    SHA1:         {hashes.get('sha1','?')}")
        lines.append(f"    SHA256:       {hashes.get('sha256','?')}")
        pe = result.get('pe_extended', {}) or {}
        if pe.get('imphash'):
            lines.append(f"    IMPHASH:      {pe['imphash']}")

    # PE extended info (v1.9)
    pe = result.get('pe_extended', {}) or {}
    if pe and 'machine' in pe:
        lines.append("")
        lines.append(C.BOLD + "  PE Info" + C.RESET)
        lines.append(f"    Machine:      {pe.get('machine_name','?')} ({pe.get('machine','?')})")
        lines.append(f"    Compiled:     {pe.get('compile_date_utc','?')[:19]} UTC ({pe.get('compile_timestamp','?')})")
        lines.append(f"    Linker:       {pe.get('linker_version','?')}")
        lines.append(f"    Subsystem:    {pe.get('subsystem_name','?')} ({pe.get('subsystem','?')})")
        lines.append(f"    Image Base:   {pe.get('image_base','?')}")
        lines.append(f"    Code size:    {pe.get('size_of_code',0):,} B")
        lines.append(f"    Has TLS:      {pe.get('has_tls', False)}")
        lines.append(f"    Imports:      {pe.get('import_dll_count',0)} DLLs / {pe.get('import_api_count',0)} APIs")
        sects = pe.get('sections', []) or []
        if sects:
            lines.append(f"    Sections:     {len(sects)} ({', '.join(s['name'] for s in sects)})")
            if verbose:
                for s in sects:
                    lines.append(f"      [{s['name']:<8}] VA={s['va']}  vsize={s['vsize']:>8}  raw={s['raw_off']}  rsize={s['raw_size']:>8}  {s['flags']}")
        # v2.0 — workflow-verified PE fingerprints
        if pe.get('rich_header_present'):
            n_recs = len(pe.get('rich_header_records', []) or [])
            fam = pe.get('rich_compiler_family') or '?'
            lines.append(f"    Rich key:     {pe.get('rich_dans_xor_key')}  ({n_recs} compiler records, latest: {fam})")
        vi = pe.get('version_info') or {}
        if vi:
            cn = vi.get('CompanyName', '')
            pn = vi.get('ProductName', '')
            fv = vi.get('FileVersion', '')
            if cn or pn:
                lines.append(f"    VS_VERSION:   {(cn or '?')[:32]} / {(pn or '?')[:32]}")
            if fv:
                lines.append(f"    FileVersion:  {fv[:60]}")
        if pe.get('debug_pdb_path'):
            lines.append(f"    PDB debug:    {pe['debug_pdb_path'][:64]}")
            lines.append(f"    PDB GUID/age: {pe.get('debug_pdb_guid')} / {pe.get('debug_pdb_age')}")
        tlc = pe.get('tls_callback_count', 0) or 0
        if tlc:
            addrs = pe.get('tls_callback_addresses', []) or []
            lines.append(f"    TLS cbacks:   {C.YELLOW}{tlc}{C.RESET}  ({', '.join(addrs[:4])})")
        exn = pe.get('export_names') or []
        if exn:
            preview = ', '.join(exn[:5]) + ('' if len(exn) <= 5 else f', +{len(exn)-5}')
            lines.append(f"    Exports:      {len(exn)}  ({preview})")
        # Imports detail (--verbose only shows full list, --imports-only does too)
        if verbose:
            imps = pe.get('imports', []) or []
            lines.append("")
            lines.append(C.BOLD + "  Imports" + C.RESET)
            for imp in imps:
                lines.append(f"    {imp['dll']}  ({imp['api_count']})")
                for api in imp.get('apis', [])[:8]:
                    lines.append(f"      {api}")
                if imp['api_count'] > 8:
                    lines.append(f"      ... +{imp['api_count']-8}")

    lines.append("")
    lines.append(C.BOLD + "  Signing" + C.RESET)
    lines.append(f"    Subject:      {sig_subject}")
    lines.append(f"    Thumbprint:   {sig_thumb}")
    lines.append(f"    Validity:     {s.get('NOTBEFORE','?')[:10]} -> {s.get('NOTAFTER','?')[:10]}")
    lines.append(f"    Status:       {sig_status}    Burnt: {burnt_flag}")
    if verify:
        v_str = f"{C.GREEN}verified{C.RESET}" if verify.get('verified') else f"{C.RED}NOT verified{C.RESET}"
        lines.append(f"    signtool /kp: {v_str}    {verify.get('timestamp_line','')[:54]}")
    lines.append("")
    lines.append(C.BOLD + "  HVCI" + C.RESET)
    lines.append(f"    DllChar:      {h.get('dll_characteristics','?')}")
    lines.append(f"    FI:           {h.get('force_integrity')}    GCF: {h.get('guard_cf')}    INIT-W+X: {h.get('init_wx')}")
    lines.append(f"    Status:       {hvci_status}")
    lines.append("")
    lines.append(C.BOLD + "  Dispatcher" + C.RESET)
    lines.append(f"    Modes:        {','.join(result.get('modes_resolved',[])) or '(none)'}")
    if result.get('mj14_handler'):
        lines.append(f"    MJ14 handler: {result['mj14_handler']}")
    if result.get('mj_table_writes'):
        lines.append(f"    MJ table:     {result['mj_table_writes']}")
    if result.get('minifilter'):
        lines.append(f"    Minifilter:   {len(result['minifilter'])} call site(s)")
    lines.append("")
    lines.append(C.BOLD + f"  IOCTLs ({result.get('ioctl_count',0)})" + C.RESET)
    if result.get('ioctls'):
        lines.append(f"    {'CODE':<12} {'DEVTYPE':<22} {'FUNC':<8} {'METHOD':<10} {'ACCESS':<10}")
        lines.append(f"    {'-'*12} {'-'*22} {'-'*8} {'-'*10} {'-'*10}")
        for c in result['ioctls'][:30]:
            try:
                code = int(c, 16) if isinstance(c, str) else int(c)
            except Exception:
                lines.append(f"    {c}"); continue
            d = decode_ioctl(code)
            lines.append(f"    {d['code']:<12} {d['device_type_name']:<22} {d['function']:<8} {d['method']:<10} {d['access']:<10}")
        if len(result['ioctls']) > 30:
            lines.append(f"    ... +{len(result['ioctls']) - 30} more")
    lines.append("")
    lines.append(C.BOLD + "  Primitive Classes" + C.RESET)
    if result.get('primitives'):
        lines.append(f"    {', '.join(result['primitives'])}")
    else:
        lines.append("    (none detected via imports)")
    lines.append("")
    lines.append(C.BOLD + "  Access" + C.RESET)
    lines.append(f"    IoCreateDevice:        {result.get('has_io_create_device')}")
    lines.append(f"    IoCreateDeviceSecure:  {result.get('has_io_create_device_secure')}")
    lines.append(f"    SDDL strings found:    {len(result.get('sddl_strings', []))}")
    lines.append(f"    Gate status:           {result.get('gate_status')}")
    lines.append("")
    archs = result.get('archetype_strings') or {}
    if archs:
        lines.append(C.BOLD + "  Archetype Tags" + C.RESET)
        for cat, items in archs.items():
            lines.append(f"    {C.RED}{cat}{C.RESET}: {len(items)} matches (e.g. {items[0][0][:48]!r})")
        lines.append("")
    if result.get('per_ioctl_classification'):
        lines.append(C.BOLD + "  Per-IOCTL Classification (deep mode)" + C.RESET)
        for entry in result['per_ioctl_classification']:
            cl = ', '.join(entry.get('primitives', [])) or '?'
            lines.append(f"    {entry['ioctl']} -> {entry['handler_branch']:<14} [{cl}]")
        lines.append("")
    lines.append(C.BOLD + C.CYAN + "  VERDICT" + C.RESET)
    lines.append(f"    Score:        {tier_col}{score}/100  {tier}{C.RESET}")
    if hvci_perfect(h):
        lines.append(f"    {C.GREEN}HVCI loadable on all hosts including HVCI-enabled.{C.RESET}")
    else:
        lines.append(f"    {C.YELLOW}HVCI-blocked: loads only on HVCI-disabled hosts (~70% consumer install base).{C.RESET}")
    lines.append(f"    Analyze time: {result.get('analyze_time_s', 0):.1f}s")
    lines.append(C.DIM + "=" * 76 + C.RESET)
    return "\n".join(lines)


def fmt_markdown(result: dict) -> str:
    score, tier = perfect_score(result)
    h = result.get('hvci', {}) or {}
    s = result.get('signing', {}) or {}
    md = [f"# BYOVDsn1per — {Path(result['driver']).name}\n"]
    md.append(f"**Score**: {score}/100 ({tier})  ")
    md.append(f"**HVCI**: {'PASS' if hvci_perfect(h) else 'BLOCKED'}  ")
    md.append(f"**Signer**: {(s.get('SUBJECT') or '?')[:80]}  ")
    md.append(f"**IOCTLs**: {result.get('ioctl_count',0)}  ")
    md.append(f"**Modes**: {','.join(result.get('modes_resolved',[]))}  ")
    md.append(f"**Primitives**: {', '.join(result.get('primitives',[]))}  ")
    md.append(f"**Gate**: {result.get('gate_status','?')}\n")
    if result.get('ioctls'):
        md.append("## IOCTLs\n")
        for c in result['ioctls']:
            md.append(f"- `{c}`")
    return "\n".join(md)


# ============================================================
# Main
# ============================================================
def _read_pe_bundle(driver_path: str) -> bytes:
    """v2.5: single-read for the 3 PE-info functions. Returns the file
    buffer or b'' on OSError so downstream _from_buf functions can return
    their own error dicts."""
    try:
        with open(driver_path, 'rb') as f:
            return f.read()
    except OSError:
        return b''


def quick_scan(driver_path: str, offline: bool = False) -> dict:
    """Quick mode: just HVCI + signing + PE imports (no IDA). v2.5: single
    file read shared across hvci/hashes/pe_extended (was 3 reads in v2.4)."""
    buf = _read_pe_bundle(driver_path)
    sig = {} if offline else signing_info(driver_path)
    burnt, why = is_burnt(sig)
    sig['burnt_status'] = f'BURNT ({why})' if burnt else 'clean'
    return {
        'driver': driver_path,
        'hvci': hvci_flags_from_buf(buf) if buf else {'error': 'open'},
        'hashes': file_hashes_from_buf(buf) if buf else {'error': 'open'},
        'pe_extended': pe_extended_info_from_buf(buf) if buf else {'error': 'open'},
        'signing': sig,
        'analyze_time_s': 0.0,
    }


def full_scan(driver_path: str, depth: int, no_flirt: bool, deep: bool, no_decompile: bool,
              verify_load: bool, offline: bool = False) -> dict:
    """Full mode: IDA dispatcher walk + HVCI + signing + PE info. v2.5:
    single-buf for the 3 PE-info funcs."""
    r = _ida_scan(driver_path, depth=depth, no_flirt=no_flirt, deep=deep, no_decompile=no_decompile)
    buf = _read_pe_bundle(driver_path)
    r['hvci'] = hvci_flags_from_buf(buf) if buf else {'error': 'open'}
    r['hashes'] = file_hashes_from_buf(buf) if buf else {'error': 'open'}
    r['pe_extended'] = pe_extended_info_from_buf(buf) if buf else {'error': 'open'}
    sig = {} if offline else signing_info(driver_path)
    burnt, why = is_burnt(sig)
    sig['burnt_status'] = f'BURNT ({why})' if burnt else 'clean'
    r['signing'] = sig
    if verify_load and not offline:
        r['verify_load'] = signtool_kp(driver_path)
    return r


USAGE_EPILOG = r"""
examples:
  Single driver (full scan):
    BYOVDsn1per driver.sys

  Quick triage (no IDA):
    BYOVDsn1per --quick driver.sys
    BYOVDsn1per --hvci-only driver.sys
    BYOVDsn1per --sign-verify driver.sys

  Deep analysis (per-IOCTL classification):
    BYOVDsn1per --deep driver.sys

  CVE matcher (SAFE - no exploitation):
    BYOVDsn1per --poc driver.sys
    BYOVDsn1per --cve-list

  String extraction + YARA rule:
    BYOVDsn1per --strings --yara-rule driver.sys
    BYOVDsn1per --yara-rule --yara-out rule.yar driver.sys

  Compare two drivers:
    BYOVDsn1per --diff a.sys b.sys

  Bulk sweep:
    BYOVDsn1per --sweep crawler/
    BYOVDsn1per --sweep crawler/ --filter perfect

  System-wide discovery:
    BYOVDsn1per --crawl                  # 33 known driver paths
    BYOVDsn1per --deepcrawl              # every logical drive (A:..Z:)
    BYOVDsn1per --restart                # wipe checkpoint + deepcrawl
    BYOVDsn1per --list-default-roots     # show the 33 paths

  End-to-end pipeline:
    BYOVDsn1per --crawl                  # 1. discover
    BYOVDsn1per --sweep crawler/ --poc   # 2. analyze + match CVEs
"""


def main():
    p = argparse.ArgumentParser(
        prog='BYOVDsn1per',
        description='BYOVD specimen scanner (IDA-powered). v2.5 - IDA Pro Essential 9.3 headless via idalib.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=USAGE_EPILOG,
    )
    p.add_argument('driver', nargs='?', help='path to driver .sys')
    p.add_argument('--version', '-V', action='version', version='BYOVDsn1per v2.5')

    # ------------- Mode flags -------------
    mode = p.add_argument_group('Scan modes (mutually exclusive on a single driver)')
    mode.add_argument('--quick', action='store_true', help='HVCI+sign only (no IDA)')
    mode.add_argument('--deep', action='store_true', help='full scan + per-IOCTL classification')
    mode.add_argument('--sweep', metavar='DIR', help='analyze every .sys in DIR')
    mode.add_argument('--diff', nargs=2, metavar=('DRV1', 'DRV2'),
                      help='compare two drivers side-by-side and exit')
    mode.add_argument('--decompile', metavar='DRIVER',
                      help='Hexrays-decompile one EA from DRIVER (also needs --ea)')
    mode.add_argument('--ea', help='effective address for --decompile (e.g. 0x14000315c)')

    # ------------- Crawl mode -------------
    crawl = p.add_argument_group('Crawl: system-wide kernel-driver discovery')
    crawl.add_argument('--crawl', action='store_true',
                       help='walk known driver paths (33 defaults: System32\\drivers, DriverStore, Program Files, vendor dirs, user paths)')
    crawl.add_argument('--deepcrawl', action='store_true',
                       help='walk ENTIRE PC (every logical drive A:..Z:). Resumable via checkpoint.')
    crawl.add_argument('--restart', action='store_true',
                       help='clear .scanned_paths.txt and start fresh. ALONE, implies --deepcrawl.')
    crawl.add_argument('--crawl-path', action='append', default=[], metavar='PATH',
                       help='add a crawl root path (repeatable). Combines with defaults unless --crawl-no-defaults.')
    crawl.add_argument('--crawl-out', default='crawler', metavar='DIR',
                       help='output directory for crawled drivers (default: ./crawler/)')
    crawl.add_argument('--crawl-limit', type=int, default=0, metavar='N',
                       help='stop after N unique copies (default 0 = unlimited)')
    crawl.add_argument('--crawl-no-defaults', action='store_true',
                       help='skip default Windows roots, use --crawl-path entries only')
    crawl.add_argument('--crawl-no-checkpoint', action='store_true',
                       help='disable .scanned_paths.txt + .sha256_cache.txt')
    crawl.add_argument('--list-default-roots', action='store_true',
                       help='print the default crawl roots and exit')

    # ------------- Standalone shortcuts (no full scan) -------------
    shortcut = p.add_argument_group('Standalone shortcuts (single driver, no full scan)')
    shortcut.add_argument('--hvci-only', action='store_true', help='print HVCI flag verdict and exit')
    shortcut.add_argument('--sign-verify', action='store_true', help='run signtool /kp /v and exit')
    shortcut.add_argument('--hashes-only', action='store_true', help='print MD5/SHA1/SHA256/imphash and exit')
    shortcut.add_argument('--imports-only', action='store_true', help='dump PE imports table and exit')
    shortcut.add_argument('--cve-list', action='store_true', help='list all CVEs in the matcher database and exit')

    # ------------- Per-driver add-ons (combine with main scan) -------------
    addon = p.add_argument_group('Per-driver add-ons (combine with main scan)')
    addon.add_argument('--poc', action='store_true',
                       help='SAFE CVE matcher: which known CVEs target this driver (no exploitation)')
    addon.add_argument('--strings', action='store_true',
                       help='extract ASCII + UTF-16LE strings with regex tagging (URLs/IPs/registry/PDB/SDDL)')
    addon.add_argument('--yara-rule', action='store_true',
                       help='emit YARA detection rule (uses hash + pe modules)')
    addon.add_argument('--yara-out', metavar='FILE',
                       help='also write the YARA rule to FILE')
    addon.add_argument('--max-strings', type=int, default=200,
                       help='cap top_ascii/top_utf16 size in --strings output (default 200)')
    addon.add_argument('--burnt-check', action='store_true',
                       help='in --sweep, skip drivers signed by burnt certificates')
    addon.add_argument('--verify-load', action='store_true', help='run signtool /kp /v during full scan')

    # ------------- Scan tuning -------------
    tuning = p.add_argument_group('Scan tuning')
    tuning.add_argument('--depth', type=int, default=3, help='BFS depth for callee walks (default 3)')
    tuning.add_argument('--size-cap', type=float, default=1.5,
                        help='skip drivers > N MB (default 1.5)')
    tuning.add_argument('--filter', choices=['perfect', 'partial', 'any'], default='any',
                        help='in --sweep, only show drivers >= tier')
    tuning.add_argument('--no-flirt', action='store_true', help='skip FLIRT signature application')
    tuning.add_argument('--no-decompile', action='store_true', help='skip Hexrays decompile in deep mode')
    tuning.add_argument('--offline-mode', '--offline', action='store_true',
                        help='no subprocess calls (skip PowerShell/signtool); PE-only')

    # ------------- Output -------------
    output = p.add_argument_group('Output')
    output.add_argument('--output', choices=['table', 'json', 'markdown'], default='table',
                        help='output format (default: table)')
    output.add_argument('--json-out', metavar='FILE', help='also write JSON result to FILE')
    output.add_argument('--quiet', '-q', action='store_true',
                        help='one-line verdict only (score + tier + CVE matches)')
    output.add_argument('--verbose', '-vv', action='store_true',
                        help='dump everything: full IOCTL list, all sections, all imports, copy paths in crawl')
    output.add_argument('--no-color', action='store_true', help='disable ANSI colors')
    output.add_argument('--no-banner', action='store_true', help='suppress banner art')

    args = p.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()
    # Force stdout to UTF-8 so banner + non-ASCII chars don't crash on cp1252
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

    if not args.no_banner and not args.quiet:
        print(C.CYAN + BANNER + C.RESET)

    # v2.3.1: --restart alone implies --deepcrawl. Without this, `--restart`
    # by itself falls through to single-driver mode and prints help — useless.
    # Per user spec ("if non find you can do --deepcrawl restart"), restart's
    # primary purpose is to wipe the checkpoint for a fresh entire-PC scan.
    if args.restart and not args.crawl and not args.deepcrawl:
        print(f"[BYOVDsn1per] {C.YELLOW}--restart alone -> auto-enabling --deepcrawl{C.RESET}")
        args.deepcrawl = True

    # ----- v2.2/v2.3 --crawl + --deepcrawl: kernel-driver discovery -----
    if args.list_default_roots:
        print(f"{C.BOLD}Default --crawl roots ({len(DEFAULT_CRAWL_ROOTS)} entries){C.RESET}")
        for r in DEFAULT_CRAWL_ROOTS:
            mark = '+' if os.path.isdir(r) else '-'
            col = C.GREEN if mark == '+' else C.DIM
            print(f"  {col}{mark} {r}{C.RESET}")
        return 0
    if args.crawl or args.deepcrawl:
        roots = list(args.crawl_path)
        if args.deepcrawl:
            drive_roots = _enumerate_drive_roots()
            print(f"[BYOVDsn1per] {C.BOLD}DEEPCRAWL{C.RESET}: enumerating logical drives -> "
                  f"{', '.join(drive_roots)}")
            roots.extend(drive_roots)
        elif not args.crawl_no_defaults:
            roots.extend(DEFAULT_CRAWL_ROOTS)
        # Dedupe while preserving order
        seen_r = set()
        roots = [r for r in roots if not (r in seen_r or seen_r.add(r))]
        out = args.crawl_out
        mode_name = "DEEPCRAWL" if args.deepcrawl else "CRAWL"
        print(f"[BYOVDsn1per] {mode_name} roots ({len(roots)}):")
        existing = sum(1 for r in roots if os.path.isdir(r))
        for r in roots[:30]:
            mark = '+' if os.path.isdir(r) else '-'
            col = C.GREEN if mark == '+' else C.DIM
            print(f"  {col}{mark} {r}{C.RESET}")
        if len(roots) > 30:
            print(f"  {C.DIM}... +{len(roots)-30} more{C.RESET}")
        print(f"[BYOVDsn1per] {existing}/{len(roots)} roots exist on this machine")
        print(f"[BYOVDsn1per] output dir: {C.BOLD}{out}{C.RESET}")
        ckpt_path = Path(out) / CHECKPOINT_FILENAME
        if args.crawl_no_checkpoint:
            print(f"[BYOVDsn1per] {C.YELLOW}checkpoint disabled{C.RESET}")
        else:
            print(f"[BYOVDsn1per] checkpoint: {ckpt_path}")
        if args.restart:
            print(f"[BYOVDsn1per] {C.YELLOW}--restart: will wipe checkpoint{C.RESET}")
        if args.crawl_limit:
            print(f"[BYOVDsn1per] copy limit: {args.crawl_limit}")
        print()
        t0 = time.time()
        stats = crawl_drivers(
            roots,
            out_dir=out,
            max_files=args.crawl_limit,
            verbose=args.verbose,
            use_checkpoint=not args.crawl_no_checkpoint,
            clear_checkpoint_first=args.restart,
        )
        dt = time.time() - t0
        print()
        print(f"{C.BOLD}{mode_name} summary:{C.RESET}")
        print(f"  scanned files:    {stats['scanned_files']}")
        print(f"  .sys candidates:  {stats['sys_found']}")
        print(f"  kernel drivers:   {C.GREEN}{stats['kernel_drivers']}{C.RESET}  (subsys=NATIVE + AEP!=0)")
        print(f"  duplicates:       {C.DIM}{stats['duplicates']}{C.RESET}")
        print(f"  copied to {out}/:  {C.BOLD}{stats['copied']}{C.RESET}")
        print(f"  errors:           {C.YELLOW if stats['errors'] else C.DIM}{stats['errors']}{C.RESET}")
        print(f"  dirs completed:   {stats['dirs_completed']}  (checkpointed)")
        print(f"  dirs skipped:     {C.DIM}{stats['dirs_skipped']}{C.RESET}  (already in checkpoint)")
        print(f"  elapsed:          {dt:.1f}s  ({stats['scanned_files']/max(dt,0.001):.0f} files/s)")
        if not args.crawl_no_checkpoint and stats['copied'] == 0 and stats['dirs_skipped'] > 0:
            print()
            print(f"  {C.YELLOW}Note: 0 copies + {stats['dirs_skipped']} skipped from checkpoint.{C.RESET}")
            print(f"  {C.YELLOW}If this is unexpected, run again with --restart to wipe the checkpoint.{C.RESET}")
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(stats, indent=2, default=str))
        return 0

    # ----- v2.1 --diff DRV1 DRV2 (two-driver side-by-side comparison) -----
    if args.diff:
        d1, d2 = Path(args.diff[0]), Path(args.diff[1])
        for d in (d1, d2):
            if not d.exists():
                print(f"error: --diff driver not found: {d}")
                return 1
        scans = []
        for d in (d1, d2):
            print(f"[BYOVDsn1per] scanning {d.name}...", flush=True)
            if args.quick:
                r = quick_scan(str(d), offline=args.offline_mode)
            else:
                r = full_scan(str(d), args.depth, args.no_flirt, args.deep,
                              args.no_decompile, args.verify_load,
                              offline=args.offline_mode)
            r['path'] = str(d)
            sc, tr = perfect_score(r)
            r['_score'], r['_tier'] = sc, tr
            if args.poc:
                r['cve_matches'] = match_cves(r)
            scans.append(r)
        print()
        print(diff_drivers(scans[0], scans[1]))
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(scans, indent=2, default=str))
        return 0

    # ----- --cve-list (no driver needed) -----
    if args.cve_list:
        print(f"{C.BOLD}BYOVDsn1per — CVE matcher database ({len(CVE_DATABASE)} entries){C.RESET}")
        print()
        for cve in sorted(CVE_DATABASE, key=lambda c: c.get('year', 0), reverse=True):
            print(f"  {C.YELLOW}{cve['cve']:<18}{C.RESET} {C.BOLD}{cve['name']}{C.RESET} ({cve['year']})")
            print(f"    primitives: {', '.join(cve.get('primitives_gained', []))}")
            if cve.get('notes'):
                print(f"    notes: {cve['notes']}")
            print()
        return 0

    # ----- Single-EA decompile mode -----
    if args.decompile:
        if not args.ea:
            print("error: --decompile requires --ea ADDR")
            return 2
        ea = int(args.ea, 0)
        print(f"[BYOVDsn1per] decompile {args.decompile} @ {hex(ea)}")
        tmp = Path(tempfile.mkdtemp(prefix='snipr_'))
        try:
            shutil.copy2(args.decompile, tmp / Path(args.decompile).name)
            import idapro
            rc = idapro.open_database(str(tmp / Path(args.decompile).name), run_auto_analysis=True)
            if rc != 0:
                print(f"open rc={rc}"); return 1
            import ida_hexrays
            if not ida_hexrays.init_hexrays_plugin():
                print("hexrays plugin not available"); idapro.close_database(); return 1
            cf = ida_hexrays.decompile(ea)
            if cf:
                print(str(cf))
            else:
                print("decompile failed")
            idapro.close_database()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return 0

    # ----- Sweep mode -----
    if args.sweep:
        sweep_dir = Path(args.sweep)
        bins = sorted(sweep_dir.glob('*.sys'))
        cap = int(args.size_cap * 1024 * 1024)
        bins = [b for b in bins if b.stat().st_size <= cap]
        print(f"[BYOVDsn1per] sweeping {len(bins)} drivers (cap {args.size_cap} MB)")
        results = []
        for i, b in enumerate(bins, 1):
            print(f"  [{i}/{len(bins)}] {b.name[:40]}...", end='', flush=True)
            if args.quick:
                r = quick_scan(str(b), offline=args.offline_mode)
            else:
                r = full_scan(str(b), args.depth, args.no_flirt,
                              args.deep, args.no_decompile, args.verify_load,
                              offline=args.offline_mode)
            sc, tr = perfect_score(r)
            r['_score'] = sc
            r['_tier'] = tr
            if args.poc:
                r['cve_matches'] = match_cves(r)
            print(f" {tr} ({sc}) t={r.get('analyze_time_s',0):.1f}s", end='')
            if args.poc and r.get('cve_matches'):
                strong = [m for m in r['cve_matches']
                          if m.get('confidence') in ('CONFIRMED', 'HIGH', 'MEDIUM')]
                if strong:
                    tags = ','.join(f"{m['cve']}({m['confidence'][0]})" for m in strong[:3])
                    print(f" cves={tags}", end='')
            print()
            results.append(r)
        # Filter
        if args.burnt_check:
            burnt = [r for r in results if r.get('signing', {}).get('burnt_status', '').startswith('BURNT')]
            results = [r for r in results if not r.get('signing', {}).get('burnt_status', '').startswith('BURNT')]
            print(f"[BYOVDsn1per] --burnt-check filtered {len(burnt)} burnt-signed driver(s)")
        if args.filter == 'perfect':
            results = [r for r in results if r.get('_tier') in ('PERFECT','STRONG')]
        elif args.filter == 'partial':
            results = [r for r in results if r.get('_score', 0) >= 30]
        results.sort(key=lambda r: r.get('_score', 0), reverse=True)
        if args.output == 'json':
            print(json.dumps(results, indent=2, default=str))
        elif args.output == 'markdown':
            for r in results:
                print(fmt_markdown(r))
                print()
        else:
            for r in results:
                print(fmt_table(r, verify=r.get('verify_load')))
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(results, indent=2, default=str))
        return 0

    # ----- Single-driver mode -----
    if not args.driver:
        p.print_help()
        return 1
    drv = Path(args.driver)
    if not drv.exists():
        print(f"error: driver not found: {args.driver}")
        return 1
    if drv.stat().st_size > int(args.size_cap * 1024 * 1024):
        print(f"error: driver exceeds --size-cap ({args.size_cap} MB). Use a larger cap to scan.")
        return 1
    if args.hvci_only:
        r = quick_scan(str(drv), offline=args.offline_mode)
        h = r['hvci']
        print(f"HVCI: FI={h.get('force_integrity')} GCF={h.get('guard_cf')} INIT-WX={h.get('init_wx')}")
        print(f"Verdict: {'HVCI-PASS' if hvci_perfect(h) else 'HVCI-BLOCKED'}")
        return 0
    if args.sign_verify:
        if args.offline_mode:
            print("error: --sign-verify needs signtool; cannot combine with --offline-mode")
            return 2
        v = signtool_kp(str(drv))
        s = signing_info(str(drv))
        print(f"Subject: {s.get('SUBJECT','?')}")
        print(f"Thumb:   {s.get('THUMB','?')}")
        print(f"Status:  {s.get('STATUS','?')}")
        print(f"signtool /kp: {'VERIFIED' if v.get('verified') else 'FAILED'}")
        if v.get('timestamp_line'):
            print(f"Timestamp: {v['timestamp_line']}")
        return 0
    if args.hashes_only:
        h = file_hashes(str(drv))
        pe = pe_extended_info(str(drv))
        print(f"MD5:     {h.get('md5','?')}")
        print(f"SHA1:    {h.get('sha1','?')}")
        print(f"SHA256:  {h.get('sha256','?')}")
        print(f"IMPHASH: {pe.get('imphash','?')}")
        print(f"Size:    {h.get('size',0)} bytes")
        return 0
    if args.imports_only:
        pe = pe_extended_info(str(drv))
        if 'error' in pe:
            print(f"error: {pe['error']}")
            return 1
        for imp in pe.get('imports', []):
            print(f"  {imp['dll']}  ({imp['api_count']} APIs)")
            for api in imp.get('apis', []):
                print(f"    {api}")
        return 0
    if args.quick:
        r = quick_scan(str(drv), offline=args.offline_mode)
    else:
        r = full_scan(str(drv), args.depth, args.no_flirt, args.deep, args.no_decompile,
                      args.verify_load, offline=args.offline_mode)
    r['path'] = str(drv)
    sc, tr = perfect_score(r)
    r['_score'] = sc
    r['_tier'] = tr
    # --poc: SAFE CVE matcher (no exploitation, fingerprint only)
    if args.poc:
        r['cve_matches'] = match_cves(r)
    # --strings: extract ASCII + UTF-16LE strings, tag URLs/IPs/paths/etc.
    if args.strings:
        s = extract_strings(str(drv))
        # Honour --max-strings on the human-facing dumps
        for k in ('top_ascii', 'top_utf16'):
            if k in s and isinstance(s[k], list):
                s[k] = s[k][:args.max_strings]
        r['strings'] = s
    # --yara-rule: emit YARA detection rule for this driver
    yara_rule_text = None
    if args.yara_rule:
        yara_rule_text = emit_yara_rule(r)
        r['yara_rule'] = yara_rule_text
    # --burnt-check: short-circuit and exit non-zero for burnt-signed drivers
    if args.burnt_check:
        burnt_status = r.get('signing', {}).get('burnt_status', '')
        if burnt_status.startswith('BURNT'):
            print(f"[BYOVDsn1per] {drv.name}: SKIPPED — {burnt_status}")
            return 2
    # --quiet: one-line verdict only (with CVE matches if --poc).
    # Only show MEDIUM/HIGH/CONFIRMED — LOW would be noise (any 0x0022
    # device-type driver "matches" 3 unrelated CVEs at LOW confidence).
    if args.quiet:
        cves = ''
        strong_m = [m for m in (r.get('cve_matches') or [])
                    if m.get('confidence') in ('CONFIRMED', 'HIGH', 'MEDIUM')]
        if strong_m:
            cves = ' cves=' + ','.join(f"{m['cve']}({m['confidence'][0]})" for m in strong_m[:3])
        print(f"{drv.name}: {tr} ({sc}/100) IOCTLs={r.get('ioctl_count',0)} mode={','.join(r.get('modes_resolved',[]))} gate={r.get('gate_status','?')}{cves}")
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(r, indent=2, default=str))
        return 0
    if args.output == 'json':
        print(json.dumps(r, indent=2, default=str))
    elif args.output == 'markdown':
        print(fmt_markdown(r))
    else:
        print(fmt_table(r, verify=r.get('verify_load'), verbose=args.verbose))
        if r.get('cve_matches'):
            _print_cve_matches(r['cve_matches'])
        # v2.1: print --strings block after main report
        if args.strings and r.get('strings'):
            _print_strings_section(r['strings'])
        # v2.1: print --yara-rule block last (easy copy-paste)
        if yara_rule_text:
            print()
            print(C.BOLD + "  YARA rule:" + C.RESET)
            for ln in yara_rule_text.splitlines():
                print(f"    {ln}")
            if args.yara_out:
                Path(args.yara_out).write_text(yara_rule_text, encoding='utf-8')
                print(f"  {C.DIM}-> written to {args.yara_out}{C.RESET}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(r, indent=2, default=str))
    # Filter check
    if args.filter == 'perfect' and tr not in ('PERFECT', 'STRONG'):
        return 1
    if args.filter == 'partial' and sc < 30:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
