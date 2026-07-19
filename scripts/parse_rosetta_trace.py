#!/usr/bin/env python3
"""
Parser for Rosetta runtime hardware trace files.

Trace files are produced by setting:
  ROSETTA_HARDWARE_TRACING_PATH=/path/to/trace
  (optionally) ROSETTA_SCRIBBLE_TRANSLATIONS=1

The runtime creates: /path/to/trace.<pid>

Wire format:
  Each record = 48-byte fixed header + variable payload + 0-7 NUL padding bytes.
  Header = 6 little-endian uint64 fields:
    [0] event_type         (1-6)
    [1] mach_thread_port   (send right from mach_thread_self())
    [2..4]                 type-specific fields
    [5] payload_len        (byte count of the variable payload; 0 if none)
  Total per-record size is always 8-byte aligned.
  Written atomically via writev(fd, iov, 3) under a lock (dword_32ECC).

Event types:
  1 = AOT translation created (payload = image name string)
  2 = AOT fragment freed
  3 = JIT code emitted (payload = raw ARM64 machine code)
  4 = JIT fragment freed (requires ROSETTA_SCRIBBLE_TRANSLATIONS=1)
  5 = Runtime routines page mapped
  6 = Runtime binary mapped
"""

import struct
import sys
from dataclasses import dataclass
from typing import Optional


HEADER_SIZE = 48
HEADER_FMT = '<6Q'  # 6 little-endian uint64


# --- Base record ---

@dataclass
class TraceRecord:
    event_type: int
    mach_thread_port: int
    field_2: int
    field_3: int
    field_4: int
    payload: bytes


# --- Typed sub-records ---

@dataclass
class JitTranslationCreated:
    """Type 1: A new JIT code fragment was translated from x86_64 to ARM64."""
    event_type: int  # 1
    mach_thread_port: int      # Mach thread port (send right) via mach_thread_self()
    x86_source_addr: int       # x86_64 PC that was translated
    arm64_code_size: int       # bytes of ARM64 code generated (code_end - code_start)
    arm64_code_addr: int       # base address of the generated ARM64 translation
    source_image_name: str     # NUL-terminated dylib/image name containing the x86 code


@dataclass
class AotFragmentFreed:
    """Type 2: An AOT (ahead-of-time) shared-cache fragment was evicted."""
    event_type: int  # 2
    mach_thread_port: int      # Mach thread port (send right) via mach_thread_self()
    aot_header_addr: int       # pointer to the AOT shared cache entry header
    mapped_region_size: int    # size of the mapped code region that was freed


@dataclass
class JitCodeEmitted:
    """Type 3: JIT translation completed — dumps the generated ARM64 machine code.

    Emitted from TranslationCacheJit.cpp (sub_D048 at 0xEB30) after
    translator_apply_fixups copies the final code into the JIT heap.
    """
    event_type: int  # 3
    mach_thread_port: int      # Mach thread port (send right) via mach_thread_self()
    arm64_code_addr: int       # destination address in the JIT heap
    arm64_code_size: int       # size of generated ARM64 code (== payload_len)
    x86_source_addr: int       # x86_64 PC that was translated
    code_bytes: bytes          # raw ARM64 machine code


@dataclass
class JitFragmentFreed:
    """Type 4: A JIT fragment was freed (only emitted with ROSETTA_SCRIBBLE_TRANSLATIONS=1)."""
    event_type: int  # 4
    mach_thread_port: int      # Mach thread port (send right) via mach_thread_self()
    jit_code_addr: int         # base address of the freed JIT translation
    native_code_size: int      # size of the ARM64 code that was freed


@dataclass
class RuntimeRoutinesMapped:
    """Type 5: The runtime routines page (trampolines/stubs) was mapped."""
    event_type: int  # 5
    mach_thread_port: int      # Mach thread port (send right) via mach_thread_self()
    mapping_base_addr: int     # base address where routines page was placed
    mapping_size: int          # always 0x4000 (16 KiB)


@dataclass
class RuntimeBinaryMapped:
    """Type 6: The Rosetta runtime binary (/usr/libexec/rosetta/runtime) was mapped."""
    event_type: int  # 6
    mach_thread_port: int      # Mach thread port (send right) via mach_thread_self()
    runtime_image_base: int    # base address of the runtime Mach-O (after ASLR slide)
    text_segment_size: int     # size of the runtime's __TEXT segment


def parse_record(raw: TraceRecord):
    """Convert a raw TraceRecord into a typed sub-record."""
    t = raw.event_type

    if t == 1:
        name = raw.payload.rstrip(b'\x00').decode('utf-8', errors='replace')
        return JitTranslationCreated(
            event_type=1,
            mach_thread_port=raw.mach_thread_port,
            x86_source_addr=raw.field_2,
            arm64_code_size=raw.field_3,
            arm64_code_addr=raw.field_4,
            source_image_name=name,
        )
    elif t == 2:
        return AotFragmentFreed(
            event_type=2,
            mach_thread_port=raw.mach_thread_port,
            aot_header_addr=raw.field_2,
            mapped_region_size=raw.field_3,
        )
    elif t == 3:
        return JitCodeEmitted(
            event_type=3,
            mach_thread_port=raw.mach_thread_port,
            arm64_code_addr=raw.field_2,
            arm64_code_size=raw.field_3,
            x86_source_addr=raw.field_4,
            code_bytes=raw.payload,
        )
    elif t == 4:
        return JitFragmentFreed(
            event_type=4,
            mach_thread_port=raw.mach_thread_port,
            jit_code_addr=raw.field_2,
            native_code_size=raw.field_3,
        )
    elif t == 5:
        return RuntimeRoutinesMapped(
            event_type=5,
            mach_thread_port=raw.mach_thread_port,
            mapping_base_addr=raw.field_2,
            mapping_size=raw.field_3,
        )
    elif t == 6:
        return RuntimeBinaryMapped(
            event_type=6,
            mach_thread_port=raw.mach_thread_port,
            runtime_image_base=raw.field_2,
            text_segment_size=raw.field_3,
        )
    else:
        return raw


def parse_trace(path: str):
    """Parse a Rosetta trace file into a list of typed records."""
    with open(path, 'rb') as f:
        data = f.read()

    records = []
    offset = 0

    while offset + HEADER_SIZE <= len(data):
        fields = struct.unpack_from(HEADER_FMT, data, offset)
        event_type, mach_thread_port, f2, f3, f4, payload_len = fields
        offset += HEADER_SIZE

        payload = data[offset:offset + payload_len]
        offset += payload_len
        offset += (8 - (payload_len % 8)) % 8

        raw = TraceRecord(event_type, mach_thread_port, f2, f3, f4, payload)
        records.append(parse_record(raw))

    return records


def format_record(rec) -> str:
    """Pretty-print a single record."""
    if isinstance(rec, JitTranslationCreated):
        return (
            f"[JIT CREATED] thr={rec.mach_thread_port:#x}  "
            f"x86={rec.x86_source_addr:#x}  "
            f"arm64={rec.arm64_code_addr:#x}  "
            f"size={rec.arm64_code_size:#x}  "
            f"image=\"{rec.source_image_name}\""
        )
    elif isinstance(rec, JitCodeEmitted):
        return (
            f"[JIT CODE]    thr={rec.mach_thread_port:#x}  "
            f"x86={rec.x86_source_addr:#x}  "
            f"arm64={rec.arm64_code_addr:#x}  "
            f"size={rec.arm64_code_size:#x}"
        )
    elif isinstance(rec, AotFragmentFreed):
        return (
            f"[AOT FREED]   thr={rec.mach_thread_port:#x}  "
            f"header={rec.aot_header_addr:#x}  "
            f"region_size={rec.mapped_region_size:#x}"
        )
    elif isinstance(rec, JitFragmentFreed):
        return (
            f"[JIT FREED]   thr={rec.mach_thread_port:#x}  "
            f"code={rec.jit_code_addr:#x}  "
            f"size={rec.native_code_size:#x}"
        )
    elif isinstance(rec, RuntimeRoutinesMapped):
        return (
            f"[RT ROUTINES] thr={rec.mach_thread_port:#x}  "
            f"base={rec.mapping_base_addr:#x}  "
            f"size={rec.mapping_size:#x}"
        )
    elif isinstance(rec, RuntimeBinaryMapped):
        return (
            f"[RT BINARY]   thr={rec.mach_thread_port:#x}  "
            f"base={rec.runtime_image_base:#x}  "
            f"text_size={rec.text_segment_size:#x}"
        )
    else:
        return (
            f"[UNKNOWN t={rec.event_type}] thr={rec.mach_thread_port:#x}  "
            f"f2={rec.field_2:#x}  f3={rec.field_3:#x}  "
            f"f4={rec.field_4:#x}  payload={rec.payload!r}"
        )


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <trace_file>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    records = parse_trace(path)

    print(f"Parsed {len(records)} records from {path}\n")

    type_counts = {}
    for rec in records:
        t = rec.event_type
        type_counts[t] = type_counts.get(t, 0) + 1
        print(format_record(rec))

    print(f"\n--- Summary ---")
    type_names = {
        1: "JIT Created (AOT path)",
        2: "AOT Freed",
        3: "JIT Code Emitted",
        4: "JIT Freed (scribble)",
        5: "Runtime Routines Mapped",
        6: "Runtime Binary Mapped",
    }
    for t in sorted(type_counts):
        name = type_names.get(t, f"Unknown({t})")
        print(f"  Type {t} ({name}): {type_counts[t]}")


if __name__ == '__main__':
    main()
