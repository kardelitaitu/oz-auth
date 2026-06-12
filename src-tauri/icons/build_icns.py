#!/usr/bin/env python3
"""Build a proper multi-resolution Apple .icns file from individual PNGs.

.icns format:
  - 4 bytes: 'icns' magic
  - 4 bytes: total file size (big-endian u32)
  - For each icon:
      - 4 bytes: OSType code
      - 4 bytes: entry size including this 8-byte header (big-endian u32)
      - N bytes: PNG data

OSType codes (PNG-based, Apple standard):
  icp4 = 16x16
  icp5 = 32x32
  icp6 = 64x64
  ic07 = 128x128
  ic08 = 256x256
  ic09 = 512x512
  ic10 = 1024x1024

Usage: python build_icns.py
(Place fingerprint.png in the same directory, ImageMagick required for resizing)
"""

import struct
import os
import subprocess
import sys

ICON_ENTRIES = [
    (b"icp4", 16),
    (b"icp5", 32),
    (b"icp6", 64),
    (b"ic07", 128),
    (b"ic08", 256),
    (b"ic09", 512),
    (b"ic10", 1024),
]

SOURCE = "fingerprint.png"
OUTPUT = "fingerprint.icns"
TEMP_PREFIX = "icns_"


def build_icns() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    if not os.path.exists(SOURCE):
        raise SystemExit(f"ERROR: {SOURCE} not found in {script_dir}")

    temp_files: list[str] = []

    # Step 1: Resize fingerprint.png to all required sizes via ImageMagick
    print(f"Resizing {SOURCE} to {len(ICON_ENTRIES)} sizes...")
    for _, size in ICON_ENTRIES:
        png_path = f"{TEMP_PREFIX}{size}.png"
        temp_files.append(png_path)
        result = subprocess.run(
            ["magick", SOURCE, "-resize", f"{size}x{size}", png_path],
            capture_output=True,
        )
        if result.returncode != 0:
            raise SystemExit(f"ImageMagick failed for {size}x{size}: {result.stderr.decode()}")

    # Step 2: Read all PNG data
    entries: list[tuple[bytes, bytes]] = []
    for ostype, size in ICON_ENTRIES:
        png_path = f"{TEMP_PREFIX}{size}.png"
        with open(png_path, "rb") as f:
            data = f.read()
        entries.append((ostype, data))
        print(f"  {ostype.decode()} ({size}x{size}) <- {png_path} ({len(data)} bytes)")

    # Step 3: Calculate total size
    total_size = 8  # magic + size field
    for _, data in entries:
        total_size += 8 + len(data)

    # Step 4: Write .icns
    with open(OUTPUT, "wb") as f:
        f.write(b"icns")
        f.write(struct.pack(">I", total_size))
        for ostype, data in entries:
            entry_size = 8 + len(data)
            f.write(ostype)
            f.write(struct.pack(">I", entry_size))
            f.write(data)

    # Step 5: Cleanup temp PNGs
    for png_path in temp_files:
        os.remove(png_path)

    print(f"\nWrote {OUTPUT} ({total_size:,} bytes) with {len(entries)} icon sizes")


if __name__ == "__main__":
    build_icns()
