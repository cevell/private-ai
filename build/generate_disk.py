#!/usr/bin/env python3
"""
generate_disk.py — Cevell Deterministic GPT Disk Image & Verity Hasher
"""

import sys
import os
import json
import subprocess
import shutil

def main():
    if len(sys.argv) < 8:
        print("Usage: generate_disk.py <rootfs_tar> <output_raw> <repart_defs> <repart_seed> <kernel> <initrd> <out_dir> [uki_efi]")
        sys.exit(1)

    rootfs_tar = sys.argv[1]
    output_raw = sys.argv[2]
    repart_defs = sys.argv[3]
    repart_seed = sys.argv[4]
    kernel_path = sys.argv[5]
    initrd_path = sys.argv[6]
    out_dir = sys.argv[7]
    uki_path = sys.argv[8] if len(sys.argv) > 8 and sys.argv[8] != "" else None

    tmp_dir = os.environ.get("TMPDIR", "/tmp")
    root_stage = os.path.join(tmp_dir, "rootfs_stage")
    os.makedirs(root_stage, exist_ok=True)
    os.makedirs(out_dir, exist_ok=True)

    # 1. Extract rootfs
    subprocess.run([
        "tar", "--extract", f"--file={rootfs_tar}", f"--directory={root_stage}",
        "--numeric-owner", "--same-owner", "--same-permissions"
    ], check=True)

    # Ensure /boot directory always exists
    esp_boot = os.path.join(root_stage, "boot", "EFI", "BOOT")
    os.makedirs(esp_boot, exist_ok=True)

    # 2. Stage UKI into ESP boot directory and add startup.nsh fallback
    if uki_path and os.path.exists(uki_path):
        shutil.copy2(uki_path, os.path.join(esp_boot, "BOOTX64.EFI"))

        # Create startup.nsh at ESP root to automatically launch UKI from EFI shell
        with open(os.path.join(root_stage, "boot", "startup.nsh"), "w") as f:
            f.write("\\EFI\\BOOT\\BOOTX64.EFI\r\n")

    # 3. Execute deterministic systemd-repart
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = "0"

    cmd = [
        "systemd-repart",
        "--empty=create",
        "--size=auto",
        "--dry-run=no",
        "--offline=yes",
        "--discard=no",
        f"--seed={repart_seed}",
        f"--definitions={repart_defs}",
        f"--copy-source={root_stage}",
        "--json=short",
        "--pretty=no",
        "--no-pager",
        output_raw
    ]

    res = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print(f"systemd-repart failed (code {res.returncode}):\n{res.stderr}\n{res.stdout}")
        sys.exit(res.returncode)

    # 4. Parse partition roothash
    roothash = None
    try:
        parts = json.loads(res.stdout)
        for p in parts:
            if p.get("type") in ["root-x86-64-verity", "root-verity"] and "roothash" in p:
                roothash = p["roothash"]
                break
    except Exception as e:
        print(f"Error parsing repart JSON output: {e}\nOutput was:\n{res.stdout}")
        sys.exit(1)

    if not roothash or len(roothash) != 64:
        print(f"Failed to find valid 64-character verity root hash in partitions.json: {roothash}")
        sys.exit(1)

    # 5. Write artifacts
    basename = os.path.splitext(os.path.basename(output_raw))[0]
    roothash_file = os.path.join(out_dir, f"{basename}.roothash")
    with open(roothash_file, "w") as f:
        f.write(roothash)

    shutil.copy2(kernel_path, os.path.join(out_dir, f"{basename}.vmlinuz"))
    shutil.copy2(initrd_path, os.path.join(out_dir, f"{basename}.initrd"))

    print(f"Successfully generated {basename}.raw with root hash {roothash}")

if __name__ == "__main__":
    main()
