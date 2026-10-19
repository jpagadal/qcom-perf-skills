#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""
data-collection -- Memory Data Collection & Normalization
Collects memory diagnostic data from a Qualcomm Linux device via ADB or SSH
and normalizes it into a MemorySnapshot JSON contract.

Usage (ADB — single device, auto-detected):
    python collect.py [--output <dir>] [--label <label>]

Usage (ADB — specify device):
    python collect.py --serial <serial> [--output <dir>] [--label <label>]

Usage (SSH):
    python collect.py --host <ip> [--user root] [--port 22] [--key ~/.ssh/id_rsa]
                      [--output <dir>] [--label <label>]
    # Password is prompted interactively (not accepted on command line)

Usage (interactive — no args):
    python collect.py
    # Detects ADB devices and prompts for selection, or falls back to SSH

Offline (no device):
    python collect.py --no-pull --output <dir> [--label <label>]

Transport selection:
  --host   → SSH (password prompted interactively if no --key)
  --serial → ADB with specified serial
  neither  → auto-detect: lists ADB devices, prompts if multiple, falls back to SSH
Output files and snapshot.json schema are identical regardless of transport.
"""

import argparse
import getpass
import json
import os
import re
import struct
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Transport abstraction (ADB and SSH)
# ---------------------------------------------------------------------------

class Transport:
    """Abstract device transport. Subclasses implement shell() and pull()."""

    def shell(self, cmd: str) -> tuple[int, str]:
        """Run a shell command on the device. Returns (returncode, stdout)."""
        raise NotImplementedError

    def pull(self, remote: str, local: str) -> bool:
        """Copy a single file from device to local path. Returns True on success."""
        raise NotImplementedError

    def pull_dir(self, remote_dir: str, local_dir: str) -> bool:
        """
        Recursively copy a remote directory to local_dir.
        Default implementation: list remote dir and pull each file.
        Returns True if at least one file was pulled.
        """
        rc, listing = self.shell(f"ls {remote_dir} 2>/dev/null")
        if rc != 0 or not listing.strip():
            return False
        os.makedirs(local_dir, exist_ok=True)
        ok = False
        for name in listing.split():
            remote_path = f"{remote_dir}/{name}"
            local_path = os.path.join(local_dir, name)
            if self.pull(remote_path, local_path):
                ok = True
        return ok

    def close(self):
        """Release any resources held by the transport."""
        pass

    @property
    def device_id(self) -> str:
        """Human-readable device identifier (serial or host)."""
        return "unknown"


class AdbTransport(Transport):
    """Transport using Android Debug Bridge (adb)."""

    def __init__(self, serial: str | None = None):
        self._serial = serial

    @property
    def device_id(self) -> str:
        return self._serial or "auto"

    def _adb(self, *args) -> tuple[int, str]:
        cmd = ["adb"]
        if self._serial:
            cmd += ["-s", self._serial]
        cmd += list(args)
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout

    def shell(self, cmd: str) -> tuple[int, str]:
        return self._adb("shell", cmd)

    def pull(self, remote: str, local: str) -> bool:
        os.makedirs(os.path.dirname(os.path.abspath(local)), exist_ok=True)
        rc, _ = self._adb("pull", remote, local)
        return rc == 0

    def pull_dir(self, remote_dir: str, local_dir: str) -> bool:
        """Use 'adb pull <dir>' for efficient recursive directory pull."""
        rc, _ = self._adb("pull", remote_dir, local_dir)
        return rc == 0


class SshTransport(Transport):
    """
    Transport using SSH via paramiko (pure Python, no external tools needed).

    Install: pip install paramiko
    """

    def __init__(self, host: str, user: str = "root", port: int = 22,
                 key_file: str | None = None, password: str | None = None):
        try:
            import paramiko
        except ImportError:
            print("ERROR: paramiko is required for SSH transport.")
            print("       Install with: pip install paramiko")
            sys.exit(1)

        self._host = host
        self._user = user
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {"hostname": host, "port": port, "username": user}
        if key_file:
            connect_kwargs["key_filename"] = os.path.expanduser(key_file)
        elif password:
            connect_kwargs["password"] = password
        else:
            # Try default key locations (~/.ssh/id_rsa, id_ed25519, etc.)
            connect_kwargs["look_for_keys"] = True
            connect_kwargs["allow_agent"] = True

        self._client.connect(**connect_kwargs)
        self._sftp = self._client.open_sftp()

    @property
    def device_id(self) -> str:
        return f"{self._user}@{self._host}"

    def shell(self, cmd: str) -> tuple[int, str]:
        try:
            _, stdout, _ = self._client.exec_command(cmd, timeout=30)
            output = stdout.read().decode("utf-8", errors="replace")
            rc = stdout.channel.recv_exit_status()
            return rc, output
        except Exception as e:
            return 1, ""

    def pull(self, remote: str, local: str) -> bool:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(local)), exist_ok=True)
            self._sftp.get(remote, local)
            return True
        except Exception:
            return False

    def pull_dir(self, remote_dir: str, local_dir: str) -> bool:
        """Recursively pull a remote directory via SFTP."""
        try:
            entries = self._sftp.listdir_attr(remote_dir)
        except Exception:
            return False
        os.makedirs(local_dir, exist_ok=True)
        ok = False
        import stat as _stat
        for entry in entries:
            remote_path = f"{remote_dir}/{entry.filename}"
            local_path = os.path.join(local_dir, entry.filename)
            if _stat.S_ISDIR(entry.st_mode or 0):
                if self.pull_dir(remote_path, local_path):
                    ok = True
            else:
                if self.pull(remote_path, local_path):
                    ok = True
        return ok

    def close(self):
        try:
            self._sftp.close()
            self._client.close()
        except Exception:
            pass


def list_adb_devices() -> list:
    """
    Run 'adb devices' and return list of (serial, status) tuples.
    Returns empty list if ADB is not available or no devices connected.
    """
    try:
        result = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True, timeout=5
        )
        devices = []
        for line in result.stdout.splitlines()[1:]:  # skip header line
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) == 2:
                serial, status = parts[0].strip(), parts[1].strip()
                if status in ("device", "root"):
                    devices.append((serial, status))
        return devices
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def select_transport_interactive(args) -> Transport:
    """
    Interactively select transport when no --serial or --host is provided.

    Logic:
      1. Check if ADB is available and list connected devices
         - 0 devices → offer SSH
         - 1 device  → use automatically
         - 2+ devices → ask user to select one (or choose SSH)
      2. If SSH selected → prompt for hostname, username, password
    """
    devices = list_adb_devices()

    # Single device: use automatically
    if len(devices) == 1:
        serial, status = devices[0]
        print(f"[data-collection] Found 1 ADB device: {serial} ({status})")
        return AdbTransport(serial=serial)

    # Multiple devices: ask user to select
    if len(devices) > 1:
        print("[data-collection] Multiple ADB devices found:")
        for i, (serial, status) in enumerate(devices, 1):
            print(f"  {i}. {serial}  ({status})")
        print(f"  {len(devices) + 1}. Use SSH instead")
        while True:
            choice = input(f"Select device [1-{len(devices) + 1}]: ").strip()
            try:
                idx = int(choice)
                if 1 <= idx <= len(devices):
                    serial = devices[idx - 1][0]
                    print(f"[data-collection] Using ADB device: {serial}")
                    return AdbTransport(serial=serial)
                elif idx == len(devices) + 1:
                    break  # fall through to SSH
            except ValueError:
                # Allow entering serial directly
                for serial, status in devices:
                    if choice == serial:
                        print(f"[data-collection] Using ADB device: {serial}")
                        return AdbTransport(serial=serial)
            print(f"  Invalid selection. Enter a number (1-{len(devices) + 1}) or a serial number.")

    # No ADB devices available
    if not devices:
        try:
            subprocess.run(["adb", "version"], capture_output=True, timeout=3)
            print("[data-collection] ADB available but no devices connected.")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("[data-collection] ADB not available on this host.")

    # SSH transport
    print("[data-collection] Using SSH transport.")
    host = input("  Hostname or IP address: ").strip()
    if not host:
        print("ERROR: hostname is required.")
        sys.exit(1)
    user = input("  Username [root]: ").strip() or "root"
    password = getpass.getpass("  Password: ")
    port = getattr(args, "port", 22) or 22
    key_file = getattr(args, "key", None)
    return SshTransport(host=host, user=user, port=port,
                        key_file=key_file, password=password)


def make_transport(args) -> Transport:
    """
    Select transport from CLI args or interactively:
      --host   → SshTransport (prompts for password if no --key provided)
      --serial → AdbTransport(serial)
      neither  → interactive selection (auto-detect ADB or prompt for SSH)
    """
    if hasattr(args, "host") and args.host:
        key_file = getattr(args, "key", None)
        password = getattr(args, "password", None)
        if not key_file and not password:
            password = getpass.getpass(
                f"  SSH password for {getattr(args, 'user', 'root') or 'root'}@{args.host}: "
            )
        return SshTransport(
            host=args.host,
            user=getattr(args, "user", "root") or "root",
            port=getattr(args, "port", 22) or 22,
            key_file=key_file,
            password=password,
        )
    if hasattr(args, "serial") and args.serial:
        return AdbTransport(serial=args.serial)
    # Neither --host nor --serial: interactive selection
    return select_transport_interactive(args)


def get_device_info(transport: Transport) -> dict:
    """
    Collect device metadata from Qualcomm Linux sources.
    Priority: /proc/device-tree/model > /sys/devices/soc0/machine > getprop
    Works identically over ADB and SSH.
    """
    # Determine transport type and populate device identifier fields accordingly.
    # For SSH: store the IP/host as "network_address"; try to read hardware serial.
    # For ADB: store the ADB serial as "serial"; no network_address.
    connection_id = transport.device_id  # e.g. "ubuntu@10.92.165.93" or ADB serial

    if "@" in connection_id:
        # SSH transport
        transport_type = "ssh"
        network_address = connection_id.split("@", 1)[1]  # strip "user@", keep IP
        _, hw_serial = transport.shell("cat /sys/devices/soc0/serial_num 2>/dev/null")
        serial = hw_serial.strip()  # hardware serial if available, else empty
    else:
        # ADB transport
        transport_type = "adb"
        network_address = ""
        serial = connection_id  # ADB serial number

    info = {
        "serial": serial,
        "network_address": network_address,
        "transport_type": transport_type,
    }

    # Kernel version (always available)
    _, kernel = transport.shell("uname -r")
    info["kernel_version"] = kernel.strip()

    # Machine name: prefer /proc/device-tree/model (full board name)
    _, dt_model = transport.shell("cat /proc/device-tree/model 2>/dev/null")
    dt_model = dt_model.strip().rstrip("\x00")  # strip null bytes from DT strings
    if dt_model:
        info["model"] = dt_model
    else:
        # Fallback: /sys/devices/soc0/machine (board codename)
        _, soc_machine = transport.shell("cat /sys/devices/soc0/machine 2>/dev/null")
        soc_machine = soc_machine.strip()
        if soc_machine:
            info["model"] = soc_machine
        else:
            # Last resort: Android getprop
            _, model = transport.shell("getprop ro.product.model")
            info["model"] = model.strip()

    # SoC info from /sys/devices/soc0/
    _, soc_machine = transport.shell("cat /sys/devices/soc0/machine 2>/dev/null")
    _, soc_id = transport.shell("cat /sys/devices/soc0/soc_id 2>/dev/null")
    _, soc_family = transport.shell("cat /sys/devices/soc0/family 2>/dev/null")
    _, soc_revision = transport.shell("cat /sys/devices/soc0/revision 2>/dev/null")
    info["soc_name"] = soc_machine.strip()   # e.g. QCS6490 -- public SoC codename
    info["soc_id"] = soc_id.strip()
    info["soc_family"] = soc_family.strip()
    info["soc_revision"] = soc_revision.strip()

    # OS info from /etc/os-release
    _, os_release = transport.shell("cat /etc/os-release 2>/dev/null")
    os_info = {}
    for line in os_release.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            os_info[k.strip()] = v.strip().strip('"')
    info["os_name"] = os_info.get("PRETTY_NAME") or os_info.get("NAME", "")
    info["os_version"] = os_info.get("VERSION", os_info.get("VERSION_ID", ""))
    info["build_id"] = os_info.get("BUILD_ID", "")

    return info


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_meminfo(text: str) -> dict:
    """Parse /proc/meminfo into {key: value_kb} dict."""
    result = {}
    for line in text.splitlines():
        m = re.match(r"^(\w+):\s+(\d+)", line)
        if m:
            result[m.group(1)] = int(m.group(2))
    return result


def parse_slabinfo(text: str) -> list:
    """Parse /proc/slabinfo into list of slab entries."""
    slabs = []
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            name = parts[0]
            active_objs = int(parts[1])
            num_objs = int(parts[2])
            obj_size = int(parts[3])
            total_kb = (num_objs * obj_size) // 1024
            slabs.append({
                "name": name,
                "active_objs": active_objs,
                "num_objs": num_objs,
                "obj_size": obj_size,
                "total_kb": total_kb,
            })
        except (ValueError, IndexError):
            continue
    return slabs


def parse_vmstat(text: str) -> dict:
    """Parse /proc/vmstat into {key: value} dict."""
    result = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return result


def parse_buddyinfo(text: str) -> dict:
    """Parse /proc/buddyinfo into {zone: {order_N: count}} dict."""
    result = {}
    for line in text.splitlines():
        m = re.match(r"Node\s+\d+,\s+zone\s+(\S+)\s+([\d\s]+)", line)
        if m:
            zone = m.group(1)
            counts = m.group(2).split()
            result[zone] = {f"order_{i}": int(c) for i, c in enumerate(counts)}
    return result


def parse_zoneinfo(text: str) -> list:
    """Parse /proc/zoneinfo into list of zone entries."""
    zones = []
    current: dict | None = None
    for line in text.splitlines():
        m = re.match(r"Node\s+\d+,\s+zone\s+(\S+)", line)
        if m:
            if current:
                zones.append(current)
            current = {"zone": m.group(1)}
            continue
        if current is None:
            continue
        for key in ("present", "managed", "spanned", "free"):
            m2 = re.match(rf"\s+{key}\s+(\d+)", line)
            if m2:
                current[key] = int(m2.group(1))
    if current:
        zones.append(current)
    return zones


def parse_pagetypeinfo(text: str) -> dict:
    """Parse /proc/pagetypeinfo into {zone: {type: count}} dict."""
    result: dict = {}
    for line in text.splitlines():
        m = re.match(
            r"Node\s+\d+,\s+zone\s+(\S+),\s+type\s+(\S+)\s+([\d\s]+)", line
        )
        if m:
            zone, ptype, counts_str = m.group(1), m.group(2), m.group(3)
            total = sum(int(c) for c in counts_str.split())
            result.setdefault(zone, {})[ptype] = total
    return result


def parse_dmabuf(text: str) -> dict:
    """
    Parse /sys/kernel/debug/dma_buf/bufinfo.

    Supports two formats:
    1. New format (kernel >= 5.10):
       Header: 'Dma-buf Objects:'
       Columns (tab-separated): size  flags  mode  count  exp_name  ino  name
       Size is in bytes (decimal, zero-padded)
       Summary: 'Total N objects, M bytes'

    2. Old format:
       Columns (space-separated): <size_bytes> <flags> <mode> <count> <ino> <exp_name> <name>
       Size is decimal bytes

    Returns:
        total_kb: total DMA-BUF memory in kB
        by_allocator: {exporter: total_kb} dict
        by_exporter_detail: {exporter: [{size_kb, count, total_kb}]} grouped by size
    """
    from collections import Counter
    total_kb = 0
    by_allocator: dict = {}
    # Track (exporter, size_kb) → buffer count for grouping
    size_counter: Counter = Counter()

    # Try to extract total from summary line first
    for line in text.splitlines():
        m = re.match(r"Total\s+\d+\s+objects,\s+(\d+)\s+bytes", line)
        if m:
            total_kb = int(m.group(1)) // 1024
            break

    # Parse per-buffer lines
    for line in text.splitlines():
        line = line.strip()
        # Skip header and section lines (non-buffer lines)
        if not line or line.startswith("Dma-buf") or line.startswith("size") \
                or line.startswith("Attached") or line.startswith("Total") \
                or not line[0].isdigit():
            continue

        # New format: tab-separated with zero-padded DECIMAL size
        # e.g.: 18874368\t00000002\t02080007\t00000004\tcamera_qcm6490\t00000276\t<none>
        parts = line.split("\t")
        if len(parts) >= 5:
            try:
                size_bytes = int(parts[0])  # decimal size
                allocator = parts[4].strip()
                size_kb = size_bytes // 1024
                by_allocator[allocator] = by_allocator.get(allocator, 0) + size_kb
                size_counter[(allocator, size_kb)] += 1
                if total_kb == 0:  # only accumulate if no summary line found
                    total_kb += size_kb
                continue
            except (ValueError, IndexError):
                pass

        # Old format: space-separated with decimal size
        m = re.match(r"(\d+)\s+\S+\s+\S+\s+\d+\s+\d+\s+(\S+)", line)
        if m:
            size_bytes = int(m.group(1))
            allocator = m.group(2)
            size_kb = size_bytes // 1024
            by_allocator[allocator] = by_allocator.get(allocator, 0) + size_kb
            size_counter[(allocator, size_kb)] += 1
            if total_kb == 0:
                total_kb += size_kb

    # Build per-exporter size-grouped detail
    # Format: {exporter: [{size_kb, count, total_kb}, ...]} sorted by total_kb desc
    by_exporter_detail: dict = {}
    for (allocator, size_kb), count in size_counter.items():
        by_exporter_detail.setdefault(allocator, []).append({
            "size_kb": size_kb,
            "count": count,
            "total_kb": size_kb * count,
        })
    for exp in by_exporter_detail:
        by_exporter_detail[exp].sort(key=lambda x: x["total_kb"], reverse=True)

    return {
        "total_kb": total_kb,
        "by_allocator": by_allocator,
        "by_exporter_detail": by_exporter_detail,
    }


def parse_cma(text: str, region_name: str = "unknown") -> list:
    """Parse /sys/kernel/debug/cma/<region>/used (single value per file)."""
    try:
        pages = int(text.strip())
        return [{"region": region_name, "used_kb": pages * 4}]
    except ValueError:
        return []


def parse_kgsl_total(text: str) -> int:
    """Parse /sys/class/kgsl/kgsl/page_alloc (total bytes)."""
    try:
        return int(text.strip()) // 1024  # bytes -> kB
    except ValueError:
        return 0


def parse_kgsl_proc(proc_dir: str) -> list:
    """Parse per-process KGSL memory from /sys/class/kgsl/kgsl/proc/<pid>/mem."""
    procs = []
    if not os.path.isdir(proc_dir):
        return procs
    for pid in os.listdir(proc_dir):
        mem_file = os.path.join(proc_dir, pid, "mem")
        if not os.path.isfile(mem_file):
            continue
        try:
            with open(mem_file) as f:
                content = f.read()
            total_kb = 0
            for line in content.splitlines():
                m = re.search(r"(\d+)\s+kB", line)
                if m:
                    total_kb += int(m.group(1))
            # Try to get process name
            name = pid
            cmdline_file = f"/proc/{pid}/cmdline"
            if os.path.isfile(cmdline_file):
                with open(cmdline_file) as f:
                    name = f.read().split("\x00")[0] or pid
            procs.append({"pid": int(pid), "name": name, "kb": total_kb})
        except (OSError, ValueError):
            continue
    return procs


def parse_procrank(text: str) -> list:
    """
    Parse procrank -p output into list of process entries.

    Supports two formats:
    - Old: PID  Vss  Rss  Pss  Uss  cmdline
    - New: PID  Vss  Rss  Pss  Uss  Swap  PSwap  USwap  ZSwap  cmdline

    The cmdline is always the last whitespace-separated token that does NOT
    end with 'K'. All size fields end with 'K'.
    """
    procs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("PID"):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue

        # Collect all size fields (end with K) and find where cmdline starts
        # PID is parts[0], then size fields (end with K), then cmdline (rest)
        size_fields = []
        cmdline_start = 1
        for i, p in enumerate(parts[1:], 1):
            if p.endswith("K"):
                size_fields.append(p)
                cmdline_start = i + 1
            else:
                break

        # cmdline is everything from cmdline_start onward
        cmdline = " ".join(parts[cmdline_start:]).strip()
        if not cmdline:
            continue

        # Extract Vss, Rss, Pss, Uss from size_fields (first 4)
        def kb(s):
            try:
                return int(s.rstrip("K"))
            except ValueError:
                return 0

        vss_kb = kb(size_fields[0]) if len(size_fields) > 0 else 0
        rss_kb = kb(size_fields[1]) if len(size_fields) > 1 else 0
        pss_kb = kb(size_fields[2]) if len(size_fields) > 2 else 0
        uss_kb = kb(size_fields[3]) if len(size_fields) > 3 else 0

        procs.append({
            "pid": pid,
            "vss_kb": vss_kb,
            "rss_kb": rss_kb,
            "pss_kb": pss_kb,
            "uss_kb": uss_kb,
            "name": cmdline,
        })
    return procs


def parse_dt_reserved_memory(reserved_dir: str) -> list:
    """Parse device tree reserved-memory binary nodes."""
    nodes = []
    if not os.path.isdir(reserved_dir):
        return nodes
    for fname in sorted(os.listdir(reserved_dir)):
        fpath = os.path.join(reserved_dir, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            data = open(fpath, "rb").read()
            # Each reg entry is 2x 64-bit big-endian values (base, size)
            # or 2x 32-bit values depending on #address-cells/#size-cells
            if len(data) >= 16:
                base = int.from_bytes(data[0:8], "big")
                size = int.from_bytes(data[8:16], "big")
            elif len(data) >= 8:
                base = int.from_bytes(data[0:4], "big")
                size = int.from_bytes(data[4:8], "big")
            else:
                continue
            # Strip .bin extension and use as node name
            node_name = fname.replace(".bin", "")
            nodes.append({
                "name": node_name,
                "base": hex(base),
                "size_kb": size // 1024,
            })
        except (OSError, struct.error):
            continue
    return nodes


def parse_modules(text: str) -> dict:
    """
    Parse /proc/modules into total size and per-module list.
    Format: name size refcount deps state offset
    Returns {"total_kb": int, "modules": [{name, size_kb}]}
    """
    total_kb = 0
    modules = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            try:
                name = parts[0]
                size_kb = int(parts[1]) // 1024
                total_kb += size_kb
                modules.append({"name": name, "size_kb": size_kb})
            except (ValueError, IndexError):
                continue
    # Sort by size descending
    modules.sort(key=lambda x: x["size_kb"], reverse=True)
    return {"total_kb": total_kb, "modules": modules}


def parse_iomem(text: str) -> dict:
    """Parse /proc/iomem to extract System RAM ranges."""
    ranges = []
    for line in text.splitlines():
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s*:\s*System RAM", line, re.I)
        if m:
            ranges.append({
                "start": "0x" + m.group(1),
                "end": "0x" + m.group(2),
            })
    return {"system_ram_ranges": ranges}


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def parse_dmesg_kernel_static(text: str) -> dict:
    """
    Parse dmesg output to extract kernel static memory breakdown.
    Returns dict with vmlinux components, page structs, hash tables (all in kB).

    Supports two sources:
    1. dmesg Memory line: "Memory: ... available (28812K kernel code, ...)"
    2. Fallback: hash tables from dmesg hash table entries lines
    """
    result = {
        "kernel_code_kb":   0,
        "rodata_kb":        0,
        "init_kb":          0,
        "rwdata_kb":        0,
        "bss_kb":           0,
        "vmlinux_total_kb": 0,
        "page_structs_kb":  0,
        "hash_tables_kb":   0,
    }

    for line in text.splitlines():
        # Memory line: "Memory: 5389916K/6291456K available (28812K kernel code, 4946K rwdata, ...)"
        m = re.search(
            r"Memory:.*available\s*\((\d+)K kernel code,\s*(\d+)K rwdata,\s*(\d+)K rodata,\s*(\d+)K init,\s*(\d+)K bss",
            line
        )
        if m:
            result["kernel_code_kb"] = int(m.group(1))
            result["rwdata_kb"]      = int(m.group(2))
            result["rodata_kb"]      = int(m.group(3))
            result["init_kb"]        = int(m.group(4))
            result["bss_kb"]         = int(m.group(5))
            result["vmlinux_total_kb"] = (
                result["kernel_code_kb"] + result["rwdata_kb"] +
                result["rodata_kb"] + result["init_kb"] + result["bss_kb"]
            )
            continue

        # Kernel/User page tables (older kernels)
        m2 = re.search(r"Kernel/User page tables:\s*(\d+)K", line)
        if m2:
            result["page_structs_kb"] = int(m2.group(1))
            continue

        # Pages used for memmap (zone initialization)
        m2b = re.search(r"(\d+)\s+pages used for memmap", line)
        if m2b:
            result["page_structs_kb"] += int(m2b.group(1)) * 4  # 4KB per page
            continue

        # Hash tables (sum all hash table entries)
        m3 = re.search(r"hash table entries.*?(\d+)\s+bytes", line, re.I)
        if m3:
            result["hash_tables_kb"] += int(m3.group(1)) // 1024

    return result


def parse_iomem_kernel_sections(iomem_text: str) -> dict:
    """
    Parse /proc/iomem to extract Kernel code and Kernel data section sizes.
    These are available on kernels that don't print the Memory: line in dmesg.

    Returns dict with kernel_code_kb, kernel_data_kb, vmlinux_total_kb.
    """
    result = {"kernel_code_kb": 0, "kernel_data_kb": 0, "vmlinux_total_kb": 0}
    for line in iomem_text.splitlines():
        # Format: "start-end : Kernel code" or "start-end : Kernel data"
        m = re.match(r"\s*([0-9a-f]+)-([0-9a-f]+)\s*:\s*(Kernel\s+\w+)", line, re.I)
        if m:
            start = int(m.group(1), 16)
            end   = int(m.group(2), 16)
            size_kb = (end - start + 1) // 1024
            label = m.group(3).lower()
            if "code" in label:
                result["kernel_code_kb"] += size_kb
            elif "data" in label:
                result["kernel_data_kb"] += size_kb
    result["vmlinux_total_kb"] = result["kernel_code_kb"] + result["kernel_data_kb"]
    return result


def parse_swapinfo(text: str) -> list:
    """Parse /proc/swaps into list of swap entries."""
    entries = []
    for line in text.splitlines():
        if line.startswith("Filename") or not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 4:
            try:
                entries.append({
                    "filename": parts[0],
                    "type":     parts[1],
                    "size_kb":  int(parts[2]),
                    "used_kb":  int(parts[3]),
                })
            except (ValueError, IndexError):
                continue
    return entries


def parse_zramstat(text: str) -> dict:
    """
    Parse /sys/block/zram0/mm_stat.
    Format: orig_data_size compr_data_size mem_used_total mem_limit mem_used_max
            same_pages pages_compacted huge_pages huge_pages_since
    All values in bytes.
    """
    parts = text.split()
    try:
        return {
            "orig_data_kb":   int(parts[0]) // 1024,
            "compr_data_kb":  int(parts[1]) // 1024,
            "mem_used_kb":    int(parts[2]) // 1024,
            "mem_limit_kb":   int(parts[3]) // 1024 if len(parts) > 3 else 0,
            "savings_kb":     max(0, int(parts[0]) - int(parts[2])) // 1024,
        }
    except (ValueError, IndexError):
        return {}


def parse_memblock(text: str) -> dict:
    """
    Parse /sys/kernel/debug/memblock/memory.
    Each line: idx  base  size  [flags]
    Returns total physical RAM in kB.
    """
    total_kb = 0
    regions = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("cnt") or line.startswith("idx"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            try:
                base = int(parts[1], 16)
                size = int(parts[2], 16)
                total_kb += size // 1024
                regions.append({"base": hex(base), "size_kb": size // 1024})
            except (ValueError, IndexError):
                continue
    return {"total_kb": total_kb, "regions": regions}


def parse_kgsl_gpu_mem(text: str) -> list:
    """
    Parse /sys/kernel/debug/kgsl/kgsl-3d0/mem.
    Returns list of {pid, name, size_kb} entries.
    """
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("pid") or line.startswith("---"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            try:
                pid  = int(parts[0])
                size = int(parts[1])  # bytes
                name = " ".join(parts[2:])
                entries.append({"pid": pid, "size_kb": size // 1024, "name": name})
            except (ValueError, IndexError):
                continue
    return entries


def parse_smaps(text: str, pid: int = 0) -> dict:
    """
    Parse /proc/<pid>/smaps into a summary dict.
    Returns totals for key fields (all in kB).
    """
    result = {
        "pid": pid,
        "size_kb": 0, "rss_kb": 0, "pss_kb": 0,
        "private_clean_kb": 0, "private_dirty_kb": 0,
        "shared_clean_kb": 0, "shared_dirty_kb": 0,
        "swap_kb": 0, "swap_pss_kb": 0,
        "top_mappings": [],
    }
    current_mapping = None
    mapping_pss = {}

    for line in text.splitlines():
        # New mapping header: address perms offset dev inode [name]
        if line and not line[0].isspace() and "-" in line.split()[0]:
            parts = line.split()
            name = parts[5] if len(parts) > 5 else "[anon]"
            current_mapping = name
            mapping_pss[name] = mapping_pss.get(name, 0)
            continue

        m = re.match(r"(\w+):\s+(\d+)\s+kB", line)
        if not m:
            continue
        key, val = m.group(1), int(m.group(2))
        if key == "Size":          result["size_kb"]         += val
        elif key == "Rss":         result["rss_kb"]          += val
        elif key == "Pss":
            result["pss_kb"] += val
            if current_mapping:
                mapping_pss[current_mapping] = mapping_pss.get(current_mapping, 0) + val
        elif key == "Private_Clean": result["private_clean_kb"] += val
        elif key == "Private_Dirty": result["private_dirty_kb"] += val
        elif key == "Shared_Clean":  result["shared_clean_kb"]  += val
        elif key == "Shared_Dirty":  result["shared_dirty_kb"]  += val
        elif key == "Swap":          result["swap_kb"]           += val
        elif key == "SwapPss":       result["swap_pss_kb"]       += val

    # Top 10 mappings by PSS
    result["top_mappings"] = sorted(
        [{"name": k, "pss_kb": v} for k, v in mapping_pss.items() if v > 0],
        key=lambda x: x["pss_kb"], reverse=True
    )[:10]
    return result


PROC_SOURCES = [
    ("meminfo",     "/proc/meminfo",     "meminfo.txt"),
    ("slabinfo",    "/proc/slabinfo",    "slabinfo.txt"),
    ("vmstat",      "/proc/vmstat",      "vmstat.txt"),
    ("buddyinfo",   "/proc/buddyinfo",   "buddyinfo.txt"),
    ("zoneinfo",    "/proc/zoneinfo",    "zoneinfo.txt"),
    ("pagetypeinfo","/proc/pagetypeinfo","pagetypeinfo.txt"),
    ("iomem",       "/proc/iomem",       "iomem.txt"),
    ("modules",     "/proc/modules",     "modules.txt"),
    ("vmallocinfo", "/proc/vmallocinfo", "vmallocinfo.txt"),
    ("swaps",       "/proc/swaps",       "swapinfo.txt"),
]

DEBUGFS_SOURCES = [
    ("dmabuf",           "/sys/kernel/debug/dma_buf/bufinfo",       "dmabuf_bufinfo.txt"),
    ("kgsl",             "/sys/class/kgsl/kgsl/page_alloc",         "kgsl_alloc.txt"),
    ("memblock",         "/sys/kernel/debug/memblock/memory",        "memblock.txt"),
    ("memblock_reserved","/sys/kernel/debug/memblock/reserved",      "memblock_reserved.txt"),
    ("kgsl_gpu",         "/sys/kernel/debug/kgsl/kgsl-3d0/mem",     "kgsl_gpu_mem.txt"),
]


def pull_with_sudo_fallback(transport: Transport, remote: str, local: str) -> bool:
    """
    Pull a file from the device, falling back to 'sudo cat' if direct pull fails.
    This handles /proc files that require elevated permissions (e.g. slabinfo, pagetypeinfo).
    Uses 'sudo -n' (non-interactive) to avoid password prompts.
    Returns True if the file was successfully retrieved by any method.
    """
    # Try normal pull first (works for most files)
    if transport.pull(remote, local):
        return True

    # Fallback: try sudo cat (for permission-restricted files)
    rc, output = transport.shell(f"sudo -n cat {remote} 2>/dev/null")
    if rc == 0 and output.strip():
        os.makedirs(os.path.dirname(os.path.abspath(local)), exist_ok=True)
        with open(local, "w", encoding="utf-8", errors="replace") as f:
            f.write(output)
        return True

    return False


def collect_from_device(transport: Transport, output_dir: str) -> list:
    """
    Pull all memory files from device using the given transport.
    Returns list of collection errors.
    Output files are identical regardless of whether ADB or SSH is used.
    For files that fail due to permissions, a sudo fallback is attempted automatically.
    """
    errors = []
    os.makedirs(output_dir, exist_ok=True)

    # /proc sources (sudo fallback for permission-restricted files)
    for key, remote, local_name in PROC_SOURCES:
        local = os.path.join(output_dir, local_name)
        if not pull_with_sudo_fallback(transport, remote, local):
            errors.append({"source": key, "error": f"pull failed: {remote}"})

    # debugfs sources (sudo fallback for debugfs files)
    for key, remote, local_name in DEBUGFS_SOURCES:
        local = os.path.join(output_dir, local_name)
        if not pull_with_sudo_fallback(transport, remote, local):
            errors.append({"source": key, "error": f"pull failed: {remote}"})

    # CMA used (glob)
    rc, cma_list = transport.shell("ls /sys/kernel/debug/cma/")
    if rc == 0:
        cma_dir = os.path.join(output_dir, "cma")
        os.makedirs(cma_dir, exist_ok=True)
        for region in cma_list.split():
            remote = f"/sys/kernel/debug/cma/{region}/used"
            local = os.path.join(cma_dir, f"{region}_used.txt")
            transport.pull(remote, local)
    else:
        errors.append({"source": "cma", "error": "cma debugfs not available"})

    # KGSL per-process (directory pull)
    kgsl_proc_dir = os.path.join(output_dir, "kgsl_procs")
    if not transport.pull_dir("/sys/class/kgsl/kgsl/proc", kgsl_proc_dir):
        errors.append({"source": "kgsl_procs", "error": "kgsl proc dir not available"})

    # procrank (Android/Qualcomm Linux)
    _, procrank_out = transport.shell("procrank -p 2>/dev/null || echo ''")
    if procrank_out.strip():
        with open(os.path.join(output_dir, "procrank.txt"), "w") as f:
            f.write(procrank_out)
    else:
        # Fallback: collect PSS from /proc/*/smaps_rollup (standard Linux / Debian)
        # Format per line: <pid> <pss_kb> <name>
        _, fallback_out = transport.shell(
            "for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do "
            "  pss=$(grep ^Pss: /proc/$pid/smaps_rollup 2>/dev/null | awk '{print $2}'); "
            "  rss=$(grep ^VmRSS: /proc/$pid/status 2>/dev/null | awk '{print $2}'); "
            "  name=$(cat /proc/$pid/comm 2>/dev/null); "
            "  cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' ' | cut -c1-80); "
            "  [ -n \"$pss\" ] && [ \"$pss\" -gt 0 ] 2>/dev/null && "
            "  echo \"$pid $pss ${rss:-0} ${cmdline:-$name}\"; "
            "done 2>/dev/null | sort -k2 -rn"
        )
        if fallback_out.strip():
            with open(os.path.join(output_dir, "proc_stats_fallback.txt"), "w") as f:
                f.write(fallback_out)
        else:
            errors.append({"source": "process_stats", "error": "procrank not available and smaps_rollup fallback failed"})

    # zram stats
    _, zram_out = transport.shell("cat /sys/block/zram0/mm_stat 2>/dev/null")
    if zram_out.strip():
        with open(os.path.join(output_dir, "zramstat.txt"), "w") as f:
            f.write(zram_out)
    else:
        errors.append({"source": "zram", "error": "zram not available"})

    # smaps for top PSS processes (top 5 by PSS from procrank)
    smaps_dir = os.path.join(output_dir, "smaps")
    os.makedirs(smaps_dir, exist_ok=True)
    procrank_path = os.path.join(output_dir, "procrank.txt")
    if os.path.isfile(procrank_path):
        procs = parse_procrank(open(procrank_path).read())
        top_procs = sorted(procs, key=lambda p: p["pss_kb"], reverse=True)[:5]
        for proc in top_procs:
            pid = proc["pid"]
            _, smaps_out = transport.shell(f"cat /proc/{pid}/smaps 2>/dev/null")
            if smaps_out.strip():
                safe_name = proc["name"].split("/")[-1].split()[0][:20]
                fname = os.path.join(smaps_dir, f"{pid}_{safe_name}_smaps.txt")
                with open(fname, "w", encoding="utf-8", errors="replace") as f:
                    f.write(smaps_out)
    else:
        errors.append({"source": "smaps", "error": "procrank.txt not available for smaps selection"})

    # dmesg (for kernel static breakdown)
    # Try journalctl -k first -- it preserves the full boot log including early
    # messages (Memory line, hash tables) that may be overwritten in dmesg ring buffer.
    # Fall back to dmesg if journalctl is not available.
    rc_jctl, jctl_out = transport.shell("journalctl -k --no-pager 2>/dev/null")
    if rc_jctl == 0 and jctl_out.strip() and "kernel code" in jctl_out:
        with open(os.path.join(output_dir, "dmesg.txt"), "w", encoding="utf-8",
                  errors="replace") as f:
            f.write(jctl_out)
    else:
        _, dmesg_out = transport.shell("dmesg 2>/dev/null")
        if dmesg_out.strip():
            with open(os.path.join(output_dir, "dmesg.txt"), "w", encoding="utf-8",
                      errors="replace") as f:
                f.write(dmesg_out)
        else:
            errors.append({"source": "dmesg", "error": "dmesg not available"})

    # Device tree reserved-memory
    reserved_dir = os.path.join(output_dir, "reserved-memory")
    os.makedirs(reserved_dir, exist_ok=True)
    rc4, dt_nodes = transport.shell(
        "ls /sys/firmware/devicetree/base/reserved-memory/ 2>/dev/null"
    )
    if rc4 == 0:
        for node in dt_nodes.split():
            remote = f"/sys/firmware/devicetree/base/reserved-memory/{node}/reg"
            local = os.path.join(reserved_dir, f"{node}.bin")
            transport.pull(remote, local)
    else:
        errors.append({"source": "reserved_memory", "error": "DT reserved-memory not accessible"})

    return errors


def normalize(output_dir: str) -> tuple[dict, list]:
    """Parse all collected files into normalized sources dict."""
    sources: dict = {}
    errors: list = []

    def read_file(fname: str) -> str | None:
        path = os.path.join(output_dir, fname)
        if os.path.isfile(path):
            try:
                return open(path).read()
            except OSError:
                return None
        return None

    def add_source(key: str, fname: str, parser, *args):
        text = read_file(fname)
        if text is not None:
            try:
                sources[key] = {
                    "available": True,
                    "path": os.path.join(output_dir, fname),
                    "parsed": parser(text, *args),
                }
            except Exception as e:
                sources[key] = {"available": False}
                errors.append({"source": key, "error": f"parse error: {e}"})
        else:
            sources[key] = {"available": False}
            errors.append({"source": key, "error": f"file not found: {fname}"})

    add_source("meminfo",     "meminfo.txt",     parse_meminfo)
    add_source("slabinfo",    "slabinfo.txt",    parse_slabinfo)
    add_source("vmstat",      "vmstat.txt",      parse_vmstat)
    add_source("buddyinfo",   "buddyinfo.txt",   parse_buddyinfo)
    add_source("zoneinfo",    "zoneinfo.txt",    parse_zoneinfo)
    add_source("pagetypeinfo","pagetypeinfo.txt",parse_pagetypeinfo)
    add_source("iomem",       "iomem.txt",       parse_iomem)
    add_source("modules",     "modules.txt",     parse_modules)

    # debugfs -- dmabuf
    dmabuf_text = read_file("dmabuf_bufinfo.txt")
    if dmabuf_text:
        sources["debugfs"] = sources.get("debugfs", {})
        sources["debugfs"]["dmabuf"] = {
            "available": True,
            "path": os.path.join(output_dir, "dmabuf_bufinfo.txt"),
            "parsed": parse_dmabuf(dmabuf_text),
        }
    else:
        sources.setdefault("debugfs", {})["dmabuf"] = {"available": False}
        errors.append({"source": "dmabuf", "error": "dmabuf_bufinfo.txt not found"})

    # debugfs -- cma
    cma_dir = os.path.join(output_dir, "cma")
    cma_entries = []
    if os.path.isdir(cma_dir):
        for fname in os.listdir(cma_dir):
            if fname.endswith("_used.txt"):
                region = fname.replace("_used.txt", "")
                text = open(os.path.join(cma_dir, fname)).read()
                cma_entries.extend(parse_cma(text, region))
    sources.setdefault("debugfs", {})["cma"] = {
        "available": bool(cma_entries),
        "path": cma_dir,
        "parsed": cma_entries,
    }

    # debugfs -- kgsl
    kgsl_text = read_file("kgsl_alloc.txt")
    kgsl_total = parse_kgsl_total(kgsl_text) if kgsl_text else 0
    kgsl_proc_dir = os.path.join(output_dir, "kgsl_procs")
    kgsl_procs = parse_kgsl_proc(kgsl_proc_dir)
    sources.setdefault("debugfs", {})["kgsl"] = {
        "available": kgsl_text is not None,
        "path": os.path.join(output_dir, "kgsl_alloc.txt"),
        "parsed": {"total_kb": kgsl_total, "by_process": kgsl_procs},
    }

    # process_stats -- procrank (primary) or smaps_rollup fallback
    procrank_text = read_file("procrank.txt")
    fallback_text = read_file("proc_stats_fallback.txt")
    if procrank_text:
        sources["process_stats"] = {
            "available": True,
            "path": os.path.join(output_dir, "procrank.txt"),
            "parsed": parse_procrank(procrank_text),
        }
    elif fallback_text:
        # Parse "pid pss_kb rss_kb cmdline" format from smaps_rollup fallback
        procs = []
        for line in fallback_text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 3)  # pid pss_kb rss_kb cmdline
            if len(parts) < 2:
                continue
            try:
                pid = int(parts[0])
                pss_kb = int(parts[1])
                rss_kb = int(parts[2]) if len(parts) > 2 else 0
                name = parts[3].strip() if len(parts) > 3 else str(pid)
                procs.append({
                    "pid": pid,
                    "vss_kb": 0,
                    "rss_kb": rss_kb,
                    "pss_kb": pss_kb,
                    "uss_kb": 0,
                    "name": name,
                })
            except (ValueError, IndexError):
                continue
        sources["process_stats"] = {
            "available": bool(procs),
            "path": os.path.join(output_dir, "proc_stats_fallback.txt"),
            "parsed": procs,
        }
        if not procs:
            errors.append({"source": "process_stats", "error": "proc_stats_fallback.txt parse failed"})
    else:
        sources["process_stats"] = {"available": False}
        errors.append({"source": "process_stats", "error": "procrank.txt not found"})

    # dmesg -- kernel static breakdown
    dmesg_text = read_file("dmesg.txt")
    if dmesg_text:
        sources["dmesg"] = {
            "available": True,
            "path": os.path.join(output_dir, "dmesg.txt"),
            "parsed": parse_dmesg_kernel_static(dmesg_text),
        }
    else:
        sources["dmesg"] = {"available": False}
        errors.append({"source": "dmesg", "error": "dmesg.txt not found"})

    # swapinfo
    swap_text = read_file("swapinfo.txt")
    if swap_text:
        sources["swapinfo"] = {
            "available": True,
            "path": os.path.join(output_dir, "swapinfo.txt"),
            "parsed": parse_swapinfo(swap_text),
        }
    else:
        sources["swapinfo"] = {"available": False}
        errors.append({"source": "swapinfo", "error": "swapinfo.txt not found"})

    # zramstat
    zram_text = read_file("zramstat.txt")
    if zram_text:
        sources["zramstat"] = {
            "available": True,
            "path": os.path.join(output_dir, "zramstat.txt"),
            "parsed": parse_zramstat(zram_text),
        }
    else:
        sources["zramstat"] = {"available": False}
        errors.append({"source": "zramstat", "error": "zramstat.txt not found"})

    # memblock
    memblock_text = read_file("memblock.txt")
    if memblock_text:
        sources["memblock"] = {
            "available": True,
            "path": os.path.join(output_dir, "memblock.txt"),
            "parsed": parse_memblock(memblock_text),
        }
    else:
        sources["memblock"] = {"available": False}
        errors.append({"source": "memblock", "error": "memblock.txt not found"})

    # kgsl_gpu_mem
    kgsl_gpu_text = read_file("kgsl_gpu_mem.txt")
    if kgsl_gpu_text:
        sources.setdefault("debugfs", {})["kgsl_gpu"] = {
            "available": True,
            "path": os.path.join(output_dir, "kgsl_gpu_mem.txt"),
            "parsed": parse_kgsl_gpu_mem(kgsl_gpu_text),
        }
    else:
        sources.setdefault("debugfs", {})["kgsl_gpu"] = {"available": False}
        errors.append({"source": "kgsl_gpu", "error": "kgsl_gpu_mem.txt not found"})

    # smaps -- per-process detailed mappings
    smaps_dir = os.path.join(output_dir, "smaps")
    smaps_entries = []
    if os.path.isdir(smaps_dir):
        for fname in sorted(os.listdir(smaps_dir)):
            if fname.endswith("_smaps.txt"):
                try:
                    pid = int(fname.split("_")[0])
                    text = open(os.path.join(smaps_dir, fname),
                                encoding="utf-8", errors="replace").read()
                    smaps_entries.append(parse_smaps(text, pid))
                except (ValueError, OSError):
                    continue
    sources["smaps"] = {
        "available": bool(smaps_entries),
        "path": smaps_dir,
        "parsed": smaps_entries,
    }
    if not smaps_entries:
        errors.append({"source": "smaps", "error": "no smaps files found"})

    # reserved_memory
    reserved_dir = os.path.join(output_dir, "reserved-memory")
    nodes = parse_dt_reserved_memory(reserved_dir)
    sources["reserved_memory"] = {
        "available": bool(nodes),
        "nodes": nodes,
    }
    if not nodes:
        errors.append({"source": "reserved_memory", "error": "no DT reserved-memory nodes found"})

    return sources, errors


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Collect and normalize memory data from a Qualcomm Linux device."
    )
    # Connection args (mutually exclusive: --serial for ADB, --host for SSH)
    conn = parser.add_argument_group("Connection (auto-selects transport)")
    conn.add_argument("-s", "--serial",
                      help="ADB device serial (from 'adb devices') -- uses ADB transport")
    conn.add_argument("--host",
                      help="SSH hostname or IP address -- uses SSH transport")
    conn.add_argument("--user", default="root",
                      help="SSH username (default: root)")
    conn.add_argument("--port", type=int, default=22,
                      help="SSH port (default: 22)")
    conn.add_argument("--key", metavar="KEY_FILE",
                      help="SSH private key file (default: ~/.ssh/id_rsa)")
    conn.add_argument("--password", metavar="PASSWORD",
                      help="SSH password (if not provided, prompted interactively)")

    parser.add_argument("-o", "--output", default="mem_dump",
                        help="Output directory (default: mem_dump)")
    parser.add_argument("--label", default="snapshot",
                        help="Human-readable label for this snapshot")
    parser.add_argument("--no-pull", action="store_true",
                        help="Skip collection; normalize files already in --output")
    args = parser.parse_args()

    output_dir = args.output
    collection_errors: list = []

    # Step 1: collect from device (unless --no-pull)
    if not args.no_pull:
        transport = make_transport(args)
        transport_type = "SSH" if isinstance(transport, SshTransport) else "ADB"
        print(f"[data-collection] Collecting from device ({transport_type}: {transport.device_id})...")
        device_info = get_device_info(transport)
        errs = collect_from_device(transport, output_dir)
        transport.close()
        collection_errors.extend(errs)
        if errs:
            print(f"[data-collection] {len(errs)} source(s) unavailable (non-fatal):")
            for e in errs:
                print(f"  - {e['source']}: {e['error']}")
    else:
        print(f"[data-collection] Offline mode -- normalizing files in {output_dir}/")
        device_info = {"serial": "offline"}

    # Step 2: normalize
    print("[data-collection] Normalizing sources...")
    sources, parse_errors = normalize(output_dir)
    collection_errors.extend(parse_errors)

    # Step 3: build snapshot
    snapshot = {
        "schema_version": "1.0.0",
        "snapshot_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "label": args.label,
        "device": device_info,
        "dump_dir": output_dir,
        "sources": sources,
        "collection_errors": collection_errors,
    }

    # Step 4: write snapshot.json
    out_path = os.path.join(output_dir, "snapshot.json")
    os.makedirs(output_dir, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(snapshot, f, indent=2)

    available = sum(
        1 for v in sources.values()
        if isinstance(v, dict) and v.get("available")
    )
    print(f"[data-collection] Done. {available}/{len(sources)} sources available.")
    print(f"[data-collection] Snapshot written to: {out_path}")

    if collection_errors:
        print(f"[data-collection] {len(collection_errors)} error(s) recorded in snapshot.json")

    return 0


if __name__ == "__main__":
    sys.exit(main())