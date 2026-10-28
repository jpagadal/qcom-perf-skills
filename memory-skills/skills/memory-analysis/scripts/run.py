#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""
memory-analysis -- Unified Memory Analysis Skill

Supports four analysis modes, auto-detected from the parameters provided:

  1. Snapshot      : Single memory snapshot from a connected device
  2. Workload      : Measure memory impact of a workload or application
     2A. Preset    : Use a named preset from usecases/presets.json
     2B. Custom    : Provide a custom shell command
     2C. User-Launched : User launches the workload manually; skill collects before/after
  3. Regression    : Compare live device against a pre-collected reference snapshot
  4. Comparison    : Compare two pre-collected snapshots (no device needed)

Usage:
    # Mode 1: Single snapshot
    python run.py [--serial <serial>] [--host <ip>] [--user root]

    # Mode 2A: Workload impact (preset)
    python run.py --workload <preset> [--serial <serial>] [--wait <seconds>]

    # Mode 2B: Workload impact (custom command)
    python run.py --command "<cmd>" --workload-name "<label>" [--serial <serial>]

    # Mode 2C: Workload impact (user-launched, interactive — single command)
    python run.py --user-launched --interactive [--reboot] [--serial <serial>]

    # Mode 2C: Workload impact (user-launched, agent-driven — multi-step)
    python run.py --user-launched --label baseline [--reboot] [--serial <serial>] [--output-dir <dir>]
    # ... user launches use-case on device ...
    python run.py --user-launched --label active [--serial <serial>] --output-dir <same-dir>
    python run.py --compare-snapshots <baseline_dir> <active_dir>

    # Mode 3: Regression test (live device vs reference)
    python run.py --reference <path> [--serial <serial>]

    # Mode 4: Compare two pre-collected snapshots (no device needed)
    python run.py --current <path> --reference <path>

Standard Prompts (for AI agents):
    "Give me a memory report for the connected device"
    "How much memory does the camera use?"
    "I want to measure memory of a use-case I'll launch manually"
    "Collect baseline, then I'll launch my app, then collect active"
    "Is this device using more memory than the reference?"
    "Compare results/build_v2/ against results/build_v1/"

Examples:
    python skills/memory-analysis/scripts/run.py --serial 0426df75
    python skills/memory-analysis/scripts/run.py --workload camera_h264_encoding --serial 0426df75
    python skills/memory-analysis/scripts/run.py --user-launched --interactive --serial 0426df75
    python skills/memory-analysis/scripts/run.py --user-launched --interactive --reboot --serial 0426df75
    python skills/memory-analysis/scripts/run.py --user-launched --label baseline --serial 0426df75 --output-dir results/my_session
    python skills/memory-analysis/scripts/run.py --user-launched --label active --serial 0426df75 --output-dir results/my_session
    python skills/memory-analysis/scripts/run.py --compare-snapshots results/my_session/baseline results/my_session/active
    python skills/memory-analysis/scripts/run.py --reference results/golden/ --serial 0426df75
    python skills/memory-analysis/scripts/run.py --current results/build_v2/ --reference results/build_v1/
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Resolve internal module paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
INTERNAL  = REPO_ROOT / "internal"
SKILLS    = REPO_ROOT / "skills"

COLLECT           = INTERNAL / "data-collection"     / "scripts" / "collect.py"
COMPARE_SNAPSHOTS = INTERNAL / "snapshot-comparison" / "scripts" / "compare_snapshots.py"
KERNEL_DIFF       = INTERNAL / "kernel-diff"          / "scripts" / "analyze_kernel_diff.py"
USERSPACE_DIFF    = INTERNAL / "userspace-diff"       / "scripts" / "analyze_userspace_diff.py"
ANALYZE_RCA       = INTERNAL / "anomaly-rca"          / "scripts" / "analyze_rca.py"
GENERATE_REPORT   = INTERNAL / "report-generation"    / "scripts" / "generate_report.py"

PRESETS_FILE = SKILLS / "memory-analysis" / "usecases" / "presets.json"

# Default working directory for systemd-run on device
DEVICE_WORKING_DIR = "/opt/models_data"

TAG = "[memory-analysis]"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: list, step: str) -> None:
    """Run a subprocess command and exit on failure."""
    print(f"\n{TAG} {step}")
    result = subprocess.run(cmd, text=True)
    if result.returncode != 0:
        print(f"{TAG} ERROR: {step} failed (exit {result.returncode})")
        sys.exit(result.returncode)


def run_on_device(serial: str | None, host: str | None, user: str, cmd: str,
                  capture: bool = False) -> tuple[int, str]:
    """Run a shell command on the device via ADB or SSH."""
    if host:
        result = subprocess.run(
            ["ssh", f"{user}@{host}", cmd],
            text=True, capture_output=capture
        )
    elif serial:
        result = subprocess.run(
            ["adb", "-s", serial, "shell", cmd],
            text=True, capture_output=capture
        )
    else:
        result = subprocess.run(
            ["adb", "shell", cmd],
            text=True, capture_output=capture
        )
    stdout = result.stdout.strip() if capture and result.stdout else ""
    return result.returncode, stdout


def load_preset(name: str) -> dict:
    """Load a use-case preset from presets.json."""
    if not PRESETS_FILE.is_file():
        print(f"{TAG} ERROR: presets.json not found at {PRESETS_FILE}")
        sys.exit(1)
    with open(PRESETS_FILE) as f:
        data = json.load(f)
    presets = data.get("presets", data)
    if name not in presets:
        available = ", ".join(k for k in presets.keys() if not k.startswith("_"))
        print(f"{TAG} ERROR: preset '{name}' not found.")
        print(f"  Available presets: {available}")
        sys.exit(1)
    return presets[name]


def read_snapshot_label(snapshot_dir: Path) -> str:
    """Read the label field from snapshot.json."""
    snap_path = snapshot_dir / "snapshot.json"
    try:
        with open(snap_path) as f:
            return json.load(f).get("label", snapshot_dir.name)
    except Exception:
        return snapshot_dir.name


def read_device_info(snapshot_path: Path) -> dict:
    """Read device info from snapshot.json for report title."""
    try:
        with open(snapshot_path) as f:
            return json.load(f).get("device", {})
    except Exception:
        return {}


def validate_snapshot_dir(path: str, label: str) -> Path:
    """Validate that a snapshot directory contains snapshot.json."""
    p = Path(path)
    snap = p / "snapshot.json"
    if not snap.is_file():
        print(f"{TAG} ERROR: {label} snapshot not found: {snap}")
        print(f"  Expected a directory containing snapshot.json")
        sys.exit(1)
    return p


def collect_cmd(args, out_dir: Path, label: str) -> list:
    """Build the data-collection command."""
    cmd = [sys.executable, str(COLLECT),
           "--output", str(out_dir),
           "--label",  label]
    if args.serial:
        cmd += ["--serial", args.serial]
    elif args.host:
        cmd += ["--host", args.host, "--user", args.user]
        if getattr(args, "password", None):
            cmd += ["--password", args.password]
    return cmd


def move_intermediates(reports_dir: Path) -> None:
    """Move intermediate JSON files to _intermediate/ subdirectory."""
    intermediate_dir = reports_dir / "_intermediate"
    intermediate_dir.mkdir(exist_ok=True)
    for json_file in reports_dir.glob("*.json"):
        json_file.rename(intermediate_dir / json_file.name)


# ---------------------------------------------------------------------------
# systemd-run workload management (Mode 2: Workload)
# ---------------------------------------------------------------------------

def make_unit_name(workload_key: str) -> str:
    """Generate a unique systemd unit name for this workload run."""
    ts = datetime.now().strftime("%H%M%S")
    safe = "".join(c if c.isalnum() or c == "-" else "-" for c in workload_key.lower())
    return f"mem-skill-{safe}-{ts}"


def start_workload_systemd(serial, host, user, command, unit_name,
                           working_dir=DEVICE_WORKING_DIR) -> bool:
    """Start workload on device using systemd-run. Returns True if started."""
    systemd_cmd = (
        f"systemd-run --unit={unit_name} "
        f"--working-directory={working_dir} "
        f"{command}"
    )
    print(f"{TAG} systemd-run unit: {unit_name}")
    print(f"{TAG} Command: {command}")
    rc, _ = run_on_device(serial, host, user, systemd_cmd)
    if rc != 0:
        print(f"{TAG} ERROR: systemd-run failed to start workload (exit {rc})")
        return False
    return True


def check_workload_alive(serial, host, user, unit_name) -> bool:
    """Check if the systemd unit is still active."""
    rc, _ = run_on_device(serial, host, user,
                          f"systemctl is-active {unit_name}", capture=True)
    return rc == 0


def stop_workload_systemd(serial, host, user, unit_name) -> None:
    """Stop the systemd unit and clean up."""
    print(f"{TAG} Stopping unit: {unit_name}")
    run_on_device(serial, host, user, f"systemctl stop {unit_name} 2>/dev/null || true")
    rc, status = run_on_device(serial, host, user,
                               f"systemctl is-active {unit_name}", capture=True)
    if rc == 0:
        print(f"{TAG} WARNING: unit {unit_name} still active after stop")
    else:
        print(f"{TAG} Unit {unit_name} stopped (status: {status})")


def wait_with_health_check(serial, host, user, unit_name, wait_sec) -> bool:
    """Wait for wait_sec seconds while monitoring workload health."""
    print(f"{TAG} Monitoring workload for {wait_sec}s...")
    check_interval = 2
    elapsed = 0
    while elapsed < wait_sec:
        time.sleep(check_interval)
        elapsed += check_interval
        alive = check_workload_alive(serial, host, user, unit_name)
        status = "alive" if alive else "STOPPED"
        print(f"{TAG}   [{elapsed:3d}s / {wait_sec}s] workload: {status}")
        if not alive:
            print(f"{TAG} WARNING: workload stopped early at {elapsed}s")
            rc, log = run_on_device(serial, host, user,
                                    f"journalctl -u {unit_name} --no-pager -n 5 2>/dev/null",
                                    capture=True)
            if log:
                print(f"{TAG} Last log lines:\n{log}")
            return False
    return True


def reboot_and_wait(args) -> None:
    """Reboot device and wait for it to come back online."""
    print(f"\n{TAG} Rebooting device for clean baseline state...")
    if args.host:
        subprocess.run(["ssh", f"{args.user}@{args.host}", "reboot"], text=True)
    elif args.serial:
        subprocess.run(["adb", "-s", args.serial, "reboot"], text=True)
    else:
        subprocess.run(["adb", "reboot"], text=True)

    print(f"{TAG} Waiting for device to come back online...")
    if args.host:
        for _ in range(60):
            time.sleep(2)
            try:
                s = socket.create_connection((args.host, 22), timeout=3)
                s.close()
                break
            except OSError:
                pass
    elif args.serial:
        subprocess.run(["adb", "-s", args.serial, "wait-for-device"], text=True)
    else:
        subprocess.run(["adb", "wait-for-device"], text=True)
    print(f"{TAG} Device online.")


# ---------------------------------------------------------------------------
# Mode implementations
# ---------------------------------------------------------------------------

def mode_snapshot(args, output_dir: Path) -> Path:
    """
    Mode 1: Single Snapshot
    Collect one memory snapshot and generate a standalone report.
    """
    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    print(f"{TAG} Mode: Snapshot")
    print(f"{TAG} Output: {output_dir}")

    # Collect snapshot
    snapshot_dir = output_dir / "snapshot"
    run(collect_cmd(args, snapshot_dir, args.label or "snapshot"),
        "Collecting memory snapshot")

    snapshot_path = snapshot_dir / "snapshot.json"
    if not snapshot_path.is_file():
        print(f"{TAG} ERROR: snapshot.json not found at {snapshot_path}")
        sys.exit(1)

    # Build report title
    device = read_device_info(snapshot_path)
    model  = device.get("model", "Unknown Device")
    soc    = device.get("soc_id", "")
    title  = f"Memory Snapshot -- {model}" + (f" ({soc})" if soc else "")

    snap    = str(snapshot_path)
    reports = str(reports_dir)

    # Snapshot comparison against itself (produces summary table)
    run([sys.executable, str(COMPARE_SNAPSHOTS),
         "--current",    snap,
         "--reference",  snap,
         "--output-dir", reports,
         "--format",     "json"],
        "Running snapshot analysis")

    # Generate report
    run([sys.executable, str(GENERATE_REPORT),
         "--input",              os.path.join(reports, "snapshot_comparison_report.json"),
         "--format",             "html,xlsx",
         "--unified",
         "--title",              title,
         "--output-dir",         reports,
         "--snapshot-current",   snap,
         "--snapshot-reference", snap],
        "Generating snapshot report")

    src = reports_dir / "unified_report.html"
    dst = reports_dir / "snapshot_report.html"
    if src.is_file():
        src.rename(dst)

    move_intermediates(reports_dir)
    return dst


def mode_workload(args, output_dir: Path) -> Path:
    """
    Mode 2: Workload Impact
    Collect idle baseline, run workload, collect active snapshot, compare.
    """
    # Resolve workload definition
    if args.workload:
        preset        = load_preset(args.workload)
        workload_name = preset.get("name", args.workload)
        workload_key  = args.workload
        command       = preset.get("command", "")
        setup_cmds    = preset.get("setup", [])
        teardown_cmds = preset.get("teardown", [])
        wait_sec      = args.wait or preset.get("wait_sec", 15)
    else:
        if not args.workload_name:
            print(f"{TAG} ERROR: --workload-name is required when using --command")
            sys.exit(1)
        workload_name = args.workload_name
        workload_key  = args.workload_name.replace(" ", "_").lower()
        command       = args.command
        setup_cmds    = []
        teardown_cmds = []
        wait_sec      = args.wait or 15

    baseline_dir = output_dir / "baseline"
    active_dir   = output_dir / "active"
    reports_dir  = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    print(f"{TAG} Mode: Workload Impact")
    print(f"{TAG} Workload: {workload_name}")
    print(f"{TAG} Command:  {command}")
    print(f"{TAG} Wait:     {wait_sec}s")
    print(f"{TAG} Output:   {output_dir}")

    # Reboot for clean baseline (unless skipped)
    if not args.skip_reboot:
        reboot_and_wait(args)
    else:
        print(f"\n{TAG} Skipping reboot (--skip-reboot specified)")

    # Collect idle baseline
    run(collect_cmd(args, baseline_dir, "baseline_idle"),
        "Collecting idle baseline snapshot")

    # Run setup commands
    for cmd in setup_cmds:
        print(f"{TAG} Setup: {cmd}")
        run_on_device(args.serial, args.host, args.user, cmd)

    # Start workload via systemd-run
    unit_name = make_unit_name(workload_key)
    started = start_workload_systemd(
        args.serial, args.host, args.user,
        command, unit_name, args.working_dir
    )
    if not started:
        sys.exit(1)

    # Wait with health monitoring
    workload_survived = wait_with_health_check(
        args.serial, args.host, args.user, unit_name, wait_sec
    )
    if not workload_survived:
        print(f"{TAG} NOTE: workload completed before wait_sec elapsed.")
        print(f"{TAG} Proceeding with snapshot collection.")

    # Collect active snapshot
    run(collect_cmd(args, active_dir, workload_key),
        "Collecting active snapshot")

    # Stop workload and run teardown
    stop_workload_systemd(args.serial, args.host, args.user, unit_name)
    for cmd in teardown_cmds:
        print(f"{TAG} Teardown: {cmd}")
        run_on_device(args.serial, args.host, args.user, cmd)

    baseline_snap  = str(baseline_dir / "snapshot.json")
    active_snap    = str(active_dir   / "snapshot.json")
    reports        = str(reports_dir)
    baseline_label = read_snapshot_label(baseline_dir)
    active_label   = read_snapshot_label(active_dir)
    title = f"{active_label} vs {baseline_label} -- {workload_name} Memory Impact"

    # Snapshot comparison
    run([sys.executable, str(COMPARE_SNAPSHOTS),
         "--current",         active_snap,
         "--reference",       baseline_snap,
         "--output-dir",      reports,
         "--threshold-pct",   "3.0",
         "--threshold-mb",    "5.0",
         "--usecase-name",    workload_name,
         "--usecase-command", command,
         "--format",          "json"],
        "Running snapshot comparison")

    # Kernel diff
    run([sys.executable, str(KERNEL_DIFF),
         "--current",    active_snap,
         "--reference",  baseline_snap,
         "--output-dir", reports,
         "--format",     "json"],
        "Running kernel memory diff")

    # Userspace diff
    run([sys.executable, str(USERSPACE_DIFF),
         "--current",        active_snap,
         "--reference",      baseline_snap,
         "--output-dir",     reports,
         "--pss-growth-pct", "10.0",
         "--pss-growth-mb",  "5.0",
         "--format",         "json"],
        "Running userspace memory diff")

    # Generate report
    # Anomaly RCA
    run([sys.executable, str(ANALYZE_RCA),
         "--comparison-report", os.path.join(reports, "snapshot_comparison_report.json"),
         "--kernel-diff",       os.path.join(reports, "kernel_diff_report.json"),
         "--userspace-diff",    os.path.join(reports, "userspace_diff_report.json"),
         "--output-dir",        reports],
        "Running anomaly root cause analysis")

    run([sys.executable, str(GENERATE_REPORT),
         "--input",
             os.path.join(reports, "snapshot_comparison_report.json"),
             os.path.join(reports, "kernel_diff_report.json"),
             os.path.join(reports, "userspace_diff_report.json"),
             os.path.join(reports, "rca_report.json"),
         "--format",             "html,xlsx",
         "--unified",
         "--title",              title,
         "--output-dir",         reports,
         "--snapshot-current",   active_snap,
         "--snapshot-reference", baseline_snap],
        "Generating workload impact report")

    src = reports_dir / "unified_report.html"
    dst = reports_dir / "workload_impact_report.html"
    if src.is_file():
        src.rename(dst)

    move_intermediates(reports_dir)
    return dst


def mode_regression(args, output_dir: Path) -> Path:
    """
    Mode 3: Regression Test (Live Device vs Reference)
    Collect current snapshot from device, compare against reference.
    """
    reference_dir   = validate_snapshot_dir(args.reference, "reference")
    reference_label = read_snapshot_label(reference_dir)

    snapshot_dir = output_dir / "snapshot"
    reports_dir  = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    print(f"{TAG} Mode: Regression Test")
    print(f"{TAG} Reference: {reference_dir}")
    print(f"{TAG} Output:    {output_dir}")

    # Collect current snapshot from device
    run(collect_cmd(args, snapshot_dir, args.label or "current"),
        "Collecting snapshot from device")

    current_snap   = str(snapshot_dir  / "snapshot.json")
    reference_snap = str(reference_dir / "snapshot.json")
    reports        = str(reports_dir)
    current_label  = read_snapshot_label(snapshot_dir)
    title = args.title or f"{current_label} vs {reference_label} -- Regression Test"

    # Snapshot comparison
    run([sys.executable, str(COMPARE_SNAPSHOTS),
         "--current",       current_snap,
         "--reference",     reference_snap,
         "--output-dir",    reports,
         "--threshold-pct", "3.0",
         "--threshold-mb",  "5.0",
         "--format",        "json"],
        "Running snapshot comparison")

    # Kernel diff
    run([sys.executable, str(KERNEL_DIFF),
         "--current",    current_snap,
         "--reference",  reference_snap,
         "--output-dir", reports,
         "--format",     "json"],
        "Running kernel memory diff")

    # Userspace diff
    run([sys.executable, str(USERSPACE_DIFF),
         "--current",        current_snap,
         "--reference",      reference_snap,
         "--output-dir",     reports,
         "--pss-growth-pct", "10.0",
         "--pss-growth-mb",  "5.0",
         "--format",         "json"],
        "Running userspace memory diff")

    # Generate report
    # Anomaly RCA
    run([sys.executable, str(ANALYZE_RCA),
         "--comparison-report", os.path.join(reports, "snapshot_comparison_report.json"),
         "--kernel-diff",       os.path.join(reports, "kernel_diff_report.json"),
         "--userspace-diff",    os.path.join(reports, "userspace_diff_report.json"),
         "--output-dir",        reports],
        "Running anomaly root cause analysis")

    run([sys.executable, str(GENERATE_REPORT),
         "--input",
             os.path.join(reports, "snapshot_comparison_report.json"),
             os.path.join(reports, "kernel_diff_report.json"),
             os.path.join(reports, "userspace_diff_report.json"),
             os.path.join(reports, "rca_report.json"),
         "--format",             "html,xlsx",
         "--unified",
         "--title",              title,
         "--output-dir",         reports,
         "--snapshot-current",   current_snap,
         "--snapshot-reference", reference_snap],
        "Generating regression report")

    src = reports_dir / "unified_report.html"
    dst = reports_dir / "regression_report.html"
    if src.is_file():
        src.rename(dst)

    move_intermediates(reports_dir)
    return dst


def mode_comparison(args, output_dir: Path) -> Path:
    """
    Mode 4: Compare Two Pre-Collected Snapshots (Offline)
    No device connection required.
    """
    current_dir   = validate_snapshot_dir(args.current,   "current")
    reference_dir = validate_snapshot_dir(args.reference, "reference")

    current_label   = read_snapshot_label(current_dir)
    reference_label = read_snapshot_label(reference_dir)

    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    title = args.title or f"{current_label} vs {reference_label} -- Memory Comparison"

    current_snap   = str(current_dir   / "snapshot.json")
    reference_snap = str(reference_dir / "snapshot.json")
    reports        = str(reports_dir)

    print(f"{TAG} Mode: Snapshot Comparison")
    print(f"{TAG} Current:   {current_dir}")
    print(f"{TAG} Reference: {reference_dir}")
    print(f"{TAG} Output:    {output_dir}")

    # Snapshot comparison
    run([sys.executable, str(COMPARE_SNAPSHOTS),
         "--current",       current_snap,
         "--reference",     reference_snap,
         "--output-dir",    reports,
         "--threshold-pct", "3.0",
         "--threshold-mb",  "5.0",
         "--format",        "json"],
        "Running snapshot comparison")

    # Kernel diff
    run([sys.executable, str(KERNEL_DIFF),
         "--current",    current_snap,
         "--reference",  reference_snap,
         "--output-dir", reports,
         "--format",     "json"],
        "Running kernel memory diff")

    # Userspace diff
    run([sys.executable, str(USERSPACE_DIFF),
         "--current",        current_snap,
         "--reference",      reference_snap,
         "--output-dir",     reports,
         "--pss-growth-pct", "10.0",
         "--pss-growth-mb",  "5.0",
         "--format",         "json"],
        "Running userspace memory diff")

    # Generate report
    # Anomaly RCA
    run([sys.executable, str(ANALYZE_RCA),
         "--comparison-report", os.path.join(reports, "snapshot_comparison_report.json"),
         "--kernel-diff",       os.path.join(reports, "kernel_diff_report.json"),
         "--userspace-diff",    os.path.join(reports, "userspace_diff_report.json"),
         "--output-dir",        reports],
        "Running anomaly root cause analysis")

    run([sys.executable, str(GENERATE_REPORT),
         "--input",
             os.path.join(reports, "snapshot_comparison_report.json"),
             os.path.join(reports, "kernel_diff_report.json"),
             os.path.join(reports, "userspace_diff_report.json"),
             os.path.join(reports, "rca_report.json"),
         "--format",             "html,xlsx",
         "--unified",
         "--title",              title,
         "--output-dir",         reports,
         "--snapshot-current",   current_snap,
         "--snapshot-reference", reference_snap],
        "Generating comparison report")

    src = reports_dir / "unified_report.html"
    dst = reports_dir / "comparison_report.html"
    if src.is_file():
        src.rename(dst)

    move_intermediates(reports_dir)
    return dst


def mode_user_launched_collect(args, output_dir: Path) -> None:
    """
    Mode 2C: Workload Impact (User-Launched) — Collection Step
    Collect a single snapshot with a given label (baseline or active).
    The user is responsible for launching/stopping the workload between steps.
    The AI agent orchestrates the multi-step workflow.
    """
    label = args.label or "snapshot"
    snapshot_dir = output_dir / label

    print(f"{TAG} Mode: Workload Impact (User-Launched)")
    print(f"{TAG} Step:   Collect {label} snapshot")
    print(f"{TAG} Output: {output_dir}")

    # Optional reboot before baseline collection
    if label == "baseline" and args.reboot:
        reboot_and_wait(args)

    run(collect_cmd(args, snapshot_dir, label),
        f"Collecting {label} snapshot")

    snapshot_path = snapshot_dir / "snapshot.json"
    if not snapshot_path.is_file():
        print(f"{TAG} ERROR: snapshot.json not found at {snapshot_path}")
        sys.exit(1)

    print(f"\n{TAG} Done.")
    print(f"{TAG} Snapshot saved: {snapshot_dir}")
    print(f"{TAG} Session dir:    {output_dir}")

    # Print next-step guidance for agent
    if label == "baseline":
        active_dir = output_dir / "active"
        print(f"\n{TAG} ── Agent: Next Steps ──────────────────────────────────")
        print(f"{TAG}   1. Ask user to launch their use-case on the device")
        print(f"{TAG}   2. Collect active: python run.py --user-launched --label active --output-dir {output_dir}")
        print(f"{TAG}   3. Compare:        python run.py --compare-snapshots {snapshot_dir} {active_dir}")
        print(f"{TAG} ────────────────────────────────────────────────────────")
    elif label == "active":
        baseline_dir = output_dir / "baseline"
        print(f"\n{TAG} ── Agent: Next Step ───────────────────────────────────")
        print(f"{TAG}   Compare: python run.py --compare-snapshots {baseline_dir} {snapshot_dir}")
        print(f"{TAG} ────────────────────────────────────────────────────────")


def mode_user_launched_interactive(args, output_dir: Path) -> Path:
    """
    Mode 2C: Workload Impact (User-Launched) — Interactive Mode
    Single command that guides the user through the entire workflow:
      1. (Optional) Reboot device
      2. Collect baseline snapshot
      3. Prompt user to launch use-case
      4. Collect active snapshot
      5. Compare and generate report
    """
    baseline_dir = output_dir / "baseline"
    active_dir   = output_dir / "active"
    reports_dir  = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    print(f"{TAG} Mode: Workload Impact (User-Launched, Interactive)")
    print(f"{TAG} Output: {output_dir}")

    # Step 0: Optional reboot
    if args.reboot:
        reboot_and_wait(args)

    # Step 1: Collect baseline
    print(f"\n{TAG} ── Step 1/4: Collecting baseline snapshot ──────────────")
    run(collect_cmd(args, baseline_dir, "baseline"),
        "Collecting baseline snapshot")
    print(f"{TAG} Baseline snapshot saved.")

    # Step 2: Prompt user to launch use-case
    print(f"\n{TAG} ── Step 2/4: Launch your use-case ──────────────────────")
    print(f"{TAG} Please launch your use-case on the device now.")
    print(f"{TAG} Wait for it to stabilize before pressing ENTER.")
    print(f"{TAG}")
    try:
        input(f"{TAG} >>> Press ENTER when your use-case is running and stable: ")
    except EOFError:
        # Non-interactive environment (e.g., piped input) — proceed immediately
        print(f"{TAG} (non-interactive: proceeding automatically)")

    # Step 3: Collect active snapshot
    print(f"\n{TAG} ── Step 3/4: Collecting active snapshot ────────────────")
    run(collect_cmd(args, active_dir, "active"),
        "Collecting active snapshot")
    print(f"{TAG} Active snapshot saved.")

    # Step 4: Compare and generate report
    print(f"\n{TAG} ── Step 4/4: Comparing snapshots ────────────────────────")

    baseline_snap  = str(baseline_dir / "snapshot.json")
    active_snap    = str(active_dir   / "snapshot.json")
    reports        = str(reports_dir)
    baseline_label = read_snapshot_label(baseline_dir)
    active_label   = read_snapshot_label(active_dir)
    title = args.title or f"{active_label} vs {baseline_label} -- User-Launched Workload Memory Impact"

    # Snapshot comparison
    run([sys.executable, str(COMPARE_SNAPSHOTS),
         "--current",       active_snap,
         "--reference",     baseline_snap,
         "--output-dir",    reports,
         "--threshold-pct", "3.0",
         "--threshold-mb",  "5.0",
         "--format",        "json"],
        "Running snapshot comparison")

    # Kernel diff
    run([sys.executable, str(KERNEL_DIFF),
         "--current",    active_snap,
         "--reference",  baseline_snap,
         "--output-dir", reports,
         "--format",     "json"],
        "Running kernel memory diff")

    # Userspace diff
    run([sys.executable, str(USERSPACE_DIFF),
         "--current",        active_snap,
         "--reference",      baseline_snap,
         "--output-dir",     reports,
         "--pss-growth-pct", "10.0",
         "--pss-growth-mb",  "5.0",
         "--format",         "json"],
        "Running userspace memory diff")

    # Anomaly RCA
    run([sys.executable, str(ANALYZE_RCA),
         "--comparison-report", os.path.join(reports, "snapshot_comparison_report.json"),
         "--kernel-diff",       os.path.join(reports, "kernel_diff_report.json"),
         "--userspace-diff",    os.path.join(reports, "userspace_diff_report.json"),
         "--output-dir",        reports],
        "Running anomaly root cause analysis")

    # Generate report
    run([sys.executable, str(GENERATE_REPORT),
         "--input",
             os.path.join(reports, "snapshot_comparison_report.json"),
             os.path.join(reports, "kernel_diff_report.json"),
             os.path.join(reports, "userspace_diff_report.json"),
             os.path.join(reports, "rca_report.json"),
         "--format",             "html,xlsx",
         "--unified",
         "--title",              title,
         "--output-dir",         reports,
         "--snapshot-current",   active_snap,
         "--snapshot-reference", baseline_snap],
        "Generating workload impact report")

    src = reports_dir / "unified_report.html"
    dst = reports_dir / "workload_impact_report.html"
    if src.is_file():
        src.rename(dst)

    move_intermediates(reports_dir)
    return dst


def mode_user_launched_compare(args, output_dir: Path) -> Path:
    """
    Mode 2C: Workload Impact (User-Launched) — Comparison Step
    Compare baseline and active snapshots collected via --user-launched.
    Generates a workload_impact_report.html identical in format to Mode 2A/2B.
    """
    baseline_dir = validate_snapshot_dir(args.compare_snapshots[0], "baseline")
    active_dir   = validate_snapshot_dir(args.compare_snapshots[1], "active")

    baseline_label = read_snapshot_label(baseline_dir)
    active_label   = read_snapshot_label(active_dir)

    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    title = args.title or f"{active_label} vs {baseline_label} -- User-Launched Workload Memory Impact"

    baseline_snap = str(baseline_dir / "snapshot.json")
    active_snap   = str(active_dir   / "snapshot.json")
    reports       = str(reports_dir)

    print(f"{TAG} Mode: Workload Impact (User-Launched)")
    print(f"{TAG} Step:     Compare snapshots")
    print(f"{TAG} Baseline: {baseline_dir}")
    print(f"{TAG} Active:   {active_dir}")
    print(f"{TAG} Output:   {output_dir}")

    # Snapshot comparison
    run([sys.executable, str(COMPARE_SNAPSHOTS),
         "--current",       active_snap,
         "--reference",     baseline_snap,
         "--output-dir",    reports,
         "--threshold-pct", "3.0",
         "--threshold-mb",  "5.0",
         "--format",        "json"],
        "Running snapshot comparison")

    # Kernel diff
    run([sys.executable, str(KERNEL_DIFF),
         "--current",    active_snap,
         "--reference",  baseline_snap,
         "--output-dir", reports,
         "--format",     "json"],
        "Running kernel memory diff")

    # Userspace diff
    run([sys.executable, str(USERSPACE_DIFF),
         "--current",        active_snap,
         "--reference",      baseline_snap,
         "--output-dir",     reports,
         "--pss-growth-pct", "10.0",
         "--pss-growth-mb",  "5.0",
         "--format",         "json"],
        "Running userspace memory diff")

    # Anomaly RCA
    run([sys.executable, str(ANALYZE_RCA),
         "--comparison-report", os.path.join(reports, "snapshot_comparison_report.json"),
         "--kernel-diff",       os.path.join(reports, "kernel_diff_report.json"),
         "--userspace-diff",    os.path.join(reports, "userspace_diff_report.json"),
         "--output-dir",        reports],
        "Running anomaly root cause analysis")

    # Generate report
    run([sys.executable, str(GENERATE_REPORT),
         "--input",
             os.path.join(reports, "snapshot_comparison_report.json"),
             os.path.join(reports, "kernel_diff_report.json"),
             os.path.join(reports, "userspace_diff_report.json"),
             os.path.join(reports, "rca_report.json"),
         "--format",             "html,xlsx",
         "--unified",
         "--title",              title,
         "--output-dir",         reports,
         "--snapshot-current",   active_snap,
         "--snapshot-reference", baseline_snap],
        "Generating workload impact report")

    src = reports_dir / "unified_report.html"
    dst = reports_dir / "workload_impact_report.html"
    if src.is_file():
        src.rename(dst)

    move_intermediates(reports_dir)
    return dst


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="memory-analysis",
        description=(
            "Unified memory analysis for Qualcomm Linux devices.\n\n"
            "Mode is auto-detected from the parameters provided:\n"
            "  Snapshot   : --serial / --host (no --reference, no --workload)\n"
            "  Workload   : --workload <preset> or --command <cmd>\n"
            "  Regression : --reference <path> with a connected device\n"
            "  Comparison : --current <path> --reference <path>\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Standard Prompts (for AI agents):\n"
            '  "Give me a memory report for the connected device"\n'
            '  "How much memory does the camera use?"\n'
            '  "Is this device using more memory than the reference?"\n'
            '  "Compare results/build_v2/ against results/build_v1/"\n\n'
            "Examples:\n"
            "  python skills/memory-analysis/scripts/run.py --serial 0426df75\n"
            "  python skills/memory-analysis/scripts/run.py --workload camera_h264_encoding\n"
            "  python skills/memory-analysis/scripts/run.py --reference results/golden/\n"
            "  python skills/memory-analysis/scripts/run.py --current results/build_v2/ --reference results/build_v1/\n"
        )
    )

    # --- Workload parameters (Mode 2) ---
    workload_group = parser.add_mutually_exclusive_group()
    workload_group.add_argument(
        "--workload", metavar="PRESET",
        help="Workload preset name from usecases/presets.json (Mode 2)"
    )
    workload_group.add_argument(
        "--command", metavar="CMD",
        help="Custom shell command to run on device (Mode 2)"
    )
    parser.add_argument(
        "--workload-name", default=None,
        help="Label for the workload (required when using --command)"
    )
    parser.add_argument(
        "--wait", type=int, default=None,
        help="Seconds to wait for workload to stabilize (default: from preset or 15)"
    )
    parser.add_argument(
        "--skip-reboot", action="store_true",
        help="Skip device reboot before collecting baseline (Mode 2 only)"
    )
    parser.add_argument(
        "--working-dir", default=DEVICE_WORKING_DIR,
        help=f"Working directory on device for systemd-run (default: {DEVICE_WORKING_DIR})"
    )

    # --- Comparison parameters (Modes 3 & 4) ---
    parser.add_argument(
        "--reference", metavar="PATH", default=None,
        help="Reference snapshot directory (Mode 3: live vs reference, Mode 4: offline comparison)"
    )
    parser.add_argument(
        "--current", metavar="PATH", default=None,
        help="Current snapshot directory for offline comparison (Mode 4, requires --reference)"
    )

    # --- Device parameters (Modes 1, 2, 3) ---
    parser.add_argument(
        "--serial", default=None,
        help="ADB device serial number (auto-detected if only one device connected)"
    )
    parser.add_argument(
        "--host", default=None,
        help="SSH hostname or IP address"
    )
    parser.add_argument(
        "--user", default="root",
        help="SSH username (default: root)"
    )
    parser.add_argument(
        "--password", default=None,
        help="SSH password (if not provided, prompted interactively)"
    )

    # --- Output parameters (all modes) ---
    parser.add_argument(
        "--output-dir", default=None,
        help="Output directory (default: results/<mode>_<timestamp>/)"
    )
    parser.add_argument(
        "--label", default=None,
        help="Label for the collected snapshot (Modes 1, 3, and 2C)"
    )
    parser.add_argument(
        "--title", default=None,
        help="Report title (Modes 3, 4, and 2C compare, default: auto-generated)"
    )

    # --- User-Launched parameters (Mode 2C) ---
    parser.add_argument(
        "--user-launched", action="store_true",
        help=(
            "Mode 2C: Measure memory of a user-launched use-case. "
            "Use with --interactive for a single guided command, "
            "or with --label baseline/active for agent-driven multi-step workflow."
        )
    )
    parser.add_argument(
        "--interactive", action="store_true",
        help=(
            "Mode 2C: Enable interactive guided workflow. "
            "Single command: collects baseline, prompts user to launch use-case, "
            "collects active, compares, and generates report. "
            "Use with --user-launched."
        )
    )
    parser.add_argument(
        "--reboot", action="store_true",
        help=(
            "Mode 2C: Reboot device before collecting baseline snapshot. "
            "Use for a clean baseline state. Default: no reboot. "
            "Use with --user-launched."
        )
    )
    parser.add_argument(
        "--compare-snapshots", nargs=2, metavar=("BASELINE_DIR", "ACTIVE_DIR"),
        help=(
            "Mode 2C: Compare two snapshots collected via --user-launched. "
            "Provide paths to the baseline and active snapshot directories."
        )
    )

    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # Mode detection
    # -----------------------------------------------------------------------

    if args.current and args.reference:
        # Mode 4: Compare two pre-collected snapshots (offline)
        mode = "comparison"
        default_prefix = "comparison"
    elif args.reference and not args.current:
        # Mode 3: Regression test (live device vs reference)
        mode = "regression"
        default_prefix = "regression"
    elif args.workload or args.command:
        # Mode 2A/2B: Workload impact (preset or custom command)
        mode = "workload"
        key  = (args.workload or (args.workload_name or "workload").replace(" ", "_").lower())
        default_prefix = key
    elif args.compare_snapshots:
        # Mode 2C: User-launched workload — compare step
        mode = "user_launched_compare"
        default_prefix = "user_launched"
    elif args.user_launched and args.interactive:
        # Mode 2C: User-launched workload — interactive single-command mode
        mode = "user_launched_interactive"
        default_prefix = "user_launched"
    elif args.user_launched:
        # Mode 2C: User-launched workload — agent-driven collect step
        mode = "user_launched_collect"
        label = args.label or "snapshot"
        default_prefix = f"user_launched_{label}"
    else:
        # Mode 1: Single snapshot
        mode = "snapshot"
        default_prefix = "snapshot"

    # -----------------------------------------------------------------------
    # Determine output directory
    # -----------------------------------------------------------------------

    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("results") / f"{default_prefix}_{ts}"

    # -----------------------------------------------------------------------
    # Execute selected mode
    # -----------------------------------------------------------------------

    if mode == "snapshot":
        report_path = mode_snapshot(args, output_dir)
    elif mode == "workload":
        report_path = mode_workload(args, output_dir)
    elif mode == "regression":
        report_path = mode_regression(args, output_dir)
    elif mode == "comparison":
        report_path = mode_comparison(args, output_dir)
    elif mode == "user_launched_interactive":
        report_path = mode_user_launched_interactive(args, output_dir)
    elif mode == "user_launched_collect":
        mode_user_launched_collect(args, output_dir)
        return 0
    elif mode == "user_launched_compare":
        report_path = mode_user_launched_compare(args, output_dir)

    print(f"\n{TAG} Done.")
    print(f"{TAG} Report: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())