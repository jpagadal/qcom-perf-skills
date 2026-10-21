---
name: memory-analysis
description: >
  Use this skill for all memory analysis tasks on Qualcomm Linux devices.
  Supports four modes auto-detected from the parameters provided:
  (1) Snapshot: single memory snapshot from a connected device;
  (2) Workload: measure memory impact of a workload or application —
      2A Preset: use a named preset; 2B Custom: provide a shell command;
      2C User-Launched: user launches the workload manually, skill collects before/after;
  (3) Regression: compare a live device against a pre-collected reference snapshot;
  (4) Comparison: compare two pre-collected snapshots offline (no device needed).
  Generates a unified HTML report with memory breakdown, process ranking,
  kernel/userspace diffs, and root cause analysis.
license: BSD 3-Clause License
compatibility: >
  Requires Python 3.10+. pip install -r requirements.txt.
  ADB transport: adb in PATH, Qualcomm Linux device with adbd enabled.
  SSH transport: pip install paramiko, any Linux device reachable over network.
  Host OS: Windows or Linux.
metadata:
  author: "Jagadeesh Pagadala"
  version: "0.0.1"
  platform: "Qualcomm Linux"
  category: "Memory Analysis"
  internal-dependencies: "data-collection,snapshot-comparison,kernel-diff,userspace-diff,anomaly-rca,report-generation"
  entry-point: "skills/memory-analysis/scripts/run.py"
  presets: "skills/memory-analysis/usecases/presets.json"
---

Unified memory analysis skill for Qualcomm Linux devices.
One skill, four modes — auto-detected from the parameters you provide.

---

## Standard Prompts (for AI agents)

Use these prompts when talking to an AI agent (Cline, Cursor, etc.):

### Snapshot — Current memory state
```
"Give me a memory report for the connected device"
"What is the memory usage on this board?"
"Show me the memory breakdown for device 0426df75"
"Memory report for device at 192.168.1.100, user=root"
```

### Workload (Preset/Custom) — Measure memory impact
```
"How much memory does the camera use?"
"Measure memory impact of camera_h264_encoding"
"Run the camera and tell me the memory impact"
"Measure memory impact of: gst-launch-1.0 qtiqmmfsrc ..."
```

### Workload (User-Launched) — Measure user-launched use-case
```
"I want to measure memory of a use-case I'll launch manually"
"Collect baseline, then I'll launch my app, then collect active"
"Help me measure memory impact of my custom workload"
"I have a GStreamer command I want to run — measure its memory usage"
"Baseline first, then I'll start the camera, then active snapshot"
"Measure memory of my use-case — reboot first for a clean baseline"
```

### Regression — Compare device against reference
```
"Is this device using more memory than the reference?"
"Compare device 0426df75 against the golden baseline in results/golden/"
"Regression test: collect from device and compare with results/build_v1/"
"Has memory changed since the last build?"
```

### Comparison — Compare two pre-collected snapshots
```
"Compare results/build_v2/ against results/build_v1/"
"Offline comparison: current=results/camera_active/ reference=results/baseline/"
"Compare two snapshots: A=data/device_A/ B=data/device_B/"
"I have two snapshot folders — compare them"
```

---

## Mode Selection Guide

```
What do you want to do?
│
├─ "I want a memory report for my device"
│  └─ Snapshot mode: python run.py [--serial <serial>]
│
├─ "I want to measure memory impact of a workload"
│  ├─ Variant A (Preset):  python run.py --workload <preset> [--serial <serial>]
│  ├─ Variant B (Custom):  python run.py --command "<cmd>" --workload-name "<label>" [--serial <serial>]
│  ├─ Variant C1 (User-Launched, Interactive — single command):
│  │    python run.py --user-launched --interactive [--reboot] --serial <serial>
│  └─ Variant C2 (User-Launched, Agent-Driven — multi-step):
│       python run.py --user-launched --label baseline [--reboot] --serial <serial> --output-dir results/my_session
│       # ... user launches use-case on device ...
│       python run.py --user-launched --label active --serial <serial> --output-dir results/my_session
│       python run.py --compare-snapshots results/my_session/baseline results/my_session/active
│
├─ "I want to check if my device uses more memory than a reference"
│  └─ Regression mode: python run.py --reference <path> [--serial <serial>]
│
└─ "I want to compare two pre-collected snapshots"
   └─ Comparison mode: python run.py --current <path> --reference <path>
```

---

## Mode 1: Snapshot

**Use when:** You want the current memory state of a connected device.

**Command:**
```bash
python skills/memory-analysis/scripts/run.py [--serial <serial>]
```

**Examples:**
```bash
# Auto-detect connected device
python skills/memory-analysis/scripts/run.py

# Specific ADB device
python skills/memory-analysis/scripts/run.py --serial 0426df75

# SSH device
python skills/memory-analysis/scripts/run.py --host 192.168.1.100 --user root
```

**Output:** `results/snapshot_<timestamp>/reports/snapshot_report.html`

---

## Mode 2: Workload Impact

**Use when:** You want to measure how much memory a specific workload consumes.

**Command (preset):**
```bash
python skills/memory-analysis/scripts/run.py --workload <preset> [--serial <serial>]
```

**Command (custom):**
```bash
python skills/memory-analysis/scripts/run.py \
  --command "<shell_command>" \
  --workload-name "<label>" \
  [--serial <serial>] [--wait <seconds>]
```

**Examples:**
```bash
# Using a preset
python skills/memory-analysis/scripts/run.py --workload camera_h264_encoding

# Custom command
python skills/memory-analysis/scripts/run.py \
  --command "gst-launch-1.0 -e qtiqmmfsrc name=camsrc camera=0 ! fakesink" \
  --workload-name "camera_preview" \
  --serial 0426df75 \
  --wait 15

# Skip reboot (use current device state as baseline)
python skills/memory-analysis/scripts/run.py \
  --workload camera_h264_encoding \
  --skip-reboot
```

**Available Presets:**
See `usecases/presets.json` for the full list. Current presets:
- `camera_preview_vhdr` — Camera preview with vHDR at 2688x1512 @ 30fps
- `camera_h264_encoding` — Camera H.264 encoding to MP4 at 1280x720 @ 30fps
- `clip_snpe` — CLIP SNPE model inference on DSP
- `convnext_snpe` — ConvNeXt SNPE model inference on DSP

**Adding a New Preset:**
Edit `usecases/presets.json`:
```json
"my_workload": {
  "name": "My Workload",
  "description": "What this workload does",
  "setup": ["optional setup commands", "sleep 3"],
  "command": "the command to run on the device",
  "wait_sec": 15,
  "teardown": ["optional cleanup, e.g. pkill myapp"]
}
```

**Output:** `results/<preset>_<timestamp>/reports/workload_impact_report.html`

---

## Mode 2C: Workload Impact (User-Launched)

**Use when:** The user launches a use-case manually on the device and you want to measure its memory impact.
The skill collects a baseline snapshot before the workload starts, and an active snapshot while it is running.

> **Note:** Users interact through the AI agent only — not directly with scripts.
> The agent orchestrates the workflow based on natural language prompts.

---

### Variant C1: Interactive Mode (Recommended — Single Command)

The agent runs a single command that guides the user through the entire workflow.

```bash
# Without reboot (use current device state as baseline)
python skills/memory-analysis/scripts/run.py \
  --user-launched --interactive \
  --serial <serial>

# With reboot (clean baseline state)
python skills/memory-analysis/scripts/run.py \
  --user-launched --interactive --reboot \
  --serial <serial>
```

**What happens:**
```
[memory-analysis] Mode: Workload Impact (User-Launched, Interactive)

── Step 1/4: Collecting baseline snapshot ──────────────
[memory-analysis] Collecting baseline snapshot...
[memory-analysis] Baseline snapshot saved.

── Step 2/4: Launch your use-case ──────────────────────
[memory-analysis] Please launch your use-case on the device now.
[memory-analysis] Wait for it to stabilize before pressing ENTER.
[memory-analysis] >>> Press ENTER when your use-case is running and stable:

── Step 3/4: Collecting active snapshot ────────────────
[memory-analysis] Collecting active snapshot...
[memory-analysis] Active snapshot saved.

── Step 4/4: Comparing snapshots ────────────────────────
[memory-analysis] Running snapshot comparison...
[memory-analysis] Running kernel memory diff...
[memory-analysis] Running userspace memory diff...
[memory-analysis] Generating workload impact report...

[memory-analysis] Done.
[memory-analysis] Report: results/user_launched_<timestamp>/reports/workload_impact_report.html
```

**Key points:**
- Single command — no multi-step workflow
- Agent pauses at Step 2 and waits for user to launch use-case
- Optional `--reboot` for clean baseline state
- Auto-manages session directory (no `--output-dir` needed)
- Generates the same `workload_impact_report.html` as Mode 2A/2B

**Output:** `results/user_launched_<timestamp>/reports/workload_impact_report.html`

---

### Variant C2: Agent-Driven Multi-Step Mode

For cases where the agent needs to orchestrate each step separately.
The skill prints exact next-step commands after each collection.

```bash
# Step 1: Collect baseline (optionally with reboot)
python skills/memory-analysis/scripts/run.py \
  --user-launched --label baseline \
  [--reboot] --serial <serial> \
  --output-dir results/my_session

# Step 2: User launches use-case on device
# (e.g., gst-launch-1.0 qtiqmmfsrc video_0::type=preview vhdr=1 ! fakesink)

# Step 3: Collect active snapshot (use-case running)
python skills/memory-analysis/scripts/run.py \
  --user-launched --label active \
  --serial <serial> \
  --output-dir results/my_session

# Step 4: Compare snapshots and generate report
python skills/memory-analysis/scripts/run.py \
  --compare-snapshots results/my_session/baseline results/my_session/active
```

**Key points:**
- Use the **same `--output-dir`** for both baseline and active collection steps
- The skill prints exact next-step commands after each collection step
- Optional `--reboot` on the baseline step for clean state
- Generates the same `workload_impact_report.html` as Mode 2A/2B

**Output:** `results/user_launched_<timestamp>/reports/workload_impact_report.html`

---

## Mode 3: Regression Test

**Use when:** You want to check if a connected device uses more memory than a reference.

**Command:**
```bash
python skills/memory-analysis/scripts/run.py \
  --reference <path> \
  [--serial <serial>]
```

**Examples:**
```bash
# Compare against golden baseline
python skills/memory-analysis/scripts/run.py \
  --reference results/golden_baseline/ \
  --serial 0426df75

# SSH device
python skills/memory-analysis/scripts/run.py \
  --reference results/build_v1/ \
  --host 192.168.1.100 --user root
```

**Output:** `results/regression_<timestamp>/reports/regression_report.html`

---

## Mode 4: Snapshot Comparison (Offline)

**Use when:** You want to compare two pre-collected snapshots. No device needed.

**Command:**
```bash
python skills/memory-analysis/scripts/run.py \
  --current <path> \
  --reference <path>
```

**Examples:**
```bash
# Compare two builds
python skills/memory-analysis/scripts/run.py \
  --current results/build_v2/ \
  --reference results/build_v1/

# Compare camera active vs idle
python skills/memory-analysis/scripts/run.py \
  --current results/camera_active/ \
  --reference results/baseline/ \
  --output-dir results/camera_comparison/
```

**Output:** `results/comparison_<timestamp>/reports/comparison_report.html`

---

## Parameters Reference

| Parameter | Mode(s) | Required | Default | Description |
|---|---|---|---|---|
| `--workload` | 2A | Yes* | -- | Preset name from `usecases/presets.json` |
| `--command` | 2B | Yes* | -- | Custom shell command to run on device |
| `--workload-name` | 2B | Yes** | -- | Label when using `--command` |
| `--wait` | 2A,2B | No | preset or 15 | Seconds to wait for workload to stabilize |
| `--skip-reboot` | 2A,2B | No | false | Skip device reboot before baseline collection |
| `--user-launched` | 2C | Yes | -- | Measure memory of a user-launched use-case |
| `--interactive` | 2C | No | false | Enable single-command interactive guided workflow (use with --user-launched) |
| `--reboot` | 2C | No | false | Reboot device before baseline collection (use with --user-launched) |
| `--compare-snapshots` | 2C | Yes*** | -- | Compare two snapshots: baseline and active dirs |
| `--reference` | 3,4 | Yes | -- | Reference snapshot directory |
| `--current` | 4 | Yes | -- | Current snapshot directory (offline comparison) |
| `--serial` | 1,2,3 | No | auto-detect | ADB device serial number |
| `--host` | 1,2,3 | No | -- | SSH hostname or IP address |
| `--user` | 1,2,3 | No | `root` | SSH username |
| `--output-dir` | all | No | `results/<mode>_<ts>/` | Output directory (use same dir for 2C collect steps) |
| `--label` | 1,3,2C | No | `snapshot` | Label for the collected snapshot (use `baseline` or `active` for 2C) |
| `--title` | 3,4,2C | No | auto | Report title |

*Either `--workload` or `--command` required for Mode 2A/2B.
**Required when using `--command`.
***Required for Mode 2C comparison step.

---

## Outputs

| File | Mode(s) | Description |
|---|---|---|
| `reports/snapshot_report.html` | 1 | Memory breakdown, process ranking, carveout layout |
| `reports/workload_impact_report.html` | 2A,2B,2C | Baseline vs active comparison, memory delta, anomalies |
| `reports/regression_report.html` | 3 | Device vs reference comparison, regression findings |
| `reports/comparison_report.html` | 4 | Snapshot comparison, kernel/userspace diffs, anomalies |
| `baseline/snapshot.json` | 2A,2B,2C | Idle/pre-workload baseline snapshot |
| `active/snapshot.json` | 2A,2B,2C | Active workload snapshot |
| `snapshot/snapshot.json` | 1,3 | Collected device snapshot |
| `reports/_intermediate/` | all | Intermediate JSON reports (for debugging) |

---

## Workflow Details

### Mode 1 (Snapshot)
```
Device → Collect snapshot → Snapshot analysis → snapshot_report.html
```

### Mode 2A/2B (Workload — Preset/Custom)
```
Device → Reboot → Collect baseline → Setup → Start workload
       → Wait 15s → Collect active → Stop workload → Teardown
       → Compare → Kernel diff → Userspace diff → workload_impact_report.html
```

### Mode 2C Variant C1 (Workload — User-Launched, Interactive)
```
(Optional Reboot) → Collect baseline → Prompt user to launch use-case
                 → User presses ENTER → Collect active
                 → Compare → Kernel diff → Userspace diff → workload_impact_report.html
```

### Mode 2C Variant C2 (Workload — User-Launched, Agent-Driven)
```
(Optional Reboot) → Collect baseline snapshot [agent prints next-step commands]
User launches use-case on device
Collect active snapshot [agent prints compare command]
Compare → Kernel diff → Userspace diff → workload_impact_report.html
```

### Mode 3 (Regression)
```
Device → Collect current → Compare vs reference
       → Kernel diff → Userspace diff → regression_report.html
```

### Mode 4 (Comparison)
```
current/snapshot.json + reference/snapshot.json
       → Compare → Kernel diff → Userspace diff → comparison_report.html
```

---

## Error Handling

- **Device not connected:** Inform the user and stop. Run `adb devices` to verify.
- **Preset not found:** List available presets and stop.
- **Snapshot directory missing:** Inform the user and ask for the correct path.
- **Partial collection failure:** Continue with available data; note missing sources in report.
- **Workload stops early:** Collect snapshot anyway and note in report.
- See `TROUBLESHOOTING.md` for common ADB and SSH errors.