#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""
report-generation -- Unified Report Generator
Renders any memory skill output JSON into HTML, TXT, and/or Excel reports.
Auto-selects the appropriate template based on the report type in the JSON.

Usage:
    python generate_report.py --input <report.json> [<report2.json> ...]
                              [--format html,txt,xlsx] [--output-dir <dir>]
                              [--unified] [--title <title>]
"""

import argparse
import json
import os
import sys
from datetime import datetime


# ---------------------------------------------------------------------------
# Report type detection
# ---------------------------------------------------------------------------

REPORT_TYPE_MAP = {
    "MemoryMapReport":            "memory_map",
    "CarveoutValidationReport":   "carveout_validation",
    "SnapshotComparisonReport":   "snapshot_comparison",
    "KernelDiffReport":           "kernel_diff",
    "UserspaceDiffReport":        "userspace_diff",
    "RCAReport":                  "rca",
}

def detect_report_type(data: dict) -> str:
    """Detect report type from JSON content."""
    # Check for type field
    if "report_type" in data:
        return REPORT_TYPE_MAP.get(data["report_type"], "unknown")
    # Heuristic detection based on key presence
    if "anomalies" in data and "summary" in data:
        return "rca"
    if "results" in data and "carveout_source" in data:
        return "carveout_validation"
    if "categories" in data and "top_growers" in data:
        return "snapshot_comparison"
    if "slab_diff" in data and "buddy_fragmentation" in data:
        return "kernel_diff"
    if "process_diff" in data and "dmabuf_diff" in data:
        return "userspace_diff"
    if "breakdown" in data and "nhlos_detail" in data:
        return "memory_map"
    return "unknown"


def load_report(path: str) -> tuple[dict, str]:
    """Load a report JSON and detect its type."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    rtype = detect_report_type(data)
    return data, rtype


# ---------------------------------------------------------------------------
# SMAPS breakdown parsing
# ---------------------------------------------------------------------------

def parse_smaps_breakdown(smaps_dir: str, pid: int) -> dict:
    """Parse raw smaps file for a process and return categorized memory breakdown."""
    import glob
    pattern = os.path.join(smaps_dir, f"{pid}_*_smaps.txt")
    files = glob.glob(pattern)
    if not files:
        return {}
    filepath = files[0]
    basename = os.path.basename(filepath)
    proc_name = basename[len(str(pid)) + 1:].replace("_smaps.txt", "")

    segments = []
    current = {}
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line and line[0] in "abcdef0123456789":
                    if current:
                        segments.append(current)
                    parts = line.split()
                    current = {
                        "addr": parts[0],
                        "perms": parts[1] if len(parts) > 1 else "----",
                        "name": parts[-1] if len(parts) > 5 else "unknown",
                        "pss": 0, "anon": 0, "size": 0,
                    }
                elif line.startswith("Size:"):
                    current["size"] = int(line.split()[1])
                elif line.startswith("Pss:"):
                    current["pss"] = int(line.split()[1])
                elif line.startswith("Anonymous:"):
                    current["anon"] = int(line.split()[1])
    except Exception:
        return {}
    if current:
        segments.append(current)

    heap_kb = stack_kb = shared_libs_kb = shared_libs_fb_kb = 0
    shared_libs_anon_kb = anon_kb = other_kb = 0
    anon_buffers: list = []
    shared_libs_map: dict = {}  # basename -> total PSS

    for i, seg in enumerate(segments):
        name, pss, anon = seg["name"], seg["pss"], seg["anon"]
        fb = pss - anon
        if "[heap]" in name:
            heap_kb += pss
        elif "[stack" in name:
            stack_kb += pss
        elif "/dmabuf:" in name:
            pass  # DMA-BUF: PSS is typically 0
        elif ".so" in name or "/lib" in name:
            shared_libs_kb += pss
            shared_libs_fb_kb += fb
            shared_libs_anon_kb += anon
            lib_base = os.path.basename(name)
            shared_libs_map[lib_base] = shared_libs_map.get(lib_base, 0) + pss
        elif name == "unknown" and anon > 0:
            anon_kb += pss
            anon_buffers.append(pss)
        else:
            other_kb += pss

    anon_buffers.sort(reverse=True)
    shared_libs_detail = sorted(
        [{"name": k, "pss_kb": v} for k, v in shared_libs_map.items()],
        key=lambda x: x["pss_kb"], reverse=True,
    )
    return {
        "pid": pid, "name": proc_name,
        "total_pss_kb": sum(s["pss"] for s in segments),
        "heap_kb": heap_kb, "stack_kb": stack_kb,
        "shared_libs_kb": shared_libs_kb,
        "shared_libs_fb_kb": shared_libs_fb_kb,
        "shared_libs_anon_kb": shared_libs_anon_kb,
        "anon_buffers_kb": anon_kb,
        "other_kb": other_kb,
        "anon_buffers": anon_buffers,
        "shared_libs_detail": shared_libs_detail,
    }


def load_smaps_for_snapshot(snapshot_path: str) -> list:
    """Load smaps breakdown for top processes from a snapshot JSON file."""
    if not os.path.isfile(snapshot_path):
        return []
    try:
        with open(snapshot_path, encoding="utf-8") as f:
            snap = json.load(f)
    except Exception:
        return []
    smaps_src = snap.get("sources", {}).get("smaps", {})
    if not smaps_src.get("available"):
        return []
    smaps_dir = smaps_src.get("path", "")
    if not smaps_dir or not os.path.isdir(smaps_dir):
        return []

    # Build PID -> display name from process_stats (more reliable than smaps filename)
    pid_to_name: dict = {}
    proc_stats = snap.get("sources", {}).get("process_stats", {})
    for proc in proc_stats.get("parsed", []):
        pid = proc.get("pid")
        if pid:
            # Use basename of first token of cmdline as display name
            cmdline = proc.get("name", "")
            exe = cmdline.split()[0] if cmdline.strip() else cmdline
            short = exe.split("/")[-1].split("\\")[-1][:40]
            pid_to_name[pid] = short or str(pid)

    breakdowns = []
    for entry in smaps_src.get("parsed", []):
        pid = entry.get("pid")
        if pid:
            bd = parse_smaps_breakdown(smaps_dir, pid)
            if bd:
                # Override name with the one from process_stats if available
                if pid in pid_to_name:
                    bd["name"] = pid_to_name[pid]
                breakdowns.append(bd)
    return breakdowns


# ---------------------------------------------------------------------------
# HTML section renderers
# ---------------------------------------------------------------------------

CSS = """
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; background: #f4f6f9; color: #222; }
h1 { color: #1a3a5c; border-bottom: 3px solid #2c6fad; padding-bottom: 10px; font-size: 1.6em; }
h2 { color: #1a3a5c; margin-top: 0; font-size: 1.1em; }
.section-block { background: #fff; border: 1px solid #c8d8ea; border-radius: 8px;
  margin-bottom: 18px; box-shadow: 0 1px 4px rgba(0,0,0,0.07); overflow: hidden; }
.section-header { background: #1a3a5c; color: white; padding: 10px 16px;
  cursor: pointer; user-select: none; display: flex; align-items: center; gap: 10px; }
.section-header:hover { background: #22507a; }
.section-toggle { font-size: 1.1em; font-weight: bold; min-width: 20px; }
.section-title { font-size: 1em; font-weight: 600; }
.section-body { padding: 16px; }
.section-body.collapsed { display: none; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 13px; }
th, td { border: 1px solid #c0cfe0; padding: 6px 12px; }
th { background: #2c6fad; color: white; font-weight: 600; }
.growing { background: #fde8e8; }
.shrinking { background: #e8f8e8; }
.pass { background: #e8f8e8; }
.over, .under { background: #fef8e0; }
.missing { background: #fde8e8; }
.critical { background: #fde8e8; }
.warning { background: #fef8e0; }
.info { background: #e8f4fd; }
.health-healthy { background: #d4edda; color: #155724; padding: 10px 16px; border-radius: 6px; font-weight: bold; }
.health-degraded { background: #fff3cd; color: #856404; padding: 10px 16px; border-radius: 6px; font-weight: bold; }
.health-critical { background: #f8d7da; color: #721c24; padding: 10px 16px; border-radius: 6px; font-weight: bold; }
.card { border: 1px solid #c0cfe0; border-radius: 6px; padding: 14px; margin: 10px 0; background: #f8fbff; }
.card.critical { border-left: 4px solid #c00; background: #fff5f5; }
.card.warning  { border-left: 4px solid #e6a817; background: #fffdf0; }
.card.info     { border-left: 4px solid #2c6fad; background: #f0f7ff; }
</style>
<script>
function toggleSection(id) {
  var body = document.getElementById(id);
  var btn  = document.getElementById('toggle-' + id);
  if (!body) return;
  var collapsed = body.classList.toggle('collapsed');
  if (btn) btn.textContent = collapsed ? '+' : '\u2212';
}
function toggleRows(cls) {
  var rows = document.querySelectorAll('.' + cls);
  var btn  = document.getElementById('btn-' + cls);
  var open = rows[0] && rows[0].style.display !== 'none';
  rows.forEach(function(r) { r.style.display = open ? 'none' : ''; });
  if (btn) btn.textContent = open ? '+' : '\u2212';
}
function showBatch(batchCls, nextToggleId, currentToggleId) {
  document.querySelectorAll('.' + batchCls).forEach(function(r) { r.style.display = ''; });
  var cur = document.getElementById(currentToggleId);
  if (cur) cur.style.display = 'none';
  if (nextToggleId) {
    var nxt = document.getElementById(nextToggleId);
    if (nxt) nxt.style.display = '';
  }
}
</script>
"""


def _progressive_expand_html(row_htmls: list, batch_size: int, prefix: str, ncols: int) -> str:
    """
    Wrap a list of row HTML strings in progressive expansion using <tbody> groups.
    First batch_size rows are always visible.
    Each subsequent batch is hidden behind a 'Show N more' toggle row.
    Clicking the toggle reveals that batch and shows the next toggle (if any).
    """
    if not row_htmls:
        return ""
    batches = [row_htmls[i:i + batch_size] for i in range(0, len(row_htmls), batch_size)]
    html = ""
    for bi, batch in enumerate(batches):
        if bi == 0:
            html += "<tbody>" + "".join(batch) + "</tbody>\n"
        else:
            batch_cls = f"{prefix}-b{bi}"
            toggle_id = f"{prefix}-t{bi}"
            next_toggle_id = f"{prefix}-t{bi + 1}" if bi < len(batches) - 1 else ""
            show_count = len(batch)
            display = "" if bi == 1 else "display:none;"
            html += (
                f"<tbody>"
                f"<tr id='{toggle_id}' style='cursor:pointer;background:#edf3fb;{display}' "
                f"onclick=\"showBatch('{batch_cls}','{next_toggle_id}','{toggle_id}')\">"
                f"<td colspan='{ncols}' style='text-align:center;color:#2c6fad;"
                f"font-size:11px;padding:4px 8px'>"
                f"<span style='font-weight:bold'>+</span> Show {show_count} more</td></tr>"
                f"</tbody>\n"
            )
            html += (
                f"<tbody class='{batch_cls}' style='display:none'>"
                + "".join(batch)
                + "</tbody>\n"
            )
    return html


def render_rca_html(data: dict) -> str:
    s = data.get("summary", {})
    health = s.get("overall_health", "UNKNOWN")
    health_class = f"health-{health.lower()}"
    cards = ""
    for a in data.get("anomalies", []):
        sev = a.get("severity", "INFO").lower()
        evidence_items = "".join(
            f"<li><b>[{e['source']}]</b> {e['finding']}</li>"
            for e in a.get("evidence", [])
        )
        actions = "".join(f"<li>{act}</li>" for act in a.get("recommended_actions", []))
        cards += f"""
<div class='card {sev}'>
  <h3>[{a['severity']}] {a['id']}: {a['title']}</h3>
  <p><b>Confidence:</b> {a['confidence']:.0%} &nbsp; <b>Layer:</b> {a['layer']}</p>
  <p><b>Evidence:</b></p><ul>{evidence_items}</ul>
  <p><b>Hypothesis:</b> {a['hypothesis']}</p>
  <p><b>Recommended actions:</b></p><ol>{actions}</ol>
</div>"""
    return f"""
<div class='{health_class}'>
  <b>Overall Health: {health}</b> &nbsp;|&nbsp;
  Critical: {s.get('critical',0)} &nbsp; Warning: {s.get('warning',0)} &nbsp; Info: {s.get('info',0)}<br>
  Layers: {', '.join(s.get('layers_affected', [])) or 'none'} &nbsp;|&nbsp;
  Mode: {s.get('mode', 'unknown')}
</div>
{cards or '<p>No anomalies detected.</p>'}"""


def render_carveout_html(data: dict) -> str:
    rows = ""
    for r in data.get("results", []):
        size_mb = r.get("actual_size_mb", r.get("actual_size_kb", 0) / 1024)
        rows += (
            f"<tr class='pass'>"
            f"<td>{r.get('name','')}</td>"
            f"<td style='font-family:monospace'>{r.get('base_addr','')}</td>"
            f"<td style='text-align:right'>{size_mb:.2f}</td>"
            f"<td>[OK] FOUND</td>"
            f"</tr>\n"
        )
    s = data.get("summary", {})
    total_mb = s.get("total_actual_mb", 0)
    found = s.get("found", len(data.get("results", [])))
    source = data.get("carveout_source", "")
    return f"""
<p><b>Carve-outs found:</b> {found} &nbsp;|&nbsp; <b>Total size:</b> {total_mb:.2f} MB
   {f"&nbsp;|&nbsp; <b>Source:</b> {source}" if source else ""}</p>
<table>
<tr><th>Carveout</th><th>Base Address</th><th>Size (MB)</th><th>Status</th></tr>
{rows}</table>"""


def render_summary_table_html(data: dict) -> str:
    """Render the hierarchical collapsible memory summary table."""
    st = data.get("summary_table")
    if not st:
        return ""
    ref = st.get("reference", {})
    cur = st.get("current", {})
    ref_label = data.get("reference_label", "Reference")
    cur_label  = data.get("current_label",  "Current")

    # Detect self-comparison (standalone mode): same snapshot_id for both
    is_standalone = (
        data.get("current_snapshot_id") == data.get("reference_snapshot_id")
        and data.get("current_snapshot_id", "") != ""
    )

    def mb(kb):
        return f"{kb/1024:.0f}" if kb else "0"

    def mb_precise(kb):
        """Show MB with 1 decimal for values < 10 MB, KB for values < 1 MB."""
        if not kb:
            return "0"
        if kb < 1024:
            return f"{kb} KB"
        if kb < 10 * 1024:
            return f"{kb/1024:.1f} MB"
        return f"{kb//1024} MB"

    def delta_td(ref_kb, cur_kb):
        if is_standalone:
            return ""  # no delta column in standalone mode
        d = cur_kb - ref_kb
        s = f"{d/1024:+.0f}" if d != 0 else "0"
        color = "#c00" if d > 0 else ("#060" if d < 0 else "#555")
        fw = "font-weight:bold;" if d != 0 else ""
        return f"<td class='num' style='color:{color};{fw}'>{s}</td>"

    # Build NHLOS sub-rows
    nhlos_ref_nodes = {n["name"]: n["size_kb"] for n in ref.get("nhlos_nodes", [])}
    nhlos_cur_nodes = {n["name"]: n["size_kb"] for n in cur.get("nhlos_nodes", [])}
    all_nhlos = sorted(set(nhlos_ref_nodes) | set(nhlos_cur_nodes),
                       key=lambda x: nhlos_cur_nodes.get(x, 0), reverse=True)
    nhlos_sub = ""
    for name in all_nhlos:
        r_kb = nhlos_ref_nodes.get(name, 0)
        c_kb = nhlos_cur_nodes.get(name, 0)
        nhlos_sub += (
            f"<tr class='sub-row nhlos-sub' style='display:none;background:#f5f8ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>NHLOS</td>"
            f"<td style='padding-left:28px;color:#444'>&#x2514; {name}</td>"
            f"<td class='num'>{mb(r_kb)}</td><td class='num'>{mb(c_kb)}</td>"
            f"{delta_td(r_kb, c_kb)}</tr>\n"
        )
    # Add unaccounted gap row (NHLOS total - sum of named nodes)
    ref_named_sum = sum(nhlos_ref_nodes.values())
    cur_named_sum = sum(nhlos_cur_nodes.values())
    ref_gap = max(0, ref.get("nhlos_kb", 0) - ref_named_sum)
    cur_gap = max(0, cur.get("nhlos_kb", 0) - cur_named_sum)
    if ref_gap > 0 or cur_gap > 0:
        nhlos_sub += (
            f"<tr class='sub-row nhlos-sub' style='display:none;background:#f0f3ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>NHLOS</td>"
            f"<td style='padding-left:28px;color:#888;font-style:italic'>"
            f"&#x2514; HYP + TZ + UEFI Reservations</td>"
            f"<td class='num' style='color:#888'>{mb(ref_gap)}</td>"
            f"<td class='num' style='color:#888'>{mb(cur_gap)}</td>"
            f"{delta_td(ref_gap, cur_gap)}</tr>\n"
        )

    # Human-readable display names for technical kernel field names
    DISPLAY_NAMES = {
        "Slab":          "Slab Allocator",
        "Vmalloc":       "Vmalloc",
        "KernelStack":   "Kernel Stack",
        "PageTables":    "Page Tables",
        "Percpu":        "Per-CPU",
        "SecPageTables": "Secondary Page Tables (Stage-2)",
        "Modules":       "Kernel Modules",
        "CMA":           "CMA (Contiguous Memory)",
        "KDA":           "KDA (Kernel Direct Allocations)",
        "AnonPages":     "Anonymous Pages",
        "Shmem":         "Shared Memory",
        "DMA-BUF":       "DMA-BUF Buffers",
        "KGSL":          "KGSL GPU Memory",
    }

    # Build Kernel Dynamic sub-rows (includes CMA and KDA)
    kd_ref = ref.get("kernel_dynamic_breakdown", {})
    kd_cur = cur.get("kernel_dynamic_breakdown", {})
    kd_sub = ""
    for key in ["Slab", "Vmalloc", "KernelStack", "PageTables", "Percpu", "SecPageTables", "Modules", "CMA", "KDA"]:
        r_kb = kd_ref.get(key, 0)
        c_kb = kd_cur.get(key, 0)
        label = DISPLAY_NAMES.get(key, key)
        # Style KDA differently (italic, grey) to indicate it's a residual
        if key == "KDA":
            kd_sub += (
                f"<tr class='sub-row kd-sub' style='display:none;background:#f0f3ff'>"
                f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                f"<td style='padding-left:28px;color:#888;font-style:italic'>&#x2514; {label}</td>"
                f"<td class='num' style='color:#888'>{mb(r_kb)}</td>"
                f"<td class='num' style='color:#888'>{mb(c_kb)}</td>"
                f"{delta_td(r_kb, c_kb)}</tr>\n"
            )
        else:
            kd_sub += (
                f"<tr class='sub-row kd-sub' style='display:none;background:#f5f8ff'>"
                f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                f"<td style='padding-left:28px;color:#444'>&#x2514; {label}</td>"
                f"<td class='num'>{mb(r_kb)}</td><td class='num'>{mb(c_kb)}</td>"
                f"{delta_td(r_kb, c_kb)}</tr>\n"
            )

    # Build User Space sub-rows (AnonPages + Shmem only)
    us_ref = ref.get("user_space_breakdown", {})
    us_cur = cur.get("user_space_breakdown", {})
    us_sub = ""
    for key in ["AnonPages", "Shmem"]:
        r_kb = us_ref.get(key, 0)
        c_kb = us_cur.get(key, 0)
        label = DISPLAY_NAMES.get(key, key)
        us_sub += (
            f"<tr class='sub-row us-sub' style='display:none;background:#f5f8ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
            f"<td style='padding-left:28px;color:#444'>&#x2514; {label}</td>"
            f"<td class='num'>{mb(r_kb)}</td><td class='num'>{mb(c_kb)}</td>"
            f"{delta_td(r_kb, c_kb)}</tr>\n"
        )

    # Build Hardware / Driver Buffers sub-rows (DMA-BUF + per-exporter + KGSL)
    hw_ref = ref.get("hw_driver_breakdown", {})
    hw_cur = cur.get("hw_driver_breakdown", {})
    hw_sub = ""

    # DMA-BUF total row (expandable to show exporters)
    dmabuf_r = hw_ref.get("DMA-BUF", 0)
    dmabuf_c = hw_cur.get("DMA-BUF", 0)
    hw_sub += (
        f"<tr class='sub-row hw-sub' style='display:none;background:#f5f8ff' "
        f"onclick=\"toggleRows('dmabuf-exp')\" style='cursor:pointer'>"
        f"<td style='color:#888;font-size:11px;text-align:center'>"
        f"<span id='btn-dmabuf-exp' style='font-weight:bold;cursor:pointer'>+</span></td>"
        f"<td style='padding-left:28px;color:#444'>&#x2514; DMA-BUF Buffers</td>"
        f"<td class='num'>{mb(dmabuf_r)}</td><td class='num'>{mb(dmabuf_c)}</td>"
        f"{delta_td(dmabuf_r, dmabuf_c)}</tr>\n"
    )

    # DMA-BUF per-exporter sub-rows
    ref_exporters = hw_ref.get("DMA-BUF_exporters", {})
    cur_exporters = hw_cur.get("DMA-BUF_exporters", {})
    all_exporters = sorted(
        set(ref_exporters) | set(cur_exporters),
        key=lambda x: cur_exporters.get(x, 0) + ref_exporters.get(x, 0),
        reverse=True
    )
    for exp in all_exporters:
        r_kb = ref_exporters.get(exp, 0)
        c_kb = cur_exporters.get(exp, 0)
        hw_sub += (
            f"<tr class='sub-row hw-sub dmabuf-exp' style='display:none;background:#f0f5ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
            f"<td style='padding-left:44px;color:#555;font-size:12px'>&#x2514; {exp}</td>"
            f"<td class='num' style='font-size:12px'>{mb(r_kb)}</td>"
            f"<td class='num' style='font-size:12px'>{mb(c_kb)}</td>"
            f"{delta_td(r_kb, c_kb)}</tr>\n"
        )

    # KGSL row
    kgsl_r = hw_ref.get("KGSL", 0)
    kgsl_c = hw_cur.get("KGSL", 0)
    hw_sub += (
        f"<tr class='sub-row hw-sub' style='display:none;background:#f5f8ff'>"
        f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
        f"<td style='padding-left:28px;color:#444'>&#x2514; KGSL GPU Memory</td>"
        f"<td class='num'>{mb(kgsl_r)}</td><td class='num'>{mb(kgsl_c)}</td>"
        f"{delta_td(kgsl_r, kgsl_c)}</tr>\n"
    )

    # Build Kernel Static sub-rows (from dmesg -- may be empty if dmesg not collected)
    ks_ref = ref.get("kernel_static_breakdown", {})
    ks_cur = cur.get("kernel_static_breakdown", {})
    ks_has_data = bool(ks_ref) or bool(ks_cur)
    ks_sub = ""
    if ks_has_data:
        # Show Vmlinux as a top-level sub-entry, then its components
        for key in ["Vmlinux", "Page Structs", "Hash Tables", "Early Boot Reservations"]:
            r_kb = ks_ref.get(key, 0)
            c_kb = ks_cur.get(key, 0)
            ks_sub += (
                f"<tr class='sub-row ks-sub' style='display:none;background:#f5f8ff'>"
                f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                f"<td style='padding-left:28px;color:#444'>&#x2514; {key}</td>"
                f"<td class='num'>{mb(r_kb)}</td><td class='num'>{mb(c_kb)}</td>"
                f"{delta_td(r_kb, c_kb)}</tr>\n"
            )

    # Row styles
    R_TOP  = "background:#d0dff0;font-weight:bold;"          # Total RAM, Total Available
    R_MID  = "background:#e4edf8;"                            # System RAM, NHLOS
    R_HLOS = "background:#edf3fb;"                            # HLOS section header
    R_SUB  = "background:#f0f5fb;"                            # Kernel Static, Kernel Dynamic, User Space

    def expand_btn(cls):
        return f"<span style='display:inline-block;width:18px;text-align:center;font-weight:bold;color:#1a3a5c;cursor:pointer' id='btn-{cls}'>+</span>"

    # In standalone mode: single value column; in comparison mode: ref + cur + delta
    def val_cells(ref_kb, cur_kb):
        if is_standalone:
            return f"<td style='padding:8px 14px;text-align:right'>{mb(cur_kb)}</td>"
        return (f"<td style='padding:8px 14px;text-align:right'>{mb(ref_kb)}</td>"
                f"<td style='padding:8px 14px;text-align:right'>{mb(cur_kb)}</td>"
                f"{delta_td(ref_kb, cur_kb)}")

    def sub_val_cells(r_kb, c_kb):
        if is_standalone:
            return f"<td class='num'>{mb(c_kb)}</td>"
        return f"<td class='num'>{mb(r_kb)}</td><td class='num'>{mb(c_kb)}</td>{delta_td(r_kb, c_kb)}"

    # Rebuild sub-rows using sub_val_cells
    nhlos_sub2 = ""
    for name in all_nhlos:
        r_kb = nhlos_ref_nodes.get(name, 0)
        c_kb = nhlos_cur_nodes.get(name, 0)
        nhlos_sub2 += (
            f"<tr class='sub-row nhlos-sub' style='display:none;background:#f5f8ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>NHLOS</td>"
            f"<td style='padding-left:28px;color:#444'>&#x2514; {name}</td>"
            f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
        )
    if ref_gap > 0 or cur_gap > 0:
        nhlos_sub2 += (
            f"<tr class='sub-row nhlos-sub' style='display:none;background:#f0f3ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>NHLOS</td>"
            f"<td style='padding-left:28px;color:#888;font-style:italic'>&#x2514; HYP + TZ + UEFI Reservations</td>"
            f"{sub_val_cells(ref_gap, cur_gap)}</tr>\n"
        )

    # Rebuild kd_sub, ks_sub, us_sub, hw_sub using sub_val_cells
    kd_sub2 = ""
    for key in ["Slab", "Vmalloc", "KernelStack", "PageTables", "Percpu", "SecPageTables", "Modules", "CMA", "KDA"]:
        r_kb = kd_ref.get(key, 0)
        c_kb = kd_cur.get(key, 0)
        label = DISPLAY_NAMES.get(key, key)
        if key == "KDA":
            kd_sub2 += (
                f"<tr class='sub-row kd-sub' style='display:none;background:#f0f3ff'>"
                f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                f"<td style='padding-left:28px;color:#888;font-style:italic'>&#x2514; {label}</td>"
                f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
            )
        else:
            kd_sub2 += (
                f"<tr class='sub-row kd-sub' style='display:none;background:#f5f8ff'>"
                f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                f"<td style='padding-left:28px;color:#444'>&#x2514; {label}</td>"
                f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
            )

    ks_sub2 = ""
    if ks_has_data:
        for key in ["Vmlinux", "Page Structs", "Hash Tables", "Early Boot Reservations"]:
            r_kb = ks_ref.get(key, 0)
            c_kb = ks_cur.get(key, 0)
            ks_sub2 += (
                f"<tr class='sub-row ks-sub' style='display:none;background:#f5f8ff'>"
                f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                f"<td style='padding-left:28px;color:#444'>&#x2514; {key}</td>"
                f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
            )

    us_sub2 = ""
    for key in ["AnonPages", "Shmem"]:
        r_kb = us_ref.get(key, 0)
        c_kb = us_cur.get(key, 0)
        label = DISPLAY_NAMES.get(key, key)
        us_sub2 += (
            f"<tr class='sub-row us-sub' style='display:none;background:#f5f8ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
            f"<td style='padding-left:28px;color:#444'>&#x2514; {label}</td>"
            f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
        )

    # Total Available sub-rows: MemFree, Cached, Buffers
    avail_ref = ref.get("total_available_breakdown", {})
    avail_cur = cur.get("total_available_breakdown", {})
    avail_sub2 = ""
    for key, label in [("MemFree", "Free Memory"), ("Cached", "Page Cache"), ("Buffers", "Buffers")]:
        r_kb = avail_ref.get(key, 0)
        c_kb = avail_cur.get(key, 0)
        avail_sub2 += (
            f"<tr class='sub-row avail-sub' style='display:none;background:#e8f0fa'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
            f"<td style='padding-left:28px;color:#444'>&#x2514; {label}</td>"
            f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
        )

    # DMA-BUF exporter detail (size groups per exporter)
    ref_exp_detail = hw_ref.get("DMA-BUF_exporter_detail", {})
    cur_exp_detail = hw_cur.get("DMA-BUF_exporter_detail", {})

    hw_sub2 = (
        f"<tr class='sub-row hw-sub' style='display:none;background:#f5f8ff' "
        f"onclick=\"toggleRows('dmabuf-exp')\">"
        f"<td style='color:#888;font-size:11px;text-align:center'>"
        f"<span id='btn-dmabuf-exp' style='font-weight:bold;cursor:pointer'>+</span></td>"
        f"<td style='padding-left:28px;color:#444'>&#x2514; DMA-BUF Buffers</td>"
        f"{sub_val_cells(dmabuf_r, dmabuf_c)}</tr>\n"
    )
    for exp in all_exporters:
        r_kb = ref_exporters.get(exp, 0)
        c_kb = cur_exporters.get(exp, 0)
        exp_cls = f"dmabuf-exp-{exp.replace(' ','_').replace('/','_')}"
        # Exporter row -- expandable if it has size detail
        r_groups = ref_exp_detail.get(exp, [])
        c_groups = cur_exp_detail.get(exp, [])
        has_detail = bool(r_groups or c_groups)
        exp_btn = (f"<span id='btn-{exp_cls}' style='font-weight:bold;cursor:pointer;display:inline-block;width:14px;text-align:center'>+</span>"
                   if has_detail else "")
        onclick = f"onclick=\"toggleRows('{exp_cls}')\"" if has_detail else ""
        hw_sub2 += (
            f"<tr class='sub-row hw-sub dmabuf-exp' style='display:none;background:#f0f5ff' {onclick}>"
            f"<td style='color:#888;font-size:11px;text-align:center'>{exp_btn}</td>"
            f"<td style='padding-left:44px;color:#555;font-size:12px'>&#x2514; {exp}</td>"
            f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
        )
        # Size-group rows under this exporter
        if has_detail:
            # Merge ref and cur groups by size_kb
            all_sizes = sorted(
                set(g["size_kb"] for g in r_groups) | set(g["size_kb"] for g in c_groups),
                reverse=True
            )
            for size_kb in all_sizes:
                r_g = next((g for g in r_groups if g["size_kb"] == size_kb), None)
                c_g = next((g for g in c_groups if g["size_kb"] == size_kb), None)
                r_cnt = r_g["count"] if r_g else 0
                c_cnt = c_g["count"] if c_g else 0
                r_tot = r_g["total_kb"] if r_g else 0
                c_tot = c_g["total_kb"] if c_g else 0
                # Format: "18 MB × 7 = 126 MB"
                def fmt_size(kb):
                    if kb >= 1024:
                        return f"{kb//1024} MB"
                    return f"{kb} KB"
                label = f"{fmt_size(size_kb)} &times; {c_cnt if c_cnt else r_cnt} = {fmt_size(c_tot if c_tot else r_tot)}"
                # Use mb_precise for size group value cells (avoids 0 for sub-MB values)
                def precise_val_cells(r_kb, c_kb):
                    if is_standalone:
                        return f"<td class='num' style='font-size:11px'>{mb_precise(c_kb)}</td>"
                    d = c_kb - r_kb
                    d_str = (f"+{mb_precise(d)}" if d > 0 else
                             f"-{mb_precise(-d)}" if d < 0 else "0")
                    color = "#c00" if d > 0 else ("#060" if d < 0 else "#555")
                    fw = "font-weight:bold;" if d != 0 else ""
                    return (f"<td class='num' style='font-size:11px'>{mb_precise(r_kb)}</td>"
                            f"<td class='num' style='font-size:11px'>{mb_precise(c_kb)}</td>"
                            f"<td class='num' style='color:{color};{fw};font-size:11px'>{d_str}</td>")
                hw_sub2 += (
                    f"<tr class='sub-row hw-sub dmabuf-exp {exp_cls}' style='display:none;background:#eef2ff'>"
                    f"<td style='color:#aaa;font-size:10px;text-align:center'></td>"
                    f"<td style='padding-left:60px;color:#666;font-size:11px'>&#x2514; {label}</td>"
                    f"{precise_val_cells(r_tot, c_tot)}</tr>\n"
                )

    hw_sub2 += (
        f"<tr class='sub-row hw-sub' style='display:none;background:#f5f8ff'>"
        f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
        f"<td style='padding-left:28px;color:#444'>&#x2514; KGSL GPU Memory</td>"
        f"{sub_val_cells(kgsl_r, kgsl_c)}</tr>\n"
    )

    # Table header: single-column in standalone, three-column in comparison
    hdr_cols = (
        f"<th style='padding:10px 14px;text-align:right'>Value<br><span style='font-weight:normal;font-size:11px'>(MB)</span></th>"
        if is_standalone else
        f"<th style='padding:10px 14px;text-align:right'>{ref_label}<br><span style='font-weight:normal;font-size:11px'>(MB)</span></th>"
        f"<th style='padding:10px 14px;text-align:right'>{cur_label}<br><span style='font-weight:normal;font-size:11px'>(MB)</span></th>"
        f"<th style='padding:10px 14px;text-align:right'>Delta<br><span style='font-weight:normal;font-size:11px'>(MB)</span></th>"
    )
    hlos_colspan = 4 if is_standalone else 5

    html = f"""
<div style='max-width:{"640px" if is_standalone else "860px"};margin:0 auto'>
<table style='border-collapse:collapse;width:100%;font-family:Segoe UI,Arial,sans-serif;font-size:13px;box-shadow:0 2px 8px rgba(0,0,0,0.1);border-radius:6px;overflow:hidden'>
<thead>
<tr style='background:#1a3a5c;color:white'>
  <th style='padding:10px 14px;text-align:left;width:120px'>Group</th>
  <th style='padding:10px 14px;text-align:left'>Memory Category</th>
  {hdr_cols}
</tr>
</thead>
<tbody>
<tr style='{R_TOP}'>
  <td style='padding:8px 14px;color:#1a3a5c;font-size:11px;text-align:center'></td>
  <td style='padding:8px 14px'>Total RAM</td>
  {val_cells(ref.get("total_ram_kb",0), cur.get("total_ram_kb",0))}
</tr>
<tr style='{R_MID}' onclick="toggleRows('nhlos-sub')" style='cursor:pointer;{R_MID}'>
  <td style='padding:8px 14px;color:#555;font-size:11px;text-align:center'>{expand_btn("nhlos-sub")} NHLOS</td>
  <td style='padding:8px 14px'>NHLOS Reserved</td>
  {val_cells(ref.get("nhlos_kb",0), cur.get("nhlos_kb",0))}
</tr>
{nhlos_sub2}
<tr style='{R_MID}'>
  <td style='padding:8px 14px;color:#555;font-size:11px;text-align:center'></td>
  <td style='padding:8px 14px'>System RAM</td>
  {val_cells(ref.get("system_ram_kb",0), cur.get("system_ram_kb",0))}
</tr>
<tr style='background:#2c6fad;color:white'>
  <td colspan='{hlos_colspan}' style='padding:5px 14px;font-size:11px;font-weight:600;letter-spacing:1px'>
    &#x25B6; HLOS -- High Level OS
  </td>
</tr>
<tr style='{"cursor:pointer;" if ks_has_data else ""}{R_SUB}' {"onclick=\"toggleRows('ks-sub')\"" if ks_has_data else ""}>
  <td style='padding:8px 14px;color:#555;font-size:11px;text-align:center'>{"" + expand_btn("ks-sub") if ks_has_data else ""}</td>
  <td style='padding:8px 14px'>Kernel Static Memory</td>
  {val_cells(ref.get("kernel_static_kb",0), cur.get("kernel_static_kb",0))}
</tr>
{ks_sub2}
<tr style='cursor:pointer;{R_SUB}' onclick="toggleRows('kd-sub')">
  <td style='padding:8px 14px;color:#555;font-size:11px;text-align:center'>{expand_btn("kd-sub")}</td>
  <td style='padding:8px 14px'>Kernel Dynamic Memory</td>
  {val_cells(ref.get("kernel_dynamic_kb",0), cur.get("kernel_dynamic_kb",0))}
</tr>
{kd_sub2}
<tr style='cursor:pointer;{R_SUB}' onclick="toggleRows('hw-sub')">
  <td style='padding:8px 14px;color:#555;font-size:11px;text-align:center'>{expand_btn("hw-sub")}</td>
  <td style='padding:8px 14px'>Hardware / Driver Buffers</td>
  {val_cells(ref.get("hw_driver_kb",0), cur.get("hw_driver_kb",0))}
</tr>
{hw_sub2}
<tr style='cursor:pointer;{R_SUB}' onclick="toggleRows('us-sub')">
  <td style='padding:8px 14px;color:#555;font-size:11px;text-align:center'>{expand_btn("us-sub")}</td>
  <td style='padding:8px 14px'>User Space Apps</td>
  {val_cells(ref.get("user_space_kb",0), cur.get("user_space_kb",0))}
</tr>
{us_sub2}
<tr style='cursor:pointer;{R_TOP}' onclick="toggleRows('avail-sub')">
  <td style='padding:8px 14px;color:#1a3a5c;font-size:11px;text-align:center'>{expand_btn("avail-sub")}</td>
  <td style='padding:8px 14px;font-weight:bold'>Total Available Memory</td>
  {val_cells(ref.get("total_available_kb",0), cur.get("total_available_kb",0))}
</tr>
{avail_sub2}
</tbody>
</table>
</div>"""
    return html


# Human-readable names for the Detailed Category Deltas table
CATEGORY_DISPLAY_NAMES = {
    "MemTotal":    "Total Memory",
    "MemFree":     "Free Memory",
    "Slab":        "Slab Allocator",
    "Vmalloc":     "Vmalloc",
    "VmallocUsed": "Vmalloc",
    "PageTables":  "Page Tables",
    "KernelStack": "Kernel Stack",
    "AnonPages":   "Anonymous Pages",
    "Shmem":       "Shared Memory",
    "Cached":      "Cached",
    "Buffers":     "Buffers",
    "SwapCached":  "Swap Cached",
    "DMA-BUF":     "DMA-BUF Buffers",
    "KGSL":        "KGSL GPU Memory",
    "CMA Used":    "CMA Used",
    "NHLOS Total": "NHLOS Total",
}


def _render_top_processes_html(st: dict) -> str:
    """Render top processes by PSS as a collapsible section for standalone mode."""
    procs = st.get("current", {}).get("top_processes", [])
    if not procs:
        return ""
    rows = ""
    for i, p in enumerate(procs, 1):
        pss = p.get("pss_kb", 0)
        name = p.get("name", "")
        # Shorten the name: take basename of first token
        exe = name.split()[0] if name.strip() else name
        short = exe.split("/")[-1][:40]
        rows += (
            f"<tr>"
            f"<td style='text-align:right;color:#888;font-size:11px;padding:5px 10px'>{i}</td>"
            f"<td style='padding:5px 10px' title='{name[:100]}'>{short}</td>"
            f"<td style='text-align:right;padding:5px 10px'>{pss/1024:.1f}</td>"
            f"</tr>\n"
        )
    sec_id = "top-procs"
    return f"""
<div style='max-width:640px;margin:12px auto 0'>
<div style='background:#1a3a5c;color:white;padding:8px 14px;border-radius:6px 6px 0 0;
     cursor:pointer;display:flex;align-items:center;gap:8px'
     onclick="var b=document.getElementById('{sec_id}');var btn=document.getElementById('btn-{sec_id}');
              var c=b.style.display==='none';b.style.display=c?'':'none';btn.textContent=c?'\u2212':'+';">
  <span id='btn-{sec_id}' style='font-weight:bold;min-width:16px'>+</span>
  <span style='font-size:0.95em;font-weight:600'>Top Processes by PSS
    <span style='font-weight:normal;font-size:11px;opacity:0.8'>({len(procs)} shown)</span>
  </span>
</div>
<div id='{sec_id}' style='display:none;border:1px solid #c8d8ea;border-top:none;
     border-radius:0 0 6px 6px;background:#fff;padding:8px'>
<table style='width:100%;border-collapse:collapse;font-size:13px'>
<tr style='background:#2c6fad;color:white'>
  <th style='padding:6px 10px;text-align:right;width:32px'>#</th>
  <th style='padding:6px 10px;text-align:left'>Process</th>
  <th style='padding:6px 10px;text-align:right'>PSS (MB)</th>
</tr>
{rows}
</table>
</div>
</div>"""


def render_top_processes_details_html(
        cur_breakdowns: list, ref_breakdowns: list, is_standalone: bool) -> str:
    """Render 'Top Processes Memory Details' section with collapsible rows using native HTML details/summary."""
    if not cur_breakdowns and not ref_breakdowns:
        return ""

    cur_by_name = {bd["name"]: bd for bd in cur_breakdowns}
    ref_by_name = {bd["name"]: bd for bd in ref_breakdowns}

    # Union: cur first, then ref-only
    seen: set = set()
    all_names: list = []
    for bd in cur_breakdowns + ref_breakdowns:
        if bd["name"] not in seen:
            all_names.append(bd["name"])
            seen.add(bd["name"])
    if not all_names:
        return ""

    def _mb(kb):
        return f"{kb / 1024:.1f}"

    def _ds(d):  # delta style
        if d > 0:
            return "color:#c00;font-weight:bold"
        if d < 0:
            return "color:#060;font-weight:bold"
        return "color:#555"

    def _vc(ref_kb, cur_kb):  # value cells
        if is_standalone:
            return f"<td style='text-align:right;padding:5px 10px'>{_mb(cur_kb)}</td>"
        d = cur_kb - ref_kb
        return (
            f"<td style='text-align:right;padding:5px 10px'>{_mb(ref_kb)}</td>"
            f"<td style='text-align:right;padding:5px 10px'>{_mb(cur_kb)}</td>"
            f"<td style='text-align:right;padding:5px 10px;{_ds(d)}'>{d/1024:+.1f}</td>"
        )

    hdr = (
        "<th style='text-align:left;padding:6px 10px'>Category</th>"
        "<th style='text-align:right;padding:6px 10px'>PSS (MB)</th>"
        if is_standalone else
        "<th style='text-align:left;padding:6px 10px'>Category</th>"
        "<th style='text-align:right;padding:6px 10px'>Ref (MB)</th>"
        "<th style='text-align:right;padding:6px 10px'>Cur (MB)</th>"
        "<th style='text-align:right;padding:6px 10px'>Delta (MB)</th>"
    )
    ncols = 2 if is_standalone else 4

    processes_html = ""
    for name in all_names:
        cur = cur_by_name.get(name)
        ref = ref_by_name.get(name)
        cur_total = cur["total_pss_kb"] if cur else 0
        ref_total = ref["total_pss_kb"] if ref else 0

        if cur and ref:
            status, status_bg = "Changed", "#2c6fad"
        elif cur:
            status, status_bg = "New", "#155724"
        else:
            status, status_bg = "Removed", "#721c24"

        delta_total = cur_total - ref_total

        # --- Anonymous Buffers: show by size only (no per-library attribution) ---
        # Attribution via "nearest preceding named mapping" is unreliable across runs
        # (library load order changes with ASLR), so we show raw buffer sizes only.
        cur_bufs = cur["anon_buffers"] if cur else []
        ref_bufs = ref["anon_buffers"] if ref else []
        display_bufs = cur_bufs if cur_bufs else ref_bufs
        proc_safe_anon = name.replace(" ", "_").replace("-", "_").replace(".", "_")
        _anon_rows = [
            f"<tr style='background:#f8f9ff'>"
            f"<td style='padding:3px 8px 3px 24px;font-size:11px;color:#555'>"
            f"&#x2514; {s:,} KB &nbsp;({s/1024:.1f} MB)</td>"
            f"</tr>\n"
            for s in display_bufs
        ]
        seg_rows_html = _progressive_expand_html(_anon_rows, 5, f"anon-{proc_safe_anon}", 1)
        note_row = ""

        anon_ref_kb = ref["anon_buffers_kb"] if ref else 0
        anon_cur_kb = cur["anon_buffers_kb"] if cur else 0
        d_anon = anon_cur_kb - anon_ref_kb
        anon_delta_hint = (f" &nbsp;<span style='{_ds(d_anon)};font-size:12px'>Δ {d_anon/1024:+.1f} MB</span>"
                           if not is_standalone else "")
        anon_section = f"""
<tr>
  <td colspan='{ncols}' style='padding:0;border-top:1px solid #e0e8f0'>
    <details>
      <summary style='padding:6px 12px;cursor:pointer;background:#edf3fb;
                      font-size:13px;list-style:none;display:list-item'>
        <b>Anonymous Buffers</b>
        <span style='color:#888;font-size:12px;margin-left:8px'>
          {_mb(anon_cur_kb) if is_standalone else (_mb(anon_ref_kb) + ' &rarr; ' + _mb(anon_cur_kb))} MB
        </span>{anon_delta_hint}
      </summary>
      <table style='width:100%;border-collapse:collapse'>{seg_rows_html}</table>
    </details>
  </td>
</tr>"""

        # --- Shared Libraries: build per-library breakdown ---
        cur_libs = cur["shared_libs_detail"] if cur else []
        ref_libs = ref["shared_libs_detail"] if ref else []
        # Build merged list of all library names (union of cur + ref), sorted by cur PSS
        seen_l: set = set()
        all_lib_names: list = []
        for lib in cur_libs + ref_libs:
            if lib["name"] not in seen_l:
                all_lib_names.append(lib["name"])
                seen_l.add(lib["name"])
        cur_libs_map = {lib["name"]: lib["pss_kb"] for lib in cur_libs}
        ref_libs_map = {lib["name"]: lib["pss_kb"] for lib in ref_libs}

        def _lib_row(lname):
            c_kb = cur_libs_map.get(lname, 0)
            r_kb = ref_libs_map.get(lname, 0)
            d = c_kb - r_kb
            if is_standalone:
                val = f"<td style='text-align:right;padding:4px 8px;font-size:12px'>{_mb(c_kb)}</td>"
            else:
                val = (
                    f"<td style='text-align:right;padding:4px 8px;font-size:12px'>{_mb(r_kb)}</td>"
                    f"<td style='text-align:right;padding:4px 8px;font-size:12px'>{_mb(c_kb)}</td>"
                    f"<td style='text-align:right;padding:4px 8px;font-size:12px;{_ds(d)}'>{d/1024:+.1f}</td>"
                )
            return (
                f"<tr style='background:#f5f8ff'>"
                f"<td style='padding:4px 8px 4px 24px;font-size:12px;color:#444'>"
                f"&#x2514; {lname}</td>"
                f"{val}</tr>\n"
            )

        lib_hdr_cols = (
            "<th style='text-align:right;padding:4px 8px;font-size:11px'>PSS (MB)</th>"
            if is_standalone else
            "<th style='text-align:right;padding:4px 8px;font-size:11px'>Ref (MB)</th>"
            "<th style='text-align:right;padding:4px 8px;font-size:11px'>Cur (MB)</th>"
            "<th style='text-align:right;padding:4px 8px;font-size:11px'>Delta (MB)</th>"
        )

        proc_safe_libs = name.replace(" ", "_").replace("-", "_").replace(".", "_")
        _all_lib_rows = [_lib_row(n) for n in all_lib_names]
        libs_progressive = _progressive_expand_html(_all_lib_rows, 5, f"libs-{proc_safe_libs}", ncols)

        libs_table = (
            f"<table style='width:100%;border-collapse:collapse'>"
            f"<tr style='background:#2c6fad;color:white'>"
            f"<th style='text-align:left;padding:4px 8px;font-size:11px'>Library</th>"
            f"{lib_hdr_cols}</tr>"
            f"{libs_progressive}"
            f"</table>"
        )

        libs_ref_kb = ref["shared_libs_kb"] if ref else 0
        libs_cur_kb = cur["shared_libs_kb"] if cur else 0
        d_libs = libs_cur_kb - libs_ref_kb
        libs_delta_hint = (f" &nbsp;<span style='{_ds(d_libs)};font-size:12px'>Δ {d_libs/1024:+.1f} MB</span>"
                           if not is_standalone else "")
        shared_libs_section = f"""
<tr>
  <td colspan='{ncols}' style='padding:0;border-top:1px solid #e0e8f0'>
    <details>
      <summary style='padding:6px 12px;cursor:pointer;background:#edf3fb;
                      font-size:13px;list-style:none;display:list-item'>
        <b>Shared Libraries</b>
        <span style='color:#888;font-size:12px;margin-left:8px'>
          {_mb(libs_cur_kb) if is_standalone else (_mb(libs_ref_kb) + ' &rarr; ' + _mb(libs_cur_kb))} MB
        </span>{libs_delta_hint}
        <span style='color:#aaa;font-size:11px;margin-left:8px'>({len(all_lib_names)} libraries)</span>
      </summary>
      {libs_table}
    </details>
  </td>
</tr>"""

        # Build category rows
        cat_rows = ""
        for cat_name, ref_kb, cur_kb in [
            ("Heap",  ref["heap_kb"]  if ref else 0, cur["heap_kb"]  if cur else 0),
            ("Stack", ref["stack_kb"] if ref else 0, cur["stack_kb"] if cur else 0),
        ]:
            cat_rows += (
                f"<tr style='background:#f8fbff'>"
                f"<td style='padding:5px 10px;font-size:13px'>{cat_name}</td>"
                f"{_vc(ref_kb, cur_kb)}"
                f"</tr>\n"
            )
        cat_rows += shared_libs_section
        cat_rows += anon_section
        cat_rows += (
            f"<tr style='background:#f8fbff'>"
            f"<td style='padding:5px 10px;font-size:13px'>Other</td>"
            f"{_vc(ref['other_kb'] if ref else 0, cur['other_kb'] if cur else 0)}"
            f"</tr>\n"
        )
        cat_rows += (
            f"<tr style='background:#e4edf8;font-weight:bold'>"
            f"<td style='padding:6px 10px'>Total PSS</td>"
            f"{_vc(ref_total, cur_total)}"
            f"</tr>\n"
        )

        # Process summary line
        status_badge = (
            f"<span style='background:{status_bg};color:white;padding:2px 8px;"
            f"border-radius:4px;font-size:11px;font-weight:600;margin-left:8px'>{status}</span>"
        )
        if is_standalone:
            summary_line = f"{name} {status_badge} &nbsp; <span style='font-size:12px;opacity:0.8'>{_mb(cur_total)} MB</span>"
        else:
            d_str = f"Δ {delta_total/1024:+.1f} MB"
            summary_line = (
                f"{name} {status_badge} &nbsp;"
                f"<span style='font-size:12px;opacity:0.8'>"
                f"{_mb(ref_total)} &rarr; {_mb(cur_total)} MB &nbsp; {d_str}</span>"
            )

        processes_html += f"""
<details style='margin-bottom:8px;border:1px solid #c8d8ea;border-radius:6px;overflow:hidden'>
  <summary style='background:#1a3a5c;color:white;padding:10px 16px;cursor:pointer;
                  list-style:none;display:list-item;font-size:14px;font-weight:600'>
    {summary_line}
  </summary>
  <div style='padding:0'>
    <table style='width:100%;border-collapse:collapse;font-size:13px'>
      <thead><tr style='background:#2c6fad;color:white'>{hdr}</tr></thead>
      <tbody>{cat_rows}</tbody>
    </table>
  </div>
</details>"""

    return f"""
<h3 style='margin-top:20px'>Top Processes Memory Details
  <span style='font-weight:normal;font-size:12px;color:#888'>({len(all_names)} processes — click to expand)</span>
</h3>
{processes_html}"""


def render_comparison_html(data: dict) -> str:
    # Detect standalone mode (self-comparison)
    is_standalone = (
        data.get("current_snapshot_id") == data.get("reference_snapshot_id")
        and data.get("current_snapshot_id", "") != ""
    )

    # Summary table at the top
    summary_html = render_summary_table_html(data)

    if is_standalone:
        # In standalone mode: memory breakdown + top processes, no delta table
        top_procs_html = _render_top_processes_html(data.get("summary_table", {}))
        smaps_html = render_top_processes_details_html(
            data.get("_smaps_cur", []), [], True)
        return summary_html + top_procs_html + smaps_html

    rows = ""
    for cat in data.get("categories", []):
        trend = cat.get("trend", "STABLE")
        css = {"GROWING": "growing", "SHRINKING": "shrinking"}.get(trend, "")
        display_name = CATEGORY_DISPLAY_NAMES.get(cat["category"], cat["category"])
        rows += (
            f"<tr class='{css}'>"
            f"<td>{display_name}</td>"
            f"<td style='text-align:right'>{cat['reference_kb']/1024:.1f}</td>"
            f"<td style='text-align:right'>{cat['current_kb']/1024:.1f}</td>"
            f"<td style='text-align:right'>{cat['delta_kb']/1024:+.1f}</td>"
            f"<td style='text-align:right'>{cat['delta_pct']:+.1f}%</td>"
            f"<td>{trend}</td>"
            f"</tr>\n"
        )
    return f"""
<p><b>Current:</b> {data.get('current_label','')} &nbsp;|&nbsp;
   <b>Reference:</b> {data.get('reference_label','')}</p>
{summary_html}"""


def render_kernel_diff_html(data: dict) -> str:
    bd = data.get("buddy_fragmentation", {})
    slab_rows = ""
    for s in data.get("slab_diff", [])[:50]:
        css = "warning" if s.get("flagged") else ""
        slab_rows += (
            f"<tr class='{css}'>"
            f"<td>{s['name']}</td>"
            f"<td style='text-align:right'>{s['ref_kb']}</td>"
            f"<td style='text-align:right'>{s['cur_kb']}</td>"
            f"<td style='text-align:right'>{s['delta_kb']:+}</td>"
            f"<td style='text-align:right'>{s['delta_pct']:+.1f}%</td>"
            f"<td>{'[!]' if s.get('flagged') else ''}</td>"
            f"</tr>\n"
        )
    findings = "".join(
        f"<li class='{f['severity'].lower()}'>[{f['severity']}] {f['message']}</li>"
        for f in data.get("findings", [])
    )
    return f"""
<h3>Buddy Fragmentation</h3>
<p>Reference: {bd.get('reference_index',0):.4f} &rarr;
   Current: {bd.get('current_index',0):.4f}
   (delta: {bd.get('fragmentation_index_delta',0):+.4f})</p>
<h3>Slab Changes (top 50 by delta)</h3>
<table><tr><th>Slab</th><th>Ref KB</th><th>Cur KB</th>
<th>Delta KB</th><th>Delta %</th><th>Flag</th></tr>
{slab_rows}</table>
{'<h3>Findings</h3><ul>' + findings + '</ul>' if findings else ''}"""


def _short_name(cmdline: str) -> str:
    """Return a short readable process name from a full cmdline string."""
    # Take the first token (the executable), then basename
    exe = cmdline.split()[0] if cmdline.strip() else cmdline
    # Strip path
    name = exe.split("/")[-1].split("\\")[-1]
    # Truncate to 40 chars
    return name[:40]


def render_userspace_diff_html(data: dict) -> str:
    # Filter out 0-delta processes and sort by |delta_pss_kb| descending
    all_procs = data.get("process_diff", [])
    changed = sorted(
        [p for p in all_procs if p.get("delta_pss_kb", 0) != 0],
        key=lambda x: abs(x.get("delta_pss_kb", 0)),
        reverse=True
    )
    total_changed = len(changed)

    def proc_row(p):
        css = "warning" if p.get("flagged") else ""
        short = _short_name(p["name"])
        full  = p["name"][:80] + ("..." if len(p["name"]) > 80 else "")
        return (
            f"<tr class='{css}'>"
            f"<td title='{full}'>{short}</td>"
            f"<td style='text-align:right'>{p['ref_pss_kb']/1024:.1f}</td>"
            f"<td style='text-align:right'>{p['cur_pss_kb']/1024:.1f}</td>"
            f"<td style='text-align:right'>{p['delta_pss_kb']/1024:+.1f}</td>"
            f"<td style='text-align:right'>{p['delta_pct']:+.1f}%</td>"
            f"<td>{'[!]' if p.get('flagged') else ''}</td>"
            f"</tr>\n"
        )

    subtitle = f"({total_changed} processes changed" + (f", {len(all_procs)-total_changed} unchanged hidden" if len(all_procs) > total_changed else "") + ")"

    dma = data.get("dmabuf_diff", {})
    kgsl = data.get("kgsl_diff", {})
    findings = "".join(
        f"<li class='{f['severity'].lower()}'>[{f['severity']}] {f['message']}</li>"
        for f in data.get("findings", [])
    )

    if not changed:
        proc_table = "<p style='color:#888'>No process PSS changes detected.</p>"
    else:
        all_proc_rows = [proc_row(p) for p in changed]
        proc_rows_html = _progressive_expand_html(all_proc_rows, 5, "proc", 6)
        proc_table = f"""
<table><tr><th>Process</th><th>Ref PSS MB</th><th>Cur PSS MB</th>
<th>Delta MB</th><th>Delta %</th><th>Flag</th></tr>
{proc_rows_html}
</table>"""

    # New and exited processes
    new_procs = data.get("new_processes", [])
    exited_procs = data.get("exited_processes", [])

    def _proc_row_simple(p):
        return (
            f"<tr>"
            f"<td title='{p.get('name','')[:80]}'>{_short_name(p.get('name',''))}</td>"
            f"<td style='text-align:right'>{p.get('pss_kb',0)/1024:.1f}</td>"
            f"</tr>\n"
        )

    new_exited_section = ""
    if new_procs:
        rows_new = "".join(_proc_row_simple(p) for p in
                           sorted(new_procs, key=lambda x: x.get("pss_kb", 0), reverse=True))
        new_exited_section += f"""
<h3>New Processes <span style='font-weight:normal;font-size:12px;color:#888'>({len(new_procs)} appeared since baseline)</span></h3>
<table><tr><th>Process</th><th>PSS (MB)</th></tr>
{rows_new}</table>"""
    if exited_procs:
        rows_exited = "".join(_proc_row_simple(p) for p in
                              sorted(exited_procs, key=lambda x: x.get("pss_kb", 0), reverse=True))
        new_exited_section += f"""
<h3>Exited Processes <span style='font-weight:normal;font-size:12px;color:#888'>({len(exited_procs)} present in baseline only)</span></h3>
<table><tr><th>Process</th><th>PSS (MB)</th></tr>
{rows_exited}</table>"""

    smaps_html = render_top_processes_details_html(
        data.get("_smaps_cur", []), data.get("_smaps_ref", []), False)
    return f"""
<h3>Process PSS Changes <span style='font-weight:normal;font-size:12px;color:#888'>{subtitle}</span></h3>
{proc_table}
{new_exited_section}
{smaps_html}"""


def _section_title_for(rtype: str, data: dict) -> str:
    """Return section title, using 'Memory Summary' for standalone snapshots."""
    titles = {
        "rca":                 "Root Cause Analysis",
        "carveout_validation": "NHLOS Carveout Validation",
        "snapshot_comparison": "Memory Delta Summary",
        "kernel_diff":         "Kernel Memory Changes",
        "userspace_diff":      "Userspace Memory Changes",
    }
    title = titles.get(rtype, f"Report ({rtype})")
    # Override for standalone mode (self-comparison)
    if rtype == "snapshot_comparison":
        is_standalone = (
            data.get("current_snapshot_id") == data.get("reference_snapshot_id")
            and data.get("current_snapshot_id", "") != ""
        )
        if is_standalone:
            title = "Memory Summary"
    return title


SECTION_RENDERERS = {
    "rca":                 ("Root Cause Analysis",          render_rca_html),
    "carveout_validation": ("NHLOS Carveout Validation",    render_carveout_html),
    "snapshot_comparison": ("Memory Delta Summary",         render_comparison_html),
    "kernel_diff":         ("Kernel Memory Changes",        render_kernel_diff_html),
    "userspace_diff":      ("Userspace Memory Changes",     render_userspace_diff_html),
}


# ---------------------------------------------------------------------------
# Unified HTML report
# ---------------------------------------------------------------------------

def render_device_info_html(device: dict, max_width: str = "640px") -> str:
    """Render a compact device info table for the top of the report."""
    if not device:
        return ""
    model    = device.get("model", "")
    kernel   = device.get("kernel_version", "")
    os_name  = device.get("os_name", "")
    build_id = device.get("build_id", "")
    soc_name = device.get("soc_name", "")   # e.g. QCS6490 from /sys/devices/soc0/machine
    soc_rev  = device.get("soc_revision", "")
    serial          = device.get("serial", "")
    network_address = device.get("network_address", "")
    transport_type  = device.get("transport_type", "")
    ts              = device.get("captured_at", "")

    # Build SoC string: "QCS6490 rev 1.0" or just "QCS6490"
    soc_str = soc_name
    if soc_rev and soc_name:
        soc_str += f" rev {soc_rev}"

    row_styles = ["background:#e4edf8;", "background:#f0f5fb;"]
    row_idx = [0]
    rows = ""
    def row(label, value):
        if not value:
            return ""
        style = row_styles[row_idx[0] % 2]
        row_idx[0] += 1
        return (f"<tr style='{style}'>"
                f"<td style='color:#555;font-size:12px;padding:6px 20px;white-space:nowrap;font-weight:500'>{label}</td>"
                f"<td style='padding:6px 20px;font-size:12px'>{value}</td>"
                f"</tr>\n")

    rows += row("Machine", model)
    rows += row("SoC", soc_str)
    rows += row("OS", os_name)
    rows += row("Build", build_id)
    rows += row("Kernel", kernel)
    # Show "Network Address" for SSH transport, "Device ID" for ADB transport
    if transport_type == "ssh":
        rows += row("Network Address", network_address)
    else:
        rows += row("Device ID", serial)
    rows += row("Captured", ts)

    if not rows:
        return ""

    return f"""
<div style='max-width:{max_width};margin:0 auto 16px'>
<div style='background:#fff;border:1px solid #c8d8ea;border-radius:6px;
     overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)'>
<div style='background:#2c6fad;color:white;padding:8px 16px;font-size:11px;font-weight:600;letter-spacing:0.5px'>
  &#x1F4BB; Device Information
</div>
<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:13px;width:100%'>
<thead>
<tr style='background:#1a3a5c;color:white'>
  <th style='padding:8px 14px;text-align:left;font-weight:600;width:140px'>Field</th>
  <th style='padding:8px 14px;text-align:left;font-weight:600'>Value</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</div>
</div>"""


def render_usecase_details_html(data: dict, max_width: str = "860px") -> str:
    """Render Use Case Details block for comparison reports."""
    usecase_name = data.get("usecase_name", "")
    usecase_cmd  = data.get("usecase_command", "")
    cur_label    = data.get("current_label", "")
    ref_label    = data.get("reference_label", "")

    if not usecase_name and not usecase_cmd:
        return ""

    row_styles = ["background:#e4edf8;", "background:#f0f5fb;"]
    row_idx = [0]
    rows = ""
    def row(label, value, mono=False):
        if not value:
            return ""
        style = row_styles[row_idx[0] % 2]
        row_idx[0] += 1
        val_style = "font-family:monospace;font-size:11px" if mono else "font-size:12px"
        return (f"<tr style='{style}'>"
                f"<td style='color:#555;font-size:12px;padding:6px 20px;white-space:nowrap;font-weight:500'>{label}</td>"
                f"<td style='padding:6px 20px;{val_style}'>{value}</td>"
                f"</tr>\n")

    rows += row("Use-Case", usecase_name)
    rows += row("Command", usecase_cmd, mono=True)
    rows += row("Baseline", ref_label)
    rows += row("Active", cur_label)

    return f"""
<div style='max-width:{max_width};margin:0 auto 16px'>
<div style='background:#fff;border:1px solid #c8d8ea;border-radius:6px;
     overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)'>
<div style='background:#2c6fad;color:white;padding:8px 16px;font-size:11px;font-weight:600;letter-spacing:0.5px'>
  &#x1F9EA; Use Case Details
</div>
<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:13px;width:100%'>
<thead>
<tr style='background:#1a3a5c;color:white'>
  <th style='padding:8px 14px;text-align:left;font-weight:600;width:140px'>Field</th>
  <th style='padding:8px 14px;text-align:left;font-weight:600'>Value</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</div>
</div>"""


def render_findings_html(sections: list[tuple[str, str, dict]]) -> str:
    """Collect findings from all loaded reports and render as a unified section."""
    SEV_ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    SEV_COLORS = {
        "CRITICAL": ("#c00",    "#fff5f5", "#fde8e8"),
        "WARNING":  ("#e6a817", "#fffdf0", "#fef8e0"),
        "INFO":     ("#2c6fad", "#f0f7ff", "#e8f4fd"),
    }
    SOURCE_LABELS = {
        "snapshot_comparison": "Memory Delta",
        "userspace_diff":      "Userspace Diff",
        "kernel_diff":         "Kernel Diff",
        "rca":                 "RCA",
        "carveout_validation": "Carveout",
    }

    all_findings = []
    for rtype, path, data in sections:
        source_label = SOURCE_LABELS.get(rtype, rtype)
        for f in data.get("findings", []):
            all_findings.append({
                "severity": f.get("severity", "INFO"),
                "message":  f.get("message", ""),
                "source":   source_label,
            })

    if not all_findings:
        return ""

    # Sort by severity
    all_findings.sort(key=lambda x: SEV_ORDER.get(x["severity"], 99))

    counts = {s: sum(1 for f in all_findings if f["severity"] == s) for s in SEV_ORDER}
    summary_badges = ""
    for sev, cnt in counts.items():
        if cnt == 0:
            continue
        color, _, bg = SEV_COLORS.get(sev, ("#555", "#fff", "#f8f8f8"))
        summary_badges += (
            f"<span style='background:{bg};color:{color};border:1px solid {color};"
            f"padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;"
            f"margin-right:6px'>{sev}: {cnt}</span>"
        )

    rows = ""
    for f in all_findings:
        sev = f["severity"]
        color, bg_card, bg_row = SEV_COLORS.get(sev, ("#555", "#fff", "#f8f8f8"))
        icon = {"CRITICAL": "&#x26A0;", "WARNING": "&#x26A0;", "INFO": "&#x2139;"}.get(sev, "")
        rows += (
            f"<tr style='background:{bg_row}'>"
            f"<td style='padding:8px 12px;white-space:nowrap'>"
            f"<span style='color:{color};font-weight:600;font-size:12px'>{icon} {sev}</span></td>"
            f"<td style='padding:8px 12px;color:#555;font-size:12px;white-space:nowrap'>"
            f"{f['source']}</td>"
            f"<td style='padding:8px 12px;font-size:13px'>{f['message']}</td>"
            f"</tr>\n"
        )

    return f"""
<div style='margin-bottom:8px'>{summary_badges}</div>
<table style='border-collapse:collapse;width:100%;font-size:13px'>
<thead>
<tr style='background:#1a3a5c;color:white'>
  <th style='padding:8px 12px;text-align:left;white-space:nowrap'>Severity</th>
  <th style='padding:8px 12px;text-align:left;white-space:nowrap'>Source</th>
  <th style='padding:8px 12px;text-align:left'>Message</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>"""


def render_npoint_comparison_html(snap_sections: list) -> str:
    """
    Render a unified N-point comparison table for multiple snapshot_comparison sections.
    Shows all N data points side-by-side with delta (last - first).
    """
    if len(snap_sections) < 2:
        return ""

    # Extract labels and summary_table.current from each section
    labels = []
    snaps  = []
    for _, _, data in snap_sections:
        label = data.get("current_label", "Snapshot")
        st    = data.get("summary_table", {})
        snap  = st.get("current", st.get("reference", {}))
        labels.append(label)
        snaps.append(snap)

    n = len(snaps)

    # Rows to display: (group, display_name, key, is_bold, is_hlos_banner_before)
    ROWS = [
        ("",      "Total RAM",                  "total_ram_kb",        True,  False),
        ("NHLOS", "NHLOS Reserved",              "nhlos_kb",            False, False),
        ("",      "System RAM",                  "system_ram_kb",       False, False),
        ("HLOS",  "Kernel Static Memory",        "kernel_static_kb",    False, True),
        ("HLOS",  "Kernel Dynamic Memory",       "kernel_dynamic_kb",   False, False),
        ("HLOS",  "Hardware / Driver Buffers",   "hw_driver_kb",        False, False),
        ("HLOS",  "User Space Apps",             "user_space_kb",       False, False),
        ("",      "Total Available Memory",      "total_available_kb",  True,  False),
    ]

    # Sub-rows for expandable categories
    KD_SUBS = [
        ("Slab Allocator",          "Slab"),
        ("Vmalloc",                 "Vmalloc"),
        ("Kernel Stack",            "KernelStack"),
        ("Page Tables",             "PageTables"),
        ("CMA (Contiguous Memory)", "CMA"),
        ("Kernel Modules",          "Modules"),
    ]
    US_SUBS = [
        ("Anonymous Pages", "AnonPages"),
        ("Shared Memory",   "Shmem"),
    ]

    delta_label = (f"Delta ({labels[-1]} &minus; {labels[0]})"
                   if n == 2 else f"Delta (Last &minus; First)")

    # Build header
    hdr_vals = "".join(
        f"<th style='text-align:right;padding:8px 12px;white-space:nowrap'>"
        f"{l}<br><span style='font-weight:normal;font-size:11px'>(MB)</span></th>"
        for l in labels
    )
    hdr_delta = (
        f"<th style='text-align:right;padding:8px 12px;white-space:nowrap'>"
        f"{delta_label}<br><span style='font-weight:normal;font-size:11px'>(MB)</span></th>"
    )

    def _mb(kb):
        return round(kb / 1024)

    def _val_cells(vals_kb, bold=False):
        fw = "font-weight:bold;" if bold else ""
        return "".join(
            f"<td style='text-align:right;padding:7px 12px;{fw}'>{_mb(v)}</td>"
            for v in vals_kb
        )

    def _delta_cell(vals_kb, bold=False):
        d = vals_kb[-1] - vals_kb[0]
        dm = _mb(d)
        color = "#c00" if d > 0 else ("#060" if d < 0 else "#555")
        fw = "font-weight:bold;" if (d != 0 or bold) else ""
        sign = f"{dm:+}"
        return (
            f"<td style='text-align:right;padding:7px 12px;color:{color};{fw}'>{sign}</td>"
        )

    rows_html = ""
    hlos_banner_shown = False

    for group, display, key, is_bold, hlos_before in ROWS:
        # HLOS banner row
        if hlos_before and not hlos_banner_shown:
            hlos_banner_shown = True
            ncols_total = 2 + n + 1
            rows_html += (
                f"<tr style='background:#2c6fad;color:white'>"
                f"<td colspan='{ncols_total}' style='padding:5px 12px;font-size:11px;"
                f"font-weight:600;letter-spacing:1px'>&#x25B6; HLOS &mdash; High Level OS</td>"
                f"</tr>\n"
            )

        vals_kb = [s.get(key, 0) for s in snaps]
        bg = "#d0dff0" if is_bold else ("#e4edf8" if group == "NHLOS" else "#f0f5fb")
        fw = "font-weight:bold;" if is_bold else ""

        # Expandable sub-rows
        sub_key = None
        if key == "kernel_dynamic_kb":
            sub_key = "kd"
        elif key == "user_space_kb":
            sub_key = "us"

        onclick = f" onclick=\"toggleRows('{sub_key}-sub')\" style='cursor:pointer'" if sub_key else ""
        expand_btn = (
            f"<span id='btn-{sub_key}-sub' style='font-weight:bold;cursor:pointer;"
            f"display:inline-block;width:14px;text-align:center'>+</span>"
            if sub_key else ""
        )

        rows_html += (
            f"<tr style='background:{bg}'{onclick}>"
            f"<td style='padding:7px 12px;color:#555;font-size:11px;text-align:center'>"
            f"{expand_btn}{group}</td>"
            f"<td style='padding:7px 12px;{fw}'>{display}</td>"
            f"{_val_cells(vals_kb, is_bold)}"
            f"{_delta_cell(vals_kb, is_bold)}"
            f"</tr>\n"
        )

        # Sub-rows
        if key == "kernel_dynamic_kb":
            for sub_display, sub_field in KD_SUBS:
                sub_vals = [s.get("kernel_dynamic_breakdown", {}).get(sub_field, 0) for s in snaps]
                rows_html += (
                    f"<tr class='kd-sub' style='display:none;background:#f5f8ff'>"
                    f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                    f"<td style='padding:6px 12px 6px 28px;color:#444'>&#x2514; {sub_display}</td>"
                    f"{_val_cells(sub_vals)}"
                    f"{_delta_cell(sub_vals)}"
                    f"</tr>\n"
                )
        elif key == "user_space_kb":
            for sub_display, sub_field in US_SUBS:
                sub_vals = [s.get("user_space_breakdown", {}).get(sub_field, 0) for s in snaps]
                rows_html += (
                    f"<tr class='us-sub' style='display:none;background:#f5f8ff'>"
                    f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                    f"<td style='padding:6px 12px 6px 28px;color:#444'>&#x2514; {sub_display}</td>"
                    f"{_val_cells(sub_vals)}"
                    f"{_delta_cell(sub_vals)}"
                    f"</tr>\n"
                )

    # Top processes comparison table
    seen_procs: set = set()
    proc_order: list = []
    proc_pss: dict = {}
    for snap, lbl in zip(snaps, labels):
        for proc in snap.get("top_processes", []):
            full_cmd = proc.get("name", "")
            short = full_cmd.split("/")[-1].split(" ")[0]
            if short not in seen_procs:
                proc_order.append(short)
                seen_procs.add(short)
            proc_pss.setdefault(short, {})[lbl] = round(proc.get("pss_kb", 0) / 1024, 1)
    proc_order.sort(key=lambda x: max(proc_pss[x].values()), reverse=True)

    proc_hdr = "".join(
        f"<th style='text-align:right;padding:6px 10px;white-space:nowrap'>{l} (MB)</th>"
        for l in labels
    )
    proc_rows = ""
    for i, name in enumerate(proc_order[:20]):
        bg = "#e4edf8" if i % 2 == 0 else "#f0f5fb"
        pss_vals = [proc_pss[name].get(l, 0) for l in labels]
        val_cells = "".join(
            f"<td style='text-align:right;padding:6px 10px'>{v}</td>"
            for v in pss_vals
        )
        proc_rows += (
            f"<tr style='background:{bg}'>"
            f"<td style='text-align:right;color:#888;font-size:11px;padding:6px 10px'>{i+1}</td>"
            f"<td style='padding:6px 10px'>{name}</td>"
            f"{val_cells}</tr>\n"
        )

    return f"""
<div style='overflow-x:auto'>
<table style='border-collapse:collapse;width:100%;font-family:Segoe UI,Arial,sans-serif;
              font-size:13px;box-shadow:0 2px 8px rgba(0,0,0,0.1);border-radius:6px;overflow:hidden'>
<thead>
<tr style='background:#1a3a5c;color:white'>
  <th style='padding:10px 12px;text-align:left;width:80px'>Group</th>
  <th style='padding:10px 12px;text-align:left'>Memory Category</th>
  {hdr_vals}
  {hdr_delta}
</tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>
</div>

<h3 style='margin-top:20px'>Top Processes by PSS
  <span style='font-weight:normal;font-size:12px;color:#888'>(top 20)</span>
</h3>
<div style='overflow-x:auto'>
<table style='border-collapse:collapse;width:100%;font-size:13px'>
<thead>
<tr style='background:#2c6fad;color:white'>
  <th style='text-align:right;padding:6px 10px;width:32px'>#</th>
  <th style='text-align:left;padding:6px 10px'>Process</th>
  {proc_hdr}
</tr>
</thead>
<tbody>
{proc_rows}
</tbody>
</table>
</div>"""


def build_unified_html(sections: list[tuple[str, str, dict]], title: str) -> str:
    """
    Build a single unified HTML report.
    Section order: snapshot_comparison -> kernel_diff -> userspace_diff -> findings -> rca -> others
    Kernel/Userspace/Findings sections are collapsed by default.
    Summary and RCA are always visible.
    """
    # Sort sections into desired order
    ORDER = ["snapshot_comparison", "kernel_diff", "userspace_diff", "rca"]
    def sort_key(item):
        rtype = item[0]
        return ORDER.index(rtype) if rtype in ORDER else len(ORDER)
    sections = sorted(sections, key=sort_key)

    # Sections that start collapsed
    COLLAPSED_BY_DEFAULT = {"kernel_diff", "userspace_diff"}

    # Detect N-point comparison (multiple snapshot_comparison sections)
    snap_secs = [(rt, p, d) for rt, p, d in sections if rt == "snapshot_comparison"]
    is_npoint = len(snap_secs) > 1

    body = ""
    sec_id = 0

    if is_npoint:
        # Render a single unified N-point comparison section
        sec_id += 1
        sid = f"sec-{sec_id}"
        n = len(snap_secs)
        labels = [d.get("current_label", f"Point {i+1}") for i, (_, _, d) in enumerate(snap_secs)]
        npoint_content = render_npoint_comparison_html(snap_secs)
        body += f"""
<div class='section-block'>
  <div class='section-header' onclick="toggleSection('{sid}')">
    <span class='section-toggle' id='toggle-{sid}'>\u2212</span>
    <span class='section-title'>Memory Comparison
      <span style='font-weight:normal;font-size:12px;opacity:0.8;margin-left:8px'>
        ({n} data points: {', '.join(labels)})
      </span>
    </span>
  </div>
  <div class='section-body' id='{sid}'>
    {npoint_content}
  </div>
</div>
"""
        # Skip individual snapshot_comparison sections in the main loop
        sections_to_render = [(rt, p, d) for rt, p, d in sections if rt != "snapshot_comparison"]
    else:
        sections_to_render = sections

    for rtype, path, data in sections_to_render:
        sec_id += 1
        sid = f"sec-{sec_id}"
        _, renderer = SECTION_RENDERERS.get(
            rtype, (f"Report ({rtype})", lambda d: f"<pre>{json.dumps(d, indent=2)}</pre>")
        )
        section_title = _section_title_for(rtype, data)
        collapsed = "collapsed" if rtype in COLLAPSED_BY_DEFAULT else ""
        btn_char  = "+" if rtype in COLLAPSED_BY_DEFAULT else "\u2212"
        content   = renderer(data)

        body += f"""
<div class='section-block'>
  <div class='section-header' onclick="toggleSection('{sid}')">
    <span class='section-toggle' id='toggle-{sid}'>{btn_char}</span>
    <span class='section-title'>{section_title}</span>
  </div>
  <div class='section-body {collapsed}' id='{sid}'>
    {content}
  </div>
</div>
"""

    # Unified Findings section (collapsed by default, after userspace_diff)
    findings_content = render_findings_html(sections)
    if findings_content:
        sec_id += 1
        sid = f"sec-{sec_id}"
        total_findings = sum(len(d.get("findings", [])) for _, _, d in sections)
        body += f"""
<div class='section-block'>
  <div class='section-header' onclick="toggleSection('{sid}')">
    <span class='section-toggle' id='toggle-{sid}'>+</span>
    <span class='section-title'>Findings
      <span style='font-weight:normal;font-size:12px;opacity:0.8;margin-left:8px'>({total_findings} total)</span>
    </span>
  </div>
  <div class='section-body collapsed' id='{sid}'>
    {findings_content}
  </div>
</div>
"""

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Extract device info and use-case details from the first snapshot_comparison section
    device_html = ""
    usecase_html = ""
    for rtype, path, data in sections:
        if rtype == "snapshot_comparison":
            dev = data.get("device", {})
            is_standalone = (
                data.get("current_snapshot_id") == data.get("reference_snapshot_id")
                and data.get("current_snapshot_id", "") != ""
            )
            max_width = "640px" if is_standalone else "860px"
            if dev:
                device_html = render_device_info_html(dev, max_width)
            if not is_standalone:
                usecase_html = render_usecase_details_html(data, max_width)
            break

    return f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>{title}</title>{CSS}</head>
<body style='max-width:1100px;margin:0 auto'>
<h1>{title}</h1>
<p style='color:#888;font-size:0.85em'>Generated: {ts}</p>
{device_html}
{usecase_html}
{body}
</body></html>"""


# ---------------------------------------------------------------------------
# Individual report HTML
# ---------------------------------------------------------------------------

def build_single_html(rtype: str, data: dict, title: str) -> str:
    section_title, renderer = SECTION_RENDERERS.get(
        rtype, (f"Report ({rtype})", lambda d: f"<pre>{json.dumps(d, indent=2)}</pre>")
    )
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>{title}</title>{CSS}</head>
<body>
<h1>{title}</h1>
<p style='color:#888'>Generated: {ts}</p>
{renderer(data)}
</body></html>"""


# ---------------------------------------------------------------------------
# TXT writers
# ---------------------------------------------------------------------------

def build_txt(rtype: str, data: dict) -> str:
    lines = [f"Report Type: {rtype}", "=" * 60, ""]
    if rtype == "rca":
        s = data.get("summary", {})
        lines += [
            f"Overall Health: {s.get('overall_health')}",
            f"Critical: {s.get('critical',0)}  Warning: {s.get('warning',0)}  Info: {s.get('info',0)}",
            "",
        ]
        for a in data.get("anomalies", []):
            lines += [
                f"[{a['severity']}] {a['id']}: {a['title']}",
                f"  Confidence: {a['confidence']:.0%}",
                f"  Hypothesis: {a['hypothesis']}",
                "",
            ]
    elif rtype == "carveout_validation":
        s = data.get("summary", {})
        lines.append(f"Carve-outs found: {s.get('found', 0)}  Total: {s.get('total_actual_mb', 0):.2f} MB")
        lines.append("")
        for r in data.get("results", []):
            size_mb = r.get("actual_size_mb", r.get("actual_size_kb", 0) / 1024)
            lines.append(f"  [OK] FOUND  {r.get('name',''):<30} {size_mb:.2f} MB")
    elif rtype == "snapshot_comparison":
        lines.append(f"{'Category':<20} {'Ref MB':>10} {'Cur MB':>10} {'Delta MB':>10} {'Trend'}")
        for cat in data.get("categories", []):
            lines.append(
                f"{cat['category']:<20} {cat['reference_kb']/1024:>10.1f} "
                f"{cat['current_kb']/1024:>10.1f} {cat['delta_kb']/1024:>+10.1f} "
                f"{cat['trend']}"
            )
    else:
        lines.append(json.dumps(data, indent=2)[:2000])
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# XLSX snapshot_comparison structured writer (supports N data points)
# ---------------------------------------------------------------------------

def _write_xlsx_snapshot_comparison(wb, snapshots: list):
    """
    Create 3-sheet Excel workbook for N-point snapshot/comparison.

    snapshots: list of (label, snap_data, device_data) tuples
        - label     : column header (e.g. "Build_v1", "Device_A", "snapshot")
        - snap_data : summary_table dict (reference or current)
        - device_data: device info dict
    Supports N=1 (single snapshot), N=2 (comparison), N>2 (multi-point).
    """
    try:
        from openpyxl.styles import PatternFill, Font, Alignment
        from openpyxl.utils import get_column_letter
    except ImportError:
        return

    n       = len(snapshots)
    labels  = [s[0] for s in snapshots]
    snaps   = [s[1] for s in snapshots]
    devices = [s[2] for s in snapshots]

    HDR_DARK  = "1A3A5C"   # dark navy  (section headers)
    HDR_MID   = "2C6FAD"   # mid blue   (column headers / HLOS banner)
    ROW_ALT1  = "E4EDF8"   # light blue (odd rows)
    ROW_ALT2  = "F0F5FB"   # lighter    (even rows)
    ROW_BOLD  = "D0DFF0"   # bold summary rows
    ROW_CHILD = "F5F8FF"   # child / sub-item rows
    DELTA_POS = "FFD0D0"   # light red  (memory increased)
    DELTA_NEG = "D0FFD0"   # light green (memory decreased)
    WHITE     = "FFFFFF"

    def hdr_font(color=WHITE):
        return Font(bold=True, color=color)

    def section_header(ws, title, ncols):
        ws.append([title] + [""] * (ncols - 1))
        r = ws.max_row
        ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=ncols)
        for cell in ws[r]:
            cell.font = Font(bold=True, color=WHITE, size=11)
            cell.fill = PatternFill("solid", fgColor=HDR_DARK)
            cell.alignment = Alignment(horizontal="left", vertical="center")
        ws.row_dimensions[r].height = 22

    def col_header(ws, col_labels):
        ws.append(col_labels)
        for cell in ws[ws.max_row]:
            cell.font = hdr_font()
            cell.fill = PatternFill("solid", fgColor=HDR_MID)
            cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[ws.max_row].height = 18

    def add_row(ws, values, bg, bold=False, outline_level=0, hidden=False):
        ws.append(values)
        r = ws.max_row
        for cell in ws[r]:
            cell.fill = PatternFill("solid", fgColor=bg)
            if bold:
                cell.font = Font(bold=True)
        if outline_level:
            ws.row_dimensions[r].outline_level = outline_level
            ws.row_dimensions[r].hidden = hidden

    def color_delta_cell(ws, col_idx, delta_kb):
        if n <= 1 or delta_kb is None:
            return
        cell = ws[ws.max_row][col_idx]
        if delta_kb > 0:
            cell.fill = PatternFill("solid", fgColor=DELTA_POS)
        elif delta_kb < 0:
            cell.fill = PatternFill("solid", fgColor=DELTA_NEG)

    # Column layout
    has_delta   = n > 1
    ncols_mem   = 2 + n + (1 if has_delta else 0)
    ncols_proc  = 2 + n
    ncols_dev   = 1 + n if n > 1 else 2

    if n == 1:
        mem_col_headers  = ["Group", "Memory Category", "Value (MB)"]
        proc_col_headers = ["#", "Process", "PSS (MB)"]
    else:
        delta_label = (f"Delta ({labels[1]} \u2212 {labels[0]})"
                       if n == 2 else "Delta (Last \u2212 First)")
        mem_col_headers  = (["Group", "Memory Category"]
                            + [f"{l} (MB)" for l in labels]
                            + [delta_label])
        proc_col_headers = ["#", "Process"] + [f"{l} (MB)" for l in labels]

    # ------------------------------------------------------------------ #
    # Sheet 1 - Device Info                                               #
    # ------------------------------------------------------------------ #
    ws_dev = wb.create_sheet("Device Info")
    ws_dev.column_dimensions["A"].width = 18
    if n == 1:
        ws_dev.column_dimensions["B"].width = 70
    else:
        for i in range(n):
            ws_dev.column_dimensions[get_column_letter(i + 2)].width = 35

    section_header(ws_dev, "DEVICE INFORMATION", ncols_dev)
    col_header(ws_dev, ["Field"] + (labels if n > 1 else ["Value"]))

    dev_fields = [
        ("Machine",  lambda d: d.get("model", "")),
        ("SoC",      lambda d: f"{d.get('soc_name','')} rev {d.get('soc_revision','')}"),
        ("OS",       lambda d: d.get("os_name", "")),
        ("Build",    lambda d: d.get("build_id", "")),
        ("Kernel",   lambda d: d.get("kernel_version", "")),
        ("Serial",   lambda d: d.get("serial", "")),
        ("Captured", lambda d: d.get("captured_at", "")),
    ]
    for i, (field_label, field_fn) in enumerate(dev_fields):
        bg = ROW_ALT1 if i % 2 == 0 else ROW_ALT2
        values = [field_fn(d) for d in devices]
        ws_dev.append([field_label] + values)
        for cell in ws_dev[ws_dev.max_row]:
            cell.fill = PatternFill("solid", fgColor=bg)
        ws_dev[ws_dev.max_row][0].font = Font(bold=True, color="444444")

    # ------------------------------------------------------------------ #
    # Sheet 2 - Memory Summary                                            #
    # ------------------------------------------------------------------ #
    ws_mem = wb.create_sheet("Memory Summary")
    ws_mem.column_dimensions["A"].width = 12
    ws_mem.column_dimensions["B"].width = 38
    for i in range(n):
        ws_mem.column_dimensions[get_column_letter(i + 3)].width = 14
    if has_delta:
        ws_mem.column_dimensions[get_column_letter(n + 3)].width = 16
    ws_mem.sheet_properties.outlinePr.summaryBelow = False

    section_header(ws_mem, "MEMORY SUMMARY", ncols_mem)
    col_header(ws_mem, mem_col_headers)

    def _vals_kb(key_fn):
        return [key_fn(s) for s in snaps]

    def _delta(vals_kb):
        return (vals_kb[-1] - vals_kb[0]) if has_delta else None

    def mem_parent(group, category, vals_kb, bold=False, bg=ROW_ALT1):
        d = _delta(vals_kb)
        vals_mb = [round(v / 1024) for v in vals_kb]
        row = [group, category] + vals_mb + ([round(d / 1024)] if has_delta else [])
        add_row(ws_mem, row, bg, bold=bold)
        color_delta_cell(ws_mem, ncols_mem - 1, d)

    def mem_child(group, category, vals_kb):
        d = _delta(vals_kb)
        vals_mb = [round(v / 1024) for v in vals_kb]
        row = [group, f"    \u2514 {category}"] + vals_mb + ([round(d / 1024)] if has_delta else [])
        add_row(ws_mem, row, ROW_CHILD, outline_level=1, hidden=True)
        color_delta_cell(ws_mem, ncols_mem - 1, d)

    # Total RAM
    mem_parent("", "Total RAM",
               _vals_kb(lambda s: s.get("total_ram_kb", 0)),
               bold=True, bg=ROW_BOLD)

    # NHLOS Reserved + sub-items (union of all nodes across snapshots)
    mem_parent("NHLOS", "NHLOS Reserved",
               _vals_kb(lambda s: s.get("nhlos_kb", 0)), bg=ROW_ALT1)
    seen_nhlos = set()
    nhlos_names = []
    for snap in snaps:
        for node in snap.get("nhlos_nodes", []):
            if node["name"] not in seen_nhlos:
                nhlos_names.append(node["name"])
                seen_nhlos.add(node["name"])
    for name in nhlos_names:
        node_maps = [{nd["name"]: nd["size_kb"] for nd in s.get("nhlos_nodes", [])} for s in snaps]
        mem_child("NHLOS", name, [m.get(name, 0) for m in node_maps])

    # System RAM
    mem_parent("", "System RAM",
               _vals_kb(lambda s: s.get("system_ram_kb", 0)), bg=ROW_ALT1)

    # HLOS banner
    ws_mem.append(["", "\u25B6 HLOS \u2014 High Level OS"] + [""] * (ncols_mem - 2))
    for cell in ws_mem[ws_mem.max_row]:
        cell.font = Font(bold=True, color=WHITE)
        cell.fill = PatternFill("solid", fgColor=HDR_MID)

    # Kernel Static Memory
    mem_parent("HLOS", "Kernel Static Memory",
               _vals_kb(lambda s: s.get("kernel_static_kb", 0)), bg=ROW_ALT2)
    for key in ["Vmlinux", "Page Structs", "Hash Tables", "Early Boot Reservations"]:
        vals = [s.get("kernel_static_breakdown", {}).get(key, 0) for s in snaps]
        if any(v > 0 for v in vals):
            mem_child("HLOS", key, vals)

    # Kernel Dynamic Memory
    kd_labels = {
        "Slab": "Slab Allocator", "Vmalloc": "Vmalloc",
        "KernelStack": "Kernel Stack", "PageTables": "Page Tables",
        "Percpu": "Per-CPU", "SecPageTables": "Secondary Page Tables (Stage-2)",
        "Modules": "Kernel Modules", "CMA": "CMA (Contiguous Memory)",
        "KDA": "KDA (Kernel Direct Allocations)",
    }
    mem_parent("HLOS", "Kernel Dynamic Memory",
               _vals_kb(lambda s: s.get("kernel_dynamic_kb", 0)), bg=ROW_ALT2)
    for key, display in kd_labels.items():
        vals = [s.get("kernel_dynamic_breakdown", {}).get(key, 0) for s in snaps]
        mem_child("HLOS", display, vals)

    # Hardware / Driver Buffers
    mem_parent("HLOS", "Hardware / Driver Buffers",
               _vals_kb(lambda s: s.get("hw_driver_kb", 0)), bg=ROW_ALT2)
    mem_child("HLOS", "DMA-BUF Buffers",
              [s.get("hw_driver_breakdown", {}).get("DMA-BUF", 0) for s in snaps])
    seen_exp = set()
    exp_names = []
    for snap in snaps:
        for exp in snap.get("hw_driver_breakdown", {}).get("DMA-BUF_exporters", {}).keys():
            if exp not in seen_exp:
                exp_names.append(exp)
                seen_exp.add(exp)
    for exp in exp_names:
        mem_child("HLOS", f"  \u2514 {exp}",
                  [s.get("hw_driver_breakdown", {}).get("DMA-BUF_exporters", {}).get(exp, 0)
                   for s in snaps])
    mem_child("HLOS", "KGSL GPU Memory",
              [s.get("hw_driver_breakdown", {}).get("KGSL", 0) for s in snaps])

    # User Space Apps
    us_labels = {"AnonPages": "Anonymous Pages", "Shmem": "Shared Memory"}
    mem_parent("HLOS", "User Space Apps",
               _vals_kb(lambda s: s.get("user_space_kb", 0)), bg=ROW_ALT2)
    for key, display in us_labels.items():
        vals = [s.get("user_space_breakdown", {}).get(key, 0) for s in snaps]
        mem_child("HLOS", display, vals)

    # Total Available Memory
    avail_labels = {"MemFree": "Free Memory", "Cached": "Page Cache", "Buffers": "Buffers"}
    mem_parent("HLOS", "Total Available Memory",
               _vals_kb(lambda s: s.get("total_available_kb", 0)),
               bold=True, bg=ROW_BOLD)
    for key, display in avail_labels.items():
        vals = [s.get("total_available_breakdown", {}).get(key, 0) for s in snaps]
        mem_child("HLOS", display, vals)

    # ------------------------------------------------------------------ #
    # Sheet 3 - Top Processes                                             #
    # ------------------------------------------------------------------ #
    ws_proc = wb.create_sheet("Top Processes")
    ws_proc.column_dimensions["A"].width = 6
    ws_proc.column_dimensions["B"].width = 45
    for i in range(n):
        ws_proc.column_dimensions[get_column_letter(i + 3)].width = 14

    section_header(ws_proc, "TOP PROCESSES BY PSS", ncols_proc)
    col_header(ws_proc, proc_col_headers)

    # Build union of all processes across all snapshots, keyed by short name
    seen_procs = set()
    proc_order = []
    proc_pss = {}   # short_name -> {label: pss_mb}
    for snap, lbl in zip(snaps, labels):
        for proc in snap.get("top_processes", []):
            full_cmd = proc.get("name", "")
            short = full_cmd.split("/")[-1].split(" ")[0]
            if short not in seen_procs:
                proc_order.append(short)
                seen_procs.add(short)
            proc_pss.setdefault(short, {})[lbl] = round(proc.get("pss_kb", 0) / 1024, 1)

    # Sort by max PSS across all snapshots (descending)
    proc_order.sort(key=lambda x: max(proc_pss[x].values()), reverse=True)

    for i, name in enumerate(proc_order, 1):
        pss_vals = [proc_pss[name].get(l, 0) for l in labels]
        bg = ROW_ALT1 if i % 2 == 1 else ROW_ALT2
        ws_proc.append([i, name] + pss_vals)
        for cell in ws_proc[ws_proc.max_row]:
            cell.fill = PatternFill("solid", fgColor=bg)
        ws_proc[ws_proc.max_row][0].alignment = Alignment(horizontal="center")
# ---------------------------------------------------------------------------
# XLSX writer
# ---------------------------------------------------------------------------

def write_xlsx_unified(sections: list[tuple[str, str, dict]], output_path: str):
    try:
        import openpyxl
        from openpyxl.styles import PatternFill, Font
    except ImportError:
        print("[report-generation] openpyxl not installed -- skipping XLSX")
        return
    wb = openpyxl.Workbook()
    wb.remove(wb.active)  # remove default sheet

    _snap_done = [False]  # flag: process snapshot_comparison only once
    for rtype, path, data in sections:
        sheet_name = rtype[:31]  # Excel sheet name limit
        ws = wb.create_sheet(sheet_name)
        ws.append([f"Source: {path}"])
        ws.append([])

        if rtype == "rca":
            from openpyxl.styles import Alignment
            from openpyxl.utils import get_column_letter
            HDR_DARK = "1A3A5C"
            HDR_MID  = "2C6FAD"
            SEV_COLORS = {"CRITICAL": "FFD0D0", "WARNING": "FFF8E0", "INFO": "E8F4FD"}
            SEV_BG     = {"CRITICAL": "C00000", "WARNING": "E6A817", "INFO": "2C6FAD"}
            ROW_ALT1   = "E4EDF8"
            ROW_ALT2   = "F0F5FB"
            WHITE      = "FFFFFF"

            s = data.get("summary", {})
            health = s.get("overall_health", "UNKNOWN")
            health_colors = {"HEALTHY": "D4EDDA", "DEGRADED": "FFF3CD", "CRITICAL": "F8D7DA"}
            health_bg = health_colors.get(health, "F0F0F0")

            # Remove the generic "Source:" rows and rebuild with proper header
            # (sheet was already created with source row — clear and redo)
            ws.delete_rows(1, ws.max_row)

            # Section header
            ws.append(["ROOT CAUSE ANALYSIS"])
            ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=6)
            for cell in ws[1]:
                cell.font = Font(bold=True, color=WHITE, size=11)
                cell.fill = PatternFill("solid", fgColor=HDR_DARK)
                cell.alignment = Alignment(horizontal="left", vertical="center")
            ws.row_dimensions[1].height = 22

            # Overall health summary row
            ws.append([f"Overall Health: {health}",
                       f"Critical: {s.get('critical',0)}",
                       f"Warning: {s.get('warning',0)}",
                       f"Info: {s.get('info',0)}",
                       f"Layers: {', '.join(s.get('layers_affected',[]))}",
                       f"Mode: {s.get('mode','')}"])
            for cell in ws[2]:
                cell.fill = PatternFill("solid", fgColor=health_bg)
                cell.font = Font(bold=True)
            ws.row_dimensions[2].height = 18

            ws.append([])  # spacer

            # Column headers
            ws.append(["Severity", "ID", "Title", "Confidence", "Layer", "Hypothesis"])
            for cell in ws[ws.max_row]:
                cell.font = Font(bold=True, color=WHITE)
                cell.fill = PatternFill("solid", fgColor=HDR_MID)
                cell.alignment = Alignment(horizontal="center", vertical="center")
            ws.row_dimensions[ws.max_row].height = 18

            anomalies = data.get("anomalies", [])
            for i, a in enumerate(anomalies):
                sev = a.get("severity", "INFO")
                bg  = SEV_COLORS.get(sev, "FFFFFF")
                sev_bg = SEV_BG.get(sev, "555555")

                # Main anomaly row
                ws.append([sev, a["id"], a["title"],
                           f"{a['confidence']:.0%}", a.get("layer",""), a["hypothesis"]])
                r = ws.max_row
                for cell in ws[r]:
                    cell.fill = PatternFill("solid", fgColor=bg)
                ws[r][0].font = Font(bold=True, color=WHITE)
                ws[r][0].fill = PatternFill("solid", fgColor=sev_bg)
                ws[r][0].alignment = Alignment(horizontal="center")
                ws.row_dimensions[r].height = 16

                # Evidence sub-rows
                for ev in a.get("evidence", []):
                    src   = ev.get("source", "")
                    finding = ev.get("finding", "")
                    ws.append(["", f"  \u2514 Evidence [{src}]", finding, "", "", ""])
                    r2 = ws.max_row
                    for cell in ws[r2]:
                        cell.fill = PatternFill("solid", fgColor="F5F8FF")
                        cell.font = Font(italic=True, size=11)
                    ws[r2][1].font = Font(bold=True, color="2C6FAD", size=11)
                    ws.row_dimensions[r2].height = 14

                # Recommended actions sub-rows
                for j, act in enumerate(a.get("recommended_actions", []), 1):
                    ws.append(["", f"  \u2514 Action {j}", act, "", "", ""])
                    r3 = ws.max_row
                    for cell in ws[r3]:
                        cell.fill = PatternFill("solid", fgColor="F0F5FF")
                        cell.font = Font(size=11)
                    ws[r3][1].font = Font(bold=True, color="155724", size=11)
                    ws.row_dimensions[r3].height = 14

                # Spacer between anomalies
                if i < len(anomalies) - 1:
                    ws.append([])

            # Column widths
            ws.column_dimensions["A"].width = 12
            ws.column_dimensions["B"].width = 18
            ws.column_dimensions["C"].width = 50
            ws.column_dimensions["D"].width = 12
            ws.column_dimensions["E"].width = 14
            ws.column_dimensions["F"].width = 60

        elif rtype == "carveout_validation":
            ws.append(["Carveout", "Base Address", "Size (MB)", "Status"])
            for cell in ws[ws.max_row]:
                cell.font = Font(bold=True)
            for r in data.get("results", []):
                size_mb = r.get("actual_size_mb", r.get("actual_size_kb", 0) / 1024)
                ws.append([r.get("name"), r.get("base_addr"),
                           round(size_mb, 2), "FOUND"])

        elif rtype == "snapshot_comparison":
            # Remove the placeholder sheet.
            # Collect ALL snapshot_comparison sections and build snapshots list once.
            wb.remove(ws)
            if not _snap_done[0]:
                _snap_done[0] = True
                snap_secs = [(rt, p, d) for rt, p, d in sections
                             if rt == "snapshot_comparison"]
                snapshots = []
                if len(snap_secs) == 1:
                    d0 = snap_secs[0][2]
                    st = d0.get("summary_table", {})
                    is_standalone = (
                        d0.get("current_snapshot_id") == d0.get("reference_snapshot_id")
                        and d0.get("current_snapshot_id", "") != ""
                    )
                    if is_standalone:
                        snapshots.append((
                            d0.get("current_label", "Snapshot"),
                            st.get("current", st.get("reference", {})),
                            d0.get("device", {}),
                        ))
                    else:
                        snapshots.append((
                            d0.get("reference_label", "Reference"),
                            st.get("reference", {}),
                            d0.get("device", {}),
                        ))
                        snapshots.append((
                            d0.get("current_label", "Current"),
                            st.get("current", {}),
                            d0.get("device", {}),
                        ))
                else:
                    import re as _re
                    # Build raw labels, enriching with timestamp from path when available
                    raw_labels = []
                    for _, p, d0 in snap_secs:
                        lbl = d0.get("current_label", "Snapshot")
                        ts_m = _re.search(r'(\d{8})_(\d{6})', p)
                        if ts_m:
                            d, t = ts_m.group(1), ts_m.group(2)
                            lbl = f"{lbl} ({d[6:]}/{d[4:6]} {t[:2]}:{t[2:4]})"
                        raw_labels.append(lbl)
                    # If duplicates remain, append a counter suffix
                    seen: dict = {}
                    final_labels = []
                    for lbl in raw_labels:
                        if raw_labels.count(lbl) > 1:
                            seen[lbl] = seen.get(lbl, 0) + 1
                            final_labels.append(f"{lbl} #{seen[lbl]}")
                        else:
                            final_labels.append(lbl)
                    for (_, _, d0), lbl in zip(snap_secs, final_labels):
                        st = d0.get("summary_table", {})
                        snapshots.append((
                            lbl,
                            st.get("current", st.get("reference", {})),
                            d0.get("device", {}),
                        ))
                _write_xlsx_snapshot_comparison(wb, snapshots)

        elif rtype == "kernel_diff":
            from openpyxl.styles import Alignment
            HDR_DARK = "1A3A5C"
            HDR_MID  = "2C6FAD"
            WHITE    = "FFFFFF"
            ROW_ALT1 = "E4EDF8"
            ROW_ALT2 = "F0F5FB"

            ws.delete_rows(1, ws.max_row)

            # Section header
            ws.append(["KERNEL MEMORY DIFF — SLAB CHANGES"])
            ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=6)
            for cell in ws[1]:
                cell.font = Font(bold=True, color=WHITE, size=11)
                cell.fill = PatternFill("solid", fgColor=HDR_DARK)
            ws.row_dimensions[1].height = 22

            # Buddy fragmentation summary
            bd = data.get("buddy_fragmentation", {})
            ws.append([f"Buddy Fragmentation Index: {bd.get('reference_index',0):.4f} \u2192 {bd.get('current_index',0):.4f}  (delta: {bd.get('fragmentation_index_delta',0):+.4f})",
                       "", "", "", "", ""])
            ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=6)
            ws[2][0].fill = PatternFill("solid", fgColor="EDF3FB")
            ws[2][0].font = Font(italic=True, size=11)
            ws.row_dimensions[2].height = 16

            ws.append([])

            # Column headers
            ws.append(["Slab", "Ref KB", "Cur KB", "Delta KB", "Delta %", "Flagged"])
            for cell in ws[ws.max_row]:
                cell.font = Font(bold=True, color=WHITE)
                cell.fill = PatternFill("solid", fgColor=HDR_MID)
                cell.alignment = Alignment(horizontal="center")
            ws.row_dimensions[ws.max_row].height = 18

            for i, s in enumerate(data.get("slab_diff", [])):
                bg = "FFF8E0" if s.get("flagged") else (ROW_ALT1 if i % 2 == 0 else ROW_ALT2)
                ws.append([s["name"], s["ref_kb"], s["cur_kb"],
                           s["delta_kb"], s["delta_pct"],
                           "\u26A0 FLAGGED" if s.get("flagged") else ""])
                for cell in ws[ws.max_row]:
                    cell.fill = PatternFill("solid", fgColor=bg)
                if s.get("flagged"):
                    ws[ws.max_row][5].font = Font(bold=True, color="C00000")

            # Findings
            findings = data.get("findings", [])
            if findings:
                ws.append([])
                ws.append(["FINDINGS", "", "", "", "", ""])
                ws.merge_cells(start_row=ws.max_row, start_column=1, end_row=ws.max_row, end_column=6)
                ws[ws.max_row][0].font = Font(bold=True, color=WHITE)
                ws[ws.max_row][0].fill = PatternFill("solid", fgColor=HDR_DARK)
                for f in findings:
                    sev_bg = {"CRITICAL": "FFD0D0", "WARNING": "FFF8E0", "INFO": "E8F4FD"}.get(f["severity"], "FFFFFF")
                    ws.append([f"[{f['severity']}] {f['message']}", "", "", "", "", ""])
                    ws.merge_cells(start_row=ws.max_row, start_column=1, end_row=ws.max_row, end_column=6)
                    ws[ws.max_row][0].fill = PatternFill("solid", fgColor=sev_bg)

            ws.column_dimensions["A"].width = 40
            ws.column_dimensions["B"].width = 12
            ws.column_dimensions["C"].width = 12
            ws.column_dimensions["D"].width = 12
            ws.column_dimensions["E"].width = 10
            ws.column_dimensions["F"].width = 14

        elif rtype == "userspace_diff":
            from openpyxl.styles import Alignment
            HDR_DARK = "1A3A5C"
            HDR_MID  = "2C6FAD"
            WHITE    = "FFFFFF"
            ROW_ALT1 = "E4EDF8"
            ROW_ALT2 = "F0F5FB"

            ws.delete_rows(1, ws.max_row)

            # Section header
            ws.append(["USERSPACE MEMORY DIFF — PROCESS CHANGES"])
            ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=6)
            for cell in ws[1]:
                cell.font = Font(bold=True, color=WHITE, size=11)
                cell.fill = PatternFill("solid", fgColor=HDR_DARK)
            ws.row_dimensions[1].height = 22

            ws.append([])

            # Changed processes
            changed = [p for p in data.get("process_diff", []) if p.get("delta_pss_kb", 0) != 0]
            if changed:
                ws.append(["CHANGED PROCESSES", "", "", "", "", ""])
                ws.merge_cells(start_row=ws.max_row, start_column=1, end_row=ws.max_row, end_column=6)
                ws[ws.max_row][0].font = Font(bold=True, color=WHITE)
                ws[ws.max_row][0].fill = PatternFill("solid", fgColor=HDR_MID)

                ws.append(["Process", "Ref PSS (MB)", "Cur PSS (MB)", "Delta (MB)", "Delta %", "Status"])
                for cell in ws[ws.max_row]:
                    cell.font = Font(bold=True, color=WHITE)
                    cell.fill = PatternFill("solid", fgColor=HDR_MID)
                    cell.alignment = Alignment(horizontal="center")

                for i, p in enumerate(sorted(changed, key=lambda x: abs(x.get("delta_pss_kb",0)), reverse=True)):
                    bg = "FFF8E0" if p.get("flagged") else (ROW_ALT1 if i % 2 == 0 else ROW_ALT2)
                    ws.append([p["name"],
                               round(p["ref_pss_kb"]/1024, 1),
                               round(p["cur_pss_kb"]/1024, 1),
                               round(p["delta_pss_kb"]/1024, 1),
                               p["delta_pct"],
                               "\u26A0 FLAGGED" if p.get("flagged") else ""])
                    for cell in ws[ws.max_row]:
                        cell.fill = PatternFill("solid", fgColor=bg)
                    delta_cell = ws[ws.max_row][3]
                    if p["delta_pss_kb"] > 0:
                        delta_cell.font = Font(bold=True, color="C00000")
                    elif p["delta_pss_kb"] < 0:
                        delta_cell.font = Font(bold=True, color="155724")

            # New processes
            new_procs = data.get("new_processes", [])
            if new_procs:
                ws.append([])
                ws.append([f"NEW PROCESSES ({len(new_procs)})", "", "", "", "", ""])
                ws.merge_cells(start_row=ws.max_row, start_column=1, end_row=ws.max_row, end_column=6)
                ws[ws.max_row][0].font = Font(bold=True, color=WHITE)
                ws[ws.max_row][0].fill = PatternFill("solid", fgColor="155724")
                for p in sorted(new_procs, key=lambda x: x.get("pss_kb",0), reverse=True):
                    ws.append([p["name"], "", round(p.get("pss_kb",0)/1024, 1), "", "", "NEW"])
                    for cell in ws[ws.max_row]:
                        cell.fill = PatternFill("solid", fgColor="D4EDDA")

            # Exited processes
            exited_procs = data.get("exited_processes", [])
            if exited_procs:
                ws.append([])
                ws.append([f"EXITED PROCESSES ({len(exited_procs)})", "", "", "", "", ""])
                ws.merge_cells(start_row=ws.max_row, start_column=1, end_row=ws.max_row, end_column=6)
                ws[ws.max_row][0].font = Font(bold=True, color=WHITE)
                ws[ws.max_row][0].fill = PatternFill("solid", fgColor="721C24")
                for p in sorted(exited_procs, key=lambda x: x.get("pss_kb",0), reverse=True):
                    ws.append([p["name"], round(p.get("pss_kb",0)/1024, 1), "", "", "", "EXITED"])
                    for cell in ws[ws.max_row]:
                        cell.fill = PatternFill("solid", fgColor="F8D7DA")

            # Findings
            findings = data.get("findings", [])
            if findings:
                ws.append([])
                ws.append(["FINDINGS", "", "", "", "", ""])
                ws.merge_cells(start_row=ws.max_row, start_column=1, end_row=ws.max_row, end_column=6)
                ws[ws.max_row][0].font = Font(bold=True, color=WHITE)
                ws[ws.max_row][0].fill = PatternFill("solid", fgColor=HDR_DARK)
                for f in findings:
                    sev_bg = {"CRITICAL": "FFD0D0", "WARNING": "FFF8E0", "INFO": "E8F4FD"}.get(f["severity"], "FFFFFF")
                    ws.append([f"[{f['severity']}] {f['message']}", "", "", "", "", ""])
                    ws.merge_cells(start_row=ws.max_row, start_column=1, end_row=ws.max_row, end_column=6)
                    ws[ws.max_row][0].fill = PatternFill("solid", fgColor=sev_bg)

            ws.column_dimensions["A"].width = 50
            ws.column_dimensions["B"].width = 14
            ws.column_dimensions["C"].width = 14
            ws.column_dimensions["D"].width = 12
            ws.column_dimensions["E"].width = 10
            ws.column_dimensions["F"].width = 12

    wb.save(output_path)
    print(f"[report-generation] XLSX  -> {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate HTML/TXT/XLSX reports from memory skill output JSONs."
    )
    parser.add_argument("--input", nargs="+", required=True,
                        help="One or more report JSON files")
    parser.add_argument("--format", default="html,txt",
                        help="Comma-separated output formats: html,txt,xlsx (default: html,txt)")
    parser.add_argument("--output-dir", default=".",
                        help="Output directory (default: .)")
    parser.add_argument("--unified", action="store_true",
                        help="Combine all inputs into a single multi-section HTML report")
    parser.add_argument("--title", default="Memory Analysis Report",
                        help="Title for the unified report")
    parser.add_argument("--snapshot-current", default="",
                        help="Current snapshot.json path (enables Top Processes Memory Details section)")
    parser.add_argument("--snapshot-reference", default="",
                        help="Reference snapshot.json path (enables Top Processes Memory Details section)")
    args = parser.parse_args()

    formats = [f.strip().lower() for f in args.format.split(",")]
    os.makedirs(args.output_dir, exist_ok=True)

    # Load all input reports
    loaded = []
    for path in args.input:
        if not os.path.isfile(path):
            print(f"[report-generation] WARNING: {path} not found -- skipping")
            continue
        data, rtype = load_report(path)
        loaded.append((rtype, path, data))
        print(f"[report-generation] Loaded {rtype} from {path}")

    if not loaded:
        print("ERROR: No valid report files found.")
        sys.exit(1)

    # Load smaps breakdowns if snapshot paths provided
    cur_breakdowns = load_smaps_for_snapshot(args.snapshot_current) if args.snapshot_current else []
    ref_breakdowns = load_smaps_for_snapshot(args.snapshot_reference) if args.snapshot_reference else []
    if cur_breakdowns or ref_breakdowns:
        for _, _, data in loaded:
            data["_smaps_cur"] = cur_breakdowns
            data["_smaps_ref"] = ref_breakdowns
        print(f"[report-generation] Loaded smaps: {len(cur_breakdowns)} current + {len(ref_breakdowns)} reference processes")

    if args.unified:
        # Single unified HTML
        if "html" in formats:
            html = build_unified_html(loaded, args.title)
            out = os.path.join(args.output_dir, "unified_report.html")
            with open(out, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"[report-generation] HTML  -> {out}")
        if "xlsx" in formats:
            out = os.path.join(args.output_dir, "unified_report.xlsx")
            write_xlsx_unified(loaded, out)
    else:
        # Individual reports per input.
        # For XLSX: group all snapshot_comparison sections together so that
        # multiple input files produce a single multi-point workbook.
        snap_comp_loaded = [(rt, p, d) for rt, p, d in loaded
                            if rt == "snapshot_comparison"]
        snap_xlsx_done = False

        for rtype, path, data in loaded:
            base = os.path.splitext(os.path.basename(path))[0]
            title = f"{rtype.replace('_', ' ').title()} Report"
            if "html" in formats:
                html = build_single_html(rtype, data, title)
                out = os.path.join(args.output_dir, f"{base}.html")
                with open(out, "w", encoding="utf-8") as f:
                    f.write(html)
                print(f"[report-generation] HTML  -> {out}")
            if "txt" in formats:
                txt = build_txt(rtype, data)
                out = os.path.join(args.output_dir, f"{base}.txt")
                with open(out, "w", encoding="utf-8") as f:
                    f.write(txt)
                print(f"[report-generation] TXT   -> {out}")
            if "xlsx" in formats:
                if rtype == "snapshot_comparison" and len(snap_comp_loaded) > 1:
                    # Multi-point: write once using all snapshot_comparison sections
                    if not snap_xlsx_done:
                        snap_xlsx_done = True
                        out = os.path.join(args.output_dir, "snapshot_comparison_report.xlsx")
                        write_xlsx_unified(snap_comp_loaded, out)
                else:
                    out = os.path.join(args.output_dir, f"{base}.xlsx")
                    write_xlsx_unified([(rtype, path, data)], out)

    print(f"\n[report-generation] Done. {len(loaded)} report(s) processed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())