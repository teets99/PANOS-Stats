#!/usr/bin/env python3
"""
PAN DP-Monitor TSF Analyzer
============================
Parses Palo Alto Networks tech support file (.tar.gz) and extracts
dataplane stats from all dp-monitor*.log files into a CSV and
interactive Plotly HTML chart.

Stats captured per 5-minute sample block:
  - Timestamp
  - CPS (new connection establish rate)
  - Active Sessions (allocated sessions)
  - DP CPU Utilization % (avg across all cores, per-minute section)
  - Packet Buffer Utilization % (avg of 15-second samples)

Usage:
  python3 pan_dp_monitor_analyzer.py <path_to_tsf.tar.gz>

Output:
  dp_monitor_stats.csv
  dp_monitor_stats.html  (interactive Plotly chart)

Requirements:
  pip install plotly
"""

import io
import re
import sys
import csv
import tarfile
import os
from datetime import datetime
from statistics import mean

# ── Optional Plotly import ────────────────────────────────────────────────────
try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    print("WARNING: plotly not installed. CSV will still be created.")
    print("         Install with:  pip install plotly\n")


# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns (based on actual dp-monitor log format)
# ─────────────────────────────────────────────────────────────────────────────

# Block header timestamp — e.g. "2026-02-22 19:37:58.557 -0800  --- panio"
RE_TIMESTAMP = re.compile(
    r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\.\d+\s+[+-]\d{4}\s+---\s+panio'
)

# CPS — ":New connection establish rate:                   4 cps"
RE_CPS = re.compile(
    r'^:New connection establish rate:\s+(\d+)\s+cps', re.MULTILINE
)

# Active sessions — ":Number of allocated sessions:                    208"
RE_SESSIONS = re.compile(
    r'^:Number of allocated sessions:\s+(\d+)', re.MULTILINE
)

# Packet buffer 15-second samples (per-second section)
# Lines look like:  ":  7   7   7   7   7   7   7   7   7   7   7   7   7   7   7 "
# They appear immediately after ":packet buffer:" (without "(average)" or "(maximum)")
RE_PKT_BUF_HEADER = re.compile(
    r'^:packet buffer:\s*$', re.MULTILINE
)

# Per-minute CPU: the avg/max table for each core row
# ":       0   0   0   1   1   1   0   1   0   0   0   0   0   1   0   0"
# Header is ":     avg max avg max avg max ..." — we grab only "avg" columns (even positions)
RE_CPU_PERMIN_HEADER = re.compile(
    r'^:CPU load \(%\) during last 15 minutes:', re.MULTILINE
)
RE_CPU_CORE_HEADER = re.compile(
    r'^:core\s+\d+', re.MULTILINE         # the "core   0   1   2 ..." line
)
RE_CPU_AVG_MAX_HEADER = re.compile(
    r'^\s*avg\s+max', re.MULTILINE        # "     avg max avg max ..." line
)


# ─────────────────────────────────────────────────────────────────────────────
# Parsing helpers
# ─────────────────────────────────────────────────────────────────────────────

def parse_packet_buffer_avg(block_text):
    """
    Find the per-second ':packet buffer:' section (not the per-minute one)
    and return the average of its 15 values.
    """
    # We want the FIRST occurrence of ':packet buffer:' that is NOT followed
    # by ' (average)' or ' (maximum)' — that's the per-second section.
    lines = block_text.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == ':packet buffer:':
            # Next non-empty line should be the values
            for j in range(i + 1, min(i + 5, len(lines))):
                val_line = lines[j].strip()
                if val_line.startswith(':'):
                    nums = re.findall(r'\d+', val_line)
                    if nums:
                        return round(mean(int(n) for n in nums), 1)
    return None


def parse_dp_cpu_avg(block_text):
    """
    Find the per-minute CPU section and compute the average of all
    'avg' columns across all 15 rows and all cores.

    The table looks like:
      :CPU load (%) during last 15 minutes:
      :core    0       1       2  ...
      :     avg max avg max avg max ...
      :       0   0   0   1   1   1 ...   (15 data rows)
    """
    lines = block_text.splitlines()
    in_permin_cpu = False
    past_avg_max_header = False
    data_rows = []

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Detect the per-minute CPU section header
        if ':CPU load (%) during last 15 minutes:' in stripped:
            in_permin_cpu = True
            past_avg_max_header = False
            data_rows = []
            continue

        if not in_permin_cpu:
            continue

        # Skip the core-number header line
        if re.match(r'^:core\s+\d', stripped):
            continue

        # The "avg max avg max ..." header line
        if re.match(r'^:\s+avg\s+max', stripped):
            past_avg_max_header = True
            # Count how many 'avg' columns there are (= number of cores)
            continue

        if past_avg_max_header:
            # Data rows start with ':' and contain numbers
            if re.match(r'^:\s+\d', stripped):
                nums = re.findall(r'\d+', stripped)
                if nums:
                    # avg columns are at even indices (0, 2, 4, ...) in the
                    # paired avg/max sequence
                    avgs = [int(nums[k]) for k in range(0, len(nums), 2)]
                    data_rows.append(avgs)
            else:
                # End of table (blank line or new section)
                if data_rows:
                    break

    if data_rows:
        all_avgs = [v for row in data_rows for v in row]
        return round(mean(all_avgs), 1)
    return None


def split_into_panio_blocks(content):
    """
    Split file content into individual panio sample blocks.
    Each block starts at a '--- panio' timestamp line.
    Returns list of (timestamp_str, block_text) tuples.
    """
    blocks = []
    current_ts = None
    current_lines = []

    for line in content.splitlines(keepends=True):
        m = RE_TIMESTAMP.match(line)
        if m:
            # Save previous block
            if current_ts is not None and current_lines:
                blocks.append((current_ts, ''.join(current_lines)))
            current_ts = m.group(1)
            current_lines = [line]
        elif current_ts is not None:
            current_lines.append(line)

    # Don't forget the last block
    if current_ts is not None and current_lines:
        blocks.append((current_ts, ''.join(current_lines)))

    return blocks


def parse_block(ts_str, block_text):
    """
    Extract the four target metrics from a single panio block.
    Returns a dict or None if key fields are missing.
    """
    try:
        timestamp = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return None

    # CPS
    m = RE_CPS.search(block_text)
    cps = int(m.group(1)) if m else None

    # Active sessions
    m = RE_SESSIONS.search(block_text)
    active_sessions = int(m.group(1)) if m else None

    # Packet buffer utilization
    pkt_buf = parse_packet_buffer_avg(block_text)

    # DP CPU utilization
    dp_cpu = parse_dp_cpu_avg(block_text)

    # Only keep records that have at least one useful metric
    if all(v is None for v in [cps, active_sessions, pkt_buf, dp_cpu]):
        return None

    return {
        'timestamp': timestamp,
        'cps': cps,
        'active_sessions': active_sessions,
        'pkt_buf_util_pct': pkt_buf,
        'dp_cpu_util_pct': dp_cpu,
    }


# ─────────────────────────────────────────────────────────────────────────────
# TSF reader
# ─────────────────────────────────────────────────────────────────────────────
RE_SYSINFO_BLOCK = re.compile(r'> show system info\s*\n(.*?)(?=\n>|\Z)', re.DOTALL)
RE_HOSTNAME      = re.compile(r'^hostname:\s+(\S+)', re.MULTILINE)
RE_MODEL         = re.compile(r'^model:\s+(\S+)',    re.MULTILINE)


def parse_hostname_and_model(content):
    """
    Parse hostname and model from the 'show system info' section of a
    techsupport_*.txt file. Looks for lines of the form:
      hostname: NADTC2-FW-PAN-1-A
      model: PA-5260
    Returns (hostname, model) tuple.
    """
    hostname = 'unknown_host'
    model    = 'unknown_model'

    block_match = RE_SYSINFO_BLOCK.search(content)
    search_area = block_match.group(1) if block_match else content

    m = RE_HOSTNAME.search(search_area)
    if m:
        hostname = m.group(1)
    m = RE_MODEL.search(search_area)
    if m:
        model = m.group(1)
    return hostname, model


def _open_tsf(source):
    """Open a TSF from a filesystem path or a binary file-like object."""
    if isinstance(source, (str, os.PathLike)):
        return tarfile.open(source, 'r:*')
    return tarfile.open(fileobj=source, mode='r:*')


def _read_member(tar, member, log):
    f = tar.extractfile(member)
    if not f:
        return None
    try:
        return f.read().decode('utf-8', errors='replace')
    except Exception as e:
        log(f"  WARNING: Could not read {member.name}: {e}")
        return None


def read_tsf(source, log=print):
    """
    Single pass over the TSF archive.
    Returns (dp_files, hostname, model) where dp_files is a list of
    (member_name, file_content_str) for every dp-monitor*.log file.
    """
    dp_files = []
    hostname, model = 'unknown_host', 'unknown_model'
    found_sysinfo = False

    with _open_tsf(source) as tar:
        for member in tar:
            if not member.isfile():
                continue
            basename = os.path.basename(member.name)

            if basename.startswith('dp-monitor') and '.log' in basename:
                content = _read_member(tar, member, log)
                if content is not None:
                    dp_files.append((member.name, content))
                    log(f"  Found: {member.name}")

            elif (not found_sysinfo and 'tmp/cli' in member.name
                  and basename.startswith('techsupport_')
                  and basename.endswith('.txt')):
                content = _read_member(tar, member, log)
                if content is not None:
                    hostname, model = parse_hostname_and_model(content)
                    found_sysinfo = True

    return dp_files, hostname, model


def analyze_tsf(source, log=print):
    """
    Parse a TSF (path or file-like object) and return a dict:
      records  – sorted, de-duplicated list of per-sample dicts
      hostname, model
      files    – list of (member_name, parsed_record_count)
    Raises ValueError if nothing usable is found.
    """
    dp_files, hostname, model = read_tsf(source, log)
    if not dp_files:
        raise ValueError("No dp-monitor*.log files found in the TSF archive. "
                         "Make sure the file is a valid PAN tech support file.")

    all_records = []
    files = []
    for fname, content in dp_files:
        log(f"\nParsing {os.path.basename(fname)}...")
        blocks = split_into_panio_blocks(content)
        log(f"  Found {len(blocks)} panio sample block(s)")
        file_records = [r for r in (parse_block(ts, txt) for ts, txt in blocks) if r]
        log(f"  Parsed {len(file_records)} valid record(s)")
        files.append((fname, len(file_records)))
        all_records.extend(file_records)

    if not all_records:
        raise ValueError("No valid records were parsed. Check log format.")

    # Sort chronologically and deduplicate by timestamp
    all_records.sort(key=lambda r: r['timestamp'])
    seen = set()
    deduped = []
    for r in all_records:
        if r['timestamp'] not in seen:
            seen.add(r['timestamp'])
            deduped.append(r)

    return {'records': deduped, 'hostname': hostname, 'model': model, 'files': files}


# ─────────────────────────────────────────────────────────────────────────────
# CSV writer
# ─────────────────────────────────────────────────────────────────────────────

CSV_FIELDS = ['timestamp', 'cps', 'active_sessions',
              'pkt_buf_util_pct', 'dp_cpu_util_pct']


def _write_csv_rows(records, f):
    writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for r in records:
        row = {k: ('' if r[k] is None else r[k]) for k in CSV_FIELDS[1:]}
        row['timestamp'] = r['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        writer.writerow(row)


def records_to_csv(records):
    """Return the records as a CSV string."""
    buf = io.StringIO()
    _write_csv_rows(records, buf)
    return buf.getvalue()


def write_csv(records, output_path):
    with open(output_path, 'w', newline='') as f:
        _write_csv_rows(records, f)
    print(f"\nCSV written to: {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Plotly chart builder
# ─────────────────────────────────────────────────────────────────────────────

def build_chart(records, output_path, hostname='', model=''):
    if not PLOTLY_AVAILABLE:
        return
    fig = build_figure(records, hostname, model)
    fig.write_html(output_path, include_plotlyjs='cdn')
    print(f"Interactive chart written to: {output_path}")


def build_figure(records, hostname='', model=''):
    """Return the 4-panel Plotly figure for the given records."""
    timestamps = [r['timestamp'] for r in records]

    def extract(key):
        return [r[key] for r in records]

    cps_vals          = extract('cps')
    session_vals      = extract('active_sessions')
    pkt_buf_vals      = extract('pkt_buf_util_pct')
    dp_cpu_vals       = extract('dp_cpu_util_pct')

    fig = make_subplots(
        rows=4, cols=1,
        shared_xaxes=True,
        subplot_titles=(
            'New Connection Establish Rate (CPS)',
            'Active Sessions',
            'Dataplane CPU Utilization (%)',
            'Packet Buffer Utilization (%)',
        ),
        vertical_spacing=0.07,
        row_heights=[0.25, 0.25, 0.25, 0.25],
    )

    common = dict(mode='lines+markers', marker=dict(size=4))

    fig.add_trace(go.Scatter(
        x=timestamps, y=cps_vals, name='CPS',
        line=dict(color='#1f77b4'), **common), row=1, col=1)

    fig.add_trace(go.Scatter(
        x=timestamps, y=session_vals, name='Active Sessions',
        line=dict(color='#ff7f0e'), **common), row=2, col=1)

    fig.add_trace(go.Scatter(
        x=timestamps, y=dp_cpu_vals, name='DP CPU %',
        line=dict(color='#2ca02c'), **common), row=3, col=1)

    # Add 80% threshold line on CPU chart
    fig.add_hline(y=80, line_dash='dash', line_color='red',
                  annotation_text='80% threshold',
                  annotation_position='top right', row=3, col=1)

    fig.add_trace(go.Scatter(
        x=timestamps, y=pkt_buf_vals, name='Pkt Buffer %',
        line=dict(color='#9467bd'), **common), row=4, col=1)

    # Add 80% threshold line on packet buffer chart
    fig.add_hline(y=80, line_dash='dash', line_color='red',
                  annotation_text='80% threshold',
                  annotation_position='top right', row=4, col=1)

    fig.update_layout(
        title=dict(
            text=f'Dataplane Performance (dp-monitor) — {hostname} ({model})' if hostname else 'PAN Firewall — Dataplane Performance (dp-monitor)',
            font=dict(size=18)
        ),
        height=900,
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1),
        hovermode='x unified',
        template='plotly_white',
        paper_bgcolor='white',
        plot_bgcolor='#F5F5F5',
    )

    # Y-axis labels
    fig.update_yaxes(title_text='CPS',       row=1, col=1)
    fig.update_yaxes(title_text='Sessions',  row=2, col=1)
    fig.update_yaxes(title_text='CPU %',     row=3, col=1, range=[0, 100])
    fig.update_yaxes(title_text='Buf %',     row=4, col=1, range=[0, 100])
    fig.update_xaxes(title_text='Timestamp', row=4, col=1)
    # Dark horizontal lines between subplots
    for i in [0.26, 0.52, 0.76]:
        fig.add_shape(
            type='line',
            xref='paper', yref='paper',
            x0=0, x1=1, y0=i, y1=i,
            line=dict(color='#333333', width=2)
        )

    return fig


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    tsf_path = sys.argv[1]
    if not os.path.isfile(tsf_path):
        print(f"ERROR: File not found: {tsf_path}")
        sys.exit(1)

    print(f"Opening TSF: {tsf_path}")
    print("Scanning for dp-monitor*.log files...")

    try:
        result = analyze_tsf(tsf_path)
    except (ValueError, tarfile.TarError) as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    deduped = result['records']
    hostname, model = result['hostname'], result['model']

    print(f"\nTotal unique records: {len(deduped)}")
    print(f"Time range: {deduped[0]['timestamp']} → {deduped[-1]['timestamp']}")

    # Determine output directory (same folder as the TSF file)
    print(f"Hostname: {hostname}")
    print(f"Model:    {model}")
    out_dir = os.path.dirname(os.path.abspath(tsf_path))
    csv_path  = os.path.join(out_dir, f'{hostname}_dp_monitor_stats.csv')
    html_path = os.path.join(out_dir, f'{hostname}_dp_monitor_stats.html')

    write_csv(deduped, csv_path)
    build_chart(deduped, html_path, hostname, model)

    # Copy output files to /var/www/html/
    import subprocess
    for src in [csv_path, html_path]:
        result = subprocess.run(
            ['sudo', 'mv', src, '/var/www/html/'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"Copied {os.path.basename(src)} to /var/www/html/")
            print("")
            print(f"To view, go to http://192.168.2.44/{os.path.basename(src)}")
        else:
            print(f"ERROR copying {os.path.basename(src)}: {result.stderr.strip()}")

    print("\nDone!")


if __name__ == '__main__':
    main()