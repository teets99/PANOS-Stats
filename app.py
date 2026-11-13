#!/usr/bin/env python3
"""
PAN DP-Monitor Web App
======================
Upload a Palo Alto Networks tech support file (.tgz / .tar.gz) and view the
dataplane stats graphs on the same page.

Run:
  pip install -r requirements.txt
  python app.py                 # http://localhost:5000
  python app.py --host 0.0.0.0 --port 8080
"""

import argparse
import tarfile

from flask import Flask, render_template_string, request

import dp_stats

app = Flask(__name__)
# Tech support files can be large; allow uploads up to 2 GB.
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 ** 3


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DP-Monitor Analyzer</title>
<style>
  :root { --fg:#1d2433; --muted:#5b6475; --line:#d9dee7; --bg:#f6f7f9;
          --card:#fff; --accent:#1f6feb; --err:#b42318; }
  * { box-sizing: border-box; }
  body { margin:0; font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;
         color:var(--fg); background:var(--bg); }
  main { max-width:1280px; margin:0 auto; padding:24px 16px 48px; }
  h1 { font-size:22px; margin:0 0 4px; }
  p.sub { margin:0 0 20px; color:var(--muted); }
  .card { background:var(--card); border:1px solid var(--line);
          border-radius:8px; padding:16px; margin-bottom:16px; }
  form { display:flex; gap:12px; flex-wrap:wrap; align-items:center; }
  input[type=file] { flex:1; min-width:240px; }
  button, .btn { background:var(--accent); color:#fff; border:0; border-radius:6px;
           padding:8px 16px; font:inherit; cursor:pointer; text-decoration:none; }
  button:disabled { opacity:.6; cursor:wait; }
  .btn.secondary { background:#fff; color:var(--accent); border:1px solid var(--accent); }
  .error { color:var(--err); border-color:#f3c4c0; background:#fff6f5; }
  .meta { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
          gap:12px; margin-bottom:12px; }
  .meta div span { display:block; color:var(--muted); font-size:13px; }
  .meta div strong { font-variant-numeric:tabular-nums; }
  details { color:var(--muted); font-size:13px; }
  #status { color:var(--muted); }
</style>
</head>
<body>
<main>
  <h1>DP-Monitor Analyzer</h1>
  <p class="sub">Upload a Palo Alto Networks tech support file to graph CPS,
     active sessions, dataplane CPU and packet buffer use.</p>

  <div class="card">
    <form method="post" enctype="multipart/form-data" id="upload">
      <input type="file" name="tsf" accept=".tgz,.gz,.tar" required>
      <button type="submit" id="go">Upload &amp; analyze</button>
      <span id="status"></span>
    </form>
  </div>

  {% if error %}
  <div class="card error"><strong>Error:</strong> {{ error }}</div>
  {% endif %}

  {% if chart %}
  <div class="card">
    <div class="meta">
      <div><span>Hostname</span><strong>{{ hostname }}</strong></div>
      <div><span>Model</span><strong>{{ model }}</strong></div>
      <div><span>Samples</span><strong>{{ count }}</strong></div>
      <div><span>Time range</span><strong>{{ start }} → {{ end }}</strong></div>
    </div>
    <a class="btn secondary" download="{{ hostname }}_dp_monitor_stats.csv"
       href="data:text/csv;charset=utf-8,{{ csv | urlencode }}">Download CSV</a>
    <details style="margin-top:12px">
      <summary>{{ files|length }} dp-monitor log file(s) from {{ filename }}</summary>
      <ul>{% for name, n in files %}<li>{{ name }} — {{ n }} record(s)</li>{% endfor %}</ul>
    </details>
  </div>
  <div class="card">{{ chart | safe }}</div>
  {% endif %}
</main>
<script>
  document.getElementById('upload').addEventListener('submit', function () {
    document.getElementById('go').disabled = true;
    document.getElementById('status').textContent =
      'Uploading and parsing… large files can take a minute.';
  });
</script>
</body>
</html>
"""


@app.errorhandler(413)
def too_large(_e):
    return render_template_string(PAGE, error='File is larger than the 2 GB upload limit.'), 413


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template_string(PAGE)

    upload = request.files.get('tsf')
    if not upload or not upload.filename:
        return render_template_string(PAGE, error='Choose a tech support file to upload.'), 400

    try:
        # upload.stream is a seekable temp file managed by Flask/Werkzeug.
        result = dp_stats.analyze_tsf(upload.stream, log=lambda *a, **k: None)
    except tarfile.TarError:
        return render_template_string(
            PAGE, error=f'"{upload.filename}" is not a readable .tgz / .tar.gz archive.'), 400
    except ValueError as e:
        return render_template_string(PAGE, error=str(e)), 400

    if not dp_stats.PLOTLY_AVAILABLE:
        return render_template_string(PAGE, error='plotly is not installed on the server.'), 500

    records = result['records']
    fig = dp_stats.build_figure(records, result['hostname'], result['model'])
    chart = fig.to_html(full_html=False, include_plotlyjs='cdn',
                        config={'responsive': True})

    return render_template_string(
        PAGE,
        chart=chart,
        hostname=result['hostname'],
        model=result['model'],
        count=len(records),
        start=records[0]['timestamp'],
        end=records[-1]['timestamp'],
        files=result['files'],
        filename=upload.filename,
        csv=dp_stats.records_to_csv(records),
    )


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='DP-Monitor TSF analyzer web app')
    ap.add_argument('--host', default='127.0.0.1',
                    help='Interface to listen on (use 0.0.0.0 for all)')
    ap.add_argument('--port', type=int, default=5000)
    args = ap.parse_args()
    app.run(host=args.host, port=args.port)
