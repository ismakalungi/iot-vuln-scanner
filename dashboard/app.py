from flask import Flask, render_template, request, flash
import subprocess
import json
import os
import sys

# Ensure repo root is on sys.path so 'dashboard' package is importable when running as a script
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, '..'))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Import DB helpers with fallback if running as a script directly
try:
    from dashboard.db import init_db, store_findings
except Exception:
    import importlib.util
    db_path = os.path.join(REPO_ROOT, 'dashboard', 'db.py')
    spec = importlib.util.spec_from_file_location('dashboard.db', db_path)
    db = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(db)
    init_db = db.init_db
    store_findings = db.store_findings

app = Flask(__name__)
app.secret_key = 'secret-key'
init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        # Run the IoT scanner CLI from repo root and request JSON output
        cmd = [
            'python', '-m', 'iot_scanner.cli', 'scan',
            '-i', '172.20.44.0/24',
            '-f', 'json'
        ]
        # Run from repository root so module import resolves correctly
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        output = result.stdout

        findings = None
        try:
            findings = json.loads(output) if output else None
        except Exception:
            findings = None

        if result.returncode == 0:
            # Build a concise summary for flash messages
            summary = {
                'active_hosts': len(findings.get('active_hosts', [])) if findings else 0,
                'open_ports_entries': len(findings.get('open_ports', [])) if findings else 0,
                'vulnerable_creds': len(findings.get('vulnerable_creds', [])) if findings else 0,
            }
            flash(
                f"Scan complete: {summary['active_hosts']} active hosts, "
                f"{summary['open_ports_entries']} open port entries, "
                f"{summary['vulnerable_creds']} potential default creds findings.",
                'success'
            )
            # Persist findings to the database
            store_findings(findings, ip_range='172.20.44.0/24', status='success', summary_json=json.dumps(findings))
            return render_template('index.html', results=findings, results_json=json.dumps(findings, indent=2))
        else:
            flash("Scan failed: " + (result.stderr or result.stdout), 'danger')
            store_findings(None, ip_range='172.20.44.0/24', status='failed', summary_json=json.dumps({'error': (result.stderr or result.stdout)}))
            return render_template('index.html')
    except Exception as e:
        flash(f"Error running scan: {str(e)}", 'danger')
        store_findings(None, ip_range='172.20.44.0/24', status='failed', summary_json=json.dumps({'error': str(e)}))
        return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
