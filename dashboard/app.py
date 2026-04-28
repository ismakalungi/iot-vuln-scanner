import os
import sys
import json
import sqlite3
import subprocess
from functools import wraps

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, '..'))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

try:
    from dashboard.db import init_db, store_findings
    from dashboard.config import SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD, DATABASE_PATH
except Exception:
    import importlib.util
    spec = importlib.util.spec_from_file_location('dashboard.db', os.path.join(THIS_DIR, 'db.py'))
    db = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(db)
    init_db = db.init_db
    store_findings = db.store_findings
    from dashboard.config import SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD, DATABASE_PATH

from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify

app = Flask(__name__)
app.secret_key = SECRET_KEY
init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 10")
    scans = cur.fetchall()
    
    cur.execute("SELECT COUNT(*) FROM hosts")
    hosts_count = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM ports")
    ports_count = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM credentials")
    creds_count = cur.fetchone()[0]
    
    conn.close()
    
    return render_template('dashboard.html', 
                   scans=scans, 
                   hosts_count=hosts_count,
                   ports_count=ports_count,
                   creds_count=creds_count)

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'GET':
        return render_template('scan.html')
    
    try:
        ip_range = request.form.get('ip_range', '172.20.44.0/24')
        
        cmd = [
            'python', '-m', 'iot_scanner.cli', 'scan',
            '-i', ip_range,
            '-f', 'json'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, cwd=REPO_ROOT)
        output = result.stdout

        findings = None
        try:
            findings = json.loads(output) if output else None
        except Exception:
            findings = None

        if result.returncode == 0:
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
            store_findings(findings, ip_range=ip_range, status='success', summary_json=json.dumps(findings))
            return render_template('scan.html', results=findings, results_json=json.dumps(findings, indent=2))
        else:
            flash("Scan failed: " + (result.stderr or result.stdout), 'danger')
            store_findings(None, ip_range=ip_range, status='failed', summary_json=json.dumps({'error': (result.stderr or result.stdout)}))
            return render_template('scan.html')
    except Exception as e:
        flash(f"Error running scan: {str(e)}", 'danger')
        store_findings(None, ip_range='172.20.44.0/24', status='failed', summary_json=json.dumps({'error': str(e)}))
        return render_template('scan.html')

@app.route('/results')
@login_required
def results():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM scans ORDER BY id DESC")
    scans = cur.fetchall()
    
    conn.close()
    
    return render_template('results.html', scans=scans)

@app.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = cur.fetchone()
    
    cur.execute("SELECT * FROM hosts WHERE scan_id = ?", (scan_id,))
    hosts = cur.fetchall()
    
    cur.execute("SELECT * FROM ports WHERE scan_id = ?", (scan_id,))
    ports = cur.fetchall()
    
    cur.execute("SELECT * FROM credentials WHERE scan_id = ?", (scan_id,))
    creds = cur.fetchall()
    
    conn.close()
    
    if not scan:
        flash('Scan not found', 'danger')
        return redirect(url_for('results'))
    
    return render_template('scan_detail.html', scan=scan, hosts=hosts, ports=ports, creds=creds)

@app.route('/api/scan-status')
@login_required
def scan_status():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
    scan = cur.fetchone()
    
    conn.close()
    
    if scan:
        return jsonify({
            'id': scan['id'],
            'timestamp': scan['timestamp'],
            'ip_range': scan['ip_range'],
            'status': scan['status']
        })
    return jsonify({'status': 'no_scans'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)