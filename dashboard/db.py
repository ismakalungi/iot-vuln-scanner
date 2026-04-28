import sqlite3
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import DATABASE_PATH

def _get_connection():
    return sqlite3.connect(DATABASE_PATH)

def init_db():
    conn = _get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            ip_range TEXT,
            status TEXT,
            summary TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            host TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            host TEXT,
            port INTEGER,
            banner TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            host TEXT,
            service TEXT,
            port INTEGER,
            creds TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
        """
    )
    conn.commit()
    conn.close()

def store_findings(findings, ip_range: str, status: str, summary_json: str = None) -> int:
    # Normalize findings to avoid crashes when None is passed
    if not findings:
        findings = {
            'active_hosts': [],
            'open_ports': [],
            'vulnerable_creds': []
        }

    conn = _get_connection()
    cur = conn.cursor()
    # Store scan entry
    cur.execute(
        "INSERT INTO scans (ip_range, status, summary) VALUES (?, ?, ?)",
        (ip_range, status, summary_json or json.dumps(findings))
    )
    scan_id = cur.lastrowid

    # Active hosts
    for host in findings.get('active_hosts', []) or []:
        cur.execute("INSERT INTO hosts (scan_id, host) VALUES (?, ?)", (scan_id, host))

    # Open ports
    for host_entry in findings.get('open_ports', []) or []:
        host = host_entry.get('host')
        for port_info in host_entry.get('ports', []) or []:
            cur.execute(
                "INSERT INTO ports (scan_id, host, port, banner) VALUES (?, ?, ?, ?)",
                (scan_id, host, int(port_info.get('port')), port_info.get('banner')),
            )

    # Credentials
    for cred in findings.get('vulnerable_creds', []) or []:
        cur.execute(
            "INSERT INTO credentials (scan_id, host, service, port, creds) VALUES (?, ?, ?, ?, ?)",
            (
                scan_id,
                cred.get('host'),
                cred.get('service'),
                int(cred.get('port')) if cred.get('port') is not None else None,
                cred.get('creds'),
            ),
        )

    conn.commit()
    conn.close()
    return scan_id
