import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'soc_fusion.db')

def get_db_connection():
    """Establish and return an SQLite connection with Row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(force_reseed=False):
    """Create schema tables and populate with realistic default SOC data."""
    conn = get_db_connection()
    cursor = conn.cursor()

    if force_reseed:
        cursor.execute('DROP TABLE IF EXISTS logs')
        cursor.execute('DROP TABLE IF EXISTS incidents')
        cursor.execute('DROP TABLE IF EXISTS queue')
        cursor.execute('DROP TABLE IF EXISTS stats')
        cursor.execute('DROP TABLE IF EXISTS capacity')

    # 1. Logs / Security Events Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            signal TEXT NOT NULL,
            severity TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL
        )
    ''')

    # 2. Composite Incidents Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            incident_type TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            confidence INTEGER NOT NULL,
            source_ip TEXT NOT NULL,
            target TEXT NOT NULL,
            signals_count INTEGER NOT NULL,
            signals TEXT NOT NULL,
            status TEXT NOT NULL,
            analyst TEXT,
            time_elapsed TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            created_at TEXT NOT NULL,
            correlation_reasons TEXT NOT NULL,
            attack_steps TEXT NOT NULL,
            recommended_actions TEXT NOT NULL,
            timeline TEXT NOT NULL
        )
    ''')

    # 3. Response Queue Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS queue (
            priority INTEGER PRIMARY KEY,
            rank INTEGER NOT NULL,
            incident_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            target TEXT NOT NULL,
            signals_count INTEGER NOT NULL,
            time_waiting TEXT NOT NULL,
            analyst TEXT,
            status TEXT NOT NULL
        )
    ''')

    # 4. Telemetry Stats Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY,
            total_events INTEGER NOT NULL,
            signals_detected INTEGER NOT NULL,
            active_incidents INTEGER NOT NULL,
            critical_incidents INTEGER NOT NULL
        )
    ''')

    # 5. Analyst Capacity Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS capacity (
            id INTEGER PRIMARY KEY,
            active_analysts INTEGER NOT NULL,
            max_analysts INTEGER NOT NULL,
            total_analysts INTEGER NOT NULL
        )
    ''')

    conn.commit()

    # Seed stats if table empty
    cursor.execute('SELECT COUNT(*) as cnt FROM stats')
    if cursor.fetchone()['cnt'] == 0:
        cursor.execute('''
            INSERT INTO stats (id, total_events, signals_detected, active_incidents, critical_incidents)
            VALUES (1, 14205, 842, 5, 2)
        ''')

    # Seed capacity if empty
    cursor.execute('SELECT COUNT(*) as cnt FROM capacity')
    if cursor.fetchone()['cnt'] == 0:
        cursor.execute('''
            INSERT INTO capacity (id, active_analysts, max_analysts, total_analysts)
            VALUES (1, 3, 3, 3)
        ''')

    # Seed logs if empty
    cursor.execute('SELECT COUNT(*) as cnt FROM logs')
    if cursor.fetchone()['cnt'] == 0:
        now_str = datetime.now().strftime('%H:%M:%S')
        initial_logs = [
            (
                '10:31:18',
                '192.168.1.50',
                'TRAFFIC_SPIKE',
                'EGRESS_BURST',
                'CRITICAL',
                'RATE_LIMITED',
                'Outbound data surge: 4.8 GB transferred within 90s to unverified ASN'
            ),
            (
                '10:31:16',
                '192.168.1.50',
                'FAILED_LOGIN',
                'BRUTE_FORCE',
                'HIGH',
                'BLOCKED',
                '5 consecutive failed authentication attempts on Auth-Gateway root account'
            ),
            (
                '10:31:12',
                '192.168.1.50',
                'PORT_SCAN',
                'TCP_SYN_SWEEP',
                'HIGH',
                'FLAGGED',
                'Rapid scan on ports 22, 80, 443, 3389, 8080 from single host'
            ),
            (
                '10:30:52',
                '10.0.12.8',
                'SQL_INJECTION',
                'ANOMALOUS_PAYLOAD',
                'CRITICAL',
                'ISOLATED',
                'UNION SELECT syntax detected on customer billing endpoint'
            ),
            (
                '10:30:35',
                '172.16.4.19',
                'DNS_QUERY',
                'FAST_FLUX_SUSPECT',
                'MEDIUM',
                'MONITORED',
                'High-frequency queries to known dynamic DNS staging domain'
            ),
            (
                '10:29:10',
                '192.168.2.105',
                'PRIVILEGE_ESCALATION',
                'SUDO_EXPLOIT',
                'HIGH',
                'ALERTED',
                'Unauthorized invocation of CVE-2021-3156 heap overflow sequence'
            )
        ]
        cursor.executemany('''
            INSERT INTO logs (timestamp, source_ip, event_type, signal, severity, action, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', initial_logs)

    # Seed incidents if empty
    cursor.execute('SELECT COUNT(*) as cnt FROM incidents')
    if cursor.fetchone()['cnt'] == 0:
        initial_incidents = [
            (
                'INC-001',
                'MULTI-STAGE ATTACK',
                'Credential Stuffing & Lateral Reconnaissance',
                'CRITICAL',
                92,
                94,
                '192.168.1.50',
                'Auth-Gateway-01',
                6,
                json.dumps(['PORT_SCAN', 'FAILED_LOGIN', 'TRAFFIC_SPIKE', 'SYN_FLOOD', 'BRUTE_FORCE', 'EGRESS_BURST']),
                'INVESTIGATING',
                'Sarah Chen',
                '4m 12s',
                '10:28:15',
                '10:32:10',
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                json.dumps([
                    '5 failed logins from single external IP within 60s window',
                    'Correlated port scanning activity targeting SSH (22) and RDP (3389)',
                    'Anomalous outbound traffic volume spike (4.8 GB) detected on egress router',
                    'Signal Fusion Confidence: 94.2% multi-stage correlation match'
                ]),
                json.dumps([
                    'Reconnaissance: High-frequency TCP SYN port scan (ports 22, 80, 443, 3389)',
                    'Initial Access: Brute-force credential stuffing against root and admin accounts',
                    'Privilege Escalation: Attempt via sudo exploit vector',
                    'Signal Fusion: Fused 6 weak signals into Composite Critical Incident INC-001'
                ]),
                json.dumps([
                    'Isolate host 192.168.1.50 at boundary firewall perimeter immediately',
                    'Revoke active Kerberos ticket-granting session for root account',
                    'Force MFA re-authentication for Auth-Gateway-01 service account',
                    'Snapshot memory dump for forensic analysis on host 10.0.12.8'
                ]),
                json.dumps([
                    { 'time': '10:28:15', 'event': 'PORT SCAN', 'ip': '192.168.1.50', 'stage': 'Reconnaissance', 'type': 'stage-recon', 'sev': 'medium' },
                    { 'time': '10:29:40', 'event': 'FAILED LOGIN', 'ip': '192.168.1.50', 'stage': 'Initial Access', 'type': 'stage-access', 'sev': 'high' },
                    { 'time': '10:31:02', 'event': 'FAILED LOGIN', 'ip': '192.168.1.50', 'stage': 'Brute Force', 'type': 'stage-access', 'sev': 'high' },
                    { 'time': '10:31:18', 'event': 'TRAFFIC SPIKE', 'ip': '192.168.1.50', 'stage': 'Anomaly Detected', 'type': 'stage-anomaly', 'sev': 'high' },
                    { 'time': '10:32:10', 'event': 'COMPOSITE INCIDENT', 'ip': '192.168.1.50', 'stage': 'Signal Fusion', 'type': 'stage-escalation', 'sev': 'critical' },
                    { 'time': '10:32:15', 'event': 'CRITICAL ESCALATION', 'ip': '192.168.1.50', 'stage': 'SOC Priority #1', 'type': 'stage-escalation', 'sev': 'critical' }
                ])
            ),
            (
                'INC-002',
                'SQL INJECTION & EXFIL',
                'Distributed SQL Injection & Data Exfiltration',
                'CRITICAL',
                88,
                91,
                '10.0.12.8',
                'DB-Cluster-Primary',
                5,
                json.dumps(['SQL_INJECTION', 'AUTH_BURST', 'INVALID_USER_SURGE', 'DISTRIBUTED_PROXY']),
                'ASSIGNED',
                'David Kim',
                '8m 45s',
                '10:24:02',
                '10:27:12',
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                json.dumps([
                    'Multiple UNION SELECT payloads detected across /api/v1/billing endpoint',
                    'Large database record read queries executed outside typical office hours',
                    'High volume egress observed to unusual external IP block'
                ]),
                json.dumps([
                    'Reconnaissance: Automated SQLMap parameter fuzzing on API endpoints',
                    'Exploitation: Blind SQL injection verified on billing account query',
                    'Exfiltration: 12.4 MB compressed schema extraction via HTTP responses'
                ]),
                json.dumps([
                    'Deploy WAF virtual patch blocking UNION SELECT parameter injections',
                    'Rotate database master credentials and drop active read sessions',
                    'Verify integrity of customer billing database tables'
                ]),
                json.dumps([
                    { 'time': '10:24:02', 'event': 'AUTH BURST', 'ip': '10.0.12.8', 'stage': 'Enumeration', 'type': 'stage-recon', 'sev': 'high' },
                    { 'time': '10:25:30', 'event': 'SQL INJECTION', 'ip': '10.0.12.8', 'stage': 'Exploitation', 'type': 'stage-anomaly', 'sev': 'critical' },
                    { 'time': '10:27:12', 'event': 'EXFILTRATION BURST', 'ip': '10.0.12.8', 'stage': 'Data Exfiltration', 'type': 'stage-escalation', 'sev': 'critical' }
                ])
            ),
            (
                'INC-003',
                'C2 BEACONING',
                'Anomalous C2 Beaconing via Encrypted DNS',
                'HIGH',
                76,
                85,
                '172.16.4.19',
                'Workstation-Fin-04',
                4,
                json.dumps(['DNS_QUERY', 'LARGE_OUTBOUND_CONN', 'UNUSUAL_PORT_EGRESS']),
                'ASSIGNED',
                'Elena Rostova',
                '14m 20s',
                '10:18:00',
                '10:20:15',
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                json.dumps([
                    'Repetitive DNS queries with 30s jitter pattern matching Cobalt Strike default beacon',
                    'Unresolved dynamic domain names with ultra-low TTL (< 10 seconds)',
                    'Base64-encoded subdomains indicating potential DNS tunneling'
                ]),
                json.dumps([
                    'Initial Access: Phishing attachment executed on Workstation-Fin-04',
                    'Command & Control: Encrypted DNS beacon established to external NS server'
                ]),
                json.dumps([
                    'Sinkhole malicious dynamic DNS domain on internal recursive DNS servers',
                    'Quarantine Workstation-Fin-04 from the corporate internal VLAN',
                    'Extract and analyze host memory dump for in-memory beacon payload'
                ]),
                json.dumps([
                    { 'time': '10:18:00', 'event': 'PHISHING OPEN', 'ip': '172.16.4.19', 'stage': 'Initial Access', 'type': 'stage-recon', 'sev': 'medium' },
                    { 'time': '10:20:15', 'event': 'DNS BEACON', 'ip': '172.16.4.19', 'stage': 'Command & Control', 'type': 'stage-anomaly', 'sev': 'high' }
                ])
            ),
            (
                'INC-004',
                'PRIVILEGE ESCALATION',
                'Privilege Escalation via Sudo CVE Exploit',
                'HIGH',
                70,
                82,
                '192.168.2.105',
                'App-Worker-Node-03',
                3,
                json.dumps(['PRIVILEGE_ESCALATION', 'SYN_SCAN', 'ICMP_SWEEP']),
                'WAITING',
                None,
                '22m 05s',
                '10:10:11',
                '10:11:45',
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                json.dumps([
                    'Abnormal sudoers process crash followed by root shell spawn',
                    'Execution of known Baron Samedit exploit payload pattern',
                    'Modification attempt on /etc/shadow timestamp attributes'
                ]),
                json.dumps([
                    'Exploitation: Heap overflow trigger attempted in sudo binary',
                    'Privilege Escalation: Spawned interactive UID 0 root shell session'
                ]),
                json.dumps([
                    'Terminate suspicious child processes spawned from worker service account',
                    'Apply updated sudo package patch across all Linux worker nodes',
                    'Audit /etc/passwd and /etc/shadow for newly injected local accounts'
                ]),
                json.dumps([
                    { 'time': '10:10:11', 'event': 'SUDO FAULT', 'ip': '192.168.2.105', 'stage': 'Exploitation', 'type': 'stage-anomaly', 'sev': 'high' },
                    { 'time': '10:11:45', 'event': 'ROOT SHELL', 'ip': '192.168.2.105', 'stage': 'Privilege Escalation', 'type': 'stage-escalation', 'sev': 'high' }
                ])
            ),
            (
                'INC-005',
                'VULNERABILITY PROBE',
                'Automated Vulnerability Probing & DirBuster Sweep',
                'MEDIUM',
                48,
                68,
                '10.200.5.44',
                'Public-Web-DMZ',
                2,
                json.dumps(['PORT_SCAN', 'RATE_LIMIT_EXCEEDED']),
                'WAITING',
                None,
                '35m 12s',
                '09:55:00',
                '10:22:30',
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                json.dumps([
                    'Over 800 HTTP 404 responses generated in 2 minutes',
                    'Sequential requests targeting .env, .git, and /admin login paths',
                    'Known DirBuster user agent string identified in access logs'
                ]),
                json.dumps([
                    'Reconnaissance: Automated directory traversal sweep across public web server'
                ]),
                json.dumps([
                    'Blacklist IP 10.200.5.44 on Cloudflare edge CDN',
                    'Verify directory listing is disabled across all web server vhosts'
                ]),
                json.dumps([
                    { 'time': '09:55:00', 'event': 'DIRBUSTER SWEEP', 'ip': '10.200.5.44', 'stage': 'Reconnaissance', 'type': 'stage-recon', 'sev': 'medium' }
                ])
            )
        ]
        cursor.executemany('''
            INSERT INTO incidents (
                id, incident_type, title, severity, risk_score, confidence,
                source_ip, target, signals_count, signals, status, analyst,
                time_elapsed, first_seen, last_seen, created_at,
                correlation_reasons, attack_steps, recommended_actions, timeline
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', initial_incidents)

    # Seed queue if empty
    cursor.execute('SELECT COUNT(*) as cnt FROM queue')
    if cursor.fetchone()['cnt'] == 0:
        initial_queue = [
            (1, 1, 'INC-001', 'Credential Stuffing & Lateral Reconnaissance', 'CRITICAL', 92, 'Auth-Gateway-01', 6, '4m 12s', 'Sarah Chen', 'INVESTIGATING'),
            (2, 2, 'INC-002', 'Distributed SQL Injection & Data Exfiltration', 'CRITICAL', 88, 'DB-Cluster-Primary', 5, '8m 45s', 'David Kim', 'ASSIGNED'),
            (3, 3, 'INC-003', 'Anomalous C2 Beaconing via Encrypted DNS', 'HIGH', 76, 'Workstation-Fin-04', 4, '14m 20s', 'Elena Rostova', 'ASSIGNED'),
            (4, 4, 'INC-004', 'Privilege Escalation via Sudo CVE Exploit', 'HIGH', 70, 'App-Worker-Node-03', 3, '22m 05s', None, 'WAITING'),
            (5, 5, 'INC-005', 'Automated Vulnerability Probing & DirBuster Sweep', 'MEDIUM', 48, 'Public-Web-DMZ', 2, '35m 12s', None, 'WAITING')
        ]
        cursor.executemany('''
            INSERT INTO queue (priority, rank, incident_id, title, severity, risk_score, target, signals_count, time_waiting, analyst, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', initial_queue)

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db(force_reseed=True)
    print("Database re-initialized and seeded successfully at:", DB_PATH)
