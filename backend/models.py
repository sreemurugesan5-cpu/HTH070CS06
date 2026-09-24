import json
from datetime import datetime
from backend.database import get_db_connection

def get_stats():
    """Retrieve the latest telemetry stats and trends."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM stats WHERE id = 1')
    row = cursor.fetchone()

    cursor.execute("SELECT COUNT(*) as active_cnt FROM incidents WHERE status != 'CLOSED'")
    active_cnt = cursor.fetchone()['active_cnt']

    cursor.execute("SELECT COUNT(*) as crit_cnt FROM incidents WHERE status != 'CLOSED' AND severity = 'CRITICAL'")
    crit_cnt = cursor.fetchone()['crit_cnt']

    conn.close()

    total_events = row['total_events'] if row else 14205
    signals_detected = row['signals_detected'] if row else 842

    return {
        'total_events': total_events,
        'signals_detected': signals_detected,
        'active_incidents': active_cnt,
        'critical_incidents': crit_cnt,
        'trends': {
            'events': '+12% from last hour',
            'signals': 'Active cross-correlation',
            'incidents': 'Prioritized response queue',
            'critical': f'{crit_cnt} Active critical' if crit_cnt > 0 else 'All clear'
        }
    }

def get_logs(limit=50):
    """Retrieve the most recent security event logs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()

    logs = []
    for r in rows:
        logs.append({
            'id': r['id'],
            'timestamp': r['timestamp'],
            'source_ip': r['source_ip'],
            'event_type': r['event_type'],
            'source': r['event_type'],
            'signal': r['signal'],
            'severity': r['severity'],
            'status': 'DETECTED',
            'action': r['action'],
            'details': r['details']
        })
    return logs

def add_log(event_data):
    """Insert a new event log and increment stats."""
    conn = get_db_connection()
    cursor = conn.cursor()

    ts = event_data.get('timestamp') or datetime.now().strftime('%H:%M:%S')
    cursor.execute('''
        INSERT INTO logs (timestamp, source_ip, event_type, signal, severity, action, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        ts,
        event_data.get('source_ip', '192.168.1.50'),
        event_data.get('event_type', 'EVENT'),
        event_data.get('signal', 'UNSPECIFIED'),
        event_data.get('severity', 'LOW'),
        event_data.get('action', 'LOGGED'),
        event_data.get('details', '')
    ))

    # Increment total_events and signals
    cursor.execute('''
        UPDATE stats
        SET total_events = total_events + 1,
            signals_detected = signals_detected + 1
        WHERE id = 1
    ''')

    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id

def _parse_incident_row(row):
    """Convert a database incident row into a fully formatted dictionary."""
    if not row:
        return None

    def safe_json_load(val, default):
        if not val:
            return default
        try:
            return json.loads(val)
        except Exception:
            return default

    correlation = safe_json_load(row['correlation_reasons'], [])
    steps = safe_json_load(row['attack_steps'], [])
    actions = safe_json_load(row['recommended_actions'], [])
    signals = safe_json_load(row['signals'], [])
    timeline = safe_json_load(row['timeline'], [])

    rec_action_str = actions[0] if actions else 'Investigate host immediately.'

    return {
        'id': row['id'],
        'title': row['title'],
        'incident_type': row['incident_type'],
        'severity': row['severity'],
        'risk_score': row['risk_score'],
        'confidence': row['confidence'],
        'source_ip': row['source_ip'],
        'target': row['target'],
        'signals_count': row['signals_count'],
        'signals': signals,
        'status': row['status'],
        'analyst': row['analyst'],
        'time_elapsed': row['time_elapsed'],
        'first_seen': row['first_seen'],
        'last_seen': row['last_seen'],
        'created_at': row['created_at'],
        'correlation_reasons': correlation,
        'reasons': correlation,
        'attack_steps': steps,
        'progression': steps,
        'recommended_actions': actions,
        'recommended_action': rec_action_str,
        'timeline': timeline
    }

def get_incidents(status_filter=None):
    """Retrieve composite incidents, sorted by risk_score descending."""
    conn = get_db_connection()
    cursor = conn.cursor()

    if status_filter:
        cursor.execute('SELECT * FROM incidents WHERE status = ? ORDER BY risk_score DESC', (status_filter,))
    else:
        cursor.execute('SELECT * FROM incidents ORDER BY risk_score DESC')

    rows = cursor.fetchall()
    conn.close()
    return [_parse_incident_row(r) for r in rows]

def get_incident_by_id(incident_id):
    """Retrieve details for a single incident by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,))
    row = cursor.fetchone()
    conn.close()
    return _parse_incident_row(row)

def assign_incident(incident_id, analyst_name='Sarah Chen'):
    """Assign an incident to an analyst."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE incidents
        SET status = 'ASSIGNED', analyst = ?
        WHERE id = ?
    ''', (analyst_name, incident_id))

    cursor.execute('''
        UPDATE queue
        SET status = 'ASSIGNED', analyst = ?
        WHERE incident_id = ?
    ''', (analyst_name, incident_id))

    conn.commit()
    conn.close()
    return get_incident_by_id(incident_id)

def investigate_incident(incident_id):
    """Mark an incident as currently under investigation."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE incidents
        SET status = 'INVESTIGATING'
        WHERE id = ?
    ''', (incident_id,))

    cursor.execute('''
        UPDATE queue
        SET status = 'INVESTIGATING'
        WHERE incident_id = ?
    ''', (incident_id,))

    conn.commit()
    conn.close()
    return get_incident_by_id(incident_id)

def close_incident(incident_id):
    """Close and resolve an incident."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE incidents
        SET status = 'CLOSED'
        WHERE id = ?
    ''', (incident_id,))

    # Remove from active queue
    cursor.execute('DELETE FROM queue WHERE incident_id = ?', (incident_id,))

    # Re-order queue priorities and ranks 1..N
    cursor.execute('SELECT incident_id FROM queue ORDER BY priority ASC')
    remaining = cursor.fetchall()
    for new_prio, item in enumerate(remaining, start=1):
        cursor.execute('UPDATE queue SET priority = ?, rank = ? WHERE incident_id = ?', (new_prio, new_prio, item['incident_id']))

    # Decrement active incidents count in stats
    cursor.execute('''
        UPDATE stats
        SET active_incidents = (SELECT COUNT(*) FROM incidents WHERE status != 'CLOSED'),
            critical_incidents = (SELECT COUNT(*) FROM incidents WHERE status != 'CLOSED' AND severity = 'CRITICAL')
        WHERE id = 1
    ''')

    # Update capacity (free 1 analyst slot)
    cursor.execute('''
        UPDATE capacity
        SET active_analysts = MAX(0, active_analysts - 1)
        WHERE id = 1
    ''')

    conn.commit()
    conn.close()
    return get_incident_by_id(incident_id)

def get_queue_with_capacity():
    """Retrieve queue items along with current analyst capacity."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM capacity WHERE id = 1')
    cap_row = cursor.fetchone()
    active_analysts = cap_row['active_analysts'] if cap_row else 3
    max_analysts = cap_row['max_analysts'] if cap_row else 3
    total_analysts = cap_row['total_analysts'] if cap_row else 3

    cursor.execute('SELECT * FROM queue ORDER BY priority ASC')
    queue_rows = cursor.fetchall()
    conn.close()

    queue_list = []
    for r in queue_rows:
        queue_list.append({
            'priority': r['priority'],
            'rank': r['rank'],
            'incident_id': r['incident_id'],
            'title': r['title'],
            'severity': r['severity'],
            'risk_score': r['risk_score'],
            'target': r['target'],
            'signals_count': r['signals_count'],
            'time_waiting': r['time_waiting'],
            'analyst': r['analyst'],
            'status': r['status']
        })

    utilization_pct = f"{round((active_analysts / max_analysts) * 100)}%" if max_analysts > 0 else '100%'

    return {
        'capacity': {
            'active_analysts': active_analysts,
            'max_analysts': max_analysts,
            'total_analysts': total_analysts,
            'utilization': utilization_pct
        },
        'queue': queue_list
    }

def execute_attack_simulation():
    """Simulate an end-to-end multi-stage intrusion attack scenario in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    now_ts = datetime.now().strftime('%H:%M:%S')
    now_dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 1. Insert attack event logs
    sim_logs = [
        (now_ts, '192.168.1.50', 'PORT_SCAN', 'TCP_SYN_SWEEP', 'HIGH', 'FLAGGED', 'Rapid scan on ports 22, 80, 443, 3389, 8080 from single host'),
        (now_ts, '192.168.1.50', 'FAILED_LOGIN', 'BRUTE_FORCE', 'HIGH', 'BLOCKED', '5 consecutive failed authentication attempts on Auth-Gateway root account'),
        (now_ts, '192.168.1.50', 'TRAFFIC_SPIKE', 'EGRESS_BURST', 'CRITICAL', 'RATE_LIMITED', 'Outbound data surge: 4.8 GB transferred within 90s to unverified ASN')
    ]

    inserted_logs = []
    for log_item in sim_logs:
        cursor.execute('''
            INSERT INTO logs (timestamp, source_ip, event_type, signal, severity, action, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', log_item)
        inserted_logs.append({
            'id': cursor.lastrowid,
            'timestamp': log_item[0],
            'source_ip': log_item[1],
            'event_type': log_item[2],
            'source': log_item[2],
            'signal': log_item[3],
            'severity': log_item[4],
            'status': 'DETECTED',
            'action': log_item[5],
            'details': log_item[6]
        })

    # 2. Update stats
    cursor.execute('''
        UPDATE stats
        SET total_events = total_events + 18,
            signals_detected = signals_detected + 6
        WHERE id = 1
    ''')

    # 3. Create or update INC-001 as Critical Composite Incident
    correlation_reasons = json.dumps([
        '5 failed logins from single external IP within 60s window',
        'Correlated port scanning activity targeting SSH (22) and RDP (3389)',
        'Anomalous outbound traffic volume spike (4.8 GB) detected on egress router',
        'Signal Fusion Confidence: 96.4% multi-stage correlation match'
    ])
    attack_steps = json.dumps([
        'Reconnaissance: High-frequency TCP SYN port scan (ports 22, 80, 443, 3389)',
        'Initial Access: Brute-force credential stuffing against root and admin accounts',
        'Privilege Escalation: Attempt via sudo exploit vector',
        'Signal Fusion: Fused 6 weak signals into Composite Critical Incident INC-001'
    ])
    recommended_actions = json.dumps([
        'Isolate host 192.168.1.50 at boundary firewall perimeter immediately',
        'Revoke active Kerberos ticket-granting session for root account',
        'Force MFA re-authentication for Auth-Gateway-01 service account',
        'Snapshot memory dump for forensic analysis on host 10.0.12.8'
    ])
    timeline = json.dumps([
        { 'time': now_ts, 'event': 'PORT SCAN', 'ip': '192.168.1.50', 'stage': 'Reconnaissance', 'type': 'stage-recon', 'sev': 'medium' },
        { 'time': now_ts, 'event': 'FAILED LOGIN', 'ip': '192.168.1.50', 'stage': 'Initial Access', 'type': 'stage-access', 'sev': 'high' },
        { 'time': now_ts, 'event': 'FAILED LOGIN', 'ip': '192.168.1.50', 'stage': 'Brute Force', 'type': 'stage-access', 'sev': 'high' },
        { 'time': now_ts, 'event': 'TRAFFIC SPIKE', 'ip': '192.168.1.50', 'stage': 'Anomaly Detected', 'type': 'stage-anomaly', 'sev': 'high' },
        { 'time': now_ts, 'event': 'COMPOSITE INCIDENT', 'ip': '192.168.1.50', 'stage': 'Signal Fusion', 'type': 'stage-escalation', 'sev': 'critical' },
        { 'time': now_ts, 'event': 'CRITICAL ESCALATION', 'ip': '192.168.1.50', 'stage': 'SOC Priority #1', 'type': 'stage-escalation', 'sev': 'critical' }
    ])

    cursor.execute('''
        INSERT INTO incidents (
            id, incident_type, title, severity, risk_score, confidence,
            source_ip, target, signals_count, signals, status, analyst,
            time_elapsed, first_seen, last_seen, created_at,
            correlation_reasons, attack_steps, recommended_actions, timeline
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            severity = 'CRITICAL',
            risk_score = 94,
            confidence = 96,
            signals_count = 6,
            status = 'ACTIVE',
            analyst = 'Unassigned',
            time_elapsed = 'Just now',
            last_seen = excluded.last_seen,
            correlation_reasons = excluded.correlation_reasons,
            attack_steps = excluded.attack_steps,
            recommended_actions = excluded.recommended_actions,
            timeline = excluded.timeline
    ''', (
        'INC-001', 'MULTI-STAGE ATTACK', 'Credential Stuffing & Lateral Reconnaissance',
        'CRITICAL', 94, 96, '192.168.1.50', 'Auth-Gateway-01', 6,
        json.dumps(['PORT_SCAN', 'FAILED_LOGIN', 'TRAFFIC_SPIKE', 'SYN_FLOOD', 'BRUTE_FORCE', 'EGRESS_BURST']),
        'ACTIVE', 'Unassigned', 'Just now', now_ts, now_ts, now_dt,
        correlation_reasons, attack_steps, recommended_actions, timeline
    ))

    # 4. Elevate INC-001 to Priority #1 in Queue
    cursor.execute('DELETE FROM queue WHERE incident_id = ?', ('INC-001',))
    cursor.execute('SELECT incident_id, title, severity, risk_score, target, signals_count, time_waiting, analyst, status FROM queue ORDER BY priority ASC')
    existing_items = cursor.fetchall()

    cursor.execute('DELETE FROM queue')

    # Priority 1: INC-001
    cursor.execute('''
        INSERT INTO queue (priority, rank, incident_id, title, severity, risk_score, target, signals_count, time_waiting, analyst, status)
        VALUES (1, 1, 'INC-001', 'Credential Stuffing & Lateral Reconnaissance', 'CRITICAL', 94, 'Auth-Gateway-01', 6, 'Just now', NULL, 'WAITING')
    ''')

    # Subsequent priorities 2..5
    for idx, row in enumerate(existing_items[:4], start=2):
        cursor.execute('''
            INSERT INTO queue (priority, rank, incident_id, title, severity, risk_score, target, signals_count, time_waiting, analyst, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (idx, idx, row['incident_id'], row['title'], row['severity'], row['risk_score'], row['target'], row['signals_count'], row['time_waiting'], row['analyst'], row['status']))

    # Capacity: Ensure 3/3 saturation
    cursor.execute('UPDATE capacity SET active_analysts = 3, max_analysts = 3, total_analysts = 3 WHERE id = 1')

    conn.commit()
    conn.close()

    return {
        'incident': get_incident_by_id('INC-001'),
        'logs': inserted_logs,
        'queue': get_queue_with_capacity(),
        'stats': get_stats()
    }

