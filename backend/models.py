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
