import os
import sys

# Ensure parent directory is in Python path for absolute imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from backend.database import init_db, query_ip_intelligence
from backend.models import (
    get_stats,
    get_logs,
    add_log,
    get_incidents,
    get_incident_by_id,
    assign_incident,
    investigate_incident,
    close_incident,
    get_queue_with_capacity,
    execute_attack_simulation
)

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# Initialize SQLite database on startup
init_db()

@app.route('/')
def serve_index():
    """Serve the SOC Dashboard frontend HTML."""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static frontend assets (css, js, images)."""
    return send_from_directory(app.static_folder, path)

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify backend status."""
    return jsonify({
        'status': 'healthy',
        'service': 'SOC-FUSION API',
        'version': '1.0.0'
    }), 200

@app.route('/api/stats', methods=['GET'])
def api_get_stats():
    """Get high-level SOC telemetry counters and trends."""
    try:
        stats_data = get_stats()
        return jsonify(stats_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs', methods=['GET'])
def api_get_logs():
    """Get recent live security event logs."""
    try:
        limit = request.args.get('limit', default=50, type=int)
        logs = get_logs(limit=limit)
        return jsonify(logs), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs', methods=['POST'])
def api_add_log():
    """Inject a new security event log."""
    try:
        data = request.get_json() or {}
        new_id = add_log(data)
        return jsonify({'status': 'created', 'log_id': new_id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/incidents', methods=['GET'])
def api_get_incidents():
    """Get active composite security incidents."""
    try:
        status_filter = request.args.get('status', default=None, type=str)
        incidents = get_incidents(status_filter=status_filter)
        return jsonify(incidents), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/incidents/<incident_id>', methods=['GET'])
def api_get_incident_detail(incident_id):
    """Get detailed investigation dossier for a specific incident."""
    try:
        inc = get_incident_by_id(incident_id)
        if not inc:
            return jsonify({'error': f'Incident {incident_id} not found'}), 404
        return jsonify(inc), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/incidents/<incident_id>/assign', methods=['POST'])
def api_assign_incident(incident_id):
    """Assign an incident to an analyst."""
    try:
        data = request.get_json(silent=True) or {}
        analyst = data.get('analyst', 'Sarah Chen')
        updated = assign_incident(incident_id, analyst_name=analyst)
        if not updated:
            return jsonify({'error': f'Incident {incident_id} not found'}), 404
        return jsonify({
            'status': 'success',
            'action': 'assigned',
            'incident': updated
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/incidents/<incident_id>/investigate', methods=['POST'])
def api_investigate_incident(incident_id):
    """Mark an incident as investigating."""
    try:
        updated = investigate_incident(incident_id)
        if not updated:
            return jsonify({'error': f'Incident {incident_id} not found'}), 404
        return jsonify({
            'status': 'success',
            'action': 'investigating',
            'incident': updated
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/incidents/<incident_id>/close', methods=['POST'])
def api_close_incident(incident_id):
    """Close and resolve an incident."""
    try:
        updated = close_incident(incident_id)
        if not updated:
            return jsonify({'error': f'Incident {incident_id} not found'}), 404
        return jsonify({
            'status': 'success',
            'action': 'closed',
            'incident': updated
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/queue', methods=['GET'])
def api_get_queue():
    """Get prioritized response queue and analyst saturation capacity."""
    try:
        queue_data = get_queue_with_capacity()
        return jsonify(queue_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/start-simulation', methods=['POST'])
def api_start_simulation():
    """Trigger or reset attack simulation scenario (Phase 12)."""
    try:
        result = execute_attack_simulation()
        return jsonify({
            'status': 'initiated',
            'message': 'Attack simulation pipeline executed and fused into INC-001',
            'scenario': 'Credential Stuffing + Port Scan + Traffic Surge -> INC-001 Fusion',
            'incident': result['incident'],
            'logs': result['logs'],
            'queue': result['queue'],
            'stats': result['stats']
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ip/<path:ip_address>', methods=['GET', 'POST'])
def api_lookup_ip(ip_address):
    """Retrieve full intelligence dossier and telemetry for a specific IP address."""
    try:
        data = query_ip_intelligence(ip_address)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"[SOC-FUSION] Starting Flask REST API backend on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=True)
