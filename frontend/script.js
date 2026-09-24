/**
 * ==========================================================================
 * SOC-FUSION — Signal-Fused Intrusion Detection & Response Dashboard
 * Phase 5: Active Composite Incidents Table & Incident Selection
 * ==========================================================================
 */

// Central API Configuration
const API_CONFIG = {
  BASE_URL: '', // Supports relative Flask REST API routes
  ENDPOINTS: {
    STATS: '/api/stats',
    LOGS: '/api/logs',
    INCIDENTS: '/api/incidents',
    QUEUE: '/api/queue',
    START_SIMULATION: '/api/start-simulation'
  },
  POLL_INTERVAL_MS: 3000
};

// Global Reactive State
const state = {
  stats: {
    total_events: 0,
    signals_detected: 0,
    active_incidents: 0,
    critical_incidents: 0,
    trends: {
      events: 'Normal flow',
      signals: 'Correlation active',
      incidents: 'Queue prioritized',
      critical: 'Normal status'
    }
  },
  logs: [],
  knownLogIds: new Set(),
  incidents: [],
  selectedIncidentId: null,
  selectedIncident: null,
  isOnline: true
};

// Standard US Locale Number Formatter (e.g. 12,540)
const numberFormatter = new Intl.NumberFormat('en-US');

/**
 * Safely format numbers with comma separators
 * @param {number|string} value
 * @returns {string}
 */
function formatNumber(value) {
  const num = Number(value);
  return isNaN(num) ? '0' : numberFormatter.format(num);
}

/**
 * Animate numeric value transitions smoothly for cyber telemetry feel
 */
function animateValue(element, start, end, duration = 650) {
  if (!element) return;
  if (start === end) {
    element.textContent = formatNumber(end);
    return;
  }
  
  const startTime = performance.now();
  const step = (currentTime) => {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const easeOut = 1 - Math.pow(1 - progress, 3);
    const current = Math.floor(start + (end - start) * easeOut);
    element.textContent = formatNumber(current);
    
    if (progress < 1) {
      requestAnimationFrame(step);
    } else {
      element.textContent = formatNumber(end);
    }
  };
  requestAnimationFrame(step);
}

/**
 * Render the 4 Major SOC Summary Cards from data
 */
function renderSummaryCards(statsData) {
  if (!statsData) return;

  const totalEventsEl = document.getElementById('stat-total-events');
  const signalsDetectedEl = document.getElementById('stat-signals-detected');
  const activeIncidentsEl = document.getElementById('stat-active-incidents');
  const criticalIncidentsEl = document.getElementById('stat-critical-incidents');

  const trendEventsEl = document.getElementById('trend-total-events');
  const trendSignalsEl = document.getElementById('trend-signals-detected');
  const trendActiveEl = document.getElementById('trend-active-incidents');
  const trendCriticalEl = document.getElementById('trend-critical-incidents');

  const prevEvents = parseInt(totalEventsEl?.textContent.replace(/,/g, '')) || 0;
  const prevSignals = parseInt(signalsDetectedEl?.textContent.replace(/,/g, '')) || 0;
  const prevActive = parseInt(activeIncidentsEl?.textContent.replace(/,/g, '')) || 0;
  const prevCritical = parseInt(criticalIncidentsEl?.textContent.replace(/,/g, '')) || 0;

  if (totalEventsEl) animateValue(totalEventsEl, prevEvents, statsData.total_events ?? 0);
  if (signalsDetectedEl) animateValue(signalsDetectedEl, prevSignals, statsData.signals_detected ?? 0);
  if (activeIncidentsEl) animateValue(activeIncidentsEl, prevActive, statsData.active_incidents ?? 0);
  if (criticalIncidentsEl) animateValue(criticalIncidentsEl, prevCritical, statsData.critical_incidents ?? 0);

  if (trendEventsEl && statsData.trends?.events) trendEventsEl.textContent = statsData.trends.events;
  if (trendSignalsEl && statsData.trends?.signals) trendSignalsEl.textContent = statsData.trends.signals;
  if (trendActiveEl && statsData.trends?.incidents) trendActiveEl.textContent = statsData.trends.incidents;
  if (trendCriticalEl && statsData.trends?.critical) trendCriticalEl.textContent = statsData.trends.critical;

  const criticalCard = document.getElementById('card-critical-incidents');
  if (criticalCard) {
    if ((statsData.critical_incidents ?? 0) > 0) {
      criticalCard.style.boxShadow = '0 0 18px rgba(239, 68, 68, 0.35)';
      criticalCard.style.borderColor = 'rgba(239, 68, 68, 0.6)';
    } else {
      criticalCard.style.boxShadow = '';
      criticalCard.style.borderColor = '';
    }
  }
}

/**
 * ==========================================================================
 * LIVE SECURITY EVENT STREAM COMPONENT
 * ==========================================================================
 */
function getSeverityForEvent(eventType = '') {
  const type = eventType.toUpperCase();
  if (type.includes('EXFIL') || type.includes('ROOT') || type.includes('MALWARE')) return 'critical';
  if (type.includes('TRAFFIC_SPIKE') || type.includes('FAILED_LOGIN') || type.includes('BRUTE')) return 'high';
  if (type.includes('PORT_SCAN') || type.includes('SYN_FLOOD')) return 'medium';
  return 'low';
}

function createEventItemElement(event, isNew = false) {
  const item = document.createElement('div');
  const sev = (event.severity || getSeverityForEvent(event.event_type)).toLowerCase();
  
  item.className = `event-item event-${sev}${isNew ? ' event-item-new' : ''}`;
  item.dataset.id = event.id || `${event.timestamp}-${event.source_ip}-${event.event_type}`;

  const rowTop = document.createElement('div');
  rowTop.className = 'event-row-top';

  const timeEl = document.createElement('span');
  timeEl.className = 'event-timestamp';
  timeEl.textContent = event.timestamp || new Date().toTimeString().split(' ')[0];

  const badgeEl = document.createElement('span');
  badgeEl.className = 'event-badge';
  badgeEl.textContent = (event.event_type || 'SECURITY_EVENT').toUpperCase();

  rowTop.appendChild(timeEl);
  rowTop.appendChild(badgeEl);

  const rowMain = document.createElement('div');
  rowMain.className = 'event-row-main';

  const ipEl = document.createElement('span');
  ipEl.className = 'event-ip';
  ipEl.textContent = event.source_ip || '0.0.0.0';

  const statusEl = document.createElement('span');
  statusEl.className = 'event-status';
  statusEl.textContent = (event.status || 'DETECTED').toUpperCase();

  rowMain.appendChild(ipEl);
  rowMain.appendChild(statusEl);

  const rowBottom = document.createElement('div');
  rowBottom.className = 'event-row-bottom';

  const sourceEl = document.createElement('span');
  sourceEl.className = 'event-source';
  sourceEl.textContent = `Source: ${event.source || 'Firewall'}`;

  const sevLabel = document.createElement('span');
  sevLabel.className = `text-${sev === 'critical' ? 'red' : sev === 'high' ? 'orange' : sev === 'medium' ? 'yellow' : 'cyan'}`;
  sevLabel.textContent = sev.toUpperCase();

  rowBottom.appendChild(sourceEl);
  rowBottom.appendChild(sevLabel);

  item.appendChild(rowTop);
  item.appendChild(rowMain);
  item.appendChild(rowBottom);

  return item;
}

function renderEventStream(logs, prependNew = false) {
  const container = document.getElementById('event-stream-container');
  const countBadge = document.getElementById('event-stream-count');
  if (!container) return;

  if (!logs || logs.length === 0) {
    if (container.children.length === 0) {
      container.innerHTML = '<div class="stream-empty-state">No real-time security events received yet.</div>';
    }
    return;
  }

  const emptyPlaceholder = container.querySelector('.stream-empty-state');
  if (emptyPlaceholder) emptyPlaceholder.remove();

  if (prependNew) {
    for (let i = logs.length - 1; i >= 0; i--) {
      const log = logs[i];
      const logKey = log.id || `${log.timestamp}-${log.source_ip}-${log.event_type}`;
      if (!state.knownLogIds.has(logKey)) {
        state.knownLogIds.add(logKey);
        const card = createEventItemElement(log, true);
        container.insertBefore(card, container.firstChild);
      }
    }
  } else {
    container.innerHTML = '';
    state.knownLogIds.clear();
    logs.forEach(log => {
      const logKey = log.id || `${log.timestamp}-${log.source_ip}-${log.event_type}`;
      state.knownLogIds.add(logKey);
      const card = createEventItemElement(log, false);
      container.appendChild(card);
    });
  }

  while (container.children.length > 50) {
    container.removeChild(container.lastChild);
  }

  if (countBadge) {
    countBadge.textContent = `${container.children.length} Events`;
  }
}

async function fetchLogs() {
  try {
    const response = await fetch(API_CONFIG.ENDPOINTS.LOGS);
    if (!response.ok) throw new Error(`HTTP ${response.status}: Failed to fetch /api/logs`);
    const data = await response.json();
    const logs = Array.isArray(data) ? data : (data.logs || []);
    const isInitial = state.logs.length === 0;
    state.logs = logs;
    renderEventStream(logs, !isInitial);
    hideOfflineAlert();
  } catch (error) {
    if (state.logs.length === 0) {
      const demoLogs = [
        {
          id: 103,
          timestamp: '10:31:16',
          source_ip: '192.168.1.50',
          event_type: 'TRAFFIC_SPIKE',
          source: 'Network Monitor',
          status: 'DETECTED',
          severity: 'HIGH'
        },
        {
          id: 102,
          timestamp: '10:31:14',
          source_ip: '192.168.1.50',
          event_type: 'FAILED_LOGIN',
          source: 'Authentication',
          status: 'DETECTED',
          severity: 'HIGH'
        },
        {
          id: 101,
          timestamp: '10:31:12',
          source_ip: '192.168.1.50',
          event_type: 'PORT_SCAN',
          source: 'Firewall',
          status: 'DETECTED',
          severity: 'MEDIUM'
        },
        {
          id: 100,
          timestamp: '10:30:52',
          source_ip: '10.0.8.22',
          event_type: 'DNS_TUNNEL_BURST',
          source: 'DPI Sensor',
          status: 'DETECTED',
          severity: 'MEDIUM'
        },
        {
          id: 99,
          timestamp: '10:30:35',
          source_ip: '172.16.0.4',
          event_type: 'CERT_EXPIRY_WARN',
          source: 'TLS Gateway',
          status: 'LOGGED',
          severity: 'LOW'
        }
      ];
      state.logs = demoLogs;
      renderEventStream(demoLogs, false);
    }
  }
}

/**
 * ==========================================================================
 * ACTIVE COMPOSITE INCIDENTS TABLE COMPONENT (PHASE 5)
 * ==========================================================================
 */

/**
 * Build a table row for an active composite incident
 * @param {Object} incident Incident data record
 * @returns {HTMLTableRowElement}
 */
function createIncidentRowElement(incident) {
  const tr = document.createElement('tr');
  tr.dataset.id = incident.id;
  tr.tabIndex = 0; // Accessible keyboard focus

  if (state.selectedIncidentId === incident.id) {
    tr.classList.add('selected-row');
  }

  // Column 1: ID
  const tdId = document.createElement('td');
  const spanId = document.createElement('span');
  spanId.className = 'table-id';
  spanId.textContent = incident.id || 'INC-???';
  tdId.appendChild(spanId);

  // Column 2: SOURCE IP
  const tdIp = document.createElement('td');
  const spanIp = document.createElement('span');
  spanIp.className = 'table-ip';
  spanIp.textContent = incident.source_ip || '0.0.0.0';
  tdIp.appendChild(spanIp);

  // Column 3: INCIDENT TYPE
  const tdType = document.createElement('td');
  tdType.textContent = incident.incident_type || 'UNKNOWN';
  tdType.style.fontWeight = '600';

  // Column 4: SIGNALS
  const tdSignals = document.createElement('td');
  const spanSignals = document.createElement('span');
  spanSignals.className = 'badge-signals';
  const sigCount = incident.signals_count ?? (Array.isArray(incident.signals) ? incident.signals.length : 1);
  spanSignals.textContent = `${sigCount} signal${sigCount === 1 ? '' : 's'}`;
  tdSignals.appendChild(spanSignals);

  // Column 5: SEVERITY (Red Critical, Orange High, Yellow Medium, Green Low)
  const tdSev = document.createElement('td');
  const sevKey = (incident.severity || 'LOW').toUpperCase();
  const spanSev = document.createElement('span');
  spanSev.className = `badge-sev badge-sev-${sevKey.toLowerCase()}`;
  spanSev.textContent = sevKey;
  tdSev.appendChild(spanSev);

  // Column 6: RISK SCORE
  const tdRisk = document.createElement('td');
  const spanRisk = document.createElement('span');
  spanRisk.className = 'table-score';
  spanRisk.textContent = incident.risk_score ?? '--';
  if ((incident.risk_score ?? 0) >= 80) spanRisk.classList.add('text-red');
  else if ((incident.risk_score ?? 0) >= 60) spanRisk.classList.add('text-orange');
  else if ((incident.risk_score ?? 0) >= 40) spanRisk.classList.add('text-yellow');
  else spanRisk.classList.add('text-green');
  tdRisk.appendChild(spanRisk);

  // Column 7: CONFIDENCE
  const tdConf = document.createElement('td');
  const spanConf = document.createElement('span');
  spanConf.className = 'table-conf';
  spanConf.textContent = typeof incident.confidence === 'number' ? `${incident.confidence}%` : (incident.confidence || '--');
  tdConf.appendChild(spanConf);

  // Column 8: STATUS
  const tdStatus = document.createElement('td');
  const statusKey = (incident.status || 'OPEN').toUpperCase();
  const spanStatus = document.createElement('span');
  spanStatus.className = `badge-status status-${statusKey.toLowerCase()}`;
  spanStatus.textContent = statusKey;
  tdStatus.appendChild(spanStatus);

  // Column 9: ACTION
  const tdAction = document.createElement('td');
  const btnAction = document.createElement('button');
  btnAction.type = 'button';
  btnAction.className = 'btn-action-view';
  btnAction.textContent = 'INVESTIGATE';
  btnAction.setAttribute('aria-label', `Investigate incident ${incident.id}`);
  
  btnAction.addEventListener('click', (e) => {
    e.stopPropagation();
    selectIncident(incident, true);
  });
  tdAction.appendChild(btnAction);

  // Assemble cells
  tr.appendChild(tdId);
  tr.appendChild(tdIp);
  tr.appendChild(tdType);
  tr.appendChild(tdSignals);
  tr.appendChild(tdSev);
  tr.appendChild(tdRisk);
  tr.appendChild(tdConf);
  tr.appendChild(tdStatus);
  tr.appendChild(tdAction);

  // Row selection listeners
  tr.addEventListener('click', () => selectIncident(incident, false));
  tr.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      selectIncident(incident, false);
    }
  });

  return tr;
}

/**
 * Render the Active Composite Incidents Table
 * @param {Array} incidents Array of composite incident objects
 */
function renderIncidentsTable(incidents) {
  const tbody = document.getElementById('incidents-table-body');
  if (!tbody) return;

  if (!incidents || incidents.length === 0) {
    tbody.innerHTML = `
      <tr class="table-empty-row">
        <td colspan="9" class="text-center">No active composite incidents loaded.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = '';
  incidents.forEach(incident => {
    const tr = createIncidentRowElement(incident);
    tbody.appendChild(tr);
  });

  // Default select first incident if none selected
  if (!state.selectedIncidentId && incidents.length > 0) {
    selectIncident(incidents[0], false);
  }
}

/**
 * Select an incident to populate the dossier and highlight the row
 * @param {Object} incident Incident object
 * @param {boolean} triggerModalOpen Whether this action explicitly requests modal opening
 */
function selectIncident(incident, triggerModalOpen = false) {
  if (!incident) return;
  state.selectedIncidentId = incident.id;
  state.selectedIncident = incident;

  // Update visual selection across table rows
  const rows = document.querySelectorAll('#incidents-table-body tr');
  rows.forEach(row => {
    if (row.dataset.id === incident.id) {
      row.classList.add('selected-row');
    } else {
      row.classList.remove('selected-row');
    }
  });

  console.log(`[SOC-FUSION] Incident selected: ${incident.id} (${incident.incident_type})`);

  // Dispatch custom event for modular consumption by subsequent phases
  document.dispatchEvent(new CustomEvent('soc:incident-selected', {
    detail: { incident, triggerModalOpen }
  }));
}

/**
 * Fetch incidents from backend API or provide demo data fallback
 */
async function fetchIncidents() {
  try {
    const response = await fetch(API_CONFIG.ENDPOINTS.INCIDENTS);
    if (!response.ok) throw new Error(`HTTP ${response.status}: Failed to fetch /api/incidents`);
    const data = await response.json();
    const incidents = Array.isArray(data) ? data : (data.incidents || []);
    state.incidents = incidents;
    renderIncidentsTable(incidents);
    hideOfflineAlert();
  } catch (error) {
    if (state.incidents.length === 0) {
      const demoIncidents = [
        {
          id: 'INC-001',
          source_ip: '192.168.1.50',
          incident_type: 'MULTI-STAGE ATTACK',
          signals_count: 3,
          signals: ['PORT_SCAN', 'FAILED_LOGIN', 'TRAFFIC_SPIKE'],
          severity: 'CRITICAL',
          risk_score: 92,
          confidence: 94,
          status: 'OPEN',
          first_seen: '10:31:12',
          last_seen: '10:31:21',
          reasons: [
            'Port scanning detected',
            'Multiple failed login attempts detected',
            'Traffic spike detected',
            'Same source IP',
            'Events occurred within correlation window'
          ],
          progression: ['Reconnaissance', 'Brute Force', 'Possible Exfiltration'],
          recommended_action: 'Investigate source host immediately. Isolate host if traffic exceeds threshold.'
        },
        {
          id: 'INC-004',
          source_ip: '10.0.12.8',
          incident_type: 'CREDENTIAL STUFFING',
          signals_count: 4,
          signals: ['AUTH_BURST', 'INVALID_USER_SURGE', 'DISTRIBUTED_PROXY'],
          severity: 'CRITICAL',
          risk_score: 88,
          confidence: 91,
          status: 'INVESTIGATING',
          first_seen: '10:28:40',
          last_seen: '10:31:05',
          reasons: [
            'Surge of 40+ failed auth attempts within 10s',
            'Multiple account targets from single subnet',
            'Behavior matches automated Hydra spray tool'
          ],
          progression: ['Account Enumeration', 'Credential Stuffing', 'Target Takeover Attempt'],
          recommended_action: 'Enforce MFA lock and rate limit source subnet.'
        },
        {
          id: 'INC-007',
          source_ip: '172.16.4.19',
          incident_type: 'DATA EXFILTRATION ATTEMPT',
          signals_count: 2,
          signals: ['LARGE_OUTBOUND_CONN', 'UNUSUAL_PORT_EGRESS'],
          severity: 'HIGH',
          risk_score: 76,
          confidence: 85,
          status: 'OPEN',
          first_seen: '10:25:10',
          last_seen: '10:29:45',
          reasons: [
            'Outbound byte volume exceeds 99th percentile baseline',
            'Encrypted traffic to unclassified external IP'
          ],
          progression: ['Internal Discovery', 'Staging', 'Exfiltration Trigger'],
          recommended_action: 'Terminate egress socket and capture packet dumps.'
        },
        {
          id: 'INC-009',
          source_ip: '192.168.2.105',
          incident_type: 'RECONNAISSANCE SCAN',
          signals_count: 2,
          signals: ['SYN_SCAN', 'ICMP_SWEEP'],
          severity: 'HIGH',
          risk_score: 70,
          confidence: 82,
          status: 'ASSIGNED',
          first_seen: '10:20:15',
          last_seen: '10:27:00',
          reasons: [
            'Horizontal network sweep across ports 22, 80, 443, 3389',
            'High volume of half-open TCP handshakes'
          ],
          progression: ['Host Discovery', 'Port Enumeration', 'Service Probing'],
          recommended_action: 'Block source IP at boundary firewall.'
        },
        {
          id: 'INC-011',
          source_ip: '10.200.5.44',
          incident_type: 'ANOMALOUS API BURST',
          signals_count: 1,
          signals: ['RATE_LIMIT_EXCEEDED'],
          severity: 'MEDIUM',
          risk_score: 48,
          confidence: 68,
          status: 'OPEN',
          first_seen: '10:15:00',
          last_seen: '10:22:30',
          reasons: [
            'API token consumption rate spiked beyond normal profile'
          ],
          progression: ['Token Access', 'API Scrubbing'],
          recommended_action: 'Review API token usage and rotate secret key.'
        }
      ];
      state.incidents = demoIncidents;
      renderIncidentsTable(demoIncidents);
    }
  }
}

async function fetchStats() {
  try {
    const response = await fetch(API_CONFIG.ENDPOINTS.STATS);
    if (!response.ok) throw new Error(`HTTP ${response.status}: Failed to fetch /api/stats`);
    const data = await response.json();
    state.stats = data;
    renderSummaryCards(state.stats);
    hideOfflineAlert();
  } catch (error) {
    if (state.stats.total_events === 0) {
      const demoStats = {
        total_events: 12540,
        signals_detected: 326,
        active_incidents: 27,
        critical_incidents: 4,
        trends: {
          events: '+14% vs last hour',
          signals: '94% correlation rate',
          incidents: 'Capacity 3/3 active',
          critical: '4 require immediate SOC action'
        }
      };
      state.stats = demoStats;
      renderSummaryCards(demoStats);
    }
  }
}

function initClock() {
  const clockEl = document.getElementById('clock-display');
  const update = () => {
    if (clockEl) {
      const now = new Date();
      clockEl.textContent = now.toTimeString().split(' ')[0];
    }
  };
  update();
  setInterval(update, 1000);
}

function showOfflineAlert() {
  const alertEl = document.getElementById('offline-alert');
  const statusEl = document.getElementById('system-status-indicator');
  const statusText = document.getElementById('system-status-text');
  if (alertEl) alertEl.classList.remove('hidden');
  if (statusEl) {
    statusEl.classList.remove('online');
    statusEl.classList.add('offline');
  }
  if (statusText) statusText.textContent = 'SYSTEM OFFLINE';
}

function hideOfflineAlert() {
  const alertEl = document.getElementById('offline-alert');
  const statusEl = document.getElementById('system-status-indicator');
  const statusText = document.getElementById('system-status-text');
  if (alertEl) alertEl.classList.add('hidden');
  if (statusEl) {
    statusEl.classList.remove('offline');
    statusEl.classList.add('online');
  }
  if (statusText) statusText.textContent = 'SYSTEM ONLINE';
}

// Global debug & test API exposed to window for automated testing and interaction
window.socDashboard = {
  updateStats: (customStats) => {
    state.stats = { ...state.stats, ...customStats };
    renderSummaryCards(state.stats);
    return state.stats;
  },
  pushEvent: (eventData) => {
    const newEvent = {
      id: Date.now(),
      timestamp: eventData.timestamp || new Date().toTimeString().split(' ')[0],
      source_ip: eventData.source_ip || '192.168.1.50',
      event_type: eventData.event_type || 'TRAFFIC_SPIKE',
      source: eventData.source || 'Network Monitor',
      status: eventData.status || 'DETECTED',
      severity: eventData.severity || getSeverityForEvent(eventData.event_type)
    };
    renderEventStream([newEvent], true);
    state.stats.total_events = (state.stats.total_events || 0) + 1;
    renderSummaryCards(state.stats);
    return newEvent;
  },
  selectIncident: (id) => {
    const target = state.incidents.find(inc => inc.id === id);
    if (target) selectIncident(target, true);
    return target;
  },
  addIncident: (incidentData) => {
    state.incidents.unshift(incidentData);
    renderIncidentsTable(state.incidents);
    return incidentData;
  },
  getState: () => state
};

// Boot initialization on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  console.log('[SOC-FUSION] Initializing Phase 5: Active Composite Incidents Table...');
  initClock();
  fetchStats();
  fetchLogs();
  fetchIncidents();

  // Periodic polling (every 3 seconds) for live telemetry, events, and incidents
  setInterval(() => {
    fetchStats();
    fetchLogs();
    fetchIncidents();
  }, API_CONFIG.POLL_INTERVAL_MS);

  const retryBtn = document.getElementById('btn-retry-connection');
  if (retryBtn) {
    retryBtn.addEventListener('click', () => {
      fetchStats();
      fetchLogs();
      fetchIncidents();
    });
  }
});
