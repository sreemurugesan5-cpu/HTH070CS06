/**
 * ==========================================================================
 * SOC-FUSION — Signal-Fused Intrusion Detection & Response Dashboard
 * Phase 10: Security Analytics & Dynamic Chart.js Telemetry
 * ==========================================================================
 */

// Central API Configuration
const API_BASE = (window.location.port === '5000')
  ? ''
  : (window.location.protocol === 'file:' || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || !window.location.port)
    ? 'http://localhost:5000'
    : '';

const API_CONFIG = {
  BASE_URL: API_BASE,
  ENDPOINTS: {
    STATS: `${API_BASE}/api/stats`,
    LOGS: `${API_BASE}/api/logs`,
    INCIDENTS: `${API_BASE}/api/incidents`,
    QUEUE: `${API_BASE}/api/queue`,
    START_SIMULATION: `${API_BASE}/api/start-simulation`
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
  queue: [],
  capacity: {
    active_analysts: 3,
    max_analysts: 3
  },
  isOnline: true,
  isSimulating: false,
  activeIpFilter: null
};

// Active Chart Instances Storage (prevents memory leakage and canvas resize bugs)
const charts = {
  eventsTimeline: null,
  severityBreakdown: null,
  signalTypes: null,
  topIps: null
};

const numberFormatter = new Intl.NumberFormat('en-US');

function formatNumber(value) {
  const num = Number(value);
  return isNaN(num) ? '0' : numberFormatter.format(num);
}

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

const renderSummaryStats = (...args) => renderSummaryCards(...args);

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

const createEventStreamElement = (...args) => createEventItemElement(...args);

function renderEventStream(logs, prependNew = false) {
  const container = document.getElementById('event-stream-container');
  const countBadge = document.getElementById('event-stream-count');
  if (!container) return;

  const filteredLogs = state.activeIpFilter
    ? (logs || []).filter(l => l.source_ip === state.activeIpFilter)
    : logs;

  if (!filteredLogs || filteredLogs.length === 0) {
    container.innerHTML = `
      <div class="cyber-empty-state stream-empty-state">
        <div class="empty-state-icon">📡</div>
        <div class="empty-state-title">${state.activeIpFilter ? 'NO EVENTS FOR THIS IP' : 'NO SECURITY EVENTS INGESTED'}</div>
        <div class="empty-state-desc">${state.activeIpFilter ? `No real-time telemetry matching host ${state.activeIpFilter}.` : 'The live event pipeline is awaiting telemetry ingest or attack simulation trigger.'}</div>
      </div>
    `;
    if (countBadge) countBadge.textContent = '0 Events';
    return;
  }

  const emptyPlaceholder = container.querySelector('.stream-empty-state, .cyber-empty-state, .event-skeleton-item');
  if (emptyPlaceholder) container.innerHTML = '';

  if (prependNew && !state.activeIpFilter) {
    for (let i = filteredLogs.length - 1; i >= 0; i--) {
      const log = filteredLogs[i];
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
    filteredLogs.forEach(log => {
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
    handleFetchSuccess();
  } catch (error) {
    handleFetchFailure(error);
    if (state.logs.length === 0) {
      const demoLogs = [
        { id: 103, timestamp: '10:31:16', source_ip: '192.168.1.50', event_type: 'TRAFFIC_SPIKE', source: 'Network Monitor', status: 'DETECTED', severity: 'HIGH' },
        { id: 102, timestamp: '10:31:14', source_ip: '192.168.1.50', event_type: 'FAILED_LOGIN', source: 'Authentication', status: 'DETECTED', severity: 'HIGH' },
        { id: 101, timestamp: '10:31:12', source_ip: '192.168.1.50', event_type: 'PORT_SCAN', source: 'Firewall', status: 'DETECTED', severity: 'MEDIUM' },
        { id: 100, timestamp: '10:30:52', source_ip: '10.0.8.22', event_type: 'DNS_TUNNEL_BURST', source: 'DPI Sensor', status: 'DETECTED', severity: 'MEDIUM' },
        { id: 99, timestamp: '10:30:35', source_ip: '172.16.0.4', event_type: 'CERT_EXPIRY_WARN', source: 'TLS Gateway', status: 'LOGGED', severity: 'LOW' }
      ];
      state.logs = demoLogs;
      renderEventStream(demoLogs, false);
    }
  }
}

/**
 * ==========================================================================
 * ACTIVE COMPOSITE INCIDENTS TABLE COMPONENT
 * ==========================================================================
 */
function createIncidentRowElement(incident) {
  const tr = document.createElement('tr');
  tr.dataset.id = incident.id;
  tr.tabIndex = 0;

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

  // Column 5: SEVERITY
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

  tr.appendChild(tdId);
  tr.appendChild(tdIp);
  tr.appendChild(tdType);
  tr.appendChild(tdSignals);
  tr.appendChild(tdSev);
  tr.appendChild(tdRisk);
  tr.appendChild(tdConf);
  tr.appendChild(tdStatus);
  tr.appendChild(tdAction);

  tr.addEventListener('click', () => selectIncident(incident, false));
  tr.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      selectIncident(incident, false);
    }
  });

  return tr;
}

function renderIncidentsTable(incidents) {
  const tbody = document.getElementById('incidents-table-body');
  if (!tbody) return;

  const filteredIncidents = state.activeIpFilter 
    ? (incidents || []).filter(i => i.source_ip === state.activeIpFilter)
    : incidents;

  if (!filteredIncidents || filteredIncidents.length === 0) {
    tbody.innerHTML = `
      <tr class="table-empty-row">
        <td colspan="9">
          <div class="empty-table-wrap cyber-empty-state">
            <div class="empty-state-icon">🛡️</div>
            <div class="empty-state-title">${state.activeIpFilter ? 'NO INCIDENTS FOR THIS IP' : 'NO COMPOSITE INCIDENTS DETECTED'}</div>
            <div class="empty-state-desc">${state.activeIpFilter ? `No composite security incidents recorded for host ${state.activeIpFilter}.` : 'Weak signals have not crossed the correlation threshold to form an incident dossier.'}</div>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = '';
  filteredIncidents.forEach(incident => {
    const tr = createIncidentRowElement(incident);
    tbody.appendChild(tr);
  });

  if (!state.selectedIncidentId && filteredIncidents.length > 0) {
    selectIncident(filteredIncidents[0], false);
  }

  // Update dynamic charts whenever incident data updates
  renderCharts();
}

function selectIncident(incident, triggerModalOpen = false) {
  if (!incident) return;
  state.selectedIncidentId = incident.id;
  state.selectedIncident = incident;

  const rows = document.querySelectorAll('#incidents-table-body tr');
  rows.forEach(row => {
    if (row.dataset.id === incident.id) {
      row.classList.add('selected-row');
    } else {
      row.classList.remove('selected-row');
    }
  });

  console.log(`[SOC-FUSION] Incident selected: ${incident.id} (${incident.incident_type})`);

  renderSignalFusionVisualizer(incident);
  renderAttackTimeline(incident);
  renderCharts();

  document.dispatchEvent(new CustomEvent('soc:incident-selected', {
    detail: { incident, triggerModalOpen }
  }));

  if (triggerModalOpen) {
    openIncidentModal(incident);
  }
}

/**
 * ==========================================================================
 * SIGNAL FUSION ENGINE VISUALIZATION
 * ==========================================================================
 */
function renderSignalFusionVisualizer(incident) {
  const container = document.getElementById('signal-fusion-visualizer');
  if (!container) return;

  if (!incident) {
    container.innerHTML = `
      <div class="cyber-empty-state fusion-empty-state">
        <div class="empty-state-icon">⚡</div>
        <div class="empty-state-title">SIGNAL FUSION MATRIX IDLE</div>
        <div class="empty-state-desc">Select an incident from the table or trigger simulation to trace signal correlation pathways.</div>
      </div>
    `;
    return;
  }

  container.innerHTML = '';

  const metaHeader = document.createElement('div');
  metaHeader.className = 'fusion-meta-header';
  
  const spanTarget = document.createElement('span');
  spanTarget.textContent = `TARGET: ${incident.source_ip || 'UNKNOWN'}`;
  
  const spanSep1 = document.createElement('span');
  spanSep1.textContent = '•';

  const spanId = document.createElement('span');
  spanId.textContent = `INCIDENT: ${incident.id}`;

  const spanSep2 = document.createElement('span');
  spanSep2.textContent = '•';

  const spanScore = document.createElement('span');
  spanScore.textContent = `RISK: ${incident.risk_score} (${incident.confidence}% CONF)`;
  if ((incident.risk_score ?? 0) >= 80) spanScore.classList.add('text-red');
  else if ((incident.risk_score ?? 0) >= 60) spanScore.classList.add('text-orange');
  else spanScore.classList.add('text-yellow');

  metaHeader.appendChild(spanTarget);
  metaHeader.appendChild(spanSep1);
  metaHeader.appendChild(spanId);
  metaHeader.appendChild(spanSep2);
  metaHeader.appendChild(spanScore);
  container.appendChild(metaHeader);

  const flowBox = document.createElement('div');
  flowBox.className = 'fusion-flow-box';

  const signals = Array.isArray(incident.signals) && incident.signals.length > 0 
    ? incident.signals 
    : ['PORT_SCAN', 'FAILED_LOGIN', 'TRAFFIC_SPIKE'];

  const signalIcons = {
    PORT_SCAN: '📡',
    SYN_SCAN: '📡',
    ICMP_SWEEP: '🔍',
    FAILED_LOGIN: '🔐',
    AUTH_BURST: '🔑',
    INVALID_USER_SURGE: '👤',
    DISTRIBUTED_PROXY: '🌐',
    TRAFFIC_SPIKE: '⚡',
    LARGE_OUTBOUND_CONN: '📤',
    UNUSUAL_PORT_EGRESS: '🚪',
    DNS_TUNNEL_BURST: '📡',
    RATE_LIMIT_EXCEEDED: '⏱️'
  };

  signals.forEach((sig, index) => {
    const node = document.createElement('div');
    node.className = 'fusion-node';

    const left = document.createElement('div');
    left.style.display = 'flex';
    left.style.alignItems = 'center';
    left.style.gap = '0.5rem';

    const icon = signalIcons[sig] || '⚠️';
    const title = document.createElement('span');
    title.className = 'fusion-node-title';
    title.textContent = `${icon} ${sig.replace(/_/g, ' ')}`;

    const tag = document.createElement('span');
    tag.className = 'fusion-signal-tag';
    tag.textContent = `Signal #${index + 1}`;

    left.appendChild(title);
    left.appendChild(tag);

    const ip = document.createElement('span');
    ip.className = 'fusion-node-ip';
    ip.textContent = incident.source_ip || '192.168.1.50';

    node.appendChild(left);
    node.appendChild(ip);
    flowBox.appendChild(node);

    const arrow = document.createElement('div');
    arrow.className = 'fusion-arrow';
    arrow.innerHTML = '&darr;';
    flowBox.appendChild(arrow);
  });

  const coreBox = document.createElement('div');
  coreBox.className = 'fusion-core-indicator';
  coreBox.innerHTML = `<span>⚡ SIGNAL FUSION ENGINE</span><span>•</span><span>TEMPORAL WINDOW: 60s</span>`;
  flowBox.appendChild(coreBox);

  const coreArrow = document.createElement('div');
  coreArrow.className = 'fusion-arrow';
  coreArrow.innerHTML = '&darr;';
  flowBox.appendChild(coreArrow);

  const sevKey = (incident.severity || 'LOW').toLowerCase();
  const compositeBox = document.createElement('div');
  compositeBox.className = `fusion-composite-box fusion-sev-${sevKey}`;

  const compMeta = document.createElement('div');
  compMeta.className = 'fusion-composite-meta';

  const compTitle = document.createElement('div');
  compTitle.className = 'fusion-composite-title';
  compTitle.textContent = `COMPOSITE INCIDENT: ${incident.incident_type || 'MULTI-STAGE ATTACK'}`;

  const compSub = document.createElement('div');
  compSub.className = 'fusion-composite-sub';
  compSub.textContent = `High-Confidence Correlation (${incident.confidence}% Conf • Risk Score: ${incident.risk_score})`;

  compMeta.appendChild(compTitle);
  compMeta.appendChild(compSub);

  const compBadge = document.createElement('span');
  compBadge.className = 'fusion-composite-badge';
  compBadge.textContent = (incident.severity || 'LOW').toUpperCase();

  compositeBox.appendChild(compMeta);
  compositeBox.appendChild(compBadge);

  flowBox.appendChild(compositeBox);
  container.appendChild(flowBox);
}

/**
 * ==========================================================================
 * ATTACK TIMELINE & PROGRESSION
 * ==========================================================================
 */
function renderAttackTimeline(incident) {
  const container = document.getElementById('attack-timeline-container');
  if (!container) return;

  if (!incident) {
    container.innerHTML = `
      <div class="cyber-empty-state timeline-empty-state">
        <div class="empty-state-icon">⏱️</div>
        <div class="empty-state-title">ATTACK TIMELINE INACTIVE</div>
        <div class="empty-state-desc">Correlated attack progression stages will render when an incident is active.</div>
      </div>
    `;
    return;
  }

  container.innerHTML = '';

  let timelineSteps = incident.timeline;
  if (!timelineSteps || timelineSteps.length === 0) {
    if (incident.id === 'INC-001') {
      timelineSteps = [
        { time: '10:31:12', event: 'PORT SCAN', ip: incident.source_ip, stage: 'Reconnaissance', type: 'stage-recon', sev: 'medium' },
        { time: '10:31:14', event: 'FAILED LOGIN', ip: incident.source_ip, stage: 'Initial Access', type: 'stage-access', sev: 'high' },
        { time: '10:31:16', event: 'FAILED LOGIN', ip: incident.source_ip, stage: 'Brute Force', type: 'stage-access', sev: 'high' },
        { time: '10:31:18', event: 'TRAFFIC SPIKE', ip: incident.source_ip, stage: 'Anomaly Detected', type: 'stage-anomaly', sev: 'high' },
        { time: '10:31:20', event: 'COMPOSITE INCIDENT', ip: incident.source_ip, stage: 'Signal Fusion', type: 'stage-escalation', sev: 'critical' },
        { time: '10:31:21', event: 'CRITICAL ESCALATION', ip: incident.source_ip, stage: 'SOC Priority #1', type: 'stage-escalation', sev: 'critical' }
      ];
    } else {
      timelineSteps = [];
      const signals = incident.signals || ['TELEMETRY_ANOMALY'];
      const baseTime = incident.first_seen || '10:20:00';
      
      signals.forEach((sig, i) => {
        timelineSteps.push({
          time: baseTime,
          event: sig.replace(/_/g, ' '),
          ip: incident.source_ip,
          stage: i === 0 ? 'Reconnaissance' : (i < signals.length - 1 ? 'Execution' : 'Pre-Exfiltration'),
          type: i === 0 ? 'stage-recon' : 'stage-anomaly',
          sev: (incident.severity || 'low').toLowerCase()
        });
      });

      timelineSteps.push({
        time: incident.last_seen || '10:30:00',
        event: `COMPOSITE INCIDENT (${incident.incident_type})`,
        ip: incident.source_ip,
        stage: 'Signal Fusion',
        type: 'stage-escalation',
        sev: (incident.severity || 'low').toLowerCase()
      });

      timelineSteps.push({
        time: incident.last_seen || '10:30:01',
        event: `${(incident.severity || 'CRITICAL').toUpperCase()} ESCALATION`,
        ip: incident.source_ip,
        stage: `Priority Queue (Risk ${incident.risk_score})`,
        type: 'stage-escalation',
        sev: (incident.severity || 'low').toLowerCase()
      });
    }
  }

  timelineSteps.forEach(step => {
    const node = document.createElement('div');
    const sevClass = (step.sev === 'critical') ? 'node-critical' : (step.sev === 'high') ? 'node-high' : 'node-medium';
    node.className = `timeline-node ${sevClass}`;

    const timeEl = document.createElement('span');
    timeEl.className = 'timeline-time';
    timeEl.textContent = step.time;

    const eventEl = document.createElement('span');
    eventEl.className = 'timeline-event';
    eventEl.textContent = step.event;

    const ipEl = document.createElement('span');
    ipEl.className = 'timeline-ip';
    ipEl.textContent = step.ip;

    const stageEl = document.createElement('span');
    stageEl.className = `timeline-stage ${step.type || 'stage-recon'}`;
    stageEl.textContent = step.stage;

    node.appendChild(timeEl);
    node.appendChild(eventEl);
    node.appendChild(ipEl);
    node.appendChild(stageEl);

    container.appendChild(node);
  });
}

/**
 * ==========================================================================
 * SOC RESPONSE QUEUE & CAPACITY COMPONENT
 * ==========================================================================
 */
function createQueueItemElement(item) {
  const card = document.createElement('div');
  const isWaiting = (item.status || '').toUpperCase() === 'WAITING';
  card.className = `queue-item${isWaiting ? ' queue-waiting' : ''}`;
  card.dataset.id = item.incident_id;

  const rankEl = document.createElement('div');
  rankEl.className = 'queue-rank';
  rankEl.textContent = `#${item.rank}`;

  const detailsEl = document.createElement('div');
  detailsEl.className = 'queue-details';

  const titleRow = document.createElement('div');
  titleRow.className = 'queue-title-row';

  const idSpan = document.createElement('span');
  idSpan.className = 'queue-id';
  idSpan.textContent = item.incident_id;

  const rightMeta = document.createElement('div');
  rightMeta.style.display = 'flex';
  rightMeta.style.alignItems = 'center';
  rightMeta.style.gap = '0.5rem';

  const sevKey = (item.severity || 'LOW').toLowerCase();
  const sevBadge = document.createElement('span');
  sevBadge.className = `badge-sev badge-sev-${sevKey}`;
  sevBadge.textContent = (item.severity || 'LOW').toUpperCase();

  const riskSpan = document.createElement('span');
  riskSpan.className = 'table-score';
  riskSpan.textContent = `Risk ${item.risk_score ?? '--'}`;
  if ((item.risk_score ?? 0) >= 80) riskSpan.classList.add('text-red');
  else if ((item.risk_score ?? 0) >= 60) riskSpan.classList.add('text-orange');
  else riskSpan.classList.add('text-yellow');

  rightMeta.appendChild(sevBadge);
  rightMeta.appendChild(riskSpan);

  titleRow.appendChild(idSpan);
  titleRow.appendChild(rightMeta);

  const metaRow = document.createElement('div');
  metaRow.className = 'queue-meta-row';

  const analystSpan = document.createElement('span');
  analystSpan.className = 'queue-analyst';
  analystSpan.textContent = item.analyst ? `👤 ${item.analyst}` : '— Unassigned';
  if (!item.analyst) analystSpan.style.color = 'var(--text-muted)';

  const statusChip = document.createElement('span');
  const statusKey = (item.status || 'WAITING').toLowerCase();
  statusChip.className = `queue-status-chip chip-${statusKey}`;
  statusChip.textContent = (item.status || 'WAITING').toUpperCase();

  metaRow.appendChild(analystSpan);
  metaRow.appendChild(statusChip);

  detailsEl.appendChild(titleRow);
  detailsEl.appendChild(metaRow);

  card.appendChild(rankEl);
  card.appendChild(detailsEl);

  card.addEventListener('click', () => {
    const matchingIncident = state.incidents.find(inc => inc.id === item.incident_id);
    if (matchingIncident) {
      selectIncident(matchingIncident, false);
    }
  });

  return card;
}

function renderResponseQueue(queueList, capacityInfo) {
  const container = document.getElementById('response-queue-container');
  const capText = document.getElementById('capacity-text');
  const capFill = document.getElementById('capacity-fill');
  const capSubtext = document.getElementById('capacity-subtext');

  const active = capacityInfo?.active_analysts ?? 3;
  const max = capacityInfo?.max_analysts ?? 3;
  const ratio = max > 0 ? (active / max) : 1;
  const percent = Math.min(100, Math.round(ratio * 100));

  if (capText) capText.textContent = `${active} / ${max} Active`;
  if (capFill) {
    capFill.style.width = `${percent}%`;
    if (percent >= 100) {
      capFill.style.background = 'linear-gradient(90deg, #f97316 0%, #ef4444 100%)';
    } else {
      capFill.style.background = 'linear-gradient(90deg, #10b981 0%, #eab308 70%, #ef4444 100%)';
    }
  }

  const waitingCount = (queueList || []).filter(item => (item.status || '').toUpperCase() === 'WAITING').length;
  if (capSubtext) {
    if (waitingCount > 0) {
      capSubtext.textContent = `⚠️ ${waitingCount} incident${waitingCount === 1 ? '' : 's'} WAITING (Capacity Saturation)`;
      capSubtext.style.color = 'var(--text-orange)';
    } else {
      capSubtext.textContent = 'Analyst bandwidth available';
      capSubtext.style.color = 'var(--text-green)';
    }
  }

  if (!container) return;

  if (!queueList || queueList.length === 0) {
    container.innerHTML = `
      <div class="cyber-empty-state queue-empty-state">
        <div class="empty-state-icon">📥</div>
        <div class="empty-state-title">RESPONSE QUEUE CLEAR</div>
        <div class="empty-state-desc">All escalated incidents have been resolved or assigned. Analyst bandwidth normal.</div>
      </div>
    `;
    return;
  }

  container.innerHTML = '';
  queueList.forEach(item => {
    const card = createQueueItemElement(item);
    container.appendChild(card);
  });
}

async function fetchQueue() {
  try {
    const response = await fetch(API_CONFIG.ENDPOINTS.QUEUE);
    if (!response.ok) throw new Error(`HTTP ${response.status}: Failed to fetch /api/queue`);
    const data = await response.json();
    state.queue = data.queue || (Array.isArray(data) ? data : []);
    state.capacity = data.capacity || state.capacity;
    renderResponseQueue(state.queue, state.capacity);
    handleFetchSuccess();
  } catch (error) {
    handleFetchFailure(error);
    if (state.queue.length === 0) {
      const demoQueue = [
        { rank: 1, incident_id: 'INC-001', severity: 'CRITICAL', risk_score: 92, analyst: 'Analyst A', status: 'INVESTIGATING' },
        { rank: 2, incident_id: 'INC-004', severity: 'CRITICAL', risk_score: 88, analyst: 'Analyst B', status: 'ASSIGNED' },
        { rank: 3, incident_id: 'INC-007', severity: 'HIGH', risk_score: 76, analyst: 'Analyst C', status: 'ASSIGNED' },
        { rank: 4, incident_id: 'INC-009', severity: 'HIGH', risk_score: 70, analyst: null, status: 'WAITING' },
        { rank: 5, incident_id: 'INC-011', severity: 'MEDIUM', risk_score: 48, analyst: null, status: 'WAITING' }
      ];
      const demoCapacity = { active_analysts: 3, max_analysts: 3 };
      state.queue = demoQueue;
      state.capacity = demoCapacity;
      renderResponseQueue(demoQueue, demoCapacity);
    }
  }
}

async function fetchIncidents() {
  try {
    const response = await fetch(API_CONFIG.ENDPOINTS.INCIDENTS);
    if (!response.ok) throw new Error(`HTTP ${response.status}: Failed to fetch /api/incidents`);
    const data = await response.json();
    const incidents = Array.isArray(data) ? data : (data.incidents || []);
    state.incidents = incidents;
    renderIncidentsTable(incidents);
    handleFetchSuccess();
  } catch (error) {
    handleFetchFailure(error);
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
          recommended_action: 'Investigate source host immediately. Isolate host if traffic exceeds threshold.',
          timeline: [
            { time: '10:31:12', event: 'PORT SCAN', ip: '192.168.1.50', stage: 'Reconnaissance', type: 'stage-recon', sev: 'medium' },
            { time: '10:31:14', event: 'FAILED LOGIN', ip: '192.168.1.50', stage: 'Initial Access', type: 'stage-access', sev: 'high' },
            { time: '10:31:16', event: 'FAILED LOGIN', ip: '192.168.1.50', stage: 'Brute Force', type: 'stage-access', sev: 'high' },
            { time: '10:31:18', event: 'TRAFFIC SPIKE', ip: '192.168.1.50', stage: 'Anomaly Detected', type: 'stage-anomaly', sev: 'high' },
            { time: '10:31:20', event: 'COMPOSITE INCIDENT', ip: '192.168.1.50', stage: 'Signal Fusion', type: 'stage-escalation', sev: 'critical' },
            { time: '10:31:21', event: 'CRITICAL ESCALATION', ip: '192.168.1.50', stage: 'SOC Priority #1', type: 'stage-escalation', sev: 'critical' }
          ]
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
          recommended_action: 'Enforce MFA lock and rate limit source subnet.',
          timeline: [
            { time: '10:28:40', event: 'AUTH BURST', ip: '10.0.12.8', stage: 'Enumeration', type: 'stage-recon', sev: 'high' },
            { time: '10:29:15', event: 'INVALID USER SURGE', ip: '10.0.12.8', stage: 'Credential Stuffing', type: 'stage-access', sev: 'high' },
            { time: '10:30:10', event: 'DISTRIBUTED PROXY', ip: '10.0.12.8', stage: 'Proxy Evasion', type: 'stage-anomaly', sev: 'high' },
            { time: '10:31:05', event: 'CRITICAL ESCALATION', ip: '10.0.12.8', stage: 'SOC Priority #2', type: 'stage-escalation', sev: 'critical' }
          ]
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
          recommended_action: 'Terminate egress socket and capture packet dumps.',
          timeline: [
            { time: '10:25:10', event: 'INTERNAL DISCOVERY', ip: '172.16.4.19', stage: 'Reconnaissance', type: 'stage-recon', sev: 'medium' },
            { time: '10:27:30', event: 'LARGE OUTBOUND CONN', ip: '172.16.4.19', stage: 'Staging', type: 'stage-anomaly', sev: 'high' },
            { time: '10:29:45', event: 'UNUSUAL PORT EGRESS', ip: '172.16.4.19', stage: 'Exfiltration Trigger', type: 'stage-anomaly', sev: 'high' },
            { time: '10:29:50', event: 'HIGH ESCALATION', ip: '172.16.4.19', stage: 'SOC Priority #3', type: 'stage-escalation', sev: 'high' }
          ]
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

/**
 * ==========================================================================
 * SECURITY ANALYTICS CHARTS (PHASE 10)
 * ==========================================================================
 */

/**
 * Configure global Chart.js dark cybersecurity theme defaults
 */
function applyChartThemeDefaults() {
  if (typeof Chart === 'undefined') return;

  Chart.defaults.color = '#94a3b8';
  Chart.defaults.font.family = "'JetBrains Mono', 'Inter', monospace";
  Chart.defaults.font.size = 11;
  Chart.defaults.responsive = true;
  Chart.defaults.maintainAspectRatio = false;

  // Tooltip defaults
  Chart.defaults.plugins.tooltip.backgroundColor = '#0b1120';
  Chart.defaults.plugins.tooltip.borderColor = 'rgba(56, 189, 248, 0.4)';
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.padding = 10;
  Chart.defaults.plugins.tooltip.cornerRadius = 6;
  Chart.defaults.plugins.tooltip.titleColor = '#ffffff';
  Chart.defaults.plugins.tooltip.bodyColor = '#38bdf8';
}

/**
 * Initialize or update the 4 Security Analytics Charts
 */
function renderCharts() {
  if (typeof Chart === 'undefined') {
    console.warn('[SOC-FUSION] Chart.js library not yet loaded. Retrying in 200ms...');
    setTimeout(renderCharts, 200);
    return;
  }

  applyChartThemeDefaults();

  // Active target IP context: either explicit filter or selected incident IP
  const activeIp = state.activeIpFilter || (state.selectedIncident ? state.selectedIncident.source_ip : null);

  // Helper to generate pseudo-hash from string for consistent custom IP metrics
  function getIpSeed(ip) {
    if (!ip) return 42;
    let hash = 0;
    for (let i = 0; i < ip.length; i++) {
      hash = (hash << 5) - hash + ip.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash);
  }

  // Known IP telemetry profiles
  const ipProfiles = {
    '192.168.1.50': {
      risk: 92,
      timeline: [85, 210, 390, 580, 840, 960, 820],
      signals: { 'FAILED_LOGIN': 180, 'PORT_SCAN': 120, 'TRAFFIC_SPIKE': 45, 'AUTH_BURST': 30, 'SYN_SCAN': 22 },
      severity: [3, 1, 0, 0] // Critical: 3, High: 1, Med: 0, Low: 0
    },
    '10.0.12.8': {
      risk: 88,
      timeline: [40, 90, 160, 320, 510, 680, 610],
      signals: { 'SQL_INJECTION': 95, 'AUTH_BURST': 65, 'INVALID_USER': 42, 'DATA_TRANSFER': 28, 'TRAFFIC_SPIKE': 15 },
      severity: [2, 2, 0, 0]
    },
    '172.16.4.19': {
      risk: 76,
      timeline: [90, 95, 88, 180, 340, 420, 260],
      signals: { 'DNS_TUNNEL': 110, 'C2_BEACON': 85, 'OUTBOUND_CONN': 50, 'PORT_SCAN': 25, 'TRAFFIC_SPIKE': 12 },
      severity: [0, 3, 1, 0]
    },
    '192.168.2.105': {
      risk: 70,
      timeline: [20, 35, 60, 110, 190, 175, 140],
      signals: { 'LATERAL_MOVE': 65, 'SMB_BURST': 40, 'PORT_SCAN': 30, 'FAILED_LOGIN': 20, 'DNS_QUERY': 15 },
      severity: [0, 1, 3, 0]
    },
    '10.200.5.44': {
      risk: 48,
      timeline: [10, 15, 12, 25, 30, 22, 18],
      signals: { 'DNS_QUERY': 45, 'HTTP_GET': 32, 'TLS_HANDSHAKE': 20, 'TRAFFIC_SPIKE': 8, 'PORT_SCAN': 5 },
      severity: [0, 0, 2, 2]
    }
  };

  // 1. CHART: EVENTS OVER TIME (Line / Area)
  const ctxTimeline = document.getElementById('chart-events-timeline');
  if (ctxTimeline) {
    const timelineLabels = ['10:20', '10:22', '10:24', '10:26', '10:28', '10:30', '10:32'];
    let timelineData;
    let timelineLabelName;

    if (activeIp && ipProfiles[activeIp]) {
      timelineData = [...ipProfiles[activeIp].timeline];
      timelineLabelName = `Events / Min (${activeIp})`;
    } else if (activeIp) {
      const seed = getIpSeed(activeIp);
      const base = (seed % 30) + 10;
      const peak = base * ((seed % 5) + 3);
      timelineData = [
        base,
        Math.floor(base * 1.5),
        Math.floor(base * 2.2),
        Math.floor(peak * 0.7),
        peak,
        Math.floor(peak * 0.85),
        Math.floor(base * 1.8)
      ];
      timelineLabelName = `Events / Min (${activeIp})`;
    } else {
      timelineData = [120, 185, 140, 290, 410, 680, 520];
      timelineLabelName = 'All Host Events / Min';
    }

    if (charts.eventsTimeline) {
      charts.eventsTimeline.data.datasets[0].label = timelineLabelName;
      charts.eventsTimeline.data.datasets[0].data = timelineData;
      charts.eventsTimeline.data.datasets[0].borderColor = activeIp ? '#00d2ff' : '#38bdf8';
      charts.eventsTimeline.update();
    } else {
      charts.eventsTimeline = new Chart(ctxTimeline, {
        type: 'line',
        data: {
          labels: timelineLabels,
          datasets: [{
            label: timelineLabelName,
            data: timelineData,
            borderColor: activeIp ? '#00d2ff' : '#38bdf8',
            backgroundColor: 'rgba(56, 189, 248, 0.12)',
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            pointBackgroundColor: '#00d2ff',
            pointBorderColor: '#0b1120',
            pointRadius: 4,
            pointHoverRadius: 6
          }]
        },
        options: {
          scales: {
            x: {
              grid: { color: 'rgba(56, 189, 248, 0.06)' },
              ticks: { color: '#94a3b8' }
            },
            y: {
              grid: { color: 'rgba(56, 189, 248, 0.06)' },
              ticks: { color: '#94a3b8' },
              beginAtZero: true
            }
          },
          plugins: {
            legend: { 
              display: !!activeIp,
              labels: { color: '#38bdf8', font: { size: 10 } }
            }
          }
        }
      });
    }
  }

  // 2. CHART: INCIDENTS BY SEVERITY (Doughnut)
  const ctxSeverity = document.getElementById('chart-severity-breakdown');
  if (ctxSeverity) {
    let severityData;
    if (activeIp && ipProfiles[activeIp]) {
      severityData = [...ipProfiles[activeIp].severity];
    } else if (activeIp) {
      const seed = getIpSeed(activeIp);
      const isHigh = (seed % 2 === 0);
      severityData = isHigh ? [1, 2, 1, 0] : [0, 1, 2, 2];
    } else {
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;

      (state.incidents || []).forEach(inc => {
        const sev = (inc.severity || '').toUpperCase();
        if (sev === 'CRITICAL') criticalCount++;
        else if (sev === 'HIGH') highCount++;
        else if (sev === 'MEDIUM') mediumCount++;
        else lowCount++;
      });

      if (criticalCount + highCount + mediumCount + lowCount === 0) {
        criticalCount = 2; highCount = 2; mediumCount = 1; lowCount = 0;
      }
      severityData = [criticalCount, highCount, mediumCount, lowCount];
    }

    if (charts.severityBreakdown) {
      charts.severityBreakdown.data.datasets[0].data = severityData;
      charts.severityBreakdown.update();
    } else {
      charts.severityBreakdown = new Chart(ctxSeverity, {
        type: 'doughnut',
        data: {
          labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
          datasets: [{
            data: severityData,
            backgroundColor: [
              '#ef4444', // Red Critical
              '#f97316', // Orange High
              '#eab308', // Yellow Medium
              '#10b981'  // Green Low
            ],
            borderColor: '#0b1120',
            borderWidth: 2,
            hoverOffset: 6
          }]
        },
        options: {
          cutout: '68%',
          plugins: {
            legend: {
              position: 'right',
              labels: {
                boxWidth: 12,
                padding: 12,
                color: '#94a3b8',
                font: { size: 10 }
              }
            }
          }
        }
      });
    }
  }

  // 3. CHART: SIGNAL TYPES DISTRIBUTION (Horizontal Bar)
  const ctxSignals = document.getElementById('chart-signal-types');
  if (ctxSignals) {
    let signalLabels;
    let signalCounts;

    if (activeIp && ipProfiles[activeIp]) {
      const sigs = ipProfiles[activeIp].signals;
      signalLabels = Object.keys(sigs);
      signalCounts = Object.values(sigs);
    } else if (activeIp) {
      const seed = getIpSeed(activeIp);
      signalLabels = ['FAILED_LOGIN', 'PORT_SCAN', 'DNS_QUERY', 'TRAFFIC_SPIKE', 'TLS_PROBE'];
      signalCounts = [
        (seed % 40) + 15,
        (seed % 30) + 10,
        (seed % 50) + 20,
        (seed % 25) + 5,
        (seed % 15) + 3
      ];
    } else {
      signalLabels = ['FAILED_LOGIN', 'PORT_SCAN', 'TRAFFIC_SPIKE', 'DNS_QUERY', 'DATA_TRANSFER'];
      signalCounts = [215, 124, 42, 35, 18];
    }

    if (charts.signalTypes) {
      charts.signalTypes.data.labels = signalLabels;
      charts.signalTypes.data.datasets[0].label = activeIp ? `Signals (${activeIp})` : 'Global Signal Count';
      charts.signalTypes.data.datasets[0].data = signalCounts;
      charts.signalTypes.update();
    } else {
      charts.signalTypes = new Chart(ctxSignals, {
        type: 'bar',
        data: {
          labels: signalLabels,
          datasets: [{
            label: activeIp ? `Signals (${activeIp})` : 'Signal Count',
            data: signalCounts,
            backgroundColor: 'rgba(0, 210, 255, 0.75)',
            borderColor: '#00d2ff',
            borderWidth: 1,
            borderRadius: 4
          }]
        },
        options: {
          indexAxis: 'y',
          scales: {
            x: {
              grid: { color: 'rgba(56, 189, 248, 0.06)' },
              ticks: { color: '#94a3b8' },
              beginAtZero: true
            },
            y: {
              grid: { display: false },
              ticks: { color: '#94a3b8', font: { size: 10 } }
            }
          },
          plugins: {
            legend: { display: false }
          }
        }
      });
    }
  }

  // 4. CHART: TOP SOURCE IPS (Vertical Bar)
  const ctxTopIps = document.getElementById('chart-top-ips');
  if (ctxTopIps) {
    let baseIps = ['192.168.1.50', '10.0.12.8', '172.16.4.19', '192.168.2.105', '10.200.5.44'];
    let baseScores = [92, 88, 76, 70, 48];

    // If active IP is not in base list, include it!
    if (activeIp && !baseIps.includes(activeIp)) {
      const calculatedRisk = (getIpSeed(activeIp) % 65) + 30;
      baseIps = [activeIp, ...baseIps.slice(0, 4)];
      baseScores = [calculatedRisk, ...baseScores.slice(0, 4)];
    }

    // Dynamic coloring: highlight active IP in neon cyan `#00d2ff`
    const bgColors = baseIps.map(ip => {
      if (activeIp && ip === activeIp) {
        return '#00d2ff'; // Active neon cyan highlight!
      }
      const score = baseScores[baseIps.indexOf(ip)];
      if (score >= 80) return 'rgba(239, 68, 68, 0.75)';
      if (score >= 60) return 'rgba(249, 115, 22, 0.75)';
      return 'rgba(234, 179, 8, 0.75)';
    });

    const borderColors = baseIps.map(ip => {
      return (activeIp && ip === activeIp) ? '#ffffff' : 'rgba(56, 189, 248, 0.3)';
    });

    const borderWidths = baseIps.map(ip => {
      return (activeIp && ip === activeIp) ? 2 : 1;
    });

    if (charts.topIps) {
      charts.topIps.data.labels = baseIps;
      charts.topIps.data.datasets[0].data = baseScores;
      charts.topIps.data.datasets[0].backgroundColor = bgColors;
      charts.topIps.data.datasets[0].borderColor = borderColors;
      charts.topIps.data.datasets[0].borderWidth = borderWidths;
      charts.topIps.update();
    } else {
      charts.topIps = new Chart(ctxTopIps, {
        type: 'bar',
        data: {
          labels: baseIps,
          datasets: [{
            label: 'Risk Score',
            data: baseScores,
            backgroundColor: bgColors,
            borderColor: borderColors,
            borderWidth: borderWidths,
            borderRadius: 4
          }]
        },
        options: {
          scales: {
            x: {
              grid: { display: false },
              ticks: { color: '#94a3b8', font: { size: 10 } }
            },
            y: {
              grid: { color: 'rgba(56, 189, 248, 0.06)' },
              ticks: { color: '#94a3b8' },
              beginAtZero: true,
              max: 100
            }
          },
          plugins: {
            legend: { display: false }
          }
        }
      });
    }
  }
}

/**
 * ==========================================================================
 * INCIDENT DETAILS MODAL / INVESTIGATION DOSSIER
 * ==========================================================================
 */
function openIncidentModal(incident) {
  if (!incident) return;

  const modalEl = document.getElementById('incident-modal');
  if (!modalEl) return;

  const titleEl = document.getElementById('modal-incident-title');
  if (titleEl) titleEl.textContent = `INCIDENT INVESTIGATION DOSSIER — ${incident.id}`;

  const idEl = document.getElementById('modal-incident-id');
  const ipEl = document.getElementById('modal-source-ip');
  const typeEl = document.getElementById('modal-incident-type');
  const sevEl = document.getElementById('modal-severity');
  const riskEl = document.getElementById('modal-risk-score');
  const confEl = document.getElementById('modal-confidence');
  const firstSeenEl = document.getElementById('modal-first-seen');
  const lastSeenEl = document.getElementById('modal-last-seen');
  const statusEl = document.getElementById('modal-status');

  if (idEl) idEl.textContent = incident.id || '--';
  if (ipEl) ipEl.textContent = incident.source_ip || '--';
  if (typeEl) typeEl.textContent = incident.incident_type || '--';

  if (sevEl) {
    sevEl.innerHTML = '';
    const sevKey = (incident.severity || 'LOW').toUpperCase();
    const spanSev = document.createElement('span');
    spanSev.className = `badge-sev badge-sev-${sevKey.toLowerCase()}`;
    spanSev.textContent = sevKey;
    sevEl.appendChild(spanSev);
  }

  if (riskEl) {
    riskEl.textContent = incident.risk_score ?? '--';
    riskEl.className = 'meta-value';
    if ((incident.risk_score ?? 0) >= 80) riskEl.classList.add('text-red');
    else if ((incident.risk_score ?? 0) >= 60) riskEl.classList.add('text-orange');
    else if ((incident.risk_score ?? 0) >= 40) riskEl.classList.add('text-yellow');
    else riskEl.classList.add('text-green');
  }

  if (confEl) {
    confEl.textContent = typeof incident.confidence === 'number' ? `${incident.confidence}%` : (incident.confidence || '--');
  }

  if (firstSeenEl) firstSeenEl.textContent = incident.first_seen || '10:31:12';
  if (lastSeenEl) lastSeenEl.textContent = incident.last_seen || '10:31:21';

  if (statusEl) {
    statusEl.innerHTML = '';
    const statusKey = (incident.status || 'OPEN').toUpperCase();
    const spanStatus = document.createElement('span');
    spanStatus.className = `badge-status status-${statusKey.toLowerCase()}`;
    spanStatus.textContent = statusKey;
    statusEl.appendChild(spanStatus);
  }

  const reasonsListEl = document.getElementById('modal-creation-reasons');
  if (reasonsListEl) {
    reasonsListEl.innerHTML = '';
    const reasons = incident.reasons || [
      'Multiple correlated signals detected from the same source IP',
      'Port scanning reconnaissance behavior confirmed',
      'Telemetry events occurred within correlation window'
    ];
    reasons.forEach(reason => {
      const li = document.createElement('li');
      li.textContent = reason;
      reasonsListEl.appendChild(li);
    });
  }

  const progressionEl = document.getElementById('modal-attack-progression');
  if (progressionEl) {
    progressionEl.innerHTML = '';
    const steps = incident.progression || ['Reconnaissance', 'Brute Force', 'Possible Exfiltration'];
    steps.forEach((step, index) => {
      const stepSpan = document.createElement('span');
      stepSpan.className = 'progression-step';
      stepSpan.textContent = step;
      progressionEl.appendChild(stepSpan);

      if (index < steps.length - 1) {
        const arrowSpan = document.createElement('span');
        arrowSpan.className = 'progression-arrow';
        arrowSpan.innerHTML = '&rarr;';
        progressionEl.appendChild(arrowSpan);
      }
    });
  }

  const actionEl = document.getElementById('modal-recommended-action');
  if (actionEl) {
    actionEl.textContent = incident.recommended_action || 'Investigate source host immediately. Isolate host if traffic exceeds threshold.';
  }

  modalEl.classList.remove('hidden');
  modalEl.setAttribute('aria-hidden', 'false');
}

function closeIncidentModal() {
  const modalEl = document.getElementById('incident-modal');
  if (modalEl) {
    modalEl.classList.add('hidden');
    modalEl.setAttribute('aria-hidden', 'true');
  }
}

async function updateIncidentStatus(newStatus) {
  if (!state.selectedIncident) return;
  const incidentId = state.selectedIncident.id;

  try {
    const endpoint = `${API_CONFIG.BASE_URL}/api/incidents/${encodeURIComponent(incidentId)}/${newStatus.toLowerCase()}`;
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
  } catch (err) {
    console.warn(`[SOC-FUSION] Live backend endpoint unavailable for ${newStatus}. Updating state locally for preview.`);
  }

  state.selectedIncident.status = newStatus;
  const idx = state.incidents.findIndex(inc => inc.id === incidentId);
  if (idx !== -1) {
    state.incidents[idx].status = newStatus;
  }

  const qIdx = state.queue.findIndex(item => item.incident_id === incidentId);
  if (qIdx !== -1) {
    state.queue[qIdx].status = newStatus;
    renderResponseQueue(state.queue, state.capacity);
  }

  if (newStatus === 'CLOSED') {
    state.stats.active_incidents = Math.max(0, (state.stats.active_incidents || 1) - 1);
    if ((state.selectedIncident.severity || '').toUpperCase() === 'CRITICAL') {
      state.stats.critical_incidents = Math.max(0, (state.stats.critical_incidents || 1) - 1);
    }
    renderSummaryCards(state.stats);
  }

  renderIncidentsTable(state.incidents);
  
  const statusEl = document.getElementById('modal-status');
  if (statusEl) {
    statusEl.innerHTML = '';
    const spanStatus = document.createElement('span');
    spanStatus.className = `badge-status status-${newStatus.toLowerCase()}`;
    spanStatus.textContent = newStatus;
    statusEl.appendChild(spanStatus);
  }

  console.log(`[SOC-FUSION] Incident ${incidentId} marked as ${newStatus}`);
}

function initModalListeners() {
  const modalEl = document.getElementById('incident-modal');
  const closeBtn = document.getElementById('btn-close-modal');

  if (closeBtn) closeBtn.addEventListener('click', closeIncidentModal);

  if (modalEl) {
    modalEl.addEventListener('click', (e) => {
      if (e.target === modalEl) closeIncidentModal();
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modalEl && !modalEl.classList.contains('hidden')) {
      closeIncidentModal();
    }
  });

  const assignBtn = document.getElementById('btn-assign-incident');
  if (assignBtn) {
    assignBtn.addEventListener('click', () => updateIncidentStatus('ASSIGNED'));
  }

  const investBtn = document.getElementById('btn-investigating-incident');
  if (investBtn) {
    investBtn.addEventListener('click', () => updateIncidentStatus('INVESTIGATING'));
  }

  const closeIncBtn = document.getElementById('btn-close-incident');
  if (closeIncBtn) {
    closeIncBtn.addEventListener('click', () => {
      updateIncidentStatus('CLOSED');
      setTimeout(closeIncidentModal, 350);
    });
  }
}

async function fetchStats() {
  try {
    const response = await fetch(API_CONFIG.ENDPOINTS.STATS);
    if (!response.ok) throw new Error(`HTTP ${response.status}: Failed to fetch /api/stats`);
    const data = await response.json();
    state.stats = data;
    renderSummaryCards(state.stats);
    handleFetchSuccess();
  } catch (error) {
    handleFetchFailure(error);
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

let consecutiveFetchFailures = 0;

function handleFetchSuccess() {
  consecutiveFetchFailures = 0;
  state.isOnline = true;
  hideOfflineAlert();
}

function handleFetchFailure(error) {
  consecutiveFetchFailures++;
  console.warn('[SOC-FUSION] Telemetry sync notice:', error?.message || error);
  if (consecutiveFetchFailures >= 2) {
    state.isOnline = false;
    showOfflineAlert();
  }
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

function renderLoadingSkeletons() {
  const tbody = document.getElementById('incidents-table-body');
  if (tbody && state.incidents.length === 0) {
    tbody.innerHTML = `
      <tr class="table-skeleton-row"><td colspan="9"><div class="skeleton-shimmer table-skeleton-cell"></div></td></tr>
      <tr class="table-skeleton-row"><td colspan="9"><div class="skeleton-shimmer table-skeleton-cell"></div></td></tr>
      <tr class="table-skeleton-row"><td colspan="9"><div class="skeleton-shimmer table-skeleton-cell"></div></td></tr>
      <tr class="table-skeleton-row"><td colspan="9"><div class="skeleton-shimmer table-skeleton-cell"></div></td></tr>
    `;
  }

  const eventContainer = document.getElementById('event-stream-container');
  if (eventContainer && state.logs.length === 0) {
    eventContainer.innerHTML = `
      <div class="skeleton-shimmer event-skeleton-item"></div>
      <div class="skeleton-shimmer event-skeleton-item"></div>
      <div class="skeleton-shimmer event-skeleton-item"></div>
      <div class="skeleton-shimmer event-skeleton-item"></div>
    `;
  }

  const queueContainer = document.getElementById('response-queue-container');
  if (queueContainer && state.queue.length === 0) {
    queueContainer.innerHTML = `
      <div class="skeleton-shimmer queue-skeleton-item"></div>
      <div class="skeleton-shimmer queue-skeleton-item"></div>
      <div class="skeleton-shimmer queue-skeleton-item"></div>
    `;
  }

  const fusionContainer = document.getElementById('signal-fusion-visualizer');
  if (fusionContainer && !state.selectedIncident) {
    fusionContainer.innerHTML = `
      <div class="cyber-empty-state fusion-empty-state">
        <div class="empty-state-icon">⚡</div>
        <div class="empty-state-title">SIGNAL FUSION MATRIX IDLE</div>
        <div class="empty-state-desc">Select an incident from the table or trigger simulation to trace signal correlation pathways.</div>
      </div>
    `;
  }

  const timelineContainer = document.getElementById('attack-timeline-container');
  if (timelineContainer && !state.selectedIncident) {
    timelineContainer.innerHTML = `
      <div class="cyber-empty-state timeline-empty-state">
        <div class="empty-state-icon">⏱️</div>
        <div class="empty-state-title">ATTACK TIMELINE INACTIVE</div>
        <div class="empty-state-desc">Correlated attack progression stages will render when an incident is active.</div>
      </div>
    `;
  }
}

async function handleRetryConnection() {
  const retryBtn = document.getElementById('btn-retry-connection');
  if (retryBtn) {
    retryBtn.textContent = '🔄 Reconnecting...';
    retryBtn.classList.add('loading');
    retryBtn.disabled = true;
  }

  try {
    await Promise.all([
      fetchStats(),
      fetchLogs(),
      fetchIncidents(),
      fetchQueue()
    ]);
  } catch (err) {
    console.error('[SOC-FUSION] Reconnect attempt failed:', err);
  } finally {
    if (retryBtn) {
      retryBtn.textContent = 'Retry';
      retryBtn.classList.remove('loading');
      retryBtn.disabled = false;
    }
  }
}

/**
 * ==========================================================================
 * ATTACK SIMULATION CONTROLLER (PHASE 12)
 * ==========================================================================
 */
let toastTimeout = null;

function showSimulationToast(title, desc, durationMs = null) {
  const toast = document.getElementById('simulation-toast');
  const titleEl = document.getElementById('toast-title');
  const descEl = document.getElementById('toast-desc');

  if (!toast || !titleEl || !descEl) return;

  titleEl.textContent = title;
  descEl.textContent = desc;
  toast.classList.remove('hidden');

  if (toastTimeout) {
    clearTimeout(toastTimeout);
    toastTimeout = null;
  }

  if (durationMs) {
    toastTimeout = setTimeout(() => {
      toast.classList.add('hidden');
    }, durationMs);
  }
}

function hideSimulationToast() {
  const toast = document.getElementById('simulation-toast');
  if (toast) toast.classList.add('hidden');
}

async function triggerAttackSimulation() {
  if (state.isSimulating) return;
  state.isSimulating = true;

  const btnSim = document.getElementById('btn-start-simulation');
  if (btnSim) {
    btnSim.textContent = '⏳ SIMULATING ATTACK...';
    btnSim.classList.add('btn-simulating');
    btnSim.disabled = true;
  }

  try {
    // Pre-seed backend simulation if available
    let backendPayload = null;
    try {
      const res = await fetch(API_CONFIG.ENDPOINTS.START_SIMULATION, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if (res.ok) {
        backendPayload = await res.json();
      }
    } catch (err) {
      console.warn('[SOC-FUSION] Live backend simulation unavailable. Running simulated telemetry client-side.', err);
    }

    const fusionContainer = document.getElementById('signal-fusion-container');
    const eventContainer = document.getElementById('event-stream-container');

    // STEP 1: Reconnaissance (T = 0ms)
    showSimulationToast(
      'STEP 1/5: RECONNAISSANCE DETECTED',
      'High-frequency TCP SYN port scan from 192.168.1.50 targeting ports 22, 80, 443, 3389...'
    );

    const nowTime = new Date().toLocaleTimeString('en-US', { hour12: false });
    const log1 = {
      id: Date.now() + 1,
      timestamp: nowTime,
      source_ip: '192.168.1.50',
      event_type: 'PORT_SCAN',
      source: 'Firewall',
      signal: 'TCP_SYN_SWEEP',
      severity: 'HIGH',
      status: 'DETECTED',
      action: 'FLAGGED',
      details: 'Rapid scan on ports 22, 80, 443, 3389, 8080 from single host'
    };

    state.logs.unshift(log1);
    if (eventContainer) {
      const logEl1 = createEventItemElement(log1, true);
      eventContainer.insertBefore(logEl1, eventContainer.firstChild);
      while (eventContainer.children.length > 50) {
        eventContainer.removeChild(eventContainer.lastChild);
      }
    }
    state.stats.total_events = (state.stats.total_events || 0) + 5;
    state.stats.signals_detected = (state.stats.signals_detected || 0) + 1;
    renderSummaryCards(state.stats);

    // STEP 2: Initial Access / Brute Force (T = 1800ms)
    setTimeout(() => {
      try {
        showSimulationToast(
          'STEP 2/5: BRUTE FORCE ATTACK',
          '5 consecutive failed logins for root account on Auth-Gateway-01 from 192.168.1.50.'
        );

        const log2 = {
          id: Date.now() + 2,
          timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
          source_ip: '192.168.1.50',
          event_type: 'FAILED_LOGIN',
          source: 'Auth Gateway',
          signal: 'BRUTE_FORCE',
          severity: 'HIGH',
          status: 'DETECTED',
          action: 'BLOCKED',
          details: '5 consecutive failed logins for root on Auth-Gateway-01'
        };

        state.logs.unshift(log2);
        if (eventContainer) {
          const logEl2 = createEventItemElement(log2, true);
          eventContainer.insertBefore(logEl2, eventContainer.firstChild);
          while (eventContainer.children.length > 50) {
            eventContainer.removeChild(eventContainer.lastChild);
          }
        }
        state.stats.total_events = (state.stats.total_events || 0) + 15;
        state.stats.signals_detected = (state.stats.signals_detected || 0) + 2;
        renderSummaryCards(state.stats);
      } catch (e) {
        console.error('Error in simulation step 2:', e);
      }
    }, 1800);

    // STEP 3: Anomaly Detected (T = 3600ms)
    setTimeout(() => {
      try {
        showSimulationToast(
          'STEP 3/5: TRAFFIC ANOMALY DETECTED',
          'Outbound egress surge (4.8 GB) detected from 192.168.1.50 to unverified ASN.'
        );

        const log3 = {
          id: Date.now() + 3,
          timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
          source_ip: '192.168.1.50',
          event_type: 'TRAFFIC_SPIKE',
          source: 'DPI Sensor',
          signal: 'EGRESS_BURST',
          severity: 'CRITICAL',
          status: 'DETECTED',
          action: 'RATE_LIMITED',
          details: 'Outbound surge: 4.8 GB transferred within 90s'
        };

        state.logs.unshift(log3);
        if (eventContainer) {
          const logEl3 = createEventItemElement(log3, true);
          eventContainer.insertBefore(logEl3, eventContainer.firstChild);
          while (eventContainer.children.length > 50) {
            eventContainer.removeChild(eventContainer.lastChild);
          }
        }
        state.stats.total_events = (state.stats.total_events || 0) + 42;
        state.stats.signals_detected = (state.stats.signals_detected || 0) + 3;
        renderSummaryCards(state.stats);
      } catch (e) {
        console.error('Error in simulation step 3:', e);
      }
    }, 3600);

    // STEP 4: Signal Fusion Engine Matrix Match (T = 5200ms)
    setTimeout(() => {
      try {
        showSimulationToast(
          'STEP 4/5: SIGNAL FUSION MATRIX MATCH',
          'Correlating 3 weak signals from 192.168.1.50 within 60s temporal window...'
        );

        if (fusionContainer) {
          fusionContainer.classList.add('fusion-pulse-active');
        }

        const simIncident = backendPayload?.incident || {
          id: 'INC-001',
          source_ip: '192.168.1.50',
          incident_type: 'MULTI-STAGE ATTACK',
          title: 'Credential Stuffing & Lateral Reconnaissance',
          target: 'Auth-Gateway-01',
          signals_count: 6,
          signals: ['PORT_SCAN', 'FAILED_LOGIN', 'TRAFFIC_SPIKE', 'SYN_FLOOD', 'BRUTE_FORCE', 'EGRESS_BURST'],
          severity: 'CRITICAL',
          risk_score: 94,
          confidence: 96,
          status: 'OPEN',
          first_seen: nowTime,
          last_seen: new Date().toLocaleTimeString('en-US', { hour12: false }),
          reasons: [
            '5 failed logins from single external IP within 60s window',
            'Correlated port scanning activity targeting SSH (22) and RDP (3389)',
            'Anomalous outbound traffic volume spike (4.8 GB) detected on egress router',
            'Signal Fusion Confidence: 96.4% multi-stage correlation match'
          ],
          progression: ['Reconnaissance', 'Initial Access', 'Brute Force', 'Signal Fusion', 'Escalation'],
          recommended_action: 'Isolate host 192.168.1.50 at firewall perimeter immediately. Revoke root Kerberos ticket.',
          timeline: [
            { time: nowTime, event: 'PORT SCAN', ip: '192.168.1.50', stage: 'Reconnaissance', type: 'stage-recon', sev: 'medium' },
            { time: nowTime, event: 'FAILED LOGIN', ip: '192.168.1.50', stage: 'Initial Access', type: 'stage-access', sev: 'high' },
            { time: nowTime, event: 'FAILED LOGIN', ip: '192.168.1.50', stage: 'Brute Force', type: 'stage-access', sev: 'high' },
            { time: nowTime, event: 'TRAFFIC SPIKE', ip: '192.168.1.50', stage: 'Anomaly Detected', type: 'stage-anomaly', sev: 'high' },
            { time: nowTime, event: 'COMPOSITE INCIDENT', ip: '192.168.1.50', stage: 'Signal Fusion', type: 'stage-escalation', sev: 'critical' },
            { time: nowTime, event: 'CRITICAL ESCALATION', ip: '192.168.1.50', stage: 'SOC Priority #1', type: 'stage-escalation', sev: 'critical' }
          ]
        };

        renderSignalFusionVisualizer(simIncident);
      } catch (e) {
        console.error('Error in simulation step 4:', e);
      }
    }, 5200);

    // STEP 5: Incident Escalation & Response Queue Priority #1 (T = 6800ms)
    setTimeout(() => {
      try {
        showSimulationToast(
          'STEP 5/5: CRITICAL INCIDENT ESCALATED',
          'INC-001 prioritized to Rank #1 in SOC Queue. Analyst bandwidth at 100% saturation!'
        );

        if (fusionContainer) {
          fusionContainer.classList.remove('fusion-pulse-active');
        }

        const simIncident = backendPayload?.incident || {
          id: 'INC-001',
          source_ip: '192.168.1.50',
          incident_type: 'MULTI-STAGE ATTACK',
          title: 'Credential Stuffing & Lateral Reconnaissance',
          target: 'Auth-Gateway-01',
          signals_count: 6,
          signals: ['PORT_SCAN', 'FAILED_LOGIN', 'TRAFFIC_SPIKE', 'SYN_FLOOD', 'BRUTE_FORCE', 'EGRESS_BURST'],
          severity: 'CRITICAL',
          risk_score: 94,
          confidence: 96,
          status: 'OPEN',
          first_seen: nowTime,
          last_seen: new Date().toLocaleTimeString('en-US', { hour12: false }),
          reasons: [
            '5 failed logins from single external IP within 60s window',
            'Correlated port scanning activity targeting SSH (22) and RDP (3389)',
            'Anomalous outbound traffic volume spike (4.8 GB) detected on egress router',
            'Signal Fusion Confidence: 96.4% multi-stage correlation match'
          ],
          progression: ['Reconnaissance', 'Initial Access', 'Brute Force', 'Signal Fusion', 'Escalation'],
          recommended_action: 'Isolate host 192.168.1.50 at firewall perimeter immediately. Revoke root Kerberos ticket.',
          timeline: [
            { time: nowTime, event: 'PORT SCAN', ip: '192.168.1.50', stage: 'Reconnaissance', type: 'stage-recon', sev: 'medium' },
            { time: nowTime, event: 'FAILED LOGIN', ip: '192.168.1.50', stage: 'Initial Access', type: 'stage-access', sev: 'high' },
            { time: nowTime, event: 'FAILED LOGIN', ip: '192.168.1.50', stage: 'Brute Force', type: 'stage-access', sev: 'high' },
            { time: nowTime, event: 'TRAFFIC SPIKE', ip: '192.168.1.50', stage: 'Anomaly Detected', type: 'stage-anomaly', sev: 'high' },
            { time: nowTime, event: 'COMPOSITE INCIDENT', ip: '192.168.1.50', stage: 'Signal Fusion', type: 'stage-escalation', sev: 'critical' },
            { time: nowTime, event: 'CRITICAL ESCALATION', ip: '192.168.1.50', stage: 'SOC Priority #1', type: 'stage-escalation', sev: 'critical' }
          ]
        };

        // Update state incidents
        const incIdx = state.incidents.findIndex(i => i.id === 'INC-001');
        if (incIdx !== -1) {
          state.incidents[incIdx] = simIncident;
        } else {
          state.incidents.unshift(simIncident);
        }
        renderIncidentsTable(state.incidents);

        // Flash the table row
        const targetRow = document.querySelector('#incidents-table-body tr[data-id="INC-001"]');
        if (targetRow) {
          targetRow.classList.add('row-flash-critical');
        }

        // Elevate INC-001 in queue
        const filteredQueue = state.queue.filter(q => q.incident_id !== 'INC-001');
        state.queue = [
          {
            rank: 1,
            priority: 1,
            incident_id: 'INC-001',
            title: simIncident.title,
            severity: 'CRITICAL',
            risk_score: 94,
            target: 'Auth-Gateway-01',
            signals_count: 6,
            time_waiting: 'Just now',
            analyst: null,
            status: 'WAITING'
          },
          ...filteredQueue.slice(0, 4)
        ].map((item, idx) => ({ ...item, rank: idx + 1, priority: idx + 1 }));

        state.capacity = {
          active_analysts: 3,
          max_analysts: 3,
          total_analysts: 3,
          utilization: '100%'
        };
        renderResponseQueue(state.queue, state.capacity);

        // Select the incident
        selectIncident(simIncident, false);

        // Update charts
        renderCharts();
      } catch (e) {
        console.error('Error in simulation step 5:', e);
      }
    }, 6800);

    // STEP 6: Complete (T = 8200ms)
    setTimeout(() => {
      showSimulationToast(
        'ATTACK SIMULATION COMPLETE',
        'Multi-stage intrusion successfully fused and prioritized into SOC Response Queue.',
        4500
      );

      if (btnSim) {
        btnSim.textContent = '↺ RE-RUN ATTACK SIMULATION';
        btnSim.classList.remove('btn-simulating');
        btnSim.disabled = false;
      }
      state.isSimulating = false;
    }, 8200);

  } catch (globalErr) {
    console.error('[SOC-FUSION] Fatal simulation error:', globalErr);
    showSimulationToast('SIMULATION ERROR', 'An error occurred during simulation. Resetting.', 3000);
    if (btnSim) {
      btnSim.textContent = '▶ START ATTACK SIMULATION';
      btnSim.classList.remove('btn-simulating');
      btnSim.disabled = false;
    }
    state.isSimulating = false;
  }
}

/**
 * ==========================================================================
 * IP THREAT INTELLIGENCE & DEEP SEARCH CONTROLLER
 * ==========================================================================
 */
let currentAnalyzedIP = null;

async function lookupIPIntelligence(ipAddress) {
  if (!ipAddress || typeof ipAddress !== 'string') return;
  const ip = ipAddress.trim();
  if (!ip) return;

  currentAnalyzedIP = ip;
  console.log(`[SOC-FUSION] Analyzing IP Threat Intelligence for: ${ip}`);

  let intelData = null;

  try {
    const response = await fetch(`${API_CONFIG.BASE_URL}/api/ip/${encodeURIComponent(ip)}`);
    if (response.ok) {
      intelData = await response.json();
    }
  } catch (err) {
    console.warn('[SOC-FUSION] Live backend IP intelligence lookup unavailable, computing locally:', err);
  }

  // Fallback: Compute intelligence locally from active state if backend not reached
  if (!intelData) {
    const matchingLogs = (state.logs || []).filter(l => l.source_ip === ip);
    const matchingIncidents = (state.incidents || []).filter(i => i.source_ip === ip);
    const isPrivate = ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.') || ip === '127.0.0.1';

    const signals = new Set();
    matchingLogs.forEach(l => {
      if (l.signal) signals.add(l.signal);
      if (l.event_type) signals.add(l.event_type);
    });
    matchingIncidents.forEach(inc => {
      if (Array.isArray(inc.signals)) inc.signals.forEach(s => signals.add(s));
    });

    const primaryIncident = matchingIncidents[0] || null;
    const maxRisk = primaryIncident ? (primaryIncident.risk_score || 80) : (matchingLogs.length > 0 ? 65 : 10);
    const verdict = primaryIncident 
      ? `${primaryIncident.severity || 'HIGH'} THREAT (${primaryIncident.incident_type || 'ATTACK'})`
      : (matchingLogs.length > 0 ? 'SUSPICIOUS HOST (LOGGED ANOMALIES)' : 'CLEAN / BENIGN (NO ACTIVE THREATS)');

    intelData = {
      ip: ip,
      found_in_database: matchingLogs.length > 0 || matchingIncidents.length > 0,
      network_type: isPrivate ? 'Private Subnet (RFC 1918)' : 'Public WAN / External Host',
      risk_score: maxRisk,
      threat_verdict: verdict,
      total_events: matchingLogs.length,
      signals_count: signals.size,
      signals: Array.from(signals),
      first_seen: primaryIncident?.first_seen || (matchingLogs[matchingLogs.length - 1]?.timestamp || 'N/A'),
      last_seen: primaryIncident?.last_seen || (matchingLogs[0]?.timestamp || 'N/A'),
      target: primaryIncident?.target || 'Corporate Network Boundary',
      incident: primaryIncident,
      logs: matchingLogs,
      recommended_action: primaryIncident?.recommended_action || (maxRisk > 60 ? 'Isolate host at boundary firewall immediately.' : 'Maintain baseline perimeter monitoring.')
    };
  }

  renderIPModal(intelData);
}

function renderIPModal(data) {
  const modal = document.getElementById('ip-intelligence-modal');
  if (!modal) return;

  const addrTitle = document.getElementById('ip-modal-address');
  const verdictBadge = document.getElementById('ip-verdict-badge');
  const verdictDesc = document.getElementById('ip-verdict-desc');
  const riskScore = document.getElementById('ip-risk-score');

  const metaAddress = document.getElementById('ip-meta-address');
  const metaNetwork = document.getElementById('ip-meta-network');
  const metaTarget = document.getElementById('ip-meta-target');
  const metaEvents = document.getElementById('ip-meta-events');
  const metaSignalsCount = document.getElementById('ip-meta-signals-count');
  const metaIncident = document.getElementById('ip-meta-incident');
  const metaFirstSeen = document.getElementById('ip-meta-first-seen');
  const metaLastSeen = document.getElementById('ip-meta-last-seen');
  const metaDbStatus = document.getElementById('ip-meta-db-status');

  const signalsContainer = document.getElementById('ip-modal-signals');
  const logsBody = document.getElementById('ip-modal-logs-body');
  const logsCount = document.getElementById('ip-modal-logs-count');
  const recAction = document.getElementById('ip-modal-recommended-action');

  if (addrTitle) addrTitle.textContent = data.ip;
  if (metaAddress) metaAddress.textContent = data.ip;
  if (metaNetwork) metaNetwork.textContent = data.network_type;
  if (metaTarget) metaTarget.textContent = data.target || 'Multiple Gateways';
  if (metaEvents) metaEvents.textContent = `${data.total_events} Event${data.total_events === 1 ? '' : 's'}`;
  if (metaSignalsCount) metaSignalsCount.textContent = `${data.signals_count} Signal${data.signals_count === 1 ? '' : 's'}`;
  if (metaIncident) metaIncident.textContent = data.incident ? `${data.incident.id} (${data.incident.incident_type || data.incident.severity})` : 'None Correlated';
  if (metaFirstSeen) metaFirstSeen.textContent = data.first_seen || 'N/A';
  if (metaLastSeen) metaLastSeen.textContent = data.last_seen || 'N/A';
  if (metaDbStatus) {
    metaDbStatus.textContent = data.found_in_database ? '✓ Recorded in Telemetry DB' : '⚪ New / External Unlogged Host';
    metaDbStatus.style.color = data.found_in_database ? 'var(--text-orange)' : 'var(--text-muted)';
  }

  // Risk Score & Verdict
  const score = data.risk_score ?? 0;
  if (riskScore) {
    riskScore.textContent = score;
    riskScore.className = 'ip-risk-score';
    if (score >= 80) riskScore.classList.add('text-red');
    else if (score >= 60) riskScore.classList.add('text-orange');
    else if (score >= 40) riskScore.classList.add('text-yellow');
    else riskScore.classList.add('text-green');
  }

  if (verdictBadge) {
    verdictBadge.textContent = data.threat_verdict;
    verdictBadge.className = 'ip-verdict-badge';
    if (score >= 80) verdictBadge.classList.add('verdict-critical');
    else if (score >= 60) verdictBadge.classList.add('verdict-high');
    else if (score >= 40) verdictBadge.classList.add('verdict-medium');
    else verdictBadge.classList.add('verdict-clean');
  }

  if (verdictDesc) {
    if (score >= 80) {
      verdictDesc.textContent = 'High-confidence multi-stage attack signatures active. Priority containment advised.';
    } else if (score >= 50) {
      verdictDesc.textContent = 'Suspicious telemetry events or port probing identified from this host.';
    } else {
      verdictDesc.textContent = 'No malicious indicators or correlated composite incidents active.';
    }
  }

  // Render Signals
  if (signalsContainer) {
    signalsContainer.innerHTML = '';
    const signals = data.signals || [];
    if (signals.length === 0) {
      signalsContainer.innerHTML = '<span class="text-neutral">No correlated signals detected for this host.</span>';
    } else {
      signals.forEach(sig => {
        const chip = document.createElement('span');
        chip.className = 'ip-signal-chip';
        chip.textContent = `📡 ${sig.replace(/_/g, ' ')}`;
        signalsContainer.appendChild(chip);
      });
    }
  }

  // Render Logs Table
  if (logsCount) logsCount.textContent = (data.logs || []).length;
  if (logsBody) {
    logsBody.innerHTML = '';
    const logs = data.logs || [];
    if (logs.length === 0) {
      logsBody.innerHTML = '<tr><td colspan="6" class="text-center text-neutral" style="padding: 1.5rem;">No historical logs associated with this IP in telemetry store.</td></tr>';
    } else {
      logs.slice(0, 20).forEach(log => {
        const tr = document.createElement('tr');
        const sevKey = (log.severity || 'LOW').toLowerCase();
        tr.innerHTML = `
          <td class="table-id">${log.timestamp || '--'}</td>
          <td><strong>${log.event_type || 'EVENT'}</strong></td>
          <td><span class="badge-signals">${log.signal || 'TELEMETRY'}</span></td>
          <td><span class="badge-sev badge-sev-${sevKey}">${(log.severity || 'LOW').toUpperCase()}</span></td>
          <td>${log.action || 'LOGGED'}</td>
          <td class="text-neutral" style="max-width: 250px; overflow: hidden; text-overflow: ellipsis;">${log.details || '--'}</td>
        `;
        logsBody.appendChild(tr);
      });
    }
  }

  // Recommended Action
  if (recAction) {
    recAction.textContent = data.recommended_action || 'Maintain perimeter logging and firewall egress monitoring.';
  }

  openIPModal();
}

function openIPModal() {
  const modal = document.getElementById('ip-intelligence-modal');
  if (modal) {
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
  }
}

function closeIPModal() {
  const modal = document.getElementById('ip-intelligence-modal');
  if (modal) {
    modal.classList.add('hidden');
    modal.setAttribute('aria-hidden', 'true');
  }
}

function filterDashboardByIP(ip) {
  if (!ip) return;
  state.activeIpFilter = ip;
  console.log(`[SOC-FUSION] Dashboard filtered to IP: ${ip}`);

  const clearBtn = document.getElementById('btn-clear-ip-filter');
  if (clearBtn) clearBtn.classList.remove('hidden');

  const inputEl = document.getElementById('input-ip-search');
  if (inputEl) inputEl.value = ip;

  closeIPModal();
  renderEventStream(state.logs, false);
  renderIncidentsTable(state.incidents);

  // If there's an incident matching this IP, select it; otherwise synthesize an incident profile
  const matchingIncident = state.incidents.find(i => i.source_ip === ip);
  if (matchingIncident) {
    selectIncident(matchingIncident, false);
  } else {
    // Generate synthetic incident for this IP so Signal Fusion and Attack Timeline also update!
    const cleanId = ip.replace(/[^0-9]/g, '').slice(-4) || 'TEL';
    const synthIncident = {
      id: `INC-HOST-${cleanId}`,
      source_ip: ip,
      incident_type: 'HOST TELEMETRY CORRELATION',
      severity: 'MEDIUM',
      risk_score: 55,
      confidence: 88,
      status: 'INVESTIGATING',
      signals: ['HOST_PROBE', 'PORT_SCAN', 'TRAFFIC_SPIKE'],
      first_seen: new Date(Date.now() - 1800000).toLocaleTimeString('en-US', { hour12: false }),
      last_seen: new Date().toLocaleTimeString('en-US', { hour12: false })
    };
    selectIncident(synthIncident, false);
  }

  // Transform all 4 charts immediately
  renderCharts();
}

function clearIPFilter() {
  state.activeIpFilter = null;
  console.log('[SOC-FUSION] IP filter cleared, restoring full dashboard telemetry');

  const clearBtn = document.getElementById('btn-clear-ip-filter');
  if (clearBtn) clearBtn.classList.add('hidden');

  const inputEl = document.getElementById('input-ip-search');
  if (inputEl) inputEl.value = '';

  renderEventStream(state.logs, false);
  renderIncidentsTable(state.incidents);

  if (state.incidents && state.incidents.length > 0) {
    selectIncident(state.incidents[0], false);
  }
  renderCharts();
}

window.socDashboard = {
  formatNumber: formatNumber,
  updateStats: (customStats) => {
    state.stats = { ...state.stats, ...customStats };
    renderSummaryStats(state.stats);
    return state.stats;
  },
  pushEvent: (eventData) => {
    const newEvent = {
      id: Date.now(),
      timestamp: eventData.timestamp || new Date().toLocaleTimeString('en-US', { hour12: false }),
      source_ip: eventData.source_ip || '192.168.1.50',
      event_type: eventData.event_type || 'TRAFFIC_SPIKE',
      source: eventData.source || 'Network Monitor',
      status: eventData.status || 'DETECTED',
      severity: eventData.severity || 'HIGH'
    };
    renderEventStream([newEvent], true);
    state.stats.total_events = (state.stats.total_events || 0) + 1;
    renderSummaryStats(state.stats);
    return newEvent;
  },
  renderSummaryStats: renderSummaryStats,
  renderEventStream: renderEventStream,
  renderIncidentsTable: renderIncidentsTable,
  selectIncident: selectIncident,
  openModal: (id) => {
    const target = state.incidents.find(inc => inc.id === id) || state.selectedIncident;
    if (target) openIncidentModal(target);
    return target;
  },
  closeModal: closeIncidentModal,
  renderFusion: (incident) => {
    renderSignalFusionVisualizer(incident || state.selectedIncident);
  },
  renderTimeline: (incident) => {
    renderAttackTimeline(incident || state.selectedIncident);
  },
  updateCapacity: (active, max) => {
    state.capacity.active_analysts = active;
    state.capacity.max_analysts = max;
    renderResponseQueue(state.queue, state.capacity);
    return state.capacity;
  },
  renderCharts: renderCharts,
  getCharts: () => charts,
  getQueue: () => state.queue,
  triggerSimulation: triggerAttackSimulation,
  renderLoadingSkeletons: renderLoadingSkeletons,
  handleRetryConnection: handleRetryConnection,
  showOfflineAlert: showOfflineAlert,
  hideOfflineAlert: hideOfflineAlert,
  lookupIP: lookupIPIntelligence,
  filterByIP: filterDashboardByIP,
  clearIPFilter: clearIPFilter,
  getState: () => state
};

// Boot initialization on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  console.log('[SOC-FUSION] Initializing Phase 14 with IP Threat Intelligence & Deep Search...');
  initClock();
  initModalListeners();
  renderLoadingSkeletons();
  fetchStats();
  fetchLogs();
  fetchIncidents();
  fetchQueue();
  renderCharts();

  const simBtn = document.getElementById('btn-start-simulation');
  if (simBtn) {
    simBtn.addEventListener('click', triggerAttackSimulation);
  }

  // IP Threat Intelligence Search & Filtering
  const ipSearchInput = document.getElementById('input-ip-search');
  const ipSearchBtn = document.getElementById('btn-ip-search');
  const clearFilterBtn = document.getElementById('btn-clear-ip-filter');
  const closeIpModalBtn = document.getElementById('btn-close-ip-modal');
  const closeIpDossierBtn = document.getElementById('btn-close-ip-dossier');
  const filterByIpBtn = document.getElementById('btn-filter-by-ip');
  const ipModal = document.getElementById('ip-intelligence-modal');

  if (ipSearchBtn && ipSearchInput) {
    const executeSearch = () => {
      const query = ipSearchInput.value.trim();
      if (query) lookupIPIntelligence(query);
    };
    ipSearchBtn.addEventListener('click', executeSearch);
    ipSearchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        executeSearch();
      }
    });
  }

  // Quick IP Target Tags
  const quickTags = document.querySelectorAll('.ip-tag-chip');
  quickTags.forEach(tag => {
    tag.addEventListener('click', () => {
      const ip = tag.dataset.ip;
      if (ip) {
        if (ipSearchInput) ipSearchInput.value = ip;
        lookupIPIntelligence(ip);
      }
    });
  });

  if (clearFilterBtn) {
    clearFilterBtn.addEventListener('click', clearIPFilter);
  }

  if (closeIpModalBtn) closeIpModalBtn.addEventListener('click', closeIPModal);
  if (closeIpDossierBtn) closeIpDossierBtn.addEventListener('click', closeIPModal);

  if (filterByIpBtn) {
    filterByIpBtn.addEventListener('click', () => {
      if (currentAnalyzedIP) filterDashboardByIP(currentAnalyzedIP);
    });
  }

  if (ipModal) {
    ipModal.addEventListener('click', (e) => {
      if (e.target === ipModal) closeIPModal();
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && ipModal && !ipModal.classList.contains('hidden')) {
      closeIPModal();
    }
  });

  setInterval(() => {
    if (state.isSimulating) return;
    fetchStats();
    fetchLogs();
    fetchIncidents();
    fetchQueue();
  }, API_CONFIG.POLL_INTERVAL_MS);

  const retryBtn = document.getElementById('btn-retry-connection');
  if (retryBtn) {
    retryBtn.addEventListener('click', handleRetryConnection);
  }

  // Active navigation link tracking
  const navLinks = document.querySelectorAll('.nav-link');
  navLinks.forEach(link => {
    link.addEventListener('click', () => {
      navLinks.forEach(l => l.classList.remove('active'));
      link.classList.add('active');
    });
  });
});
