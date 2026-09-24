/**
 * ==========================================================================
 * SOC-FUSION — Signal-Fused Intrusion Detection & Response Dashboard
 * Phase 9: Attack Timeline & Chronological Multi-Stage Progression
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
  queue: [],
  capacity: {
    active_analysts: 3,
    max_analysts: 3
  },
  isOnline: true
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

  if (!state.selectedIncidentId && incidents.length > 0) {
    selectIncident(incidents[0], false);
  }
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

  // Dynamically update the Signal Fusion Engine & Attack Timeline components
  renderSignalFusionVisualizer(incident);
  renderAttackTimeline(incident);

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
    container.innerHTML = '<div class="fusion-placeholder">Select an active composite incident to view signal correlation paths.</div>';
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
 * ATTACK TIMELINE & PROGRESSION (PHASE 9)
 * ==========================================================================
 */

/**
 * Render chronological attack timeline showing event sequence, host, and stage
 * @param {Object} incident Incident record
 */
function renderAttackTimeline(incident) {
  const container = document.getElementById('attack-timeline-container');
  if (!container) return;

  if (!incident) {
    container.innerHTML = '<div class="timeline-empty-state">Timeline awaiting incident selection.</div>';
    return;
  }

  container.innerHTML = '';

  // Determine timeline steps: use custom incident timeline or generate dynamic steps
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
    container.innerHTML = '<div class="queue-empty-state">No incidents waiting in response queue.</div>';
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
    hideOfflineAlert();
  } catch (error) {
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
    const endpoint = `/api/incidents/${encodeURIComponent(incidentId)}/${newStatus.toLowerCase()}`;
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
    if (target) selectIncident(target, false);
    return target;
  },
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
  getQueue: () => state.queue,
  getState: () => state
};

// Boot initialization on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  console.log('[SOC-FUSION] Initializing Phase 9: Attack Timeline & Progression...');
  initClock();
  initModalListeners();
  fetchStats();
  fetchLogs();
  fetchIncidents();
  fetchQueue();

  setInterval(() => {
    fetchStats();
    fetchLogs();
    fetchIncidents();
    fetchQueue();
  }, API_CONFIG.POLL_INTERVAL_MS);

  const retryBtn = document.getElementById('btn-retry-connection');
  if (retryBtn) {
    retryBtn.addEventListener('click', () => {
      fetchStats();
      fetchLogs();
      fetchIncidents();
      fetchQueue();
    });
  }
});
