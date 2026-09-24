/**
 * ==========================================================================
 * SOC-FUSION — Signal-Fused Intrusion Detection & Response Dashboard
 * Phase 4: Live Security Event Stream & Real-Time Ingest
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
 * @param {HTMLElement} element Target DOM element
 * @param {number} start Initial number
 * @param {number} end Target number
 * @param {number} duration Animation duration in milliseconds
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
    
    // Ease-out cubic: fast start, soft settle
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
 * @param {Object} statsData
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

  // Extract previous numerical values to animate from
  const prevEvents = parseInt(totalEventsEl?.textContent.replace(/,/g, '')) || 0;
  const prevSignals = parseInt(signalsDetectedEl?.textContent.replace(/,/g, '')) || 0;
  const prevActive = parseInt(activeIncidentsEl?.textContent.replace(/,/g, '')) || 0;
  const prevCritical = parseInt(criticalIncidentsEl?.textContent.replace(/,/g, '')) || 0;

  // Animate numeric counters
  if (totalEventsEl) animateValue(totalEventsEl, prevEvents, statsData.total_events ?? 0);
  if (signalsDetectedEl) animateValue(signalsDetectedEl, prevSignals, statsData.signals_detected ?? 0);
  if (activeIncidentsEl) animateValue(activeIncidentsEl, prevActive, statsData.active_incidents ?? 0);
  if (criticalIncidentsEl) animateValue(criticalIncidentsEl, prevCritical, statsData.critical_incidents ?? 0);

  // Update trend & status indicators
  if (trendEventsEl && statsData.trends?.events) {
    trendEventsEl.textContent = statsData.trends.events;
  }
  if (trendSignalsEl && statsData.trends?.signals) {
    trendSignalsEl.textContent = statsData.trends.signals;
  }
  if (trendActiveEl && statsData.trends?.incidents) {
    trendActiveEl.textContent = statsData.trends.incidents;
  }
  if (trendCriticalEl && statsData.trends?.critical) {
    trendCriticalEl.textContent = statsData.trends.critical;
  }

  // Highlight Critical Incidents card when count > 0
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

/**
 * Map event type to visual severity level
 * @param {string} eventType 
 * @returns {string} Severity string ('critical' | 'high' | 'medium' | 'low')
 */
function getSeverityForEvent(eventType = '') {
  const type = eventType.toUpperCase();
  if (type.includes('EXFIL') || type.includes('ROOT') || type.includes('MALWARE')) return 'critical';
  if (type.includes('TRAFFIC_SPIKE') || type.includes('FAILED_LOGIN') || type.includes('BRUTE')) return 'high';
  if (type.includes('PORT_SCAN') || type.includes('SYN_FLOOD')) return 'medium';
  return 'low';
}

/**
 * Create a secure DOM element representing a single security event
 * (Safe DOM manipulation preventing any XSS)
 * @param {Object} event Event object
 * @param {boolean} isNew Whether to trigger entrance animation
 * @returns {HTMLElement}
 */
function createEventItemElement(event, isNew = false) {
  const item = document.createElement('div');
  const sev = (event.severity || getSeverityForEvent(event.event_type)).toLowerCase();
  
  item.className = `event-item event-${sev}${isNew ? ' event-item-new' : ''}`;
  item.dataset.id = event.id || `${event.timestamp}-${event.source_ip}-${event.event_type}`;

  // Top row: Timestamp & Event Type Badge
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

  // Main row: Source IP & Detection Status
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

  // Bottom row: Reporting Source Subsystem
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

  // Assemble card
  item.appendChild(rowTop);
  item.appendChild(rowMain);
  item.appendChild(rowBottom);

  return item;
}

/**
 * Render the Live Security Event Stream list
 * @param {Array} logs Array of event log objects
 * @param {boolean} prependNew Whether to prepend incoming new events
 */
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

  // Remove empty placeholder if present
  const emptyPlaceholder = container.querySelector('.stream-empty-state');
  if (emptyPlaceholder) {
    emptyPlaceholder.remove();
  }

  if (prependNew) {
    // Incrementally prepend only brand new events to the top
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
    // Full initial render
    container.innerHTML = '';
    state.knownLogIds.clear();
    logs.forEach(log => {
      const logKey = log.id || `${log.timestamp}-${log.source_ip}-${log.event_type}`;
      state.knownLogIds.add(logKey);
      const card = createEventItemElement(log, false);
      container.appendChild(card);
    });
  }

  // Prune DOM nodes to 50 max to prevent memory leakage
  while (container.children.length > 50) {
    container.removeChild(container.lastChild);
  }

  // Update header count
  if (countBadge) {
    countBadge.textContent = `${container.children.length} Events`;
  }
}

/**
 * Fetch logs from backend API or provide demo data fallback during UI building
 */
async function fetchLogs() {
  try {
    const response = await fetch(API_CONFIG.ENDPOINTS.LOGS);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: Failed to fetch /api/logs`);
    }
    const data = await response.json();
    const logs = Array.isArray(data) ? data : (data.logs || []);
    
    // Check if new items arrived
    const isInitial = state.logs.length === 0;
    state.logs = logs;
    renderEventStream(logs, !isInitial);
    hideOfflineAlert();
  } catch (error) {
    // When Flask backend is not yet running, load realistic hackathon sample events
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
 * Fetch stats from backend API or provide demo data fallback during UI building
 */
async function fetchStats() {
  try {
    const response = await fetch(API_CONFIG.ENDPOINTS.STATS);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: Failed to fetch /api/stats`);
    }
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

/**
 * Initialize real-time digital system clock
 */
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

/**
 * System Offline Alert Handlers
 */
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

// Global debug & test API exposed to window for interactive testing
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
    
    // Automatically increment total events counter
    state.stats.total_events = (state.stats.total_events || 0) + 1;
    renderSummaryCards(state.stats);
    return newEvent;
  },
  getState: () => state
};

// Boot logic on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  console.log('[SOC-FUSION] Initializing Phase 4: Live Security Event Stream...');
  initClock();
  fetchStats();
  fetchLogs();

  // Periodic polling (every 3 seconds) for live events & metrics
  setInterval(() => {
    fetchStats();
    fetchLogs();
  }, API_CONFIG.POLL_INTERVAL_MS);

  // Retry connection button listener
  const retryBtn = document.getElementById('btn-retry-connection');
  if (retryBtn) {
    retryBtn.addEventListener('click', () => {
      fetchStats();
      fetchLogs();
    });
  }
});
