/**
 * ==========================================================================
 * SOC-FUSION — Signal-Fused Intrusion Detection & Response Dashboard
 * Phase 3: Summary Cards & Dynamic Metric Telemetry
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
    // When Flask backend is not yet started in Phase 3, display initial hackathon preview stats
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

// Global debug & test API exposed to window for automated testing and verification
window.socDashboard = {
  updateStats: (customStats) => {
    state.stats = { ...state.stats, ...customStats };
    renderSummaryCards(state.stats);
    return state.stats;
  },
  getState: () => state
};

// Boot logic on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  console.log('[SOC-FUSION] Initializing Phase 3: Summary Cards & Telemetry...');
  initClock();
  fetchStats();

  // Set lightweight polling (every 3 seconds) as specified
  setInterval(fetchStats, API_CONFIG.POLL_INTERVAL_MS);

  // Retry connection button listener
  const retryBtn = document.getElementById('btn-retry-connection');
  if (retryBtn) {
    retryBtn.addEventListener('click', fetchStats);
  }
});
