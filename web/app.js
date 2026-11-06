/* SASEGuard dashboard logic.
 *
 * Three rules this file follows, and why:
 *
 * 1. The access token lives in a module-scoped variable and nowhere else.
 *    Not localStorage, not sessionStorage, not a cookie, not the DOM. A
 *    refresh loses it, which is correct: a ten-minute bearer token is not
 *    something to persist, and anything in localStorage is readable by any
 *    script that manages to run on this origin.
 *
 * 2. Server values reach the page only through `textContent` or
 *    `document.createTextNode`. There is not a single `innerHTML` assignment
 *    below. Reason codes and device labels come from a server that is itself
 *    reading a database -- treating them as markup would be an XSS sink.
 *
 * 3. Every button calls the real API. Nothing is faked client-side, no
 *    metric is invented, and a denial is displayed exactly as the gateway
 *    reported it.
 */
'use strict';

/* --- state ------------------------------------------------------------- */

/** In-memory only. Never persisted, never rendered. @type {string|null} */
let accessToken = null;
let session = null;
let sessionTimer = null;
let requestCount = 0;
let deniedCount = 0;
const recentActivity = [];

/* --- tiny DOM helpers -------------------------------------------------- */

const $ = (id) => document.getElementById(id);

/** Set an element's text. The only way text enters the page. */
function setText(id, value) {
  const node = $(id);
  if (node) node.textContent = value === null || value === undefined || value === '' ? '—' : String(value);
}

/** Build an element with text content and optional class. */
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

/** Replace a node's children. */
function replaceChildren(node, children) {
  while (node.firstChild) node.removeChild(node.firstChild);
  for (const child of children) node.appendChild(child);
}

function emptyRow(columns, message) {
  const tr = el('tr', null, 'empty');
  const td = el('td', message);
  td.colSpan = columns;
  tr.appendChild(td);
  return tr;
}

/* --- API ---------------------------------------------------------------- */

/**
 * Call the gateway and return {status, body, ms}.
 * Attaches the bearer token when we hold one. Never sends identity hints --
 * the server would ignore them anyway, and pretending otherwise would
 * misrepresent how authorization works here.
 */
async function api(method, path, body) {
  const headers = {};
  if (accessToken) headers['Authorization'] = 'Bearer ' + accessToken;
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  const started = performance.now();
  let response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      signal: AbortSignal.timeout(15000),
    });
  } catch (error) {
    return { status: 0, body: { detail: 'Network error: ' + error.message, reason_code: 'NETWORK_ERROR' }, ms: performance.now() - started };
  }
  const ms = performance.now() - started;

  let parsed;
  try {
    parsed = await response.json();
  } catch (_) {
    parsed = { detail: 'Response was not JSON.' };
  }
  return { status: response.status, body: parsed, ms };
}

/* --- decision panel ----------------------------------------------------- */

function classifyStatus(status) {
  if (status === 0) return 'error';
  if (status >= 200 && status < 300) return 'allow';
  if (status === 401 || status === 403) return 'deny';
  return 'error';
}

function renderDecision(label, result) {
  const kind = classifyStatus(result.status);
  const badge = $('verdict-badge');
  badge.textContent = kind === 'allow' ? 'allowed' : kind === 'deny' ? 'denied' : 'error';
  badge.className = 'verdict-badge ' + kind;

  setText('verdict-request', label);
  setText('d-status', result.status === 0 ? 'no response' : result.status);
  setText('d-reason', result.body.reason_code);
  setText('d-detail', result.body.detail);
  setText('d-category', result.body.category);

  const dlp = result.body.dlp;
  if (dlp && Array.isArray(dlp.findings) && dlp.findings.length > 0) {
    // Rule IDs and counts only. The server never sends matched values, and
    // the dashboard has nothing to display even if someone wanted it to.
    setText('d-dlp', dlp.findings.map((f) => f.rule_id + ' x' + f.match_count).join(', '));
  } else if (dlp) {
    setText('d-dlp', 'no findings');
  } else {
    setText('d-dlp', '—');
  }

  setText('d-event', result.body.audit_event_id);
  setText('d-latency', result.ms.toFixed(1) + ' ms');
  $('d-latency').title = 'Browser round trip, including gateway, policy, audit, and upstream';
  setText('d-raw', redactedResponse(result.body));
  $('decision-symbol').className = 'decision-symbol ' + kind;
  setText('decision-summary', kind === 'allow' ? 'The gateway accepted this request.'
    : kind === 'deny' ? 'The gateway refused this request.' : 'This request could not be completed.');
  requestCount += 1;
  if (kind === 'deny') deniedCount += 1;
  setText('request-count', requestCount);
  setText('deny-count', deniedCount + ' denied');
  recentActivity.unshift({ label, kind, reason: result.body.reason_code || 'HTTP ' + result.status,
    time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) });
  recentActivity.splice(6);
  replaceChildren($('activity-list'), recentActivity.map((entry) => {
    const row = el('li', null, 'activity-entry');
    const mark = el('span', entry.kind === 'allow' ? '↗' : entry.kind === 'deny' ? '×' : '!', 'activity-mark ' + entry.kind);
    mark.setAttribute('aria-label', entry.kind);
    row.appendChild(mark);
    const description = el('div', null, 'activity-text');
    description.appendChild(el('strong', entry.label));
    description.appendChild(el('small', entry.reason));
    row.appendChild(description);
    row.appendChild(el('span', entry.time, 'activity-time'));
    return row;
  }));
}

// Login responses contain a bearer token. Redact before serializing for the
// inspector; leave the actual API response intact for in-memory authentication.
function redactedResponse(body) {
  return JSON.stringify(body, (key, value) =>
    /^(access_token|refresh_token|password|authorization|service_credential)$/i.test(key)
      ? '[redacted]' : value, 2);
}

/* --- session ------------------------------------------------------------ */

function updateSessionChip() {
  const dot = $('session-dot');
  if (session) {
    dot.className = 'dot dot-on';
    // Subject, role and device are shown. The token itself is not.
    setText('session-label', session.subject + ' · ' + session.role + ' · ' + session.device_id);
  } else {
    dot.className = 'dot dot-off';
    setText('session-label', 'Not signed in');
  }
  $('logout-btn').disabled = !session;
  setText('identity-name', session ? session.subject : 'Not connected');
  setText('identity-detail', session ? session.role + ' · 10-minute session' : 'Connect a demo user to begin');
  setText('connect-label', session ? 'Manage identity' : 'Connect identity');
  const isAdmin = session && session.role === 'administrator';
  $('refresh-devices').disabled = !isAdmin;
  $('refresh-audit').disabled = !isAdmin;
  $('device-access-notice').hidden = Boolean(isAdmin);
  $('audit-access-notice').hidden = Boolean(isAdmin);
  // Never retain an administrator's records after an identity change.
  replaceChildren($('devices-body'), [emptyRow(7, 'Refresh as an administrator to load device records.')]);
  replaceChildren($('audit-body'), [emptyRow(8, 'Refresh as an administrator to load audit events.')]);
}

async function signIn(event) {
  event.preventDefault();
  if ($('signin-btn').disabled) return;
  $('signin-btn').disabled = true;
  $('login-feedback').textContent = 'Verifying your identity…';
  const payload = {
    username: $('username').value.trim(),
    password: $('password').value,
    device_id: $('device-id').value.trim(),
  };

  const result = await api('POST', '/auth/login', payload);
  clearTimeout(sessionTimer);
  renderDecision('POST /auth/login (' + payload.username + ' @ ' + payload.device_id + ')', result);

  if (result.status === 200 && result.body.access_token) {
    accessToken = result.body.access_token;
    session = {
      subject: result.body.subject,
      role: result.body.role,
      device_id: result.body.device_id,
      expires_in: result.body.expires_in,
    };
    // Clear the password field as soon as it has been used.
    $('password').value = '';
    $('login-feedback').textContent = '';
    $('session-dialog').close();
    sessionTimer = setTimeout(() => {
      accessToken = null;
      session = null;
      updateSessionChip();
      setText('identity-detail', 'Session expired. Connect again to continue.');
    }, result.body.expires_in * 1000);
  } else {
    accessToken = null;
    session = null;
    $('login-feedback').textContent = result.body.detail || 'Could not connect. Check your credentials and device.';
  }
  $('signin-btn').disabled = false;
  updateSessionChip();
  refreshUploadCounterLabel(null);
}

async function signOut() {
  const result = await api('POST', '/auth/logout');
  renderDecision('POST /auth/logout (revoke token)', result);
  // Drop the token locally regardless. Server-side revocation is what
  // actually matters -- this just stops us sending a token we know is dead.
  accessToken = null;
  session = null;
  clearTimeout(sessionTimer);
  $('session-dialog').close();
  updateSessionChip();
}

/* --- requests ----------------------------------------------------------- */

async function requestApp(appId) {
  renderDecision('GET /apps/' + appId, await api('GET', '/apps/' + encodeURIComponent(appId)));
}

async function requestWeb(destination) {
  renderDecision('GET /web/' + destination, await api('GET', '/web/' + encodeURIComponent(destination)));
}

const SAMPLES = {
  clean: {
    filename: 'quarterly-notes.txt',
    content: 'Quarterly summary: headcount steady, no customer identifiers in this note.',
  },
  secret: {
    filename: 'deploy-notes.txt',
    content: 'Rotate the staging key SG-DEMO-SECRET-A1B2C3D4 before Friday.',
  },
  customer: {
    filename: 'support-thread.txt',
    content: 'Escalation for account SG-CUSTOMER-204517 awaiting a refund decision.',
  },
  email: {
    filename: 'contact-list.txt',
    content: 'Primary contact: dana.reyes@example.com (synthetic address).',
  },
};

function applySample(name) {
  for (const chip of document.querySelectorAll('[data-sample]')) {
    chip.classList.toggle('selected', chip.dataset.sample === name);
  }
  if (name === 'extra-field') {
    // Demonstrates extra='forbid': the server rejects the request instead of
    // silently ignoring a field the client thought was meaningful.
    $('upload-filename').value = 'tamper-attempt.txt';
    $('upload-content').value = 'This payload will be sent with an extra "skip_dlp": true field.';
    $('upload-btn').dataset.extraField = 'true';
    return;
  }
  delete $('upload-btn').dataset.extraField;
  const sample = SAMPLES[name];
  if (!sample) return;
  $('upload-filename').value = sample.filename;
  $('upload-content').value = sample.content;
}

function refreshUploadCounterLabel(value) {
  setText('upload-counter', value === null || value === undefined
    ? 'upstream accepted: —'
    : 'upstream accepted: ' + value);
}

async function doUpload() {
  const payload = {
    filename: $('upload-filename').value,
    content: $('upload-content').value,
  };
  if ($('upload-btn').dataset.extraField === 'true') {
    payload.skip_dlp = true;
  }

  const result = await api('POST', '/saas/upload', payload);
  renderDecision('POST /saas/upload (' + payload.filename + ')', result);

  // The upstream counter is the honest proof: a DLP-blocked payload leaves it
  // unchanged, because the synthetic storage service was never contacted.
  const upstream = result.body.upstream;
  if (upstream && typeof upstream.accepted_uploads === 'number') {
    refreshUploadCounterLabel(upstream.accepted_uploads);
  } else if (result.status === 403) {
    const node = $('upload-counter');
    node.textContent = node.textContent.replace(/ \(unchanged.*\)$/, '') + ' (unchanged — never forwarded)';
  }
}

/* --- admin: devices ----------------------------------------------------- */

function postureAge(lastSeen) {
  const seen = Date.parse(lastSeen);
  if (Number.isNaN(seen)) return 'unparseable';
  const hours = (Date.now() - seen) / 3600000;
  return hours < 1 ? Math.round(hours * 60) + 'm' : hours.toFixed(1) + 'h';
}

function deviceRow(device) {
  const tr = document.createElement('tr');
  tr.appendChild(el('td', device.device_id));
  tr.appendChild(el('td', device.owner));

  const managed = el('td');
  managed.appendChild(el('span', device.managed ? 'yes' : 'no', 'pill ' + (device.managed ? 'yes' : 'no')));
  tr.appendChild(managed);

  const compliant = el('td');
  compliant.appendChild(el('span', device.compliant ? 'yes' : 'no', 'pill ' + (device.compliant ? 'yes' : 'no')));
  tr.appendChild(compliant);

  tr.appendChild(el('td', device.risk_score));
  tr.appendChild(el('td', postureAge(device.last_seen)));

  const actions = el('td');
  const breakBtn = el('button', device.compliant ? 'break' : 'fix');
  breakBtn.type = 'button';
  breakBtn.addEventListener('click', () =>
    patchDevice(device.device_id, { compliant: !device.compliant }));
  actions.appendChild(breakBtn);

  const riskBtn = el('button', device.risk_score > 30 ? 'risk 5' : 'risk 90');
  riskBtn.type = 'button';
  riskBtn.addEventListener('click', () =>
    patchDevice(device.device_id, { risk_score: device.risk_score > 30 ? 5 : 90 }));
  actions.appendChild(riskBtn);

  const staleBtn = el('button', 'stale');
  staleBtn.type = 'button';
  staleBtn.title = 'Backdate last_seen by 48 hours';
  staleBtn.addEventListener('click', () =>
    patchDevice(device.device_id, { last_seen: new Date(Date.now() - 48 * 3600000).toISOString() }));
  actions.appendChild(staleBtn);

  const freshBtn = el('button', 'fresh');
  freshBtn.type = 'button';
  freshBtn.addEventListener('click', () =>
    patchDevice(device.device_id, { last_seen: new Date().toISOString(), managed: true, compliant: true, risk_score: 5 }));
  actions.appendChild(freshBtn);

  tr.appendChild(actions);
  return tr;
}

async function refreshDevices() {
  const requestedAs = accessToken;
  const result = await api('GET', '/admin/devices');
  if (requestedAs !== accessToken) return;
  renderDecision('GET /admin/devices', result);

  const body = $('devices-body');
  if (result.status !== 200 || !Array.isArray(result.body.devices)) {
    replaceChildren(body, [emptyRow(7,
      result.status === 403
        ? 'Denied: ' + (result.body.reason_code || 'administrator access required') +
          '. The server refuses this regardless of what the UI shows.'
        : 'Could not load the device registry.')]);
    return;
  }
  replaceChildren(body, result.body.devices.map(deviceRow));
}

async function patchDevice(deviceId, changes) {
  const result = await api('PUT', '/admin/devices/' + encodeURIComponent(deviceId), changes);
  renderDecision('PUT /admin/devices/' + deviceId + ' ' + JSON.stringify(changes), result);
  if (result.status === 200) await refreshDevices();
}

/* --- admin: audit ------------------------------------------------------- */

function auditRow(event) {
  const tr = document.createElement('tr');
  const occurredAt = new Date(event.occurred_at);
  tr.appendChild(el('td', Number.isNaN(occurredAt.getTime()) ? '—' : occurredAt.toLocaleString()));
  tr.appendChild(el('td', event.subject));
  tr.appendChild(el('td', event.resource));
  tr.appendChild(el('td', event.action));

  const result = el('td');
  result.appendChild(el('span', event.result, 'pill ' + event.result));
  tr.appendChild(result);

  tr.appendChild(el('td', event.reason_code));
  tr.appendChild(el('td', (event.dlp_rule_ids || []).join(' ') || '—'));
  tr.appendChild(el('td', Number(event.decision_latency_ms).toFixed(1)));
  return tr;
}

async function refreshAudit() {
  const requestedAs = accessToken;
  const params = new URLSearchParams({ limit: $('audit-limit').value || '25' });
  const filter = $('audit-result').value;
  if (filter) params.set('result', filter);

  const result = await api('GET', '/admin/events?' + params.toString());
  if (requestedAs !== accessToken) return;
  renderDecision('GET /admin/events?' + params.toString(), result);

  const body = $('audit-body');
  if (result.status !== 200 || !Array.isArray(result.body.events)) {
    replaceChildren(body, [emptyRow(8,
      result.status === 403
        ? 'Denied: ' + (result.body.reason_code || 'administrator access required') + '.'
        : 'Could not load audit events.')]);
    return;
  }
  if (result.body.events.length === 0) {
    replaceChildren(body, [emptyRow(8, 'No events match this filter.')]);
    return;
  }
  replaceChildren(body, result.body.events.map(auditRow));
}

/* --- DLP rule list ------------------------------------------------------ */

async function loadDlpRules() {
  const result = await api('GET', '/meta/dlp-rules');
  const list = $('dlp-rule-list');
  if (result.status !== 200 || !Array.isArray(result.body.rules)) {
    setText('rule-count', '—');
    replaceChildren(list, [el('li', 'Could not load DLP rules.')]);
    return;
  }
  setText('rule-count', result.body.rules.length);
  replaceChildren(list, result.body.rules.map((rule) => {
    const li = el('li', rule.rule_id + '  ' + rule.pattern);
    li.appendChild(el('span', '  — ' + rule.description));
    return li;
  }));
}

/* --- wiring ------------------------------------------------------------- */

const VIEWS = {
  overview: ['Command center', 'Run a controlled request. Inspect the outcome.', 'Command center'],
  devices: ['Device posture', 'Trust changes when the device changes. Test it in real time.', 'Device posture'],
  audit: ['Audit trail', 'Inspect the decisions recorded by the gateway.', 'Audit trail'],
};

function showView(name) {
  if (!VIEWS[name]) name = 'overview';
  for (const key of Object.keys(VIEWS)) $('view-' + key).hidden = key !== name;
  for (const button of document.querySelectorAll('[data-view]')) {
    const active = button.dataset.view === name;
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  }
  setText('page-title', VIEWS[name][0]);
  $('page-title').appendChild(el('span', '_', 'heading-dot'));
  setText('page-description', VIEWS[name][1]);
  setText('breadcrumb-current', VIEWS[name][2]);
}

function selectTab(name) {
  for (const button of document.querySelectorAll('[data-tab]')) {
    const active = button.dataset.tab === name;
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
    $('pane-' + button.dataset.tab).hidden = !active;
  }
}

async function checkHealth() {
  const result = await api('GET', '/healthz');
  const healthy = result.status === 200 && result.body.status === 'ok';
  setText('gateway-status', healthy ? 'Connected' : 'Unavailable');
  $('gateway-dot').className = 'dot ' + (healthy ? 'dot-on' : 'dot-off');
  setText('gateway-detail', healthy ? 'Checked at ' + new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Gateway could not be reached');
  $('gateway-status').title = 'Gateway health only; checked ' + new Date().toLocaleTimeString();
}

async function runAction(button, action) {
  if (button.disabled) return;
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  try { await action(); }
  finally {
    button.disabled = button.id === 'logout-btn' ? !session
      : (button.id === 'refresh-devices' || button.id === 'refresh-audit')
        && (!session || session.role !== 'administrator');
    button.removeAttribute('aria-busy');
  }
}

function init() {
  for (const button of document.querySelectorAll('[data-open-session]')) {
    button.addEventListener('click', () => {
      $('session-dialog').showModal();
      $('password').focus();
    });
  }
  $('close-session').addEventListener('click', () => $('session-dialog').close());
  for (const button of document.querySelectorAll('[data-view]')) {
    button.addEventListener('click', () => { window.location.hash = button.dataset.view; });
  }
  window.addEventListener('hashchange', () => showView(window.location.hash.slice(1)));
  showView(window.location.hash.slice(1));
  const tabs = Array.from(document.querySelectorAll('[data-tab]'));
  for (const [index, button] of tabs.entries()) {
    button.addEventListener('click', () => selectTab(button.dataset.tab));
    button.addEventListener('keydown', (event) => {
      let next;
      if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
      else if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
      else if (event.key === 'Home') next = 0;
      else if (event.key === 'End') next = tabs.length - 1;
      else return;
      event.preventDefault();
      selectTab(tabs[next].dataset.tab);
      tabs[next].focus();
    });
  }
  $('how-it-works').addEventListener('click', () => {
    $('request-flow').scrollIntoView({ behavior: 'smooth', block: 'center' });
    $('request-flow').focus({ preventScroll: true });
  });
  $('login-form').addEventListener('submit', signIn);
  $('logout-btn').addEventListener('click', () => runAction($('logout-btn'), signOut));

  for (const chip of document.querySelectorAll('[data-user]')) {
    chip.addEventListener('click', () => {
      $('username').value = chip.dataset.user;
      $('device-id').value = chip.dataset.device;
      $('password').focus();
    });
  }
  for (const button of document.querySelectorAll('[data-app]')) {
    button.addEventListener('click', () => runAction(button, () => requestApp(button.dataset.app)));
  }
  for (const button of document.querySelectorAll('[data-web]')) {
    button.addEventListener('click', () => runAction(button, () => requestWeb(button.dataset.web)));
  }
  for (const button of document.querySelectorAll('[data-sample]')) {
    button.addEventListener('click', () => applySample(button.dataset.sample));
  }

  $('custom-web-btn').addEventListener('click', () => runAction($('custom-web-btn'), () =>
    requestWeb($('custom-destination').value.trim())));
  $('upload-btn').addEventListener('click', () => runAction($('upload-btn'), doUpload));
  $('refresh-devices').addEventListener('click', () => runAction($('refresh-devices'), refreshDevices));
  $('refresh-audit').addEventListener('click', () => runAction($('refresh-audit'), refreshAudit));

  updateSessionChip();
  loadDlpRules();
  checkHealth();
  setInterval(checkHealth, 60000);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
