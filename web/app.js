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
  setText('d-latency', result.ms.toFixed(1) + ' ms (browser round trip, includes gateway + policy + audit + upstream)');
  setText('d-raw', JSON.stringify(result.body, null, 2));
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
}

async function signIn(event) {
  event.preventDefault();
  const payload = {
    username: $('username').value.trim(),
    password: $('password').value,
    device_id: $('device-id').value.trim(),
  };

  const result = await api('POST', '/auth/login', payload);
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
  } else {
    accessToken = null;
    session = null;
  }
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
  const result = await api('GET', '/admin/devices');
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
  tr.appendChild(el('td', (event.occurred_at || '').replace('T', ' ').slice(0, 19)));
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
  const params = new URLSearchParams({ limit: $('audit-limit').value || '25' });
  const filter = $('audit-result').value;
  if (filter) params.set('result', filter);

  const result = await api('GET', '/admin/events?' + params.toString());
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
    replaceChildren(list, [el('li', 'Could not load DLP rules.')]);
    return;
  }
  replaceChildren(list, result.body.rules.map((rule) => {
    const li = el('li', rule.rule_id + '  ' + rule.pattern);
    li.appendChild(el('span', '  — ' + rule.description));
    return li;
  }));
}

/* --- wiring ------------------------------------------------------------- */

function init() {
  $('login-form').addEventListener('submit', signIn);
  $('logout-btn').addEventListener('click', signOut);

  for (const chip of document.querySelectorAll('[data-user]')) {
    chip.addEventListener('click', () => {
      $('username').value = chip.dataset.user;
      $('device-id').value = chip.dataset.device;
      $('password').focus();
    });
  }
  for (const button of document.querySelectorAll('[data-app]')) {
    button.addEventListener('click', () => requestApp(button.dataset.app));
  }
  for (const button of document.querySelectorAll('[data-web]')) {
    button.addEventListener('click', () => requestWeb(button.dataset.web));
  }
  for (const button of document.querySelectorAll('[data-sample]')) {
    button.addEventListener('click', () => applySample(button.dataset.sample));
  }

  $('custom-web-btn').addEventListener('click', () =>
    requestWeb($('custom-destination').value.trim()));
  $('upload-btn').addEventListener('click', doUpload);
  $('refresh-devices').addEventListener('click', refreshDevices);
  $('refresh-audit').addEventListener('click', refreshAudit);

  updateSessionChip();
  loadDlpRules();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
