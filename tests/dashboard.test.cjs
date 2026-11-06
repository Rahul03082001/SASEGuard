const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

function dashboard() {
  const context = vm.createContext({
    document: { readyState: 'loading', addEventListener() {} },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/app.js'), 'utf8'), context);
  return context;
}

test('response inspector redacts credentials without changing the authentication response', () => {
  const context = dashboard();
  const response = {
    access_token: 'a-bearer-token-that-must-stay-out-of-the-DOM',
    subject: 'alice',
    nested: [{ password: 'secret-password', Authorization: 'Bearer private',
      refresh_token: 'private-refresh', service_credential: 'private-service' }],
  };
  const rendered = context.redactedResponse(response);
  assert.equal(JSON.parse(rendered).access_token, '[redacted]');
  assert.equal(JSON.parse(rendered).subject, 'alice');
  for (const secret of ['a-bearer-token', 'secret-password', 'Bearer private', 'private-refresh', 'private-service']) {
    assert.ok(!rendered.includes(secret));
  }
  assert.equal(response.access_token, 'a-bearer-token-that-must-stay-out-of-the-DOM');
  assert.equal(response.nested[0].password, 'secret-password');
});

test('finishing a pending action cannot enable protected controls after logout', async () => {
  const context = dashboard();
  for (const id of ['logout-btn', 'refresh-devices', 'refresh-audit']) {
    const button = { id, disabled: false, setAttribute() {}, removeAttribute() {} };
    await context.runAction(button, async () => {});
    assert.equal(button.disabled, true, id);
  }
  const ordinary = { id: 'upload-btn', disabled: false, setAttribute() {}, removeAttribute() {} };
  await context.runAction(ordinary, async () => {});
  assert.equal(ordinary.disabled, false);
});
