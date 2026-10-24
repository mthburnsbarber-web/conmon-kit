import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deployedCode, inventoryCheck, settingsCheck } from '../checks/cloudflare.mjs';

const fakeGet = (routes) => async (path) => {
  for (const [pattern, result] of routes) if (pattern.test(path)) return typeof result === 'function' ? result(path) : result;
  return { error: '10000 not found' };
};

test('settings check: 2FA, roles, TLS, HTTPS, HSTS, DNSSEC, workers.dev; live probes when a setting is unreadable', async () => {
  const get = fakeGet([
    [/^\/accounts\/a1$/, { settings: { enforce_twofactor: false } }],
    [/members/, [{ user: { email: 'jane.doe@example.com', two_factor_authentication_enabled: true }, roles: [{ name: 'Super Administrator - All Privileges' }] },
      { user: { email: 'sam@example.com', two_factor_authentication_enabled: false }, roles: [{ name: 'Super Administrator - All Privileges' }] }]],
    [/^\/zones\?name=example\.com$/, [{ id: 'z1' }]],
    [/settings\/min_tls_version/, { value: '1.0' }],
    [/settings\/always_use_https/, { value: 'on' }],
    [/dnssec/, { status: 'active' }],
    [/workers\/routes/, [{ pattern: 'app.example.com/*', script: 'example-api' }]],
    [/scripts\/example-api\/subdomain/, { enabled: false, previews_enabled: true }]
  ]);
  const probe = { hsts: async () => 'max-age=63072000; includeSubDomains', tls11: async () => { throw new Error('not used'); } };
  const rows = await settingsCheck({ account: 'a1', zone: 'example.com', workers: ['example-api'], get, probe });
  const result = Object.fromEntries(rows.map((r) => [r.check, r]));
  assert.equal(result['Account requires 2FA for all members'].pass, 'FAIL');
  assert.equal(result['Account requires 2FA for all members'].risk, 'High');
  assert.ok(!JSON.stringify(rows).includes('jane.doe@'), 'member emails are masked');
  assert.ok(result['Member s…@example.com has 2FA'], 'a short name shows one letter, not all three');
  assert.ok(!JSON.stringify(rows).includes('sam@'));
  assert.equal(result['Member jane…@example.com role'].pass, 'FAIL', 'two Super Administrators');
  assert.equal(result['Minimum TLS version'].pass, 'FAIL');
  assert.equal(result['HSTS header'].pass, 'PASS', 'read by live probe when the API does not answer');
  assert.equal(result['DNSSEC'].pass, 'PASS');
  assert.equal(result['example-api preview URLs'].pass, 'FAIL');
  assert.equal(result['example-api preview URLs'].asset, 'example-api');
});

test('inventory check: every inventory Worker exists and everything it is bound to is an inventory asset', async () => {
  const inventory = { assets: [
    { id: 'INV-APP-01', name: 'API', kind: 'code', worker: 'example-api' },
    { id: 'INV-DB-01', name: 'D1 example-db', kind: 'managed' },
    { id: 'INV-STORE-01', name: 'stores', kind: 'managed', members: ['R2 uploads'] },
    { id: 'INV-GONE-01', name: 'Old', kind: 'code', worker: 'retired' }] };
  const get = fakeGet([
    [/scripts\/example-api\/settings/, { bindings: [{ type: 'd1', name: 'DB', id: 'd1-id' }, { type: 'r2_bucket', name: 'FILES', bucket_name: 'uploads' },
      { type: 'kv_namespace', name: 'CACHE', namespace_id: 'kv9' }, { type: 'plain_text', name: 'X', text: 'y' }] }],
    [/d1\/database\/d1-id/, { name: 'example-db' }],
    [/^\/zones\?name=/, [{ id: 'z1' }]],
    [/workers\/routes/, [{ pattern: 'app.example.com/*', script: 'example-api' }, { pattern: 'beta.example.com/*', script: 'beta' }, { pattern: 'other.example.com/*', script: 'other' }]]
  ]);
  const rows = await inventoryCheck({ account: 'a1', zone: 'example.com', inventory, routePrefixes: ['app.', 'beta.'], get });
  assert.deepEqual(rows.filter((r) => r.pass === 'FAIL').map((r) => r.check), ['KV kv9 bound to example-api as CACHE', 'INV-GONE-01 retired exists', 'route beta.example.com/*']);
  assert.deepEqual(rows.filter((r) => r.pass === 'PASS').map((r) => r.actual), ['deployed', 'INV-DB-01', 'INV-STORE-01', 'example-api (INV-APP-01)']);
});

test('deployed code: every version serving traffic is read; unsafe module names are refused', async () => {
  const b64 = (s) => Buffer.from(s).toString('base64');
  const get = fakeGet([
    [/scripts\/api\/deployments/, { deployments: [{ versions: [{ version_id: 'v1', percentage: 90 }, { version_id: 'v2', percentage: 10 }] }] }],
    [/workers\/api\/versions\/v1/, { main_module: 'index.js', modules: [{ name: 'index.js', content_base64: b64('a') }] }],
    [/workers\/api\/versions\/v2/, { main_module: 'index.js', modules: [{ name: 'index.js', content_base64: b64('b') }] }],
    [/scripts\/bad\/deployments/, { deployments: [{ versions: [{ version_id: 'v3', percentage: 100 }] }] }],
    [/workers\/bad\/versions\/v3/, { modules: [{ name: '../x.js', content_base64: '' }] }]
  ]);
  const read = await deployedCode({ account: 'a1', workers: ['api', 'bad'], get });
  assert.deepEqual(read.map((w) => [w.worker, w.version, w.percentage, w.modules?.[0]?.sha256.slice(0, 8) ?? w.error]),
    [['api', 'v1', 90, 'ca978112'], ['api', 'v2', 10, '3e23e816'], ['bad', undefined, undefined, 'unsafe module name ../x.js']]);
});
