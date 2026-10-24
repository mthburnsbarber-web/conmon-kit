// Cloudflare checks for the monthly run. Every call is a GET; nothing is changed. Results use the check-file row format
// (control, check, expected, actual, pass), so failures land on the POA&M.
//  - settingsCheck: the account and zone against a baseline (2FA, administrator roles, minimum TLS, HTTPS, HSTS, DNSSEC,
//    Worker routes, workers.dev and Preview URLs). Where the token cannot read a setting, a live probe shows the effect.
//  - inventoryCheck: every Worker in the inventory exists, and every store or Worker it is bound to is an inventory asset.
//  - deployedCode: the modules each Worker actually runs, for the monthly Trivy scan of deployed code.
// Token permissions: Account Settings Read, Account Members Read (for the member rows), Zone Read, Zone Settings Read,
// DNS Read, Workers Scripts Read, Workers Routes Read, D1 Read. Member emails are masked in the results.
import { createHash } from 'node:crypto';
import tls from 'node:tls';

export function cloudflareApi(token, fetcher = fetch) {
  return async (path) => {
    const r = await fetcher('https://api.cloudflare.com/client/v4' + path, { headers: { authorization: `Bearer ${token}` } });
    const body = await r.json().catch(() => ({}));
    if (!body.success) return { error: (body.errors || []).map((e) => `${e.code} ${e.message}`).join('; ') || `HTTP ${r.status}` };
    return body.result;
  };
}

// At most four characters and never more than half of the name before the @ (a short name would otherwise show whole).
const mask = (email) => String(email || '').replace(/^([^@]*)(@.*)$/, (_, name, domain) => `${name.slice(0, Math.min(4, Math.floor(name.length / 2)))}…${domain}`);
const roleSummary = (roles) => (roles.some((r) => /Super Administrator/.test(r)) ? 'Super Administrator' : roles.slice(0, 3).join(' + ') + (roles.length > 3 ? ` (+${roles.length - 3} more)` : ''));

// Live probes for settings the token cannot read through the API. They show the effective behavior at <zone><path>.
export function probes(zone, path = '/', fetcher = fetch) {
  return {
    async httpsRedirect() {
      const r = await fetcher(`http://${zone}${path}`, { redirect: 'manual' });
      return { status: r.status, location: r.headers.get('location') || '' };
    },
    async hsts() { return (await fetcher(`https://${zone}${path}`, { method: 'HEAD' })).headers.get('strict-transport-security') || ''; },
    tls11() {
      return new Promise((resolve) => {
        const socket = tls.connect({ host: zone, port: 443, servername: zone, minVersion: 'TLSv1.1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT:@SECLEVEL=0' });
        socket.setTimeout(8000, () => { socket.destroy(); resolve('no answer'); });
        socket.on('secureConnect', () => { socket.end(); resolve('accepted'); });
        socket.on('error', () => resolve('refused'));
      });
    },
    async dnssecDs() {
      const r = await fetcher(`https://cloudflare-dns.com/dns-query?name=${zone}&type=DS`, { headers: { accept: 'application/dns-json' } });
      return ((await r.json()).Answer || []).length;
    }
  };
}

export async function settingsCheck({ account, zone, workers = [], get, probe }) {
  const rows = [];
  const add = (control, check, expected, actual, pass, extra = {}) => rows.push({ control, check, expected: String(expected), actual: String(actual), pass: pass ? 'PASS' : 'FAIL', asset: zone, ...extra });
  const high = { risk: 'High' };

  const acct = await get(`/accounts/${account}`);
  add('IA-2(1)', 'Account requires 2FA for all members', 'true', acct?.settings?.enforce_twofactor ?? acct?.error, acct?.settings?.enforce_twofactor === true, high);
  const members = await get(`/accounts/${account}/members?per_page=50`);
  if (Array.isArray(members)) {
    const supers = members.filter((x) => (x.roles || []).some((r) => /Super Administrator/.test(r.name))).length;
    for (const m of members) {
      const roles = (m.roles || []).map((r) => r.name);
      add('IA-2(1)', `Member ${mask(m.user?.email)} has 2FA`, 'true', m.user?.two_factor_authentication_enabled, m.user?.two_factor_authentication_enabled === true, high);
      add('AC-2(7), AC-6', `Member ${mask(m.user?.email)} role`, 'at most one Super Administrator; others scoped', `${roleSummary(roles)} (${supers} Super Administrators in the account)`,
        !roles.some((r) => /Super Administrator/.test(r)) || supers <= 1, high);
    }
  } else {
    add('IA-2(1)', 'Read account members', 'readable', members?.error, false);
  }

  const zones = await get(`/zones?name=${zone}`);
  const z = Array.isArray(zones) ? zones[0] : null;
  if (!z) { add('CM-6', `Zone ${zone} readable`, 'readable', zones?.error || 'not found', false); return rows; }
  const setting = async (name) => (await get(`/zones/${z.id}/settings/${name}`))?.value;
  const minTls = await setting('min_tls_version');
  if (minTls !== undefined) add('SC-8, CM-6', 'Minimum TLS version', '1.2 or higher', `${minTls} (API)`, ['1.2', '1.3'].includes(minTls));
  else { const t = await probe.tls11(); add('SC-8, CM-6', 'Minimum TLS version (TLS 1.1 handshake)', 'refused', `${t} (live probe)`, t === 'refused'); }
  const https = await setting('always_use_https');
  if (https !== undefined) add('SC-8, CM-6', 'Always Use HTTPS', 'on', `${https} (API)`, https === 'on');
  else { const r = await probe.httpsRedirect(); add('SC-8, CM-6', 'Always Use HTTPS (http://)', 'redirect to https://', `${r.status} ${r.location} (live probe)`, [301, 302, 307, 308].includes(r.status) && r.location.startsWith('https://')); }
  const header = (await setting('security_header'))?.strict_transport_security;
  if (header) add('SC-8, CM-6', 'HSTS on the zone', 'enabled, max-age >= 31536000', `${header.enabled} max-age=${header.max_age} (API)`, header.enabled === true && Number(header.max_age) >= 31536000);
  else { const h = await probe.hsts(); const age = Number(/max-age=(\d+)/.exec(h)?.[1] || 0); add('SC-8, CM-6', 'HSTS header', 'max-age >= 31536000', `${h || 'no header'} (live probe)`, age >= 31536000); }
  const dnssec = await get(`/zones/${z.id}/dnssec`);
  if (dnssec?.status) add('SC-20, SC-21', 'DNSSEC', 'active', `${dnssec.status} (API)`, dnssec.status === 'active');
  else { const ds = await probe.dnssecDs(); add('SC-20, SC-21', 'DNSSEC (DS record in public DNS)', 'present', `${ds} DS records (live probe)`, ds > 0); }
  const routes = await get(`/zones/${z.id}/workers/routes`);
  add('SC-7(3), CM-8', 'Worker routes on the zone (inventory)', 'reviewed monthly', Array.isArray(routes) ? `${routes.length} routes, ${new Set(routes.map((r) => r.script)).size} Workers` : routes?.error, Array.isArray(routes));
  for (const name of workers) {
    const sub = await get(`/accounts/${account}/workers/scripts/${name}/subdomain`);
    add('SC-7, SC-7(3)', `${name} workers.dev URL`, 'off', sub?.enabled ?? sub?.error, sub?.enabled === false, { ...high, asset: name });
    add('SC-7, SC-7(3)', `${name} preview URLs`, 'off', sub?.previews_enabled ?? sub?.error, sub?.previews_enabled === false, { ...high, asset: name });
  }
  return rows;
}

// The inventory asset covering a bound resource: a code asset for a Worker, an asset named "<Kind> <name>" (for example
// "D1 app-db" or "R2 uploads"), or a group asset listing it in members.
const covering = (inventory, kind, name) => inventory.assets.find((a) => kind === 'Worker' && a.kind === 'code' && (a.worker || a.name) === name)
  || inventory.assets.find((a) => a.name === `${kind} ${name}`)
  || inventory.assets.find((a) => (a.members || []).includes(kind === 'Worker' ? name : `${kind} ${name}`));

export async function inventoryCheck({ account, zone, inventory, routePrefixes = null, get }) {
  const rows = [];
  const add = (control, check, expected, actual, pass) => rows.push({ control, check, expected: String(expected), actual: String(actual), pass: pass ? 'PASS' : 'FAIL', asset: 'inventory' });
  const workers = inventory.assets.filter((a) => a.kind === 'code' && a.worker);
  const d1Names = new Map();
  for (const a of workers) {
    const settings = await get(`/accounts/${account}/workers/scripts/${a.worker}/settings`);
    add('CM-8', `${a.id} ${a.worker} exists`, 'deployed Worker', settings?.error ? `not found (${settings.error})` : 'deployed', !settings?.error);
    for (const b of settings?.bindings || []) {
      let kind = null, name = null;
      if (b.type === 'd1') {
        if (!d1Names.has(b.database_id || b.id)) d1Names.set(b.database_id || b.id, (await get(`/accounts/${account}/d1/database/${b.database_id || b.id}`))?.name || b.database_id || b.id);
        kind = 'D1'; name = d1Names.get(b.database_id || b.id);
      } else if (b.type === 'r2_bucket') { kind = 'R2'; name = b.bucket_name; }
      else if (b.type === 'queue') { kind = 'Queue'; name = b.queue_name; }
      else if (b.type === 'kv_namespace') { kind = 'KV'; name = b.namespace_id; }
      else if (b.type === 'service') { kind = 'Worker'; name = b.service; }
      else if (b.type === 'durable_object_namespace') { kind = 'Durable Objects'; name = b.script_name || a.worker; }
      if (!kind) continue;
      const asset = covering(inventory, kind, name);
      add('CM-8', `${kind} ${name} bound to ${a.worker} as ${b.name}`, 'an inventory asset', asset ? asset.id : 'not in the inventory', Boolean(asset));
    }
  }
  const z = (await get(`/zones?name=${zone}`))?.[0];
  const routes = z ? await get(`/zones/${z.id}/workers/routes`) : null;
  const inScope = (pattern) => !routePrefixes || routePrefixes.some((p) => pattern.startsWith(p));
  for (const r of Array.isArray(routes) ? routes.filter((x) => inScope(x.pattern)) : []) {
    const asset = r.script && covering(inventory, 'Worker', r.script);
    add('CM-8', `route ${r.pattern}`, 'runs an inventory Worker', r.script ? `${r.script}${asset ? ` (${asset.id})` : ' (not in the inventory)'}` : 'no Worker', Boolean(asset));
  }
  if (!Array.isArray(routes)) add('CM-8', `${zone} Worker routes`, 'readable', routes?.error || 'zone not found', false);
  return rows;
}

// The modules each Worker's live version runs, with their SHA-256, for a Trivy scan of what is deployed (a source folder
// can differ from it, and some Workers have none).
export async function deployedCode({ account, workers, get }) {
  const out = [];
  for (const worker of workers) {
    try {
      const versions = (await get(`/accounts/${account}/workers/scripts/${worker}/deployments`))?.deployments?.[0]?.versions || [];
      if (!versions.length) throw new Error('no deployment');
      // During a gradual deployment every version serving traffic is scanned.
      for (const { version_id: id, percentage } of versions) {
        const v = await get(`/accounts/${account}/workers/workers/${worker}/versions/${id}?include=modules`);
        if (!v || v.error) throw new Error(v?.error || `version ${id} unreadable`);
        const modules = (v.modules || []).map((m) => {
          const name = String(m.name).replace(/^\.\//, '');
          if (!name || name.startsWith('/') || name.includes('\\') || name.split('/').includes('..')) throw new Error(`unsafe module name ${m.name}`);
          const bytes = Buffer.from(m.content_base64 || '', 'base64');
          return { name, bytes, sha256: createHash('sha256').update(bytes).digest('hex') };
        });
        out.push({ worker, version: id, percentage, entrypoint: v.main_module || null, modules });
      }
    } catch (e) {
      out.push({ worker, error: String(e.message).slice(0, 300) });
    }
  }
  return out;
}

export function rowsCsv(rows) {
  const cell = (v) => `"${String(v).replaceAll('"', '""')}"`;
  return ['control,check,expected,actual,result', ...rows.map((r) => [r.control, r.check, r.expected, r.actual, r.pass].map(cell).join(','))].join('\n') + '\n';
}
