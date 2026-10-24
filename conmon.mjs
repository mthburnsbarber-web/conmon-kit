#!/usr/bin/env node
// conmon — the monthly continuous monitoring run for a FedRAMP, GovRAMP or similar authorization, built on free scanners.
//
// `conmon scan` runs each scanner your config names (only if it is installed), writes the raw results into
// <evidence-dir>/<YYYY-MM>/, then builds the month's reports. `conmon report` rebuilds the reports from the files already
// in a month folder:
//   scan-results-<date>.csv   every raw finding in one CSV
//   scan-summary-<date>.md    executive summary, detailed summary and inventory report
//   poam-<date>.csv           the POA&M, carried forward from the previous one
// Scanners: Trivy (code), nuclei (web application), testssl.sh (TLS), GitHub Dependabot, security headers, the
// administrator workstation, and optional Cloudflare checks. Everything is read-only. Zero dependencies.
//
// Usage: conmon scan <evidence-dir> [--config conmon.json]
//        conmon report <month-dir> [--config conmon.json] [--today YYYY-MM-DD]
// Env:   SCAN_COOKIE (signed-in web scan), CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID (Cloudflare checks)
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { platform, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { cloudflareApi, deployedCode, inventoryCheck, probes, rowsCsv, settingsCheck } from './checks/cloudflare.mjs';
import { buildPoam, localDay, settings, toCsv } from './poam.mjs';
import { resultsCsv } from './results-csv.mjs';
import { summary } from './summary.mjs';

export function loadConfig(path) {
  const file = resolve(path);
  const config = JSON.parse(readFileSync(file, 'utf8'));
  const base = dirname(file), at = (p) => (p ? resolve(base, p) : null);
  const inventory = at(config.inventory);
  return {
    ...config,
    inventoryData: inventory ? JSON.parse(readFileSync(inventory, 'utf8')) : null,
    gapAssessment: at(config.gapAssessment),
    trivyPaths: Object.fromEntries(Object.entries(config.scans?.trivy || {}).map(([name, p]) => [name, at(p)]))
  };
}

const defaultRun = (cmd, args, { timeoutMs = 3600000 } = {}) => {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 256 * 1024 * 1024 });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '', error: r.error };
};
const defaultHas = (cmd) => spawnSync('/bin/sh', ['-c', 'command -v "$1"', 'sh', cmd], { encoding: 'utf8' }).status === 0;

export async function scan(evidenceDir, cfg, { run = defaultRun, has = defaultHas, env = process.env, now = new Date(), fetcher = fetch, get = null, log = () => {} } = {}) {
  const stamp = localDay(now), dir = join(evidenceDir, stamp.slice(0, 7));
  const scans = cfg.scans || {};
  mkdirSync(dir, { recursive: true });
  const out = (name) => join(dir, name);
  const skip = (name, why) => { writeFileSync(out(`${name}-${stamp}.skipped`), why + '\n'); log(`skipped ${name}: ${why}`); };
  const first = (text) => text.split('\n').find((l) => l.trim()) || '';

  // Scanner, engine and signature versions, after updating the signatures, so the evidence says what each scan knew.
  const versions = [`date: ${stamp}`];
  if (has('trivy')) {
    versions.push(first(run('trivy', ['--version']).stdout));
    if (run('trivy', ['image', '--download-db-only', '--quiet']).status === 0) versions.push('trivy vulnerability database refreshed before scanning');
  }
  if (has('nuclei')) {
    run('nuclei', ['-update-templates', '-silent']);
    const v = run('nuclei', ['-version']), t = run('nuclei', ['-templates-version']);
    versions.push(...`${v.stdout}\n${v.stderr}\n${t.stdout}\n${t.stderr}`.split('\n').filter((l) => /version/i.test(l)).map((l) => l.trim()));
  }
  if (has('testssl.sh')) versions.push(first(run('testssl.sh', ['--color', '0', '--version']).stdout.split('\n').filter((l) => /testssl/.test(l)).join('\n')));
  versions.push(`node ${process.version}`);
  writeFileSync(out(`scanner-versions-${stamp}.txt`), versions.filter(Boolean).join('\n') + '\n');

  for (const [component, path] of Object.entries(cfg.trivyPaths || {})) {
    if (!has('trivy')) { skip(`trivy-${component}`, 'trivy is not installed'); continue; }
    if (!existsSync(path)) { skip(`trivy-${component}`, `${path} does not exist`); continue; }
    run('trivy', ['fs', '--quiet', '--scanners', 'vuln,secret,misconfig', '--format', 'json', '--output', out(`trivy-${component}-${stamp}.json`), path]);
  }

  const cf = scans.cloudflare;
  const account = env.CLOUDFLARE_ACCOUNT_ID, cfGet = get || (env.CLOUDFLARE_API_TOKEN && cloudflareApi(env.CLOUDFLARE_API_TOKEN, fetcher));
  if (cf?.deployedWorkers?.length) {
    if (!cfGet || !account) skip('deployed-code', 'CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID are not set');
    else {
      // The code each Worker actually runs, scanned like source (a bundle has no package manifest, so only secrets and
      // misconfiguration are found in it; dependencies come from the source scan).
      const code = mkdtempSync(join(tmpdir(), 'conmon-code-'));
      const read = await deployedCode({ account, workers: cf.deployedWorkers, get: cfGet });
      const seen = new Set();
      for (const w of read.filter((x) => !x.error).sort((a, b) => b.percentage - a.percentage)) {
        const name = seen.has(w.worker) ? `${w.worker}@${w.version.slice(0, 8)}` : w.worker;
        seen.add(w.worker);
        for (const m of w.modules) { mkdirSync(dirname(join(code, name, m.name)), { recursive: true }); writeFileSync(join(code, name, m.name), m.bytes); }
        if (has('trivy')) run('trivy', ['fs', '--quiet', '--scanners', 'vuln,secret,misconfig', '--format', 'json', '--output', out(`trivy-deployed-${name}-${stamp}.json`), join(code, name)]);
      }
      rmSync(code, { recursive: true, force: true });
      const record = read.map((w) => (w.error ? w : { ...w, modules: w.modules.map((m) => ({ name: m.name, bytes: m.bytes.length, sha256: m.sha256 })) }));
      writeFileSync(out(`deployed-code-${stamp}.json`), JSON.stringify({ checkedAt: now.toISOString(), workers: record }, null, 1) + '\n');
      if (!has('trivy')) skip('trivy-deployed', 'trivy is not installed');
    }
  }

  if (scans.nuclei?.url) {
    if (!has('nuclei')) skip('nuclei', 'nuclei is not installed');
    else {
      // Every template except denial-of-service and intrusive ones by default, at 10 requests a second. Templates were
      // updated in the versions step, so the scanner's own update check (which can stall a run) is skipped.
      const cookie = env.SCAN_COOKIE;
      writeFileSync(out(`nuclei-${stamp}.auth`), (cookie ? 'authenticated' : 'unauthenticated') + '\n');
      run('nuclei', ['-u', scans.nuclei.url, ...(scans.nuclei.tags?.length ? ['-tags', scans.nuclei.tags.join(',')] : []),
        '-etags', (scans.nuclei.excludeTags || ['dos', 'intrusive']).join(','), '-rate-limit', String(scans.nuclei.rateLimit || 10),
        '-concurrency', '5', '-disable-update-check', '-silent', '-no-color', '-jsonl', '-o', out(`nuclei-${stamp}.jsonl`), ...(cookie ? ['-H', `Cookie: ${cookie}`] : [])]);
      if (!existsSync(out(`nuclei-${stamp}.jsonl`))) writeFileSync(out(`nuclei-${stamp}.jsonl`), '');
    }
  }

  if (scans.testssl?.url) {
    if (!has('testssl.sh')) skip('testssl', 'testssl.sh is not installed');
    else run('testssl.sh', ['--quiet', '--warnings', 'off', '--overwrite', '--jsonfile', out(`testssl-${stamp}.json`), '--csvfile', out(`testssl-${stamp}.csv`), scans.testssl.url]);
  }

  if (scans.headers?.length) {
    const lines = [];
    for (const url of scans.headers) {
      try {
        const r = await fetcher(url, { method: 'HEAD', redirect: 'manual' });
        lines.push(`# HEAD ${url}`, `HTTP ${r.status}`, ...[...r.headers].map(([k, v]) => `${k}: ${v}`), '');
      } catch (e) { lines.push(`# HEAD ${url}`, `failed: ${e.message}`, ''); }
    }
    writeFileSync(out(`headers-${stamp}.txt`), lines.join('\n'));
  }

  if (scans.dependabot?.repo) {
    if (!has('gh')) skip('dependabot', 'the GitHub CLI (gh) is not installed');
    else {
      const r = run('gh', ['api', `repos/${scans.dependabot.repo}/dependabot/alerts?state=open&per_page=100`, '--paginate', '--slurp']);
      if (r.status === 0) writeFileSync(out(`dependabot-${stamp}.json`), r.stdout);
      else skip('dependabot', `gh api failed: ${first(r.stderr)}`);
    }
  }

  if (scans.workstation) {
    const sh = (cmd, args) => { const r = run(cmd, args, { timeoutMs: 300000 }); return `$ ${[cmd, ...args].join(' ')}\n${(r.stdout + r.stderr).trim()}`; };
    const facts = platform() === 'darwin'
      ? [sh('scutil', ['--get', 'ComputerName']), sh('sw_vers', []), sh('fdesetup', ['status']), sh('/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getglobalstate']), sh('softwareupdate', ['--list'])]
      : [sh('uname', ['-srm']), existsSync('/etc/os-release') ? `$ cat /etc/os-release\n${readFileSync('/etc/os-release', 'utf8').trim()}` : ''];
    writeFileSync(out(`workstation-${stamp}.txt`), `# ${stamp}\n${facts.filter(Boolean).join('\n\n')}\n`);
  }

  if (cf?.zone) {
    if (!cfGet || !account) skip('check-cloudflare', 'CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID are not set');
    else {
      const write = (name, source, rows) => {
        writeFileSync(out(`check-${name}-${stamp}.json`), JSON.stringify({ checkedAt: now.toISOString(), source, asset: cf.zone, rows }, null, 1) + '\n');
        writeFileSync(out(`check-${name}-${stamp}.csv`), rowsCsv(rows));
      };
      const workers = (cfg.inventoryData?.assets || []).filter((a) => a.kind === 'code' && a.worker).map((a) => a.worker);
      write('cloudflare', 'Cloudflare settings check', await settingsCheck({ account, zone: cf.zone, workers, get: cfGet, probe: probes(cf.zone, cf.path || '/', fetcher) }));
      if (cfg.inventoryData) write('cloudflare-inventory', 'Cloudflare inventory check', await inventoryCheck({ account, zone: cf.zone, inventory: cfg.inventoryData, routePrefixes: cf.routePrefixes || null, get: cfGet }));
    }
  }

  return { dir, ...report(dir, cfg, { today: stamp }) };
}

export function report(dir, cfg, { today = localDay() } = {}) {
  const config = settings(cfg);
  writeFileSync(join(dir, `scan-results-${today}.csv`), resultsCsv(dir));
  writeFileSync(join(dir, `scan-summary-${today}.md`), summary(dir, { inventory: cfg.inventoryData || { assets: [] }, config, day: today }));
  const items = buildPoam({ dir, gapFile: cfg.gapAssessment, today, inventory: cfg.inventoryData, config });
  // Written beside and then moved: a re-run the same day carries forward from today's earlier POA&M.
  writeFileSync(join(dir, `poam-${today}.csv.new`), toCsv(items, config));
  renameSync(join(dir, `poam-${today}.csv.new`), join(dir, `poam-${today}.csv`));
  const open = items.filter((i) => i.status === 'Open' && i.boundary === config.system);
  return {
    files: [`scan-results-${today}.csv`, `scan-summary-${today}.md`, `poam-${today}.csv`],
    open: Object.fromEntries(['High', 'Moderate', 'Low'].map((r) => [r, open.filter((i) => i.risk === r).length])),
    closed: items.filter((i) => i.status === 'Closed').length,
    outsideBoundary: items.filter((i) => i.boundary !== config.system).length
  };
}

// Run as a command, also through an npm bin symlink or from a path with spaces.
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  const args = process.argv.slice(2);
  const flag = (name) => { const i = args.indexOf(name); return i >= 0 ? args.splice(i, 2)[1] : null; };
  const configPath = flag('--config') || 'conmon.json', today = flag('--today');
  const [command, target] = args;
  if (!['scan', 'report'].includes(command) || !target || (today && !/^\d{4}-\d{2}-\d{2}$/.test(today))) {
    console.error('usage: conmon scan <evidence-dir> [--config conmon.json]\n       conmon report <month-dir> [--config conmon.json] [--today YYYY-MM-DD]');
    process.exit(2);
  }
  try {
    const cfg = loadConfig(configPath);
    const r = command === 'scan' ? await scan(target, cfg, { log: (m) => console.log(m) }) : { dir: target, ...report(target, cfg, today ? { today } : {}) };
    console.log(`${r.dir}: ${r.files.join(', ')}`);
    console.log(`POA&M: ${r.open.High} high, ${r.open.Moderate} moderate, ${r.open.Low} low open; ${r.closed} closed${r.outsideBoundary ? `; ${r.outsideBoundary} outside the boundary` : ''}`);
  } catch (error) {
    console.error(error.message);
    process.exit(2);
  }
}
