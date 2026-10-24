// Monthly scan summary report: Executive Summary, Detailed Summary and Inventory Report, as Markdown. Built from the same
// scan files and inventory as the POA&M, so the two always agree.
import { readdirSync } from 'node:fs';
import { basename } from 'node:path';
import { coverage, coverageItems, localDay, scanItems, settings } from './poam.mjs';

const esc = (v) => String(v ?? '').replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
const table = (head, rows) => [`| ${head.join(' | ')} |`, `|${head.map(() => '---').join('|')}|`, ...rows.map((r) => `| ${r.map(esc).join(' | ')} |`)].join('\n');
const RISKS = ['High', 'Moderate', 'Low'];

export function summary(dir, { inventory = { assets: [] }, config = {}, day = localDay() } = {}) {
  const cfg = settings(config);
  const { items, ran } = scanItems(dir, day, cfg);
  const covered = coverage(dir, inventory);
  const inside = items.filter((i) => i.boundary === cfg.system);
  const findings = [...inside, ...coverageItems(covered, day, cfg)];
  // Every scanner that ran is listed, including those with nothing to report.
  const sources = [...new Set([...ran, ...findings.map((i) => i.source)])].sort();
  const versions = readdirSync(dir).filter((f) => /^scanner-versions-.*\.txt$/.test(f)).sort().pop();
  const skipped = readdirSync(dir).filter((f) => f.endsWith('.skipped')).sort();
  const web = covered.find((a) => a.url);
  const unscanned = (a) => (a.kind === 'managed' ? 'none: managed service with no customer-scannable OS or database engine (request a scan exception)' : 'none');
  return [
    `# ${cfg.system} monthly vulnerability scan summary, ${basename(dir)}`, '',
    `${[cfg.organization, cfg.system].filter(Boolean).join(' · ')} · generated ${day} from the scan files in \`${basename(dir)}\`. Asset IDs match the boundary inventory.`, '',
    '## Executive Summary', '',
    table(['Source', ...RISKS, 'Total'], sources.map((s) => {
      const list = findings.filter((i) => i.source === s);
      return [s, ...RISKS.map((r) => list.filter((i) => i.risk === r).length), list.length];
    })),
    '',
    `- ${covered.filter((a) => a.scans.length).length} of ${covered.length} inventory assets were covered by at least one scan.`,
    `- Web application scan${web ? ` of ${web.url}` : ''}: ${web?.webAuth || 'none'}.`,
    ...(items.length > inside.length ? [`- ${items.length - inside.length} findings are outside the boundary. The POA&M lists them as "Outside boundary"; they are not counted here.`] : []),
    versions ? `- Scanner, engine and signature versions are recorded in \`${versions}\`.` : '- Scanner versions were not recorded this month.',
    ...(skipped.length ? [`- Not run this month: ${skipped.map((f) => `\`${f}\``).join(', ')}.`] : []),
    '', '## Detailed Summary', '',
    findings.length
      ? table(['Source', 'Finding', 'Risk', 'Asset', 'Description', 'Remediation'], findings.map((i) => [i.source, i.name, i.risk, i.asset, i.description, i.plan]))
      : 'No findings.',
    '', '## Inventory Report', '',
    covered.length ? table(['Asset ID', 'Name', 'Kind', 'Scans this month'], covered.map((a) => [a.id, a.name, a.kind, a.scans.join('; ') || unscanned(a)])) : 'No inventory was given.',
    ''
  ].join('\n');
}
