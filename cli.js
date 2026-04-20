#!/usr/bin/env node
/**
 * dugganusa-lookup — CLI threat intel scanner
 *
 * Check IPs, domains, hashes, CVEs against 1.08M+ IOCs from your terminal.
 *
 * Usage:
 *   npx dugganusa-lookup 185.39.19.176
 *   npx dugganusa-lookup --file config.js
 *   cat firewall.log | npx dugganusa-lookup --stdin
 *   npx dugganusa-lookup --aipm google.com
 *   npx dugganusa-lookup --batch iocs.txt
 *   npx dugganusa-lookup --format json 185.39.19.176
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

// ============================================================================
// Inline core (self-contained — no external deps for npx compatibility)
// ============================================================================

const PATTERNS = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g,
  domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ai|dev|xyz|info|biz|co|me|app|cloud|online|site|tech|ru|cn|ir|kp|de|fr|nl|uk|au|br|jp|kr|sg|il|sa|ae|onion)\b/gi,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  cve: /CVE-\d{4}-\d{4,7}/gi,
};

const SKIP_IPS = new Set([
  '0.0.0.0','127.0.0.1','255.255.255.255','10.0.0.1','192.168.0.1','192.168.1.1',
  '172.16.0.1','8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1','9.9.9.9',
]);

const SKIP_DOMAINS = new Set([
  'github.com','google.com','microsoft.com','apple.com','amazon.com','cloudflare.com',
  'mozilla.org','apache.org','example.com','localhost','npmjs.com','nodejs.org',
  'w3.org','schema.org','dugganusa.com','youtube.com','twitter.com','linkedin.com',
  'stackoverflow.com','wikipedia.org','reddit.com',
]);

function extractIOCs(text) {
  const iocs = [];
  for (const [type, regex] of Object.entries(PATTERNS)) {
    for (const m of text.matchAll(regex)) {
      if (type === 'ipv4' && SKIP_IPS.has(m[0])) continue;
      if (type === 'domain' && SKIP_DOMAINS.has(m[0].toLowerCase())) continue;
      iocs.push({ value: m[0], type });
    }
  }
  const seen = new Set();
  return iocs.filter(i => { if (seen.has(i.value.toLowerCase())) return false; seen.add(i.value.toLowerCase()); return true; });
}

function httpGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers, timeout: 10000 }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch { reject(new Error('Invalid JSON')); } });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

async function lookupIOC(value, apiKey, apiUrl) {
  const url = new URL(apiUrl + '/search/correlate');
  url.searchParams.set('q', value);
  const headers = {};
  if (apiKey) headers['Authorization'] = 'Bearer ' + apiKey;
  try {
    const json = await httpGet(url.toString(), headers);
    const correlations = json.data?.correlations || {};
    const hits = Object.values(correlations).reduce((s, h) => s + (Array.isArray(h) ? h.length : 0), 0);
    return hits > 0 ? { found: true, hits, data: correlations } : { found: false, hits: 0 };
  } catch (e) { return { found: false, hits: 0, error: e.message }; }
}

function summarize(data) {
  if (!data) return '';
  const parts = [];
  for (const [idx, hits] of Object.entries(data)) {
    if (!Array.isArray(hits) || !hits.length) continue;
    const f = hits[0];
    if (idx === 'iocs') parts.push('IOC: ' + (f.malware_family || f.threat_type || '?') + ' (via ' + (f.source || '?') + ')');
    else if (idx === 'block_events') parts.push('Blocked ' + hits.length + 'x');
    else if (idx === 'pulses') parts.push(hits.length + ' OTX pulse(s)');
    else if (idx === 'adversaries') parts.push('Adversary: ' + (f.name || '?'));
    else if (idx === 'cisa_kev') parts.push('CISA KEV');
    else parts.push(idx + ': ' + hits.length);
  }
  return parts.join(' | ');
}

// ============================================================================
// CLI
// ============================================================================

const USAGE = `
  dugganusa-lookup — Threat intel from your terminal. 1.08M+ IOCs.

  USAGE
    dugganusa-lookup <indicator>              Look up a single IP/domain/hash/CVE
    dugganusa-lookup --file <path>            Scan a file for IOCs
    dugganusa-lookup --stdin                  Scan stdin (pipe-friendly)
    dugganusa-lookup --batch <path>           Batch lookup (one IOC per line)
    dugganusa-lookup --aipm <domain>          AIPM audit URL for a domain
    dugganusa-lookup --tor-check <ip>         Check if an IP is a known Tor relay
    dugganusa-lookup --tor-hunt               Show suspicious Tor relays (sorted by score)
    dugganusa-lookup --tor-stats              Tor network summary statistics

  OPTIONS
    --key <api-key>       DugganUSA API key (or set DUGGANUSA_API_KEY env var)
    --format <fmt>        Output format: table (default), json, markdown
    --quiet               Only show matches (suppress clean results)
    --help                Show this help

  EXAMPLES
    dugganusa-lookup 185.39.19.176
    dugganusa-lookup CVE-2026-21643
    dugganusa-lookup --file terraform/main.tf --format markdown
    cat /var/log/auth.log | dugganusa-lookup --stdin --quiet
    dugganusa-lookup --aipm crowdstrike.com
    dugganusa-lookup --tor-check 185.220.101.42
    dugganusa-lookup --tor-hunt
    dugganusa-lookup --tor-stats

  FREE API KEY
    https://analytics.dugganusa.com/stix/register

  MORE
    https://github.com/pduggusa/dugganusa-cli
    https://www.dugganusa.com
`;

async function main() {
  const args = process.argv.slice(2);
  if (!args.length || args.includes('--help') || args.includes('-h')) {
    console.log(USAGE);
    process.exit(0);
  }

  // Parse flags
  const keyIdx = args.indexOf('--key');
  const apiKey = keyIdx >= 0 ? args.splice(keyIdx, 2)[1] : process.env.DUGGANUSA_API_KEY || '';
  const apiUrl = process.env.DUGGANUSA_API_URL || 'https://analytics.dugganusa.com/api/v1';

  const fmtIdx = args.indexOf('--format');
  const format = fmtIdx >= 0 ? args.splice(fmtIdx, 2)[1] : 'table';

  const quiet = args.includes('--quiet');
  if (quiet) args.splice(args.indexOf('--quiet'), 1);

  // AIPM mode
  if (args[0] === '--aipm') {
    const domain = args[1];
    if (!domain) { console.error('Usage: dugganusa-lookup --aipm <domain>'); process.exit(1); }
    const clean = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    console.log('AIPM Audit: https://aipmsec.com/audit.html?domain=' + encodeURIComponent(clean));
    process.exit(0);
  }

  // Tor check mode
  if (args[0] === '--tor-check') {
    const ip = args[1];
    if (!ip) { console.error('Usage: dugganusa-lookup --tor-check <ip>'); process.exit(1); }
    const url = apiUrl + '/tor/relays?q=' + encodeURIComponent(ip) + '&limit=1';
    const headers = {};
    if (apiKey) headers['Authorization'] = 'Bearer ' + apiKey;
    try {
      const json = await httpGet(url, headers);
      const relays = json.data?.relays || json.data || [];
      if (!relays.length) {
        console.log('\n  ' + ip + ' is NOT a known Tor relay.');
        process.exit(0);
      }
      const r = relays[0];
      console.log('\n  Tor Relay Found!');
      console.log('  ─────────────────────────────────────');
      console.log('  IP:         ' + ip);
      if (r.nickname) console.log('  Nickname:   ' + r.nickname);
      if (r.flags) console.log('  Flags:      ' + (Array.isArray(r.flags) ? r.flags.join(', ') : r.flags));
      if (r.country) console.log('  Country:    ' + r.country);
      if (r.asn || r.as_name) console.log('  ASN:        ' + (r.asn || '') + (r.as_name ? ' (' + r.as_name + ')' : ''));
      if (r.bandwidth != null) console.log('  Bandwidth:  ' + r.bandwidth);
      console.log('');
    } catch (e) { console.error('Error checking Tor relay:', e.message); process.exit(2); }
    process.exit(0);
  }

  // Tor hunt mode
  if (args[0] === '--tor-hunt') {
    const url = apiUrl + '/tor/hunt';
    const headers = {};
    if (apiKey) headers['Authorization'] = 'Bearer ' + apiKey;
    try {
      const json = await httpGet(url, headers);
      const relays = json.data?.relays || json.data || [];
      if (!relays.length) {
        console.log('\n  No suspicious Tor relays found.');
        process.exit(0);
      }
      console.log('\n  Suspicious Tor Relays (sorted by score)');
      console.log('  ─────────────────────────────────────────────────────────────────────');
      console.log('  ' + 'Score'.padEnd(7) + 'IP'.padEnd(18) + 'Nickname'.padEnd(20) + 'Country'.padEnd(10) + 'Flags');
      console.log('  ' + '─────'.padEnd(7) + '──'.padEnd(18) + '────────'.padEnd(20) + '───────'.padEnd(10) + '─────');
      for (const r of relays) {
        const score = String(r.score || 0).padEnd(7);
        const ip = (r.ip || r.address || '?').padEnd(18);
        const nick = (r.nickname || '?').padEnd(20);
        const country = (r.country || '?').padEnd(10);
        const flags = Array.isArray(r.flags) ? r.flags.join(', ') : (r.flags || '');
        console.log('  ' + score + ip + nick + country + flags);
      }
      console.log('\n  ' + relays.length + ' suspicious relay(s) found.');
      console.log('');
    } catch (e) { console.error('Error running Tor hunt:', e.message); process.exit(2); }
    process.exit(0);
  }

  // Tor stats mode
  if (args[0] === '--tor-stats') {
    const url = apiUrl + '/tor/stats';
    const headers = {};
    if (apiKey) headers['Authorization'] = 'Bearer ' + apiKey;
    try {
      const json = await httpGet(url, headers);
      const s = json.data || json;
      console.log('\n  Tor Network Summary');
      console.log('  ─────────────────────────────────────');
      if (s.total_relays != null) console.log('  Total Relays:   ' + s.total_relays.toLocaleString());
      if (s.exit_nodes != null) console.log('  Exit Nodes:     ' + s.exit_nodes.toLocaleString());
      if (s.guard_nodes != null) console.log('  Guard Nodes:    ' + s.guard_nodes.toLocaleString());
      if (s.countries != null) console.log('  Countries:      ' + s.countries.toLocaleString());
      if (s.top_asns && Array.isArray(s.top_asns)) {
        console.log('  Top ASNs:');
        for (const asn of s.top_asns.slice(0, 10)) {
          console.log('    ' + (asn.asn || asn.name || '?').toString().padEnd(12) + ' ' + (asn.count || asn.relays || 0) + ' relays');
        }
      }
      console.log('');
    } catch (e) { console.error('Error fetching Tor stats:', e.message); process.exit(2); }
    process.exit(0);
  }

  // Determine input source
  let text = '';
  if (args[0] === '--file') {
    const filePath = args[1];
    if (!filePath || !fs.existsSync(filePath)) { console.error('File not found: ' + (filePath || '(none)')); process.exit(1); }
    text = fs.readFileSync(filePath, 'utf8');
  } else if (args[0] === '--stdin') {
    text = fs.readFileSync(0, 'utf8'); // read stdin
  } else if (args[0] === '--batch') {
    const filePath = args[1];
    if (!filePath || !fs.existsSync(filePath)) { console.error('File not found: ' + (filePath || '(none)')); process.exit(1); }
    const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const results = [];
    for (const value of lines) {
      process.stderr.write('Checking: ' + value + '...\r');
      const r = await lookupIOC(value, apiKey, apiUrl);
      results.push({ value, ...r });
    }
    outputResults(results, format, quiet);
    process.exit(results.some(r => r.found) ? 1 : 0);
  } else {
    // Single indicator(s) as positional args
    const values = args.filter(a => !a.startsWith('--'));
    if (!values.length) { console.log(USAGE); process.exit(0); }
    const results = [];
    for (const value of values) {
      process.stderr.write('Checking: ' + value + '...\r');
      const r = await lookupIOC(value, apiKey, apiUrl);
      results.push({ value, ...r });
    }
    outputResults(results, format, quiet);
    process.exit(results.some(r => r.found) ? 1 : 0);
  }

  // File/stdin mode — extract then lookup
  if (text) {
    const iocs = extractIOCs(text);
    if (!iocs.length) {
      console.log('No IOC candidates found in input.');
      process.exit(0);
    }
    console.error('Found ' + iocs.length + ' IOC candidate(s). Checking...');
    const results = [];
    for (const ioc of iocs.slice(0, 50)) { // cap at 50 to respect rate limits
      process.stderr.write('Checking: ' + ioc.value + '...\r');
      const r = await lookupIOC(ioc.value, apiKey, apiUrl);
      results.push({ value: ioc.value, type: ioc.type, ...r });
    }
    if (iocs.length > 50) console.error('(capped at 50 lookups — ' + (iocs.length - 50) + ' skipped)');
    outputResults(results, format, quiet);
    process.exit(results.some(r => r.found) ? 1 : 0);
  }
}

function outputResults(results, format, quiet) {
  const filtered = quiet ? results.filter(r => r.found) : results;
  if (!filtered.length) {
    if (quiet) return;
    console.log('\n  All clean. No threat indicators found.');
    return;
  }

  process.stderr.write('\r' + ' '.repeat(60) + '\r'); // clear progress line

  switch (format) {
    case 'json':
      console.log(JSON.stringify({
        scanned: results.length,
        found: results.filter(r => r.found).length,
        results: filtered.map(r => ({
          value: r.value, found: r.found, hits: r.hits || 0,
          summary: r.found ? summarize(r.data) : null
        })),
        timestamp: new Date().toISOString(),
      }, null, 2));
      break;

    case 'markdown':
      console.log('| Status | Value | Hits | Summary |');
      console.log('|--------|-------|------|---------|');
      for (const r of filtered) {
        console.log('| ' + (r.found ? 'WARNING' : 'clean') + ' | `' + r.value + '` | ' + (r.hits||0) + ' | ' + (r.found ? summarize(r.data) : '') + ' |');
      }
      console.log('\n**' + results.filter(r=>r.found).length + '** threat indicator(s) in ' + results.length + ' checked.');
      break;

    default: // table
      console.log('');
      for (const r of filtered) {
        const icon = r.found ? '  !! ' : '  OK ';
        const hits = String(r.hits || 0).padStart(4);
        const val = r.value.padEnd(45).slice(0,45);
        const sum = r.found ? summarize(r.data) : 'clean';
        console.log(icon + hits + '  ' + val + ' ' + sum);
      }
      const found = results.filter(r => r.found).length;
      console.log('\n  ' + found + ' threat indicator(s) found in ' + results.length + ' checked.');
      if (found) console.log('  Full enrichment: https://analytics.dugganusa.com/api/v1/search/correlate?q=<indicator>');
      console.log('  Free API key: https://analytics.dugganusa.com/stix/register');
      break;
  }
}

main().catch(err => { console.error('Error:', err.message); process.exit(2); });
