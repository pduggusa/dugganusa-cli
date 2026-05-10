const https = require('https');
const { URL } = require('url');

function request(upstream, path, { apiKey, query } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(path, upstream);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null) u.searchParams.set(k, String(v));
      }
    }
    const headers = { accept: 'application/json' };
    if (apiKey) headers.authorization = `Bearer ${apiKey}`;
    const req = https.request(
      { method: 'GET', hostname: u.hostname, path: u.pathname + u.search, headers, timeout: 15000 },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode >= 400) {
            return reject(new Error(`upstream ${res.statusCode}: ${body.slice(0, 300)}`));
          }
          try {
            resolve(JSON.parse(body));
          } catch (e) {
            reject(new Error(`upstream parse error: ${e.message}`));
          }
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('upstream timeout')));
    req.on('error', reject);
    req.end();
  });
}

module.exports = { request };
