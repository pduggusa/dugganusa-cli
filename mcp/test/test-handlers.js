const assert = require('assert');
const { dispatch } = require('../lib/serve');

const UPSTREAM = process.env.DUGGANUSA_UPSTREAM || 'https://analytics.dugganusa.com';
const API_KEY = process.env.DUGGANUSA_API_KEY;

let pass = 0;
let fail = 0;
const failures = [];

async function check(name, fn) {
  try {
    await fn();
    pass++;
    process.stdout.write(`  ok  ${name}\n`);
  } catch (e) {
    fail++;
    failures.push({ name, err: e });
    process.stdout.write(`  FAIL ${name}: ${e.message}\n`);
  }
}

async function main() {
  const ctx = { upstream: UPSTREAM, apiKey: API_KEY, dreddGate: false };

  process.stdout.write('dispatch surface\n');

  await check('initialize returns serverInfo + protocolVersion', async () => {
    const r = await dispatch({ jsonrpc: '2.0', id: 1, method: 'initialize' }, ctx);
    assert.strictEqual(r.jsonrpc, '2.0');
    assert.strictEqual(r.id, 1);
    assert.ok(r.result.serverInfo.name === 'dugganusa-cli');
    assert.ok(r.result.protocolVersion);
    assert.ok(r.result.capabilities.tools);
  });

  await check('tools/list returns all three tools', async () => {
    const r = await dispatch({ jsonrpc: '2.0', id: 2, method: 'tools/list' }, ctx);
    assert.strictEqual(r.result.tools.length, 3);
    const names = r.result.tools.map((t) => t.name).sort();
    assert.deepStrictEqual(names, ['enrich-ioc', 'search', 'stix-feed-summary']);
    for (const t of r.result.tools) {
      assert.ok(t.description && t.description.length > 20, `${t.name} missing description`);
      assert.ok(t.inputSchema && t.inputSchema.type === 'object', `${t.name} bad schema`);
    }
  });

  await check('ping returns empty result', async () => {
    const r = await dispatch({ jsonrpc: '2.0', id: 3, method: 'ping' }, ctx);
    assert.deepStrictEqual(r.result, {});
  });

  await check('unknown method returns -32601', async () => {
    const r = await dispatch({ jsonrpc: '2.0', id: 4, method: 'totally/fake' }, ctx);
    assert.strictEqual(r.error.code, -32601);
  });

  await check('notifications/initialized returns null (no reply)', async () => {
    const r = await dispatch({ jsonrpc: '2.0', method: 'notifications/initialized' }, ctx);
    assert.strictEqual(r, null);
  });

  await check('dredd gate blocks search with empty q when enabled', async () => {
    const gated = { ...ctx, dreddGate: true };
    const r = await dispatch(
      { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'search', arguments: {} } },
      gated
    );
    assert.ok(r.result.isError, 'expected isError');
    assert.ok(r.result.content[0].text.startsWith('dredd BLOCK'), r.result.content[0].text);
  });

  await check('dredd gate blocks unknown tool when enabled', async () => {
    const gated = { ...ctx, dreddGate: true };
    const r = await dispatch(
      { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'rm-rf', arguments: {} } },
      gated
    );
    assert.ok(r.result.isError);
    assert.ok(r.result.content[0].text.startsWith('dredd BLOCK'));
  });

  if (!API_KEY) {
    process.stdout.write('\nupstream surface — SKIPPED (no DUGGANUSA_API_KEY in env)\n');
    process.stdout.write(`  ${pass} pass, ${fail} fail (live-net tests skipped)\n`);
    return;
  }

  process.stdout.write('\nupstream surface (live network calls)\n');

  await check('search?q=185.39.19.176 returns hits or empty array', async () => {
    const r = await dispatch(
      { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'search', arguments: { q: '185.39.19.176', limit: 3 } } },
      ctx
    );
    assert.ok(!r.result.isError, `unexpected error: ${r.result.content?.[0]?.text}`);
    const body = JSON.parse(r.result.content[0].text);
    assert.ok('totalHits' in body, 'missing totalHits');
    assert.ok(Array.isArray(body.hits), 'hits should be array');
  });

  await check('stix-feed-summary returns index stats', async () => {
    const r = await dispatch(
      { jsonrpc: '2.0', id: 8, method: 'tools/call', params: { name: 'stix-feed-summary', arguments: {} } },
      ctx
    );
    assert.ok(!r.result.isError, `unexpected error: ${r.result.content?.[0]?.text}`);
    const body = JSON.parse(r.result.content[0].text);
    assert.ok(body.feed.url.includes('stix-feed'), 'missing feed url');
    assert.ok(body.indexes, 'missing indexes block');
  });

  await check('enrich-ioc on a known IP returns data block', async () => {
    const r = await dispatch(
      { jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'enrich-ioc', arguments: { ip: '8.8.8.8' } } },
      ctx
    );
    assert.ok(!r.result.isError, `unexpected error: ${r.result.content?.[0]?.text}`);
    const body = JSON.parse(r.result.content[0].text);
    assert.ok(body, 'empty body');
  });

  process.stdout.write(`\n${pass} pass, ${fail} fail\n`);
  if (fail) {
    for (const f of failures) process.stdout.write(`  - ${f.name}: ${f.err.stack || f.err.message}\n`);
    process.exit(1);
  }
}

main().catch((e) => {
  process.stderr.write(`fatal: ${e.stack || e.message}\n`);
  process.exit(2);
});
