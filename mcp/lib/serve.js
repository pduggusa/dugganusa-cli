const readline = require('readline');
const { TOOLS, HANDLERS } = require('./tools');

const PROTOCOL_VERSION = '2025-03-26';
const SERVER_INFO = {
  name: 'dugganusa-cli',
  version: require('../../package.json').version
};

function reply(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function fail(id, code, message, data) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  return { jsonrpc: '2.0', id, error };
}

function dreddVerdict(ctx, toolName, args) {
  if (!ctx.dreddGate) return { decision: 'ALLOW', reason: 'gate disabled' };
  const tool = TOOLS.find((t) => t.name === toolName);
  if (!tool) return { decision: 'BLOCK', reason: 'unknown tool' };
  if (toolName === 'enrich-ioc' && !args?.ip) return { decision: 'BLOCK', reason: 'missing ip' };
  if (toolName === 'search' && !args?.q) return { decision: 'BLOCK', reason: 'missing query' };
  process.stderr.write(`[dredd] ALLOW ${toolName} args=${JSON.stringify(args).slice(0, 200)}\n`);
  return { decision: 'ALLOW', reason: 'local policy' };
}

async function dispatch(msg, ctx) {
  const { id, method, params } = msg;

  if (method === 'initialize') {
    return reply(id, {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: { listChanged: false } },
      serverInfo: SERVER_INFO,
      instructions:
        'DugganUSA threat intelligence MCP. Read-only. Local STDIO binary; customer owns the process. ' +
        'Tools: search, enrich-ioc, stix-feed-summary. Upstream: ' + ctx.upstream
    });
  }

  if (method === 'notifications/initialized' || method === 'notifications/cancelled') {
    return null;
  }

  if (method === 'ping') {
    return reply(id, {});
  }

  if (method === 'tools/list') {
    return reply(id, { tools: TOOLS });
  }

  if (method === 'tools/call') {
    const name = params?.name;
    const args = params?.arguments ?? {};
    const verdict = dreddVerdict(ctx, name, args);
    if (verdict.decision === 'BLOCK') {
      return reply(id, {
        isError: true,
        content: [{ type: 'text', text: `dredd BLOCK: ${verdict.reason}` }]
      });
    }
    const handler = HANDLERS[name];
    if (!handler) return fail(id, -32601, `unknown tool: ${name}`);
    try {
      const result = await handler(args, ctx);
      return reply(id, {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      });
    } catch (err) {
      return reply(id, {
        isError: true,
        content: [{ type: 'text', text: `tool error: ${err.message}` }]
      });
    }
  }

  return fail(id, -32601, `method not found: ${method}`);
}

async function serve(opts) {
  const ctx = {
    upstream: opts.upstream,
    apiKey: opts.apiKey,
    dreddGate: opts.dreddGate === true
  };

  process.stderr.write(
    `dugganusa-cli ${SERVER_INFO.version} mcp serve → ${ctx.upstream} ` +
      `(dredd ${ctx.dreddGate ? 'enabled' : 'off'}, auth ${ctx.apiKey ? 'on' : 'anonymous'})\n`
  );

  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  const inFlight = new Set();

  rl.on('line', (line) => {
    if (!line.trim()) return;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch (e) {
      const resp = fail(null, -32700, `parse error: ${e.message}`);
      process.stdout.write(JSON.stringify(resp) + '\n');
      return;
    }
    const p = (async () => {
      const resp = await dispatch(msg, ctx);
      if (resp !== null && msg.id !== undefined) {
        process.stdout.write(JSON.stringify(resp) + '\n');
      }
    })();
    inFlight.add(p);
    p.finally(() => inFlight.delete(p));
  });

  rl.on('close', async () => {
    await Promise.allSettled(inFlight);
    process.exit(0);
  });
}

module.exports = { serve, dispatch, dreddVerdict, TOOLS };
