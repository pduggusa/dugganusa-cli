#!/usr/bin/env node

const { serve } = require('./lib/serve');

const args = process.argv.slice(2);

function usage() {
  process.stderr.write(
    [
      'dugganusa-mcp — local STDIO MCP server for DugganUSA threat intelligence',
      '',
      'Usage:',
      '  dugganusa-mcp [--api-key KEY] [--upstream URL] [--dredd-gate]',
      '  dugganusa-mcp --version',
      '',
      'Environment:',
      '  DUGGANUSA_API_KEY    API key for higher rate limits (optional)',
      '  DUGGANUSA_UPSTREAM   override upstream (default: https://analytics.dugganusa.com)',
      '',
      'Tools exposed: search, enrich-ioc, stix-feed-summary. Read-only. No exec paths.',
      'Audit source: github.com/pduggusa/dugganusa-cli/tree/main/mcp',
      ''
    ].join('\n')
  );
}

function flag(name) {
  const i = args.indexOf(name);
  if (i === -1) return undefined;
  const v = args[i + 1];
  return v && !v.startsWith('--') ? v : true;
}

(async () => {
  if (args.includes('--version') || args.includes('-v')) {
    process.stdout.write(require('../package.json').version + '\n');
    return;
  }
  if (args.includes('--help') || args.includes('-h')) {
    usage();
    return;
  }
  await serve({
    apiKey: flag('--api-key') || process.env.DUGGANUSA_API_KEY,
    upstream: flag('--upstream') || process.env.DUGGANUSA_UPSTREAM || 'https://analytics.dugganusa.com',
    dreddGate: !!flag('--dredd-gate')
  });
})().catch((err) => {
  process.stderr.write(`fatal: ${err.message}\n`);
  process.exit(1);
});
