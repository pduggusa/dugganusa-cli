# dugganusa-cli

**Threat intel from your terminal. 1,080,000+ IOCs. Plus a local MCP server.**

```bash
# Scanner — check an IOC
npx dugganusa-lookup 185.39.19.176

# MCP server — wire DugganUSA into Claude Desktop / Cursor / Claude Code
npx dugganusa-mcp
```

This package ships two binaries from one install: the original `dugganusa-lookup` scanner (positional IOC arguments, CI/CD-friendly exit codes) and the new `dugganusa-mcp` STDIO MCP server (read-only, no exec paths, customer owns the binary).

## Install

```bash
# Run without installing
npx dugganusa-lookup 185.39.19.176
npx dugganusa-mcp --help

# Or install globally — gives you both bins
npm install -g dugganusa-cli
```

## Usage

```bash
# Single lookup
dugganusa-lookup 185.39.19.176
dugganusa-lookup welcome.supp0v3.com
dugganusa-lookup CVE-2026-21643

# Multiple indicators
dugganusa-lookup 185.39.19.176 welcome.supp0v3.com CVE-2026-21643

# Scan a file for IOCs
dugganusa-lookup --file config.js
dugganusa-lookup --file terraform/main.tf

# Pipe stdin (works with any tool)
cat firewall.log | dugganusa-lookup --stdin
grep -r "http" src/ | dugganusa-lookup --stdin

# Batch lookup (one IOC per line)
dugganusa-lookup --batch iocs.txt

# AIPM audit
dugganusa-lookup --aipm crowdstrike.com

# Output formats
dugganusa-lookup --format json 185.39.19.176
dugganusa-lookup --format markdown --file report.md
dugganusa-lookup --format table 185.39.19.176  # default

# Only show matches (suppress clean results)
dugganusa-lookup --file app.js --quiet

# With API key (higher rate limits)
dugganusa-lookup --key dugusa_YOUR_KEY 185.39.19.176
# Or set env var
export DUGGANUSA_API_KEY=dugusa_YOUR_KEY
```

## Output

```
  !!    12  185.39.19.176                                 IOC: Cobalt Strike C2 (via SSLBL) | Blocked 47x | 3 OTX pulse(s)
  OK     0  8.8.8.8                                       clean

  1 threat indicator(s) found in 2 checked.
  Full enrichment: https://analytics.dugganusa.com/api/v1/search/correlate?q=<indicator>
  Free API key: https://analytics.dugganusa.com/stix/register
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All clean — no threat indicators found |
| 1 | Threat indicator(s) found — use in CI to fail builds |
| 2 | Error (network, invalid input, etc.) |

Exit code 1 on match makes this CI/CD friendly — use it in pipelines to block deployments containing known-bad indicators.

## CI/CD Example

```yaml
# GitHub Actions
- name: Scan for threat indicators
  run: npx dugganusa-lookup --file config/production.json --quiet
```

```bash
# Shell script
if npx dugganusa-lookup --file deploy.conf --quiet; then
  echo "Clean — deploying"
  ./deploy.sh
else
  echo "BLOCKED — threat indicators found"
  exit 1
fi
```

## API Key

Free tier: 500 queries/day. No key required for basic lookups.

Get a free key for higher limits: [analytics.dugganusa.com/stix/register](https://analytics.dugganusa.com/stix/register)

Set via `--key` flag or `DUGGANUSA_API_KEY` environment variable.

## What's In The Index

1,080,000+ indicators from OTX, abuse.ch SSLBL, URLhaus, Spamhaus, CISA KEV, DugganUSA original research, exploit harvester, and edge honeypots. Cross-correlated across 44 indexes. Same feed trusted by 275+ organizations in 46 countries.

## MCP Server (dugganusa-mcp)

Local STDIO MCP server. Wire it into any MCP client and your AI assistant gets the DugganUSA threat-intel corpus as read-only tools.

### Three tools exposed

- **search** — full-text across IOCs, pulses, blog, adversaries, CISA KEV, Epstein files, and 40+ indexes. 17.9M+ documents.
- **enrich-ioc** — IP enrichment: country, ASN, threat type, malware family, cross-index correlations.
- **stix-feed-summary** — index stats and pointers to our STIX 2.1 / TAXII 2.1 feeds.

That's the whole surface. No tools that write, no tools that touch your filesystem, no tools that exec.

### Wire it into Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "dugganusa": {
      "command": "npx",
      "args": ["-y", "dugganusa-cli", "dugganusa-mcp"],
      "env": {
        "DUGGANUSA_API_KEY": "your-key-or-leave-blank-for-anonymous"
      }
    }
  }
}
```

Restart Claude Desktop. The three tools appear in the tool picker. Same pattern works for Cursor, Windsurf, Claude Code, or any MCP client that speaks STDIO.

### Local policy enforcement: --dredd-gate

```bash
dugganusa-mcp --dredd-gate
```

Validates tool name + required args before each call, logs every allowed call to stderr. Read it in `mcp/lib/serve.js` — function `dreddVerdict`. This is the hook where you wire stricter policy: deny lists, IP allow-lists, per-tool rate limits, or a remote dredd verdict endpoint.

### Why this exists

On April 20, 2026 we published "Anthropic's MCP Has a Critical RCE Vulnerability. We Don't Use MCP. Here's Why." The architectural problem we named was that MCP trusts the transport — STDIO gives an AI model a pipe to execute commands on the host. We meant it. We still don't use other people's MCPs without auditing them first. But there is a coherent answer: ship the MCP we'd audit. Read-only. No exec path. Customer owns the binary. Dredd-shaped local gate. No SDK dependency.

This is that MCP.

### Auditing the MCP binary

Everything lives under `mcp/`:

- `mcp/serve.js` — bin entry, argv parser (~45 LOC)
- `mcp/lib/serve.js` — JSON-RPC 2.0 over STDIO (~125 LOC)
- `mcp/lib/tools.js` — three tool schemas + handlers (~80 LOC)
- `mcp/lib/upstream.js` — HTTPS request to analytics.dugganusa.com (~40 LOC)

Read it. Grep for `child_process`, `exec`, `spawn`, `shell`, `eval`. You will not find them. Run the tests:

```bash
npm run test:mcp
```

10 tests covering the dispatch surface and live network calls.

---

## Part of the DugganUSA Ecosystem

- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=DugganUSALLC.dugganusa-threat-intel)
- [STIX Feed](https://analytics.dugganusa.com/api/v1/stix-feed)
- [AIPM Security](https://aipmsec.com)
- [dugganusa.com](https://www.dugganusa.com)

## License

MIT — [DugganUSA LLC](https://www.dugganusa.com), Minneapolis, MN.

---

<!-- DUGGANUSA-FAMILY-FOOTER-V1 -->
## DugganUSA Defender Family

Same threat corpus, surfaced wherever you live. Open source, MIT licensed, receipts on every repo.

| Plugin | Surface |
|---|---|
| [dugganusa-scanner-core](https://github.com/pduggusa/dugganusa-scanner-core) | Core IOC scanning engine |
| [dugganusa-vscode](https://github.com/pduggusa/dugganusa-vscode) | VS Code extension |
| [dugganusa-splunk](https://github.com/pduggusa/dugganusa-splunk) | Splunk Technology Add-on |
| [dugganusa-slack](https://github.com/pduggusa/dugganusa-slack) | Slack bot |
| [dugganusa-raycast](https://github.com/pduggusa/dugganusa-raycast) | Raycast extension |
| [dugganusa-sentinel](https://github.com/pduggusa/dugganusa-sentinel) | Microsoft Sentinel TAXII connector |
| [dugganusa-obsidian](https://github.com/pduggusa/dugganusa-obsidian) | Obsidian plugin |
| [dugganusa-nvim](https://github.com/pduggusa/dugganusa-nvim) | Neovim plugin |
| [dugganusa-elastic](https://github.com/pduggusa/dugganusa-elastic) | Elastic / OpenSearch integration |
| [dugganusa-edge-shield](https://github.com/pduggusa/dugganusa-edge-shield) | Cloudflare Worker |
| **dugganusa-cli** _(this repo)_ | CLI scanner + local STDIO MCP server |
| [dugganusa-chrome](https://github.com/pduggusa/dugganusa-chrome) | Chrome extension |
| [dugganusa-action](https://github.com/pduggusa/dugganusa-action) | GitHub Action |
| [dredd-mcp](https://github.com/pduggusa/dredd-mcp) | Pre-flight MCP security (this repo) |

Backed by the live DugganUSA threat intel platform: [analytics.dugganusa.com](https://analytics.dugganusa.com).

_Jeevesus saves. Dredd judges._
