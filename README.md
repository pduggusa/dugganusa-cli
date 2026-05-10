# dugganusa-cli

**1.08M+ IOCs. 17.9M+ documents. Two binaries. One install. The MCP we'd audit.**

```bash
# Scanner — block bad IOCs in your stack
npx dugganusa-cli 185.39.19.176

# MCP server — wire DugganUSA into Claude Desktop / Cursor / Claude Code
npx -y -p dugganusa-cli dugganusa-mcp
```

A two-person Minnesota LLC. A Bloom filter for novelty checks. Meilisearch cross-index correlation. A github-hunt cron that runs at 08:15 UTC every day.

That's the stack that named **TeamPCP** 45 days before CISA added LiteLLM CVE-2026-42208 to KEV. That named **Handala** 28 days before they exfiltrated 6 petabytes from Dubai. That named **NGINX-UI** as actively exploited 20 days before the same agency caught up.

This is the CLI that puts the same corpus in your terminal.

> **v1.3.0 rename:** the scanner bin was `dugganusa-lookup` in v1.2.0. It is now `dugganusa-cli`. The MCP bin (`dugganusa-mcp`) is unchanged. Update any pinned scripts.

## Install

```bash
# Run without installing
npx dugganusa-cli 185.39.19.176
npx -y -p dugganusa-cli dugganusa-mcp --help

# Or install globally — both bins on PATH
npm install -g dugganusa-cli
```

## Scanner usage

```bash
# Single lookup
dugganusa-cli 185.39.19.176
dugganusa-cli welcome.supp0v3.com
dugganusa-cli CVE-2026-21643

# Multiple indicators
dugganusa-cli 185.39.19.176 welcome.supp0v3.com CVE-2026-21643

# Scan a file for IOCs
dugganusa-cli --file config.js
dugganusa-cli --file terraform/main.tf

# Pipe stdin (works with any tool)
cat firewall.log | dugganusa-cli --stdin
grep -r "http" src/ | dugganusa-cli --stdin

# Batch lookup (one IOC per line)
dugganusa-cli --batch iocs.txt

# AIPM audit (AI presence + brand exposure)
dugganusa-cli --aipm crowdstrike.com

# Output formats
dugganusa-cli --format json 185.39.19.176
dugganusa-cli --format markdown --file report.md
dugganusa-cli --format table 185.39.19.176  # default

# Only show matches (suppress clean results)
dugganusa-cli --file app.js --quiet

# With API key (higher rate limits)
dugganusa-cli --key dugusa_YOUR_KEY 185.39.19.176
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

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All clean — no threat indicators found |
| 1 | Threat indicator(s) found — use in CI to fail builds |
| 2 | Error (network, invalid input, etc.) |

Exit 1 on match is the whole point. Block deployments containing known-bad indicators before they ship.

## CI/CD examples

```yaml
# GitHub Actions — block deploys containing live IOCs
- name: Scan for threat indicators
  run: npx dugganusa-cli --file config/production.json --quiet
```

```bash
# Shell pipeline
if npx dugganusa-cli --file deploy.conf --quiet; then
  echo "Clean — deploying"
  ./deploy.sh
else
  echo "BLOCKED — threat indicators found"
  exit 1
fi
```

## API key

Free tier: 500 queries/day. Anonymous lookups work for casual use.

Free key for higher limits: [analytics.dugganusa.com/stix/register](https://analytics.dugganusa.com/stix/register)

Set via `--key` flag or `DUGGANUSA_API_KEY` env var.

## What's in the index

1.08M+ indicators sourced from OTX, abuse.ch SSLBL, URLhaus, Spamhaus, CISA KEV, DugganUSA original research, our exploit harvester, and our edge honeypots. Cross-correlated across 44 indexes covering 17.9M+ documents. The same feed pulled daily by 275+ organizations in 46 countries — including Microsoft, AT&T, and Starlink.

You are getting the receipts the big platforms get. Same corpus, your terminal.

---

## MCP server (dugganusa-mcp)

Local STDIO MCP server. Wire it into any MCP client, your AI assistant gets the DugganUSA threat-intel corpus as read-only tools.

This is the MCP we wrote because the ones we audited were dangerous.

### Three tools, that's it

- **search** — full-text across IOCs, pulses, blog, adversaries, CISA KEV, Epstein files, and 40+ indexes. 17.9M+ documents.
- **enrich-ioc** — IP enrichment: country, ASN, threat type, malware family, cross-index correlations.
- **stix-feed-summary** — index stats + pointers to our STIX 2.1 / TAXII 2.1 feeds.

No tools that write. No tools that touch your filesystem. No tools that exec. Read-only, all the way down.

### Wire it into Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "dugganusa": {
      "command": "npx",
      "args": ["-y", "-p", "dugganusa-cli", "dugganusa-mcp"],
      "env": {
        "DUGGANUSA_API_KEY": "your-key-or-leave-blank-for-anonymous"
      }
    }
  }
}
```

Restart Claude Desktop. Three tools appear in the picker. Same pattern works for Cursor, Windsurf, Claude Code, or any MCP client that speaks STDIO.

### Local policy enforcement: `--dredd-gate`

```bash
dugganusa-mcp --dredd-gate
```

Pre-flights every tool call: validates tool name, required arguments, logs allowed calls to stderr. Read the verdict function in `mcp/lib/serve.js` (function `dreddVerdict`). This is the hook where you wire stricter policy: deny lists, IP allow-lists, per-tool rate limits, or a remote dredd verdict endpoint.

Default is off. Turn it on if your environment is anything more than your laptop.

### Why this MCP exists

On April 20, 2026 we published **"Anthropic's MCP Has a Critical RCE Vulnerability. We Don't Use MCP. Here's Why."** ([dugganusa.com](https://www.dugganusa.com/post/anthropic-s-mcp-has-a-critical-rce-vulnerability-we-don-t-use-mcp-here-s-why))

We named the affected vendors three weeks before they hit the headlines: **MCP Inspector, LibreChat, Windsurf, LiteLLM, Langchain-Chatchat, NGINX-UI**. The architectural problem was that MCP trusts the transport — STDIO gives an AI model a pipe to execute commands on the host, and the path from "tool definition" to "command execution" had no gate.

We meant it. We still don't trust other people's MCPs without auditing them first. The coherent answer is to ship the MCP we'd audit:

- Read-only tool surface only — no write, no exec
- No third-party MCP SDK dependency (every line is in this repo)
- Customer owns the binary, runs it locally, sees every request before it leaves the machine
- Optional `--dredd-gate` local policy hook
- Zero npm runtime dependencies

This is that MCP.

### Auditing the binary

Read the bytes you're running:

```bash
# install
npm install -g dugganusa-cli

# audit
grep -rnE 'child_process|require\(.*shell|require\(.*child|exec\(|spawn\(|eval\(' "$(npm root -g)/dugganusa-cli"
```

Should return nothing.

Source layout under `mcp/`:

- `mcp/serve.js` — bin entry, argv parser (~45 LOC)
- `mcp/lib/serve.js` — JSON-RPC 2.0 over STDIO (~125 LOC)
- `mcp/lib/tools.js` — three tool schemas + handlers (~80 LOC)
- `mcp/lib/upstream.js` — HTTPS request to analytics.dugganusa.com (~40 LOC)

Tests:

```bash
npm run test:mcp
```

10 tests covering the dispatch surface and live network calls. Every release runs them in CI before publishing.

### Provenance

Releases ≥ v1.3.0 are published via npm Trusted Publishing (GitHub Actions OIDC) with `--provenance`. Verify:

```bash
npm audit signatures dugganusa-cli
```

You get signed attestation that the published bytes came from a specific commit in a specific GitHub workflow run. No long-lived tokens involved.

---

## Receipts

The platform behind this CLI runs left-of-boom on adversary infrastructure:

| Adversary | We named them | Vendor / agency caught up | Days early |
|---|---|---|---|
| **TeamPCP** (Trivy / LiteLLM / Telnyx supply chain) | Mar 24, 2026 | CISA KEV adds CVE-2026-42208 May 8 | **45 days** |
| **NGINX-UI** (actively exploited MCP) | Apr 20, 2026 | CISA KEV adds May 8 | **20 days** |
| **Lynx ransomware** vs ACN Healthcare | indexed | Microsoft published | **43 days** |
| **Handala** (Iran/MOIS-aligned) vs Dubai | indexed | Disclosure | **28 days** |
| **Medtronic** vish chain | flagged | Microsoft published | **39 days** |

Five entries in the quantified ledger as of May 10, 2026. The pattern is not luck. The pattern is the methodology.

Read the math: [dugganusa.com/post/45-days-early-on-litellm-20-days-early-on-nginx-ui-cisa-caught-up-today-1](https://www.dugganusa.com/post/45-days-early-on-litellm-20-days-early-on-nginx-ui-cisa-caught-up-today-1)

---

## Part of the DugganUSA ecosystem

- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=DugganUSALLC.dugganusa-threat-intel)
- [STIX Feed](https://analytics.dugganusa.com/api/v1/stix-feed) — pulled daily by 275+ orgs in 46 countries
- [AIPM Security](https://aipmsec.com) — AI presence audits (776+ run, 228 domains)
- [dugganusa.com](https://www.dugganusa.com) — 1,641+ blog posts, methodology, receipts

## License

MIT — [DugganUSA LLC](https://www.dugganusa.com), Minneapolis, MN.

Free tier means free. Audit it. Fork it. Tell us when we got something wrong.

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
| [dredd-mcp](https://github.com/pduggusa/dredd-mcp) | Pre-flight MCP security judge |

Backed by the live DugganUSA threat intel platform: [analytics.dugganusa.com](https://analytics.dugganusa.com).

_Jeevesus saves. Dredd judges._
