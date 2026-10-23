# dugganusa-cli

**Docs:** https://docs.dugganusa.com/quickstart/

**You do you. I do me. We share contexts.**

Your terminal and your agent keep their own context; the DugganUSA Feed lends them its context, read-only, from a binary you own.

**Two binaries. One install. Threat intelligence you can check.** Corpus size: [live counts](https://analytics.dugganusa.com/api/v1/search/stats).

## What's New (v1.5.1)

- **Supply-chain scanning leveled up.** The corpus now ingests OSV malicious-package feeds for **both npm and PyPI** — named-malicious packages, zero-heuristic, daily — alongside daily GitHub Hunt detections of malware-staging repos and install-time execution signatures. Pipe a lockfile or `--file package.json` and known-bad packages surface next to network IOCs. This is the CI angle: catch a poisoned dependency before it ships.
- **Four live, no-auth, deploy-durable validation endpoints** now prove feed quality:
  - **Novelty** — [feed-uniqueness](https://analytics.dugganusa.com/api/v1/feed-uniqueness): how much of what we publish adds to ThreatFox, which we also carry and credit (measured live).
  - **Timeliness** — [kev-lead](https://analytics.dugganusa.com/api/v1/kev-lead): when an exploited CVE reached our corpus relative to CISA KEV, including same-day and no-receipt cases.
  - **Accuracy** — [spamhaus-validation](https://analytics.dugganusa.com/api/v1/spamhaus-validation): Spamhaus independently checks our first-hand contributions.
  - **Liveness** — [feed-efficacy](https://analytics.dugganusa.com/api/v1/feed-efficacy): opt-in consumer reports of when our indicators actually fire on real traffic — proof the feed is operationally live, not just large.

```bash
# Scanner — block bad IOCs in your stack
npx dugganusa-cli 185.39.19.176

# MCP server — wire DugganUSA into Claude Desktop / Cursor / Claude Code
npx -y -p dugganusa-cli dugganusa-mcp
```

A two-person Minnesota LLC. Most of what is in the corpus comes from other people's good work: abuse.ch, Spamhaus, CISA, OSV and the researchers we cite by name. We join it with our own GitHub hunting and edge sensors, correlate it, and hand it back with the source attached.

**What it asks of you:** nothing you cannot read. No agent to install, no inbound access, none of your data leaves your machine except the indicators you look up. Keep every tool you already use; this adds a second opinion beside them.

> **Bin rename (since v1.3.0):** the scanner bin was `dugganusa-lookup` in v1.2.0. It is now `dugganusa-cli`. The old `dugganusa-lookup` package is dead — use `dugganusa-cli`. The MCP bin (`dugganusa-mcp`) is unchanged. Update any pinned scripts.

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
  !!    12  185.39.19.176                                 IOC: Cobalt Strike C2 (via SSLBL) | Blocked 47x | 12 cross-index hits
  OK     0  8.8.8.8                                       clean

  1 threat indicator(s) found in 2 checked.
  Full enrichment: https://analytics.dugganusa.com/api/v1/search/correlate?q=<indicator>
  Free API key: https://analytics.dugganusa.com/stix/register
```

The full-enrichment (correlate) link is key-gated (free key required).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All clean — every indicator was checked and none was found |
| 1 | Threat indicator(s) found — use in CI to fail builds |
| 2 | At least one indicator could not be checked (missing/invalid key → 401, daily limit → 429, network error). Reported as UNKNOWN, never as clean |

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

The STIX feed is API-key-enforced: anonymous requests and unregistered keys get `401`; a registered key past its daily limit gets `429`. The **free tier is a free *registered* key** — not anonymous. Register here: [analytics.dugganusa.com/stix/register](https://analytics.dugganusa.com/stix/register)

Free tier: 10 queries/day ([pricing](https://analytics.dugganusa.com/pricing)). Set the key via `--key` flag or `DUGGANUSA_API_KEY` env var.

## What's in the index

Indicators sourced from external feeds (abuse.ch SSLBL, URLhaus, Spamhaus, CISA KEV, OSV malicious-package feeds for npm + PyPI, and more), plus DugganUSA original research, our exploit harvester, daily GitHub Hunt detections, and our edge honeypots. Cross-correlated across the whole corpus ([live counts](https://analytics.dugganusa.com/api/v1/search/stats)).

Same corpus, your terminal.

---

## MCP server (dugganusa-mcp)

Local STDIO MCP server. Wire it into any MCP client, your AI assistant gets the DugganUSA threat-intel corpus as read-only tools.

A small MCP server you can read end to end, so adding it to your agent costs you very little trust.

### Three tools, that's it

- **search** — full-text across IOCs, blog, adversaries, CISA KEV and the rest of the corpus ([live counts](https://analytics.dugganusa.com/api/v1/search/stats)).
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
        "DUGGANUSA_API_KEY": "your-registered-key"
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

A STDIO MCP server runs on your machine with your permissions, so the question to ask of any of them, ours included, is how much you have to trust it. We tried to make the answer "very little":

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

## Checking our work

We get things wrong and say so in public: corrections are dated and kept next to the original claim at [dugganusa.com](https://www.dugganusa.com). Every verdict carries the source it came from, so you can check it against that source instead of taking our word. If something here is wrong, open an issue; that is the most useful thing you can send us.

---

## Part of the DugganUSA ecosystem

- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=DugganUSALLC.dugganusa-threat-intel)
- [DugganUSA Feed](https://analytics.dugganusa.com/stix)
- [AIPM](https://aipmsec.com) — AI Presence Management: what AIs say about you
- [dugganusa.com](https://www.dugganusa.com) — research, methodology, receipts

## License

MIT — [DugganUSA LLC](https://www.dugganusa.com), Minnesota. Contact: help@dugganusa.com.

Free tier means free. Audit it. Fork it. Tell us when we got something wrong.

---

<!-- DUGGANUSA-FAMILY-FOOTER-V1 -->
## DugganUSA Defender Family

Same DugganUSA Feed, surfaced wherever you live. Open source, MIT licensed, receipts on every repo.

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

Backed by the [DugganUSA Feed](https://analytics.dugganusa.com/stix). Numbers are live: [/api/v1/search/stats](https://analytics.dugganusa.com/api/v1/search/stats). Pricing: [analytics.dugganusa.com/pricing](https://analytics.dugganusa.com/pricing). Contact: help@dugganusa.com.

_Threat intelligence you can check._
