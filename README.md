# dugganusa-lookup

**Threat intel from your terminal. 1,080,000+ IOCs.**

```bash
npx dugganusa-lookup 185.39.19.176
```

## Install

```bash
# Run without installing (npx)
npx dugganusa-lookup 185.39.19.176

# Or install globally
npm install -g dugganusa-lookup
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

## Part of the DugganUSA Ecosystem

- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=DugganUSALLC.dugganusa-threat-intel)
- [STIX Feed](https://analytics.dugganusa.com/api/v1/stix-feed)
- [AIPM Security](https://aipmsec.com)
- [dugganusa.com](https://www.dugganusa.com)

## License

MIT — [DugganUSA LLC](https://www.dugganusa.com), Minneapolis, MN.
