# Changelog

## 1.5.0

- Highlighted expanded supply-chain coverage: OSV malicious-package ingestion for **both npm and PyPI** (named-malicious, zero-heuristic, daily) plus daily GitHub Hunt detections of malware-staging repos and install-time execution signatures — strong CI angle for scanning lockfiles/manifests.
- Documented the three live, no-auth, deploy-durable validation endpoints: feed-uniqueness (novelty, ~75%+ unique vs ThreatFox), kev-lead (timeliness, ~31 days ahead of CISA KEV), spamhaus-validation (accuracy, independently corroborated).
- Corrected API-key copy: the STIX feed is enforced (401 anonymous / 429 unregistered). The free tier is a free *registered* key, not anonymous — removed "anonymous lookups work" and "leave blank for anonymous" guidance.
- Aligned corpus figures to 1.10M+ IOCs across 44 indexes (~17.9M+ documents), 15 external feed sources, 275+ consumers in 46 countries, 1,655+ blog posts.
- Clarified that the old `dugganusa-lookup` package is dead — use `dugganusa-cli`.

## 1.4.0

- Internal release.

## 1.3.0

- Renamed scanner bin from `dugganusa-lookup` to `dugganusa-cli`; npm Trusted Publishing with `--provenance`.

## 1.2.0

- Scanner + local STDIO MCP server (`dugganusa-mcp`) with optional `--dredd-gate` policy hook.
