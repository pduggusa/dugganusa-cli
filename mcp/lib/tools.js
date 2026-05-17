const { request } = require('./upstream');

const TOOLS = [
  {
    name: 'search',
    description: 'Search DugganUSA threat intelligence across IOCs, pulses, adversaries, blog posts, and 40+ indexes. Returns ranked hits with index attribution. Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        q: { type: 'string', description: 'Search query (IP, domain, hash, actor name, keyword)' },
        limit: { type: 'integer', minimum: 1, maximum: 50, default: 10 },
        indexes: {
          type: 'string',
          description: 'Optional comma-separated index list (e.g. iocs,pulses,blog). Omit for all-index search.'
        }
      },
      required: ['q']
    }
  },
  {
    name: 'enrich-ioc',
    description: 'Enrich a single IP indicator with country, ASN, threat type, malware family, and cross-index correlations. Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        ip: { type: 'string', description: 'IPv4 or IPv6 address to enrich' }
      },
      required: ['ip']
    }
  },
  {
    name: 'stix-feed-summary',
    description: 'Summary of the DugganUSA STIX 2.1 feed: indicator counts, recent additions, consumer geography. Read-only.',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  },
  {
    name: 'platform-status',
    description: 'DugganUSA platform health — cron-tier aggregate (per-job ok/degraded/failing/stale/unknown counts) and Meili backplane (queue depth, oldest enqueued age, top index+type write distribution, wedged/backed_up/ok status). Use to triage "is X cron working" or "is the platform accepting writes". Read-only; no auth required.',
    inputSchema: {
      type: 'object',
      properties: {
        surface: {
          type: 'string',
          enum: ['both', 'crons', 'backplane'],
          default: 'both',
          description: 'Which view: cron tier, Meili write-path backplane, or both (default).'
        }
      }
    }
  }
];

async function search({ q, limit = 10, indexes }, ctx) {
  const path = indexes ? `/api/v1/search?indexes=${encodeURIComponent(indexes)}` : '/api/v1/search';
  const data = await request(ctx.upstream, path, { apiKey: ctx.apiKey, query: { q, limit } });
  return {
    query: data?.data?.query ?? q,
    totalHits: data?.data?.totalHits ?? 0,
    indexes: data?.data?.indexes ?? [],
    hits: (data?.data?.hits ?? []).slice(0, limit)
  };
}

async function enrichIoc({ ip }, ctx) {
  const data = await request(ctx.upstream, '/api/v1/threat-intel/enrichment', {
    apiKey: ctx.apiKey,
    query: { ip }
  });
  return data?.data ?? data;
}

async function stixFeedSummary(_args, ctx) {
  const stats = await request(ctx.upstream, '/api/v1/search/stats', { apiKey: ctx.apiKey });
  const osint = await request(ctx.upstream, '/api/v1/osint/stats', { apiKey: ctx.apiKey }).catch(() => null);
  return {
    indexes: stats?.data ?? stats,
    osint: osint?.data ?? osint,
    feed: {
      url: 'https://analytics.dugganusa.com/api/v1/stix-feed',
      taxii: 'https://analytics.dugganusa.com/api/v1/stix-feed/taxii2',
      v2: 'https://analytics.dugganusa.com/api/v1/stix-feed/v2'
    }
  };
}

async function platformStatus({ surface = 'both' } = {}, ctx) {
  // Both endpoints are public (no auth) — same precedent as /tor/stats.
  // Phase 3 of the status surface (post 2026-05-17 butterbot wedge incident).
  const out = {};
  if (surface === 'both' || surface === 'crons') {
    const cron = await request(ctx.upstream, '/api/v1/status', { apiKey: ctx.apiKey }).catch((e) => ({ _error: e.message }));
    const c = cron?.data ?? cron;
    out.crons = c?._error ? c : {
      summary: c?.summary ?? null,
      problems: (c?.jobs ?? []).filter((j) => j.status !== 'ok' && j.status !== 'unknown').map((j) => ({
        id: j.id,
        status: j.status,
        latest_run: j.latest_run?.timestamp ?? null,
        age_minutes: j.latest_run?.age_minutes ?? null
      })),
      generated_at: c?.generated_at ?? null
    };
  }
  if (surface === 'both' || surface === 'backplane') {
    const bp = await request(ctx.upstream, '/api/v1/status/backplane', { apiKey: ctx.apiKey }).catch((e) => ({ _error: e.message }));
    const b = bp?.data ?? bp;
    out.backplane = b?._error ? b : {
      status: b?.status ?? null,
      meili_health: b?.meili?.health ?? null,
      tasks: b?.meili?.tasks ?? null,
      oldest_enqueued_age_seconds: b?.meili?.queue?.oldest_enqueued_age_seconds ?? null,
      oldest_enqueued_index: b?.meili?.queue?.oldest_enqueued_index ?? null,
      oldest_enqueued_type: b?.meili?.queue?.oldest_enqueued_type ?? null,
      top_enqueued_by_index_type: (b?.meili?.top_enqueued_by_index_type ?? []).slice(0, 8),
      generated_at: b?.generated_at ?? null
    };
  }
  return out;
}

const HANDLERS = {
  search,
  'enrich-ioc': enrichIoc,
  'stix-feed-summary': stixFeedSummary,
  'platform-status': platformStatus
};

module.exports = { TOOLS, HANDLERS };
