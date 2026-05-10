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

const HANDLERS = {
  search,
  'enrich-ioc': enrichIoc,
  'stix-feed-summary': stixFeedSummary
};

module.exports = { TOOLS, HANDLERS };
