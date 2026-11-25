const cookieName = '__Host-north_session';
const sessionSeconds = 8 * 60 * 60;
const maxBytes = 700_000;
const emptyNetwork = { assets: [], links: [] };
const idPattern = /^[0-9a-f]{24}$/;
const sourcePattern = /^[a-z0-9][a-z0-9-]{0,47}$/;
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$/;
const headers = { 'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8' };
const encoder = new TextEncoder();

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...headers, ...extra } });
}

async function signature(secret, value) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const hash = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
  return Array.from(hash, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function fingerprint(value) {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function equal(left, right) {
  if (!left || !right || left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return difference === 0;
}

async function sessionValid(request, secret) {
  const token = request.headers.get('Cookie')?.match(/(?:^|;\s*)__Host-north_session=([^;]+)/)?.[1];
  const parts = token?.split('.');
  if (!parts || parts.length !== 3 || !/^\d{10}$/.test(parts[0]) || !/^[0-9a-f-]{36}$/.test(parts[1])) return false;
  const expires = Number(parts[0]);
  const now = Math.floor(Date.now() / 1000);
  if (expires <= now || expires > now + sessionSeconds) return false;
  return equal(parts[2], await signature(secret, parts[0] + '.' + parts[1]));
}

function cookie(value, lifetime) {
  return `${cookieName}=${value}; Path=/; Max-Age=${lifetime}; HttpOnly; Secure; SameSite=Strict`;
}

async function readBody(request, limit) {
  if (!request.body) throw new Error('Missing body');
  const reader = request.body.getReader();
  const pieces = [];
  let length = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > limit) {
      await reader.cancel();
      throw new Error('Body too large');
    }
    pieces.push(value);
  }
  return JSON.parse(await new Blob(pieces).text());
}

function validSnapshot(body) {
  return body && Array.isArray(body.cases) && body.cases.length <= 100 &&
    Array.isArray(body.events) && body.events.length <= 150 &&
    body.events.every((event) => typeof event?.id === 'string' && idPattern.test(event.id)
      && typeof event.timestamp === 'string' && timestampPattern.test(event.timestamp) && Number.isInteger(event.kind)) &&
    Array.isArray(body.network?.assets) && Array.isArray(body.network?.links) &&
    body.reports && typeof body.reports === 'object' && !Array.isArray(body.reports) &&
    body.cases.every((item) => typeof item?.id === 'string' && idPattern.test(item.id)
      && Array.isArray(item.evidence) && typeof body.reports[item.id] === 'string');
}

async function eventPage(db, source, params) {
  const q = (params.get('q') ?? '').trim().toLowerCase().slice(0, 200);
  const kind = params.get('kind');
  const before = params.get('before');
  const limit = Math.max(1, Math.min(100, Number.parseInt(params.get('limit') ?? '25', 10) || 25));
  const terms = ['source_id = ?'];
  const values = [source];
  if (q) {
    terms.push("lower(payload) LIKE ? ESCAPE '!'");
    values.push('%' + q.replaceAll('!', '!!').replaceAll('%', '!%').replaceAll('_', '!_') + '%');
  }
  if (kind) {
    if (!/^\d{1,6}$/.test(kind)) return null;
    terms.push('kind = ?');
    values.push(Number(kind));
  }
  if (before) {
    const [timestamp, id, extra] = before.split('|');
    if (extra !== undefined || !timestampPattern.test(timestamp) || !idPattern.test(id ?? '')) return null;
    terms.push('(timestamp < ? OR (timestamp = ? AND id < ?))');
    values.push(timestamp, timestamp, id);
  }
  const { results } = await db.prepare(
    `SELECT payload FROM cloud_events WHERE ${terms.join(' AND ')} ORDER BY timestamp DESC, id DESC LIMIT ?`,
  ).bind(...values, limit + 1).all();
  const events = results.slice(0, limit).map((row) => JSON.parse(row.payload));
  const last = events.at(-1);
  return { events, next: results.length > limit ? last.timestamp + '|' + last.id : null };
}

async function saveSnapshot(db, body, now) {
  const source = body.source ?? { id: 'legacy', label: 'Earlier collector' };
  if (typeof source.id !== 'string' || !sourcePattern.test(source.id)
    || typeof source.label !== 'string' || !source.label.trim() || source.label.length > 80) return false;
  await db.batch([
    db.prepare(`INSERT INTO cloud_sources (id, label, network, updated_at) VALUES (?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET label=excluded.label, network=excluded.network, updated_at=excluded.updated_at`)
      .bind(source.id, source.label, JSON.stringify(body.network), now),
    db.prepare(`INSERT OR IGNORE INTO cloud_events (source_id, id, timestamp, kind, payload)
      SELECT ?, json_extract(value, '$.id'), json_extract(value, '$.timestamp'), json_extract(value, '$.kind'), value
      FROM json_each(?)`).bind(source.id, JSON.stringify(body.events)),
    db.prepare(`INSERT INTO cloud_cases (source_id, id, timestamp, payload, report)
      SELECT ?, json_extract(value, '$.id'), coalesce(json_extract(value, '$.evidence[#-1].timestamp'), ?),
             value, json_extract(?, '$.' || json_extract(value, '$.id'))
      FROM json_each(?) WHERE 1
      ON CONFLICT(source_id,id) DO UPDATE SET timestamp=excluded.timestamp, payload=excluded.payload, report=excluded.report`)
      .bind(source.id, now, JSON.stringify(body.reports), JSON.stringify(body.cases)),
  ]);
  return true;
}

async function relatedEvidence(db, source, caseId) {
  const stored = await db.prepare('SELECT payload FROM cloud_cases WHERE source_id = ? AND id = ?')
    .bind(source, caseId).first();
  if (!stored) return null;
  const evidence = JSON.parse(stored.payload).evidence;
  const addresses = [...new Set(evidence.flatMap((event) => [event?.source_ip, event?.destination])
    .filter((address) => typeof address === 'string' && address.length <= 45 &&
      (/^\d{1,3}(\.\d{1,3}){3}$/.test(address) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(address))))].slice(0, 20);
  const latest = evidence.reduce((time, event) => Math.max(time, Date.parse(event?.timestamp) || 0), 0);
  if (!addresses.length || !latest) return [];
  const window = 5 * 60 * 1000;
  const utc = (ms) => new Date(ms).toISOString().replace('Z', '000+00:00');
  const { results } = await db.prepare(`
    SELECT e.id, e.timestamp, e.kind, e.source_id, s.label AS collector,
      json_extract(e.payload, '$.host') AS host, refs.value AS address
    FROM cloud_events e JOIN cloud_sources s ON s.id = e.source_id
    JOIN json_each(?) refs ON refs.value IN (json_extract(e.payload, '$.source_ip'),
      json_extract(e.payload, '$.destination'))
    WHERE e.timestamp BETWEEN ? AND ? AND e.source_id <> ?
    ORDER BY e.timestamp DESC, e.source_id, e.id, refs.value LIMIT 50
  `).bind(JSON.stringify(addresses), utc(latest - window), utc(latest + window), source).all();
  return results;
}

const observations = new Map([
  [1, 'A process started.'],
  [3, 'A network connection was recorded.'],
  [5, 'A process exited.'],
  [11, 'A file was created.'],
  [1001, 'An SSH authentication attempt failed.'],
  [1002, 'A sudo command was recorded.'],
]);

async function caseDraft(env, source, caseId) {
  const stored = await env.DB.prepare('SELECT payload FROM cloud_cases WHERE source_id = ? AND id = ?')
    .bind(source, caseId).first();
  if (!stored) return json({ detail: 'Case not found' }, 404);
  const findings = JSON.parse(stored.payload).evidence
    .filter((event) => typeof event?.id === 'string' && idPattern.test(event.id) && observations.has(event.kind))
    .slice(0, 20);
  if (!findings.length) return json({ detail: 'This case has no supported observations.' }, 422);
  const field = (value) => typeof value === 'string' ? value.trim().slice(0, 160) : '';
  const claim = (event) => {
    const details = {
      1: event.process, 3: event.destination, 5: event.process, 11: event.target,
      1001: event.source_ip, 1002: event.target,
    };
    const detail = field(details[event.kind]);
    const host = field(event.host);
    return { text: [observations.get(event.kind), host && 'Host: ' + host, detail && 'Observed value: ' + detail]
      .filter(Boolean).join(' · '), evidence_ids: [event.id] };
  };
  const fallback = () => json({ claims: findings.slice(0, 3).map(claim), provider: 'evidence' });
  if (!env.AI) return fallback();
  try {
    const answer = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
      messages: [{
        role: 'user',
        content: 'Prioritize up to three verified observations based on their likely value for incident triage. Return only JSON with a finding_ids array of distinct 1-based numbers. ' +
          JSON.stringify(findings.map((event, index) => ({ id: index + 1, observation: observations.get(event.kind) }))),
      }],
      max_tokens: 60, temperature: 0, response_format: { type: 'json_object' },
    });
    const result = typeof answer?.response === 'string' ? JSON.parse(answer.response) : answer?.response;
    const ids = result?.finding_ids;
    if (!Array.isArray(ids) || ids.length < 1 || ids.length > 3 || new Set(ids).size !== ids.length ||
      !ids.every((id) => Number.isInteger(id) && id >= 1 && id <= findings.length)) {
      throw new Error('Invalid observation selection');
    }
    return json({ claims: ids.map((id) => claim(findings[id - 1])), provider: 'cloud-ai' });
  } catch {
    return fallback();
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (!path.startsWith('/api/')) return env.ASSETS.fetch(request);
    if (![env.NORTH_ACCESS_KEY, env.NORTH_INGEST_KEY, env.NORTH_SESSION_SECRET]
      .every((secret) => typeof secret === 'string' && secret.length >= 32)) {
      return json({ detail: 'Cloud service setup is incomplete.' }, 503);
    }

    if (request.method === 'POST' && path === '/api/cloud/snapshot') {
      const token = /^Bearer ([A-Za-z0-9+/=]{32,128})$/.exec(request.headers.get('Authorization') ?? '')?.[1];
      if (!token) return json({ detail: 'Unauthorized' }, 401);
      const legacyKey = equal(token, env.NORTH_INGEST_KEY);
      const paired = legacyKey ? null : await env.DB.prepare(
        'SELECT source_id, label, revoked_at FROM cloud_pairings WHERE token_hash = ?',
      ).bind(await fingerprint(token)).first();
      if (!legacyKey && (!paired || paired.revoked_at)) {
        return json({ detail: 'Unauthorized' }, 401);
      }
      try {
        const body = await readBody(request, maxBytes);
        if (!validSnapshot(body)) return json({ detail: 'Invalid collector snapshot' }, 422);
        if (paired && body.source?.id !== paired.source_id) return json({ detail: 'Pairing belongs to another collector.' }, 403);
        if (legacyKey && /^collector-[0-9a-f]{20}$/.test(body.source?.id ?? '')) return json({ detail: 'A collector pairing is required.' }, 403);
        if (paired) body.source = { id: paired.source_id, label: paired.label };
        const now = new Date().toISOString();
        if (!await saveSnapshot(env.DB, body, now)) return json({ detail: 'Invalid collector identity' }, 422);
        return json({ updated_at: now });
      } catch {
        return json({ detail: 'Could not store collector snapshot' }, 400);
      }
    }

    if (request.method === 'POST' && ['/api/cloud/login', '/api/cloud/logout'].includes(path)) {
      if (request.headers.get('Origin') !== url.origin) return json({ detail: 'Invalid origin' }, 403);
      if (path.endsWith('/logout')) return json({ signed_in: false }, 200, { 'Set-Cookie': cookie('', 0) });
      try {
        const { key } = await readBody(request, 1024);
        if (typeof key !== 'string' || !equal(key, env.NORTH_ACCESS_KEY)) return json({ detail: 'Access key did not match.' }, 401);
        const value = Math.floor(Date.now() / 1000 + sessionSeconds) + '.' + crypto.randomUUID();
        return json({ signed_in: true }, 200, {
          'Set-Cookie': cookie(value + '.' + await signature(env.NORTH_SESSION_SECRET, value), sessionSeconds),
        });
      } catch {
        return json({ detail: 'Invalid sign-in request.' }, 400);
      }
    }

    if (!await sessionValid(request, env.NORTH_SESSION_SECRET)) return json({ detail: 'Sign in required' }, 401);

    if (path === '/api/cloud/pairings') {
      if (request.method === 'GET') {
        const { results } = await env.DB.prepare(
          `SELECT p.source_id, p.label, p.created_at, p.revoked_at, s.updated_at
           FROM cloud_pairings p LEFT JOIN cloud_sources s ON s.id = p.source_id
           ORDER BY p.created_at DESC LIMIT 100`,
        ).all();
        return json({ pairings: results });
      }
      if (request.method === 'POST') {
        if (request.headers.get('Origin') !== url.origin) return json({ detail: 'Invalid origin' }, 403);
        try {
          const body = await readBody(request, 2048);
          const label = typeof body.label === 'string' ? body.label.trim() : '';
          if (!label || label.length > 80) return json({ detail: 'Enter a name up to 80 characters.' }, 422);
          const sourceId = 'collector-' + crypto.randomUUID().replaceAll('-', '').slice(0, 20);
          const token = Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) => byte.toString(16).padStart(2, '0')).join('');
          await env.DB.prepare('INSERT INTO cloud_pairings (source_id, label, token_hash, created_at) VALUES (?, ?, ?, ?)')
            .bind(sourceId, label, await fingerprint(token), new Date().toISOString()).run();
          return json({ source_id: sourceId, label, token }, 201);
        } catch {
          return json({ detail: 'Could not create the collector pairing.' }, 400);
        }
      }
    }
    const revoke = /^\/api\/cloud\/pairings\/(collector-[0-9a-f]{20})\/revoke$/.exec(path);
    if (request.method === 'POST' && revoke) {
      if (request.headers.get('Origin') !== url.origin) return json({ detail: 'Invalid origin' }, 403);
      const result = await env.DB.prepare(
        'UPDATE cloud_pairings SET revoked_at = coalesce(revoked_at, ?) WHERE source_id = ?',
      ).bind(new Date().toISOString(), revoke[1]).run();
      return result.meta.changes ? json({ revoked: true }) : json({ detail: 'Collector not found.' }, 404);
    }
    const draftId = request.method === 'POST' && /^\/api\/cases\/([0-9a-f]{24})\/draft$/.exec(path)?.[1];
    if (draftId && request.headers.get('Origin') !== url.origin) return json({ detail: 'Invalid origin' }, 403);
    if (request.method !== 'GET' && !draftId) return json({ detail: 'This cloud endpoint is read-only' }, 405);
    if (path === '/api/cloud/status') {
      const { results: sources } = await env.DB.prepare(
        'SELECT id, label, updated_at FROM cloud_sources ORDER BY updated_at DESC, id LIMIT 100',
      ).all();
      return json({ signed_in: true, sources });
    }
    const sourceId = url.searchParams.get('source');
    if (sourceId && !sourcePattern.test(sourceId)) return json({ detail: 'Invalid collector identity' }, 422);
    const source = sourceId
      ? await env.DB.prepare('SELECT id, network FROM cloud_sources WHERE id = ?').bind(sourceId).first()
      : await env.DB.prepare('SELECT id, network FROM cloud_sources ORDER BY updated_at DESC, id LIMIT 1').first();
    if (sourceId && !source) return json({ detail: 'Collector not found' }, 404);
    if (draftId) return source ? caseDraft(env, source.id, draftId) : json({ detail: 'Case not found' }, 404);
    if (path === '/api/cases') {
      if (!source) return json([]);
      const { results } = await env.DB.prepare(
        'SELECT payload FROM cloud_cases WHERE source_id = ? ORDER BY timestamp DESC, id DESC LIMIT 100',
      ).bind(source.id).all();
      return json(results.map((row) => JSON.parse(row.payload)));
    }
    const relatedId = /^\/api\/cases\/([0-9a-f]{24})\/related$/.exec(path)?.[1];
    if (relatedId) {
      const matches = source ? await relatedEvidence(env.DB, source.id, relatedId) : null;
      return matches ? json({ matches }) : json({ detail: 'Case not found' }, 404);
    }
    if (path === '/api/network') return json(source ? JSON.parse(source.network) : emptyNetwork);
    if (path === '/api/events') {
      const page = source ? await eventPage(env.DB, source.id, url.searchParams) : { events: [], next: null };
      return page ? json(page) : json({ detail: 'Invalid event filter' }, 422);
    }
    const eventId = /^\/api\/events\/([0-9a-f]{24})$/.exec(path)?.[1];
    if (eventId) {
      const row = source && await env.DB.prepare('SELECT payload FROM cloud_events WHERE source_id = ? AND id = ?')
        .bind(source.id, eventId).first();
      return row ? json(JSON.parse(row.payload)) : json({ detail: 'Evidence not found' }, 404);
    }
    const id = /^\/api\/cases\/([0-9a-f]{24})\/report$/.exec(path)?.[1];
    const stored = id && source && await env.DB.prepare(
      'SELECT report FROM cloud_cases WHERE source_id = ? AND id = ?',
    ).bind(source.id, id).first();
    if (stored) {
      return new Response(stored.report, { headers: {
        'Cache-Control': 'no-store', 'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': `attachment; filename="north-${id}.md"`,
      } });
    }
    return json({ detail: 'Not found' }, 404);
  },
};
