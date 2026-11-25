const { execFile } = require('node:child_process');
const { createHash } = require('node:crypto');
const { hostname, networkInterfaces } = require('node:os');
const path = require('node:path');
const { promisify } = require('node:util');

const execute = promisify(execFile);
const host = hostname();

async function readScript(file, args) {
  if (process.platform !== 'win32') throw new Error('Windows telemetry is unavailable.');
  const powershell = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const { stdout } = await execute(powershell, [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', file, ...args,
  ], { timeout: 12000, windowsHide: true, maxBuffer: 2_000_000 });
  return JSON.parse(stdout);
}

function cachedReader(read, fallback) {
  let cached;
  let expires = 0;
  return () => {
    if (!cached || Date.now() >= expires) {
      cached = read().then((data) => ({
        ...data, state: 'ready', updated_at: new Date().toISOString(),
      })).catch(() => ({ ...fallback, state: 'unavailable', updated_at: null }));
      expires = Date.now() + 15000;
    }
    return cached;
  };
}

function normalize(alert) {
  const { system, eventdata } = alert.data.win;
  const timestamp = new Date(system.systemTime).toISOString();
  const id = createHash('sha256').update(host + '|' + timestamp + '|' + system.eventRecordID).digest('hex').slice(0, 24);
  return { id, timestamp, kind: Number(system.eventID), host, process: eventdata.image,
    target: eventdata.targetFilename, destination: eventdata.destinationIp, raw: alert };
}

function scriptCases(events) {
  const guid = (event) => event.raw.data.win.eventdata.processGuid;
  const processes = new Map(events.filter((event) => event.kind === 1 && guid(event))
    .map((event) => [guid(event), event]));
  return events.filter((event) => event.kind === 11 && /\.ps1$/i.test(event.target)).flatMap((file) => {
    const process = processes.get(guid(file));
    if (!process || !/^(powershell|pwsh)\.exe$/i.test(process.process) || process.timestamp > file.timestamp) return [];
    const id = file.id;
    const network = events.filter((event) => event.kind === 3 && guid(event) === guid(file) &&
      event.timestamp >= process.timestamp && event.timestamp <= file.timestamp && event.destination);
    return [{
      id, host, asset_id: 'local-pc', title: 'PowerShell process wrote a script file',
      summary: 'Sysmon recorded a PowerShell process and a script file creation with the same process ID.',
      evidence: [process, ...network.reverse(), file],
      links: network.map((event) => ({ destination: event.destination, evidence_id: event.id })),
    }];
  });
}

function activity(events) {
  const types = new Map();
  const hour = 3600000;
  const countByHour = new Map();
  for (const event of events) {
    types.set(event.kind, (types.get(event.kind) ?? 0) + 1);
    const start = Math.floor(Date.parse(event.timestamp) / hour) * hour;
    countByHour.set(start, (countByHour.get(start) ?? 0) + 1);
  }
  const latest = Math.floor(Date.parse(events[0]?.timestamp) / hour) * hour;
  return {
    interval: events.length ? 'hour' : null,
    buckets: events.length ? Array.from({ length: 12 }, (_, index) => {
      const start = latest - (11 - index) * hour;
      return { start: new Date(start).toISOString(), count: countByHour.get(start) ?? 0 };
    }) : [],
    types: [...types].map(([kind, count]) => ({ kind, count })).sort((a, b) => b.count - a.count),
  };
}

function makeLocalWorkspace(scripts, read = readScript, history) {
  const neighbors = cachedReader(async () => ({
    records: await read(path.join(scripts, 'Export-NorthNeighbors.ps1'), ['-AsJson']),
  }), { records: [] });
  const sysmon = cachedReader(async () => {
    const data = await read(path.join(scripts, 'Read-NorthSysmon.ps1'), ['-Recent']);
    return { events: data.alerts.map(normalize).sort((a, b) => b.timestamp.localeCompare(a.timestamp)) };
  }, { events: [] });

  return async (request) => {
    const { pathname, searchParams } = new URL(request.url);
    const reviewId = /^\/api\/network\/devices\/([a-f0-9]{24})\/review$/.exec(pathname)?.[1];
    if (request.method === 'POST' && reviewId && history) {
      const reviewed = await history.review(reviewId, new Date().toISOString()).catch(() => null);
      if (reviewed === null) return Response.json({ detail: 'Could not update device history' }, { status: 500 });
      return reviewed ? Response.json({ reviewed }) : Response.json({ detail: 'Device not found' }, { status: 404 });
    }
    if (request.method !== 'GET') return Response.json({ detail: 'Method unavailable' }, { status: 405 });
    if (pathname === '/api/cases') return Response.json(scriptCases((await sysmon()).events));
    const reportId = /^\/api\/cases\/([a-f0-9]{24})\/report$/.exec(pathname)?.[1];
    if (reportId) {
      const incident = scriptCases((await sysmon()).events).find((item) => item.id === reportId);
      if (!incident) return Response.json({ detail: 'Investigation unavailable' }, { status: 404 });
      const lines = incident.evidence.map((event) => `- ${event.timestamp} · Sysmon ${event.kind} · Evidence ${event.id}`);
      return new Response([`# ${incident.title}`, '', incident.summary, '', ...lines].join('\n'), { headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': `attachment; filename="north-${reportId}.md"`,
      } });
    }
    if (pathname === '/api/network') {
      const [localNeighbors, localSysmon] = await Promise.all([neighbors(), sysmon()]);
      const { events, ...status } = localSysmon;
      const deviceFindings = history && await history.observe(localNeighbors.records,
        localNeighbors.updated_at ?? new Date().toISOString()).catch(() => undefined);
      const cases = scriptCases(events);
      const connections = new Map();
      for (const event of events) {
        if (event.kind !== 3 || !event.destination) continue;
        const link = connections.get(event.destination) ?? { asset_id: 'local-pc', address: event.destination,
          direction: 'outbound', source: 'Sysmon', events: 0, last_seen: event.timestamp, cases: [] };
        link.events += 1;
        connections.set(event.destination, link);
      }
      return Response.json({
        local_device: { host, addresses: Object.entries(networkInterfaces()).flatMap(([name, entries]) =>
          entries.filter((entry) => !entry.internal).map(({ address }) => ({ interface: name, address }))) },
        assets: events.length ? [{ id: 'local-pc', host, events: events.length, last_seen: events[0].timestamp,
          cases: cases.map(({ id, title }) => ({ id, title })) }] : [],
        links: [...connections.values()],
        neighbors: localNeighbors,
        device_findings: deviceFindings,
        sysmon: { ...status, recent: true, session_events: events.length },
        activity: activity(events),
      });
    }
    if (pathname === '/api/events') {
      const search = (searchParams.get('q') ?? '').toLowerCase().slice(0, 200);
      const kind = searchParams.get('kind');
      const before = searchParams.get('before');
      const cursor = (event) => event.timestamp + '|' + event.id;
      const { events, state } = await sysmon();
      const matches = events.filter((event) =>
        (!search || JSON.stringify(event).toLowerCase().includes(search)) &&
        (!kind || String(event.kind) === kind) && (!before || cursor(event) < before),
      ).sort((a, b) => cursor(b).localeCompare(cursor(a)));
      const page = matches.slice(0, 25);
      return Response.json({ events: page, next: matches.length > page.length ? cursor(page.at(-1)) : null,
        coverage: state === 'unavailable' ? 'sysmon_unavailable' : undefined });
    }
    return Response.json({ detail: 'Not found' }, { status: 404 });
  };
}

module.exports = { makeLocalWorkspace };
