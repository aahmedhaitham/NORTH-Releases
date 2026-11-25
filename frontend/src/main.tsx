import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Background, Controls, ReactFlow } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './style.css';
import { Network } from './Network';
import { Events } from './Events';
import { eventNames } from './eventNames';
import { Dashboard } from './Dashboard';
import { InstallApp } from './InstallApp';
import { CloudGate } from './CloudGate';

type Evidence = {
  id: string; timestamp: string; kind: number; process: string;
  target: string; destination: string; source_ip?: string; raw: unknown;
};
type Case = {
  id: string; title: string; host: string; asset_id: string; summary: string;
  evidence: Evidence[]; links: { destination: string; evidence_id: string; direction?: 'inbound' }[];
};
type Claim = { text: string; evidence_ids: string[] };
type RelatedEvent = { id: string; source_id: string; timestamp: string; kind: number; collector: string; host: string; address: string };

const portfolio = import.meta.env.MODE === 'portfolio';
const publicDemo = portfolio || import.meta.env.MODE === 'hosted';
const desktop = location.protocol === 'north:';
const desktopLocal = desktop && location.pathname === '/';
const cloud = import.meta.env.MODE === 'cloud' && !desktopLocal;
if (desktopLocal) document.title = 'NORTH | This computer';

function App({ source = null, openCollectors, controls }: {
  source?: string | null;
  openCollectors?: () => void;
  controls?: import('react').ReactNode;
}) {
  const [view, setView] = useState<'dashboard' | 'cases' | 'network' | 'events'>('dashboard');
  const [cases, setCases] = useState<Case[]>([]);
  const [selected, setSelected] = useState('');
  const [online, setOnline] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const incident = cases.find((item) => item.id === selected) ?? cases[0];
  const sourceQuery = source ? '?source=' + encodeURIComponent(source) : '';
  const networkEndpoint = portfolio ? '/demo/network.json' : '/api/network' + sourceQuery;

  function openCase(id: string) {
    setSelected(id);
    setView('cases');
  }

  useEffect(() => {
    if (cloud || desktopLocal) {
      const controller = new AbortController();
      let timer: number | undefined;
      async function update() {
        try {
          const response = await fetch('/api/cases' + sourceQuery, { signal: controller.signal });
          if (!response.ok) throw new Error('Cloud case feed unavailable');
          const items: Case[] = await response.json();
          if (!controller.signal.aborted) {
            setCases(items); setLoaded(true); setOnline(true); setLoadError(false);
          }
        } catch {
          if (!controller.signal.aborted) { setOnline(false); setLoadError(true); }
        } finally {
          if (!controller.signal.aborted) timer = window.setTimeout(update, 15000);
        }
      }
      void update();
      return () => { controller.abort(); window.clearTimeout(timer); };
    }
    if (portfolio) {
      const controller = new AbortController();
      fetch('/demo/cases.json', { signal: controller.signal })
        .then((response) => {
          if (!response.ok) throw new Error('Demo case data unavailable');
          return response.json() as Promise<Case[]>;
        })
        .then((items) => { setCases(items); setLoaded(true); })
        .catch(() => { if (!controller.signal.aborted) setLoadError(true); });
      return () => controller.abort();
    }

    let disposed = false;
    let socket: WebSocket | undefined;
    let retry: number | undefined;
    function connect() {
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      socket = new WebSocket(protocol + '//' + location.host + '/api/live');
      socket.onmessage = (event) => {
        if (disposed) return;
        setCases(JSON.parse(event.data));
        setLoaded(true);
        setOnline(true);
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        if (disposed) return;
        setOnline(false);
        retry = window.setTimeout(connect, 2500);
      };
    }
    connect();
    return () => {
      disposed = true;
      window.clearTimeout(retry);
      socket?.close();
    };
  }, [sourceQuery]);

  return (
    <div className="shell">
      <nav className="console-nav" aria-label="Console">
        <a className="brand" href={cloud && desktop ? '/cloud' : '/'} onClick={(event) => {
          event.preventDefault(); setView('dashboard');
        }}><img alt="" src="/icons/north-192.png" />NORTH</a>
        <button type="button" aria-current={view === 'dashboard' ? 'page' : undefined} onClick={() => setView('dashboard')}>
          <strong>Overview</strong><small>Security dashboard</small>
        </button>
        <button type="button" aria-current={view === 'network' ? 'page' : undefined} onClick={() => setView('network')}>
          <strong>ATLAS</strong><small>Devices and network</small>
        </button>
        <button type="button" aria-current={view === 'events' ? 'page' : undefined} onClick={() => setView('events')}>
          <strong>IRIS</strong><small>Events and intelligence</small>
        </button>
        <button type="button" aria-current={view === 'cases' ? 'page' : undefined} onClick={() => setView('cases')}>
          <strong>ECHO</strong><small>Investigations and replay</small>
        </button>
      </nav>
      <div className="shell-content">
      {controls}
      <header className="topbar">
        <span>{{ dashboard: 'Overview', network: 'ATLAS / Network', events: 'IRIS / Events', cases: 'ECHO / Investigations' }[view]}</span>
        <InstallApp />
        <span role="status" className={online ? 'status online' : 'status'}>
          {desktopLocal ? 'This computer · Local data' : cloud ? (online ? 'Cloud connection ready' : 'Connecting to cloud') :
            portfolio ? 'Portfolio demo · Synthetic telemetry' : online ? (publicDemo ? 'Live demo · Synthetic telemetry' : 'Live feed connected') : 'Connecting to live feed'}
        </span>
      </header>
      {view === 'dashboard' && <Dashboard endpoint={networkEndpoint} cases={cases} loaded={loaded}
        demo={publicDemo} local={desktopLocal} open={setView} openCase={openCase} connect={cloud && !source ? openCollectors : undefined} />}
      <div hidden={view !== 'network'}>
        <Network endpoint={view === 'network' ? networkEndpoint : ''} openCase={openCase} demo={publicDemo} readOnly={publicDemo || cloud} />
      </div>
      {view === 'events' && <Events portfolio={portfolio} source={source} openNetwork={() => setView('network')} />}
      {view === 'cases' && <div className="workspace">
        <aside aria-label="Investigations">
          <h2>ECHO investigations</h2>
          {cases.map((item) => (
            <button key={item.id} className="case" aria-pressed={item.id === incident?.id}
              onClick={() => setSelected(item.id)}>
              <strong>{item.title}</strong><small>{item.host}</small>
            </button>
          ))}
        </aside>
        <main>
          {incident ? <Investigation key={incident.id} incident={incident} sourceQuery={sourceQuery} /> :
            <section className="panel"><h1>{loadError ? 'Cases could not load' : loaded ? 'No investigations yet' : 'Waiting for telemetry'}</h1>
              {loaded && !loadError && <p>Investigations appear when NORTH links related events. You can inspect individual events in IRIS.</p>}
              {(loaded || loadError) && <button onClick={() => setView('events')}>Open IRIS events</button>}
            </section>}
        </main>
      </div>}
      </div>
    </div>
  );
}

function Investigation({ incident, sourceQuery }: { incident: Case; sourceQuery: string }) {
  const [cursor, setCursor] = useState<number | null>(null);
  const [playing, setPlaying] = useState(false);
  const [claims, setClaims] = useState<Claim[]>([]);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [related, setRelated] = useState<RelatedEvent[] | null>(null);
  const [relatedError, setRelatedError] = useState(false);
  const [draftProvider, setDraftProvider] = useState('');
  const last = incident.evidence.length - 1;
  const active = Math.min(cursor ?? last, last);

  useEffect(() => {
    if (!cloud) return;
    const controller = new AbortController();
    void fetch('/api/cases/' + incident.id + '/related' + sourceQuery, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error('Could not load related events');
        return response.json();
      })
      .then((body) => setRelated(body.matches))
      .catch(() => { if (!controller.signal.aborted) setRelatedError(true); });
    return () => controller.abort();
  }, [incident.id, sourceQuery]);

  useEffect(() => {
    if (!playing) return;
    const timer = window.setTimeout(() => {
      if (active >= last) setPlaying(false);
      else setCursor(active + 1);
    }, 900);
    return () => window.clearTimeout(timer);
  }, [playing, active, last]);

  async function requestDraft() {
    setBusy(true);
    setMessage('');
    setClaims([]);
    setDraftProvider('');
    try {
      const response = await fetch('/api/cases/' + incident.id + '/draft' + sourceQuery, { method: 'POST' });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || 'Draft request failed.');
      setClaims(body.claims);
      setDraftProvider(body.provider ?? '');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Draft request failed.');
    } finally {
      setBusy(false);
    }
  }

  const destinations = [...new Set(incident.links.map((link) => link.destination))];
  const inbound = incident.links.some((link) => link.direction === 'inbound');
  const nodes = [
    { id: incident.asset_id, position: { x: inbound ? 250 : 0, y: 0 }, data: { label: incident.host } },
    ...destinations.map((ip, index) => (
      { id: 'ip-' + ip, position: { x: inbound ? 0 : 250, y: index * 90 }, data: { label: ip } }
    )),
  ];
  const edges = destinations.map((ip) => {
    const inbound = incident.links.some((link) => link.destination === ip && link.direction === 'inbound');
    return {
      id: 'edge-' + ip, source: inbound ? 'ip-' + ip : incident.asset_id,
      target: inbound ? incident.asset_id : 'ip-' + ip, animated: true,
    };
  });

  return <>
    <section className="panel overview">
      <div>
        <span className="module">IRIS / INVESTIGATION</span>
        <h1>{incident.title}</h1>
        <p>{incident.summary}</p>
      </div>
      <a className="button" download={portfolio ? 'north-' + incident.id + '.md' : undefined}
        href={portfolio ? '/demo/' + incident.id + '.md' : '/api/cases/' + incident.id + '/report' + sourceQuery}>Export report</a>
    </section>
    <div className="columns">
      <section className="panel">
        <span className="module">ATLAS / INFRASTRUCTURE</span>
        <h2>Observed connections</h2>
        <div className="graph">
          <ReactFlow key={destinations.join(',')} nodes={nodes} edges={edges}
            fitView fitViewOptions={{ maxZoom: 1 }} nodesDraggable={false} nodesConnectable={false} colorMode="dark">
            <Background gap={18} /><Controls showInteractive={false} />
          </ReactFlow>
        </div>
        {incident.links.map((link) => <p key={link.evidence_id} className="reference">
          {link.destination}{' '}<a href={'#event-' + link.evidence_id}>View evidence</a>
        </p>)}
        {incident.links.length === 0 && <p>No connection events for this case.</p>}
      </section>
      <section className="panel">
        <span className="module">ECHO / RECONSTRUCTION</span>
        <h2>Evidence timeline</h2>
        <div className="replay">
          <button onClick={() => {
            if (!playing && active === last) setCursor(0);
            setPlaying(!playing);
          }}>
            {playing ? 'Pause' : 'Play'}
          </button>
          <input aria-label="Timeline position" type="range" min="0" max={last} value={active}
            onChange={(event) => { setPlaying(false); setCursor(Number(event.target.value)); }} />
          <span>{active + 1} / {last + 1}</span>
        </div>
        <ol className="timeline">
          {incident.evidence.map((item, index) => (
            <li id={'event-' + item.id} key={item.id} className={index === active ? 'current' : ''}>
              <time dateTime={item.timestamp}>{item.timestamp.slice(11, 19)} UTC</time>
              <strong>{eventNames[item.kind]}</strong>
              <small>{item.target || item.destination || item.source_ip || item.process}</small>
              <details><summary>Raw evidence</summary><pre>{JSON.stringify(item.raw, null, 2)}</pre></details>
            </li>
          ))}
        </ol>
      </section>
    </div>
    {cloud && <section className="panel">
      <h2>Related events across collectors</h2>
      <p>Matches share an IP address within five minutes of the case’s latest event. Shared addresses alone cannot establish that events are part of the same incident.</p>
      {relatedError && <p role="status">Related events are unavailable.</p>}
      {!relatedError && !related && <p>Checking other collectors…</p>}
      {related?.length === 0 && <p>No matching events from another collector.</p>}
      <ul className="network-list">{related?.map((event) => <li key={event.source_id + '/' + event.id + '/' + event.address}>
        <strong>{eventNames[event.kind] ?? 'Event ' + event.kind}</strong>
        <small>{event.collector}{event.host ? ' · ' + event.host : ''} · {event.address} · {new Date(event.timestamp).toLocaleString()}</small>
        <RelatedEvidence event={event} />
      </li>)}</ul>
    </section>}
    <section className="panel">
      <span className="module">IRIS / ANALYST REVIEW</span>
      <h2>{publicDemo || desktopLocal ? 'Review case evidence' : cloud ? 'Evidence brief' : 'Local AI draft'}</h2>
      {desktopLocal ? <p>Open any event in the timeline to review the original record.</p> :
        publicDemo ? <p>This demo uses a bundled case. Open the original events in ECHO to verify the findings. Live AI drafts are available when running NORTH with Ollama.</p> : <>
        <p>{cloud ? 'Summarize recorded activity and open the cited events to verify each observation.' :
          'Ollama ranks observations that NORTH derives from case evidence. The available events do not establish intent.'}</p>
        <button type="button" disabled={busy} onClick={requestDraft}>{busy ? 'Drafting…' : 'Generate draft'}</button>
      </>}
      {draftProvider && <p role="status">{draftProvider === 'cloud-ai' ? 'Prioritized by cloud AI' : 'Generated from recorded evidence'}</p>}
      {message && <p role="status">{message}</p>}
      {claims.length > 0 && <ul>{claims.map((claim, index) => (
        <li key={index}>{claim.text}{' '}{claim.evidence_ids.map((id, position) => (
          <a className="citation" key={id + position} href={'#event-' + id}>{id.slice(0, 8)}</a>
        ))}</li>
      ))}</ul>}
    </section>
  </>;
}

function RelatedEvidence({ event }: { event: RelatedEvent }) {
  const [open, setOpen] = useState(false);
  const [body, setBody] = useState<Evidence | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (!open || body) return;
    const request = new AbortController();
    fetch('/api/events/' + event.id + '?source=' + encodeURIComponent(event.source_id),
      { signal: request.signal }).then((response) => {
      if (!response.ok) throw new Error('Evidence unavailable');
      return response.json();
    }).then(setBody).catch(() => { if (!request.signal.aborted) setFailed(true); });
    return () => request.abort();
  }, [open, body, event.id, event.source_id]);

  return <details onToggle={(toggle) => {
    setOpen(toggle.currentTarget.open);
    if (toggle.currentTarget.open) setFailed(false);
  }}>
    <summary>Open evidence</summary>
    {body ? <pre>{JSON.stringify(body.raw ?? body, null, 2)}</pre> :
      <p>{failed ? 'Evidence is unavailable.' : 'Loading evidence…'}</p>}
  </details>;
}

createRoot(document.getElementById('root')!).render(cloud ?
  <CloudGate>{(source, openCollectors, controls) =>
    <App key={source ?? ''} source={source} openCollectors={openCollectors} controls={controls} />}</CloudGate> : <App />);
