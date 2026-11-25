import { useEffect, useState } from 'react';
import { eventNames } from './eventNames';

type Event = {
  id: string; timestamp: string; kind: number; host: string; process: string;
  target: string; destination: string; source_ip?: string; raw: unknown;
};
type Page = { events: Event[]; next: string | null; coverage?: 'sysmon_unavailable' };
const pageSize = 25;

function cursor(event: Event) {
  return event.timestamp + '|' + event.id;
}

type Filter = { search: string; kind: string; before: string | null };

function staticPage(events: Event[], filter: Filter): Page {
  const needle = filter.search.toLowerCase();
  const ordered = events.filter((event) =>
    (!filter.kind || String(event.kind) === filter.kind) &&
    (!needle || JSON.stringify(event).toLowerCase().includes(needle)) &&
    (!filter.before || cursor(event) < filter.before)
  ).sort((a, b) => cursor(a) === cursor(b) ? 0 : cursor(a) < cursor(b) ? 1 : -1);
  return {
    events: ordered.slice(0, pageSize),
    next: ordered.length > pageSize ? cursor(ordered[pageSize - 1]) : null,
  };
}

export function Events({ portfolio, source, openNetwork }: { portfolio: boolean; source: string | null; openNetwork: () => void }) {
  const [search, setSearch] = useState('');
  const [kind, setKind] = useState('');
  const [filter, setFilter] = useState<Filter>({ search: '', kind: '', before: null });
  const [page, setPage] = useState<Page | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    let timer: number | undefined;
    async function load() {
      try {
        const query = new URLSearchParams({ limit: String(pageSize) });
        if (source) query.set('source', source);
        if (filter.search) query.set('q', filter.search);
        if (filter.kind) query.set('kind', filter.kind);
        if (filter.before) query.set('before', filter.before);
        const response = await fetch(portfolio ? '/demo/events.json' : '/api/events?' + query, {
          signal: controller.signal, cache: 'no-store',
        });
        if (!response.ok) throw new Error('Event request failed');
        const data = await response.json();
        if (!controller.signal.aborted) {
          setPage(portfolio ? staticPage(data, filter) : data);
          setError(false);
        }
      } catch {
        if (!controller.signal.aborted) setError(true);
      } finally {
        if (!controller.signal.aborted && !portfolio && !filter.before) {
          timer = window.setTimeout(load, 10000);
        }
      }
    }
    void load();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [filter, portfolio, source]);

  function changeFilter(next: Filter) {
    setPage(null);
    setError(false);
    setFilter(next);
  }

  return <main className="event-explorer">
    <section className="panel">
      <h1>IRIS <span className="workspace-title">Event explorer</span></h1>
      <p>Search collected telemetry and inspect the original records behind alerts.</p>
      <form className="event-filters" onSubmit={(event) => {
        event.preventDefault();
        changeFilter({ search: search.trim(), kind, before: null });
      }}>
        <label>Search event data
          <input type="search" placeholder="Hostname, process, IP address, or keyword"
            maxLength={200} value={search} onChange={(event) => setSearch(event.target.value)} />
        </label>
        <label>Event type
          <select value={kind} onChange={(event) => setKind(event.target.value)}>
            <option value="">All types</option>
            {Object.entries(eventNames).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </label>
        <button type="submit">Apply filters</button>
      </form>
    </section>
    <section className="panel" aria-label="Event results">
      {error && <p role="status">The event feed is temporarily unavailable.</p>}
      {!error && !page && <p role="status">Loading events…</p>}
      {page?.coverage === 'sysmon_unavailable' ? <div>
        <h2>Windows events are unavailable</h2>
        <p>NORTH needs a readable Sysmon event log. The network view is still available.</p>
        <button onClick={openNetwork}>Open ATLAS network inventory</button>
      </div> : page?.events.length === 0 && <p>{filter.kind || filter.search ? 'No events match these filters.' : 'No events are available yet.'}</p>}
      <ul className="event-list">{page?.events.map((event) => (
        <li key={event.id}>
          <details>
            <summary>
              <strong>{eventNames[event.kind] ?? 'Event ' + event.kind}</strong>
              <span>{event.host}</span>
              <time dateTime={event.timestamp}>{new Date(event.timestamp).toLocaleString()}</time>
            </summary>
            <p>{event.target || event.destination || event.source_ip || event.process}</p>
            <pre>{JSON.stringify(event.raw, null, 2)}</pre>
            <small>Evidence ID {event.id}</small>
          </details>
        </li>
      ))}</ul>
      <div className="event-pagination">
        {filter.before && <button onClick={() => changeFilter({ ...filter, before: null })}>Back to newest</button>}
        {page?.next && <button onClick={() => changeFilter({ ...filter, before: page.next })}>Older events</button>}
      </div>
    </section>
  </main>;
}
