import { useEffect, useState } from 'react';

type Pairing = { source_id: string; label: string; revoked_at: string | null; updated_at: string | null };
type Created = { source_id: string; label: string; token: string };

export function CollectorSetup({ back }: { back: () => void }) {
  const [items, setItems] = useState<Pairing[]>([]);
  const [loading, setLoading] = useState(true);
  const [label, setLabel] = useState('');
  const [created, setCreated] = useState<Created | null>(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState('');

  async function update(signal?: AbortSignal) {
    const response = await fetch('/api/cloud/pairings', { signal });
    if (!response.ok) throw new Error('Could not load collectors.');
    const data = await response.json();
    if (!signal?.aborted) { setItems(data.pairings); setLoading(false); }
  }

  useEffect(() => {
    const controller = new AbortController();
    void update(controller.signal).catch(() => {
      if (!controller.signal.aborted) { setLoading(false); setMessage('Could not load collectors.'); }
    });
    return () => controller.abort();
  }, []);

  async function mutate(path: string, body: object, showKey: boolean) {
    setBusy(true);
    setMessage('');
    try {
      const response = await fetch(path, { method: 'POST',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? 'Cloud request failed.');
      if (showKey) { setCreated(result); setLabel(''); }
      setConfirm('');
      await update();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Cloud request failed.');
    } finally {
      setBusy(false);
    }
  }

  return <main className="collector-settings">
    <header className="collector-heading">
      <div><h1>Collectors</h1><p>Connect a device to this workspace and manage its access.</p></div>
      <button onClick={back}>Back to dashboard</button>
    </header>
    {message && <p role="alert">{message}</p>}
    <section className="panel">
      <h2>Add collector</h2>
      <form className="event-filters" onSubmit={(event) => {
        event.preventDefault(); void mutate('/api/cloud/pairings', { label }, true);
      }}>
        <label>Collector name <input required maxLength={80} placeholder="Office PC" value={label}
          onChange={(event) => setLabel(event.target.value)} /></label>
        <button className="primary-action" type="submit" disabled={busy || !label.trim()}>Create pairing</button>
      </form>
      {created && <div className="pairing-secret">
        <h3>Connect {created.label}</h3>
        <p>On a Windows device with Python installed, run this command from the NORTH project folder. Enter the workspace address and pairing key when prompted. After pairing, double-click Start NORTH Collector to reconnect.</p>
        <pre>{"& '.\\Start NORTH Collector.cmd' -Source " + created.source_id}</pre>
        <label>Pairing key <input readOnly value={created.token} onFocus={(event) => event.currentTarget.select()} /></label>
        <button onClick={() => setCreated(null)}>Hide key</button>
      </div>}
    </section>
    <section className="panel">
      <h2>Paired collectors</h2>
      {loading && <p>Loading collectors…</p>}
      {!loading && !items.length && <p>No collector pairings have been created.</p>}
      <ul className="network-list">{items.map((item) => <li key={item.source_id} className="collector-row">
        <div>
          <strong>{item.label}</strong>
          <small>{item.revoked_at ? 'Revoked' : item.updated_at ?
            'Last synced ' + new Date(item.updated_at).toLocaleString() : 'Waiting for first sync'}</small>
        </div>
        {!item.revoked_at && (confirm === item.source_id ? <div className="case-links">
          <button disabled={busy} onClick={() => void mutate('/api/cloud/pairings/' + item.source_id + '/revoke', {}, false)}>
            Confirm revoke
          </button>
          <button onClick={() => setConfirm('')}>Cancel</button>
        </div> : <button onClick={() => setConfirm(item.source_id)}>Revoke</button>)}
      </li>)}</ul>
    </section>
  </main>;
}
