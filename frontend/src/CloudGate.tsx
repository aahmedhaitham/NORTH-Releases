import { useEffect, useState, type ReactNode } from 'react';
import { CollectorSetup } from './CollectorSetup';

type Source = { id: string; label: string; updated_at: string };

export function CloudGate({ children }: {
  children: (source: string | null, openCollectors: () => void, controls: ReactNode) => ReactNode;
}) {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [key, setKey] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [sources, setSources] = useState<Source[]>([]);
  const [active, setActive] = useState('');
  const [setup, setSetup] = useState(false);
  const source = sources.find((item) => item.id === active) ?? sources[0];

  useEffect(() => {
    const controller = new AbortController();
    async function status() {
      try {
        const response = await fetch('/api/cloud/status', { signal: controller.signal });
        if (controller.signal.aborted) return;
        if (response.ok) {
          const data = await response.json();
          setSources(data.sources);
          setSignedIn(true);
        } else if (response.status === 401) {
          setSignedIn(false);
        } else {
          setSignedIn(false);
          setMessage('The cloud service is not ready.');
        }
      } catch {
        if (!controller.signal.aborted) {
          setSignedIn(false);
          setMessage('Could not connect to NORTH Cloud.');
        }
      }
    }
    void status();
    const timer = window.setInterval(status, 30000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [signedIn]);

  async function signIn() {
    setBusy(true);
    setMessage('');
    try {
      const response = await fetch('/api/cloud/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key }),
      });
      if (!response.ok) throw new Error(response.status === 401 ? 'Access key did not match.' : 'Could not sign in.');
      setKey('');
      setSignedIn(true);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Could not sign in.');
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    try {
      const response = await fetch('/api/cloud/logout', { method: 'POST' });
      if (!response.ok) throw new Error('Sign-out could not be completed.');
      setSignedIn(false);
      setSources([]);
      setActive('');
      setSetup(false);
      setMessage('');
    } catch {
      setMessage('Sign-out could not be completed.');
    }
  }

  if (signedIn) {
    const controls = <div className="cloud-banner">
      <div className="cloud-context">
      {source ? <label><span>Collector</span>
        <select value={source.id} onChange={(event) => setActive(event.target.value)}>
          {sources.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
        </select>
      </label> : <span>No collector connected</span>}
      {source && <span>Last sync {new Date(source.updated_at).toLocaleString()}</span>}
      </div>
      {message && <span role="alert">{message}</span>}
      <div className="cloud-actions">
        <button onClick={() => setSetup(!setup)} aria-pressed={setup}>Collectors</button>
        <button onClick={() => void signOut()}>Sign out</button>
      </div>
    </div>;
    return setup ? <>{controls}<CollectorSetup back={() => setSetup(false)} /></> :
      children(source?.id ?? null, () => setSetup(true), controls);
  }

  return <main className="cloud-sign-in">
    <section className="panel">
      <h1>NORTH Cloud</h1>
      {signedIn === null ? <p>Checking your session…</p> : <form className="event-filters" onSubmit={(event) => {
        event.preventDefault(); void signIn();
      }}>
        <label>Workspace access key
          <input type="password" autoComplete="current-password" value={key} required
            onChange={(event) => setKey(event.target.value)} />
        </label>
        <button type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>}
      {message && <p role="alert">{message}</p>}
    </section>
  </main>;
}
