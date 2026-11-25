import { useEffect, useState } from 'react';
import { explainAddress } from './deviceExplanation';

type CaseReference = { id: string; title: string };
type Host = { id: string; host: string; events: number; last_seen: string; cases: CaseReference[] };
type Connection = {
  asset_id: string; address: string; direction: 'inbound' | 'outbound';
  events: number; last_seen: string; cases: CaseReference[]; source: string;
};
type Collector = { state: 'starting' | 'disabled' | 'ready' | 'unavailable'; updated_at: string | null };
type Finding = { id: string; first_seen: string; last_seen: string; reviewed_at: string | null;
  mac: string; interface: string; addresses: string[] };
type Snapshot = {
  assets: Host[]; links: Connection[];
  local_device?: { host: string; addresses: { interface: string; address: string }[] };
  activity?: { interval: 'minute' | 'hour' | 'day' | null; buckets: { start: string; count: number }[];
    types: { kind: number; count: number }[] };
  neighbors?: Collector & { records: Neighbor[] };
  sysmon?: Collector & { session_events: number; recent?: boolean; problem?: 'access_denied' | 'channel_missing' | 'read_failed' | null };
  device_findings?: { baseline_at: string | null; unreviewed: number; items: Finding[] };
  router_usage?: Collector & { devices: { mac: string; download_bytes: number; upload_bytes: number }[] };
};
type Neighbor = { address: string; mac: string; network: string; state: string; name: string };
const megabytes = new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 });

const sysmonProblems = {
  access_denied: 'Windows denied this account access to the Sysmon event log.',
  channel_missing: 'The Sysmon event log was not found.',
  read_failed: 'NORTH could not read the Sysmon event log. It will retry.',
};

function readNeighbors(value: unknown): Neighbor[] {
  if (!Array.isArray(value)) throw new Error('Choose a JSON array of device records.');
  if (value.length > 5000) throw new Error('Choose a file with at most 5,000 device records.');
  return value.map((row, index) => {
    const address = row?.address ?? row?.dst;
    if (typeof address !== 'string' || !address.trim()) {
      throw new Error('Device record ' + (index + 1) + ' is missing an address.');
    }
    return {
      address: address.trim(),
      mac: String(row.mac ?? row.lladdr ?? ''),
      network: String(row.interface ?? row.dev ?? ''),
      state: Array.isArray(row.state) ? row.state.join(', ') : String(row.state ?? ''),
      name: String(row.name ?? ''),
    };
  });
}

export function groupNeighbors(records: Neighbor[]) {
  const devices = new Map<string, Neighbor[]>();
  for (const record of records) {
    const mac = record.mac.replace(/[:-]/g, '').toLowerCase();
    const identity = /^[0-9a-f]{12}$/.test(mac) && mac !== '000000000000'
      ? 'mac:' + mac : 'ip:' + record.address;
    const key = record.network + ':' + identity;
    const device = devices.get(key) ?? [];
    if (!device.some((item) => item.address === record.address)) device.push(record);
    devices.set(key, device);
  }
  return [...devices];
}

export function useNetworkInventory(endpoint: string) {
  const [inventory, setInventory] = useState<Snapshot | null>(null);
  const [fetchError, setFetchError] = useState(false);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    if (!endpoint) return;
    const controller = new AbortController();
    let timer: number | undefined;
    async function refresh() {
      try {
        const response = await fetch(endpoint, { signal: controller.signal, cache: 'no-store' });
        if (!response.ok) throw new Error('Inventory unavailable');
        const result: Snapshot = await response.json();
        if (result.neighbors) result.neighbors.records = readNeighbors(result.neighbors.records);
        if (!controller.signal.aborted) {
          setInventory(result);
          setFetchError(false);
        }
      } catch {
        if (!controller.signal.aborted) setFetchError(true);
      } finally {
        if (!controller.signal.aborted && endpoint.startsWith('/api/')) {
          timer = window.setTimeout(refresh, 5000);
        }
      }
    }
    void refresh();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [endpoint, revision]);

  return { inventory, fetchError, refresh: () => setRevision((value) => value + 1) };
}

export function Network({ endpoint, openCase, demo, readOnly }: {
  endpoint: string; openCase: (id: string) => void; demo: boolean; readOnly: boolean;
}) {
  const { inventory, fetchError, refresh } = useNetworkInventory(endpoint);
  const [neighbors, setNeighbors] = useState<Neighbor[]>([]);
  const [fileMessage, setFileMessage] = useState('');
  const [search, setSearch] = useState('');
  const [reviewing, setReviewing] = useState('');
  const [reviewError, setReviewError] = useState(false);
  const query = search.trim().toLowerCase();
  const fits = (...values: string[]) => values.some((value) => value.toLowerCase().includes(query));
  const hosts = new Map(inventory?.assets.map((asset) => [asset.id, asset.host]));
  const matchingHosts = inventory?.assets.filter((asset) => fits(asset.host)) ?? [];
  const matchingLinks = inventory?.links.filter((link) => fits(link.address, hosts.get(link.asset_id) ?? '')) ?? [];
  const collector = inventory?.neighbors;
  const windowsEvents = inventory?.sysmon;
  const matchesDevice = ([, records]: [string, Neighbor[]]) => records.some((record) =>
    fits(record.address, record.name, record.mac, record.network));
  const liveDevices = groupNeighbors(collector?.records ?? []);
  const importedDevices = groupNeighbors(neighbors);
  const watch = inventory?.device_findings;
  const router = inventory?.router_usage;
  const routerDevices = router?.devices.filter((device) => fits(device.mac)) ?? [];

  async function review(id: string) {
    setReviewError(false);
    setReviewing(id);
    try {
      const response = await fetch('/api/network/devices/' + encodeURIComponent(id) + '/review', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reviewed: true }),
      });
      if (!response.ok) throw new Error('Review failed');
      refresh();
    } catch {
      setReviewError(true);
    } finally {
      setReviewing('');
    }
  }

  async function importNeighbors(file: File) {
    try {
      if (file.size > 2_000_000) throw new Error('Choose a JSON file smaller than 2 MB.');
      const records = readNeighbors(JSON.parse((await file.text()).replace(/^\uFEFF/, '')));
      setNeighbors(records);
      setFileMessage(records.length + ' device records loaded in this tab.');
    } catch (error) {
      setFileMessage(error instanceof Error ? error.message : 'Could not read that file.');
    }
  }

  function caseButtons(cases: CaseReference[]) {
    return cases.map((item) => (
      <button type="button" className="network-case" key={item.id} onClick={() => openCase(item.id)}>{item.title}</button>
    ));
  }

  function devicesList(devices: [string, Neighbor[]][]) {
    const matching = devices.filter(matchesDevice);
    return <>
      <ul className="network-list">{matching.map(([key, records]) => {
        const { address, name, mac, network } = records[0];
        return <li key={key}>
          <strong>{name || address}</strong>
          <small>{[mac, network, /VMware|VirtualBox|vEthernet/i.test(network) && 'Virtual adapter'].filter(Boolean).join(' · ')}</small>
          <small>{records.map((record) => [record.address, record.state].filter(Boolean).join(' · ')).join(' / ')}</small>
          <details className="device-explanation">
            <summary>Explain this device</summary>
            <p>{name ? 'The source supplied the label “' + name + '”.' : 'The available records do not identify the device model.'}
              {' '}Addresses here were grouped by interface and hardware address when both were available.</p>
            {records.map((record) => <p key={record.address}><strong>{record.address}</strong> · {explainAddress(record.address)}</p>)}
          </details>
        </li>;
      })}</ul>
      {devices.length > 0 && !matching.length && <p>No devices match this search.</p>}
    </>;
  }

  return <main className="network">
    <header className="panel overview">
      <div>
        <h1>ATLAS <span className="workspace-title">Network inventory</span></h1>
        <p>Review devices that sent telemetry, their observed connections, and device records from your network.</p>
      </div>
      <label className="network-search">Find a host, IP address or MAC address
        <input type="search" value={search} onChange={(event) => setSearch(event.target.value)} />
      </label>
    </header>
    {fetchError && <p role="status">The telemetry inventory is temporarily unavailable.</p>}
    {inventory?.local_device && <section className="panel">
      <h2>This computer</h2>
      <strong>{inventory.local_device.host}</strong>
      <ul className="network-list">{inventory.local_device.addresses
        .filter((item) => fits(item.interface, item.address, inventory.local_device!.host))
        .map((item) => <li key={item.interface + '/' + item.address}>
          <strong>{item.interface}</strong><small>{item.address}</small>
        </li>)}</ul>
    </section>}
    {watch && (watch.baseline_at || collector?.state === 'starting') && <section className="panel">
      <h2>Newly observed devices</h2>
      <p>{watch.baseline_at ? `${watch.unreviewed} awaiting review · Baseline started ${new Date(watch.baseline_at).toLocaleString()}` :
        'Waiting for the first usable device snapshot.'}</p>
      {demo && <p>Sample finding from a synthetic network.</p>}
      {reviewError && <p role="alert">That finding could not be marked as reviewed.</p>}
      {!watch.items.length && watch.baseline_at && <p>No new devices have appeared since the first snapshot.</p>}
      <ul className="network-list">{watch.items.filter((item) => fits(item.mac, item.interface, ...item.addresses)).map((item) => (
        <li key={item.id}>
          <strong>{item.addresses.join(', ')}</strong>
          <small>{item.mac} · {item.interface} · First seen {new Date(item.first_seen).toLocaleString()}</small>
          <small>{item.reviewed_at ? 'Reviewed' : 'Needs review'} · Last seen {new Date(item.last_seen).toLocaleString()}</small>
          <details className="device-explanation">
            <summary>Why did this appear?</summary>
            <p>NORTH saw this hardware address on this interface after the first snapshot. A new device or a randomized hardware address can produce this finding.</p>
            {item.addresses.map((address) => <p key={address}><strong>{address}</strong> · {explainAddress(address)}</p>)}
          </details>
          {!readOnly && !item.reviewed_at && <button className="network-case" disabled={Boolean(reviewing)}
            onClick={() => void review(item.id)}>{reviewing === item.id ? 'Saving…' : 'Mark reviewed'}</button>}
        </li>
      ))}</ul>
    </section>}
    {windowsEvents && windowsEvents.state !== 'disabled' && <section className="panel">
      <h2>Windows event collection</h2>
      <p role="status">{windowsEvents.state === 'starting' ? 'Connecting to the Sysmon log…' :
        windowsEvents.state === 'unavailable' ? sysmonProblems[windowsEvents.problem ?? 'read_failed'] :
        `${windowsEvents.session_events} ${windowsEvents.recent ? 'recent events available' : 'new events since launch'} · Last checked ${new Date(windowsEvents.updated_at ?? '').toLocaleTimeString()}`}</p>
    </section>}
    {collector && collector.state !== 'disabled' && <section className="panel">
      <h2>Local network devices</h2>
      <p role="status">{collector.state === 'starting' ? 'Reading the local neighbor cache…' :
        collector.state === 'unavailable' ? 'The collector could not read the cache. It will retry automatically.' :
        `${liveDevices.length} device groups · Last refreshed ${new Date(collector.updated_at ?? '').toLocaleTimeString()}`}</p>
      <p>Addresses on the same interface with the same MAC are grouped. This is the PC’s recent view of the network.</p>
      {devicesList(liveDevices)}
    </section>}
    <div className="columns">
      <section className="panel">
        <h2>Reporting devices</h2>
        <ul className="network-list">{matchingHosts.map((asset) => <li key={asset.id}>
          <strong>{asset.host}</strong>
          <small>{asset.events} events · Last seen {new Date(asset.last_seen).toLocaleString()}</small>
          <div className="case-links">{caseButtons(asset.cases)}</div>
        </li>)}</ul>
        {!matchingHosts.length && <p>{inventory ? 'No reporting devices match.' : 'Loading reporting devices…'}</p>}
      </section>
      <section className="panel">
        <h2>Observed connections</h2>
        <ul className="network-list">{matchingLinks.map((link) => <li key={link.asset_id + link.address + link.direction}>
          <strong>{link.address}</strong>
          <small>{link.direction === 'inbound' ? 'Inbound to' : 'Outbound from'} {hosts.get(link.asset_id)} · {link.source} · {link.events} {link.events === 1 ? 'event' : 'events'}</small>
          <details className="device-explanation">
            <summary>Explain this address</summary>
            <p>{explainAddress(link.address)}</p>
          </details>
          <div className="case-links">{caseButtons(link.cases)}</div>
        </li>)}</ul>
        {!matchingLinks.length && <p>{inventory ? 'No observed connections match.' : 'Loading connections…'}</p>}
      </section>
    </div>
    {router && <section className="panel">
      <h2>Router traffic by device</h2>
      <p>OpenWrt accounting-period totals. Devices are ranked by their combined upload and download.</p>
      {router.state === 'unavailable' && <p role="status">Router data is unavailable. Any figures below are from the last successful refresh.</p>}
      {router.state === 'starting' && <p>Waiting for the first router update…</p>}
      {router.updated_at && <p className="reference">Last updated {new Date(router.updated_at).toLocaleString()}</p>}
      {router.state === 'ready' && !routerDevices.length && <p>No matching device totals.</p>}
      <ul className="network-list">{routerDevices.map((device) => <li key={device.mac}>
        <strong>{device.mac}</strong>
        <small>{megabytes.format(device.download_bytes / 1_000_000)} MB downloaded · {megabytes.format(device.upload_bytes / 1_000_000)} MB uploaded</small>
      </li>)}</ul>
    </section>}
    <details className="panel">
      <summary>Import a device list</summary>
      <p>Choose a Windows or Linux neighbor-cache export, or a router export formatted as JSON device records. A cache is a partial list of devices seen recently. The file stays in this browser tab.</p>
      <input type="file" accept=".json,application/json" aria-label="Import device inventory JSON"
        onChange={(event) => { const file = event.target.files?.[0]; if (file) void importNeighbors(file); event.target.value = ''; }} />
      {fileMessage && <p role="status">{fileMessage}</p>}
      {devicesList(importedDevices)}
    </details>
  </main>;
}
