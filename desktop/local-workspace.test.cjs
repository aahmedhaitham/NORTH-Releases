const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { makeLocalWorkspace } = require('./local-workspace.cjs');
const { deviceHistory } = require('./device-history.cjs');

test('local workspace reads Windows data without cloud configuration', async () => {
  const makeEvent = (id, kind, fields) => ({ data: { win: {
    system: { eventID: kind, systemTime: `2026-11-25T10:00:0${id}Z`, eventRecordID: id },
    eventdata: { processGuid: 'example-process', ...fields },
  } } });
  const records = [{ address: '192.0.2.1', interface: 'Wi-Fi' }];
  const alerts = [
    makeEvent(3, 11, { targetFilename: 'inventory.ps1' }),
    makeEvent(1, 1, { image: 'powershell.exe' }),
    makeEvent(2, 3, { destinationIp: '192.0.2.1' }),
  ];
  const invocations = [];
  const api = makeLocalWorkspace('tools', async (file, args) => {
    invocations.push(args[0]);
    return file.endsWith('Read-NorthSysmon.ps1') ? { alerts } : records;
  });
  const call = (endpoint, method = 'GET') => api(new Request('north://app' + endpoint, { method }));
  const snapshot = await (await call('/api/network')).json();
  assert.deepEqual(snapshot.neighbors.records, records);
  assert.equal(snapshot.sysmon.session_events, 3);
  assert.equal(snapshot.activity.buckets.at(-1).count, 3);
  assert.equal(snapshot.links[0].address, '192.0.2.1');
  const [incident] = await (await call('/api/cases')).json();
  assert.deepEqual(incident.evidence.map(({ kind }) => kind), [1, 3, 11]);
  const report = await call('/api/cases/' + incident.id + '/report');
  assert.match(await report.text(), /PowerShell process wrote a script file/);
  const filtered = await (await call('/api/events?kind=11&q=inventory')).json();
  assert.equal(filtered.events.length, 1);
  assert.deepEqual(invocations.sort(), ['-AsJson', '-Recent']);
  assert.equal((await call('/api/cloud/status')).status, 404);
  assert.equal((await call('/api/cases', 'POST')).status, 405);
});

test('failed Sysmon access leaves the local network view available', async () => {
  const api = makeLocalWorkspace('tools', async (file) => {
    if (file.endsWith('Read-NorthSysmon.ps1')) throw new Error('Access denied');
    return [];
  });
  const snapshot = await (await api(new Request('north://app/api/network'))).json();
  assert.equal(snapshot.neighbors.state, 'ready');
  assert.equal(snapshot.sysmon.state, 'unavailable');
  const page = await (await api(new Request('north://app/api/events'))).json();
  assert.equal(page.coverage, 'sysmon_unavailable');
});

test('local device review persists across desktop sessions', async (t) => {
  const folder = await fs.mkdtemp(path.join(tmpdir(), 'north-history-'));
  t.after(() => fs.rm(folder, { recursive: true, force: true }));
  const file = path.join(folder, 'history.json');
  const device = (last) => ({ address: '192.0.2.' + last, mac: '02:12:34:56:78:0' + last, interface: 'Wi-Fi' });
  const first = deviceHistory(file);
  const at = '2026-11-25T12:00:00.000Z';
  assert.deepEqual(await first.observe([], at), { baseline_at: null, unreviewed: 0, items: [] });
  assert.equal((await first.observe([device(1)], at)).baseline_at, at);
  const second = deviceHistory(file);
  const later = '2026-11-25T12:05:00.000Z';
  const newDevice = await second.observe([device(1), device(2)], later);
  assert.equal(newDevice.unreviewed, 1);
  const id = newDevice.items[0].id;
  const api = makeLocalWorkspace('tools', async () => [], second);
  const response = await api(new Request('north://app/api/network/devices/' + id + '/review', { method: 'POST' }));
  assert.equal(response.status, 200);
  assert.equal((await deviceHistory(file).observe([device(2)], later)).unreviewed, 0);
});
