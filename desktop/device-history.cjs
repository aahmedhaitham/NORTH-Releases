const { createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const { isIP } = require('node:net');
const { dirname } = require('node:path');

function deviceHistory(filename) {
  let pending = Promise.resolve();
  const empty = { baseline_at: null, devices: {} };

  async function edit(change) {
    const operation = pending.then(async () => {
      let state;
      try {
        state = JSON.parse(await fs.readFile(filename, 'utf8'));
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        state = structuredClone(empty);
      }
      const changed = change(state);
      if (changed) {
        await fs.mkdir(dirname(filename), { recursive: true });
        await fs.writeFile(filename + '.tmp', JSON.stringify(state), { mode: 0o600 });
        await fs.rename(filename + '.tmp', filename);
      }
      const items = Object.values(state.devices).filter((device) => !device.baseline)
        .sort((a, b) => b.first_seen.localeCompare(a.first_seen));
      return { baseline_at: state.baseline_at, unreviewed: items.filter((device) => !device.reviewed_at).length, items };
    });
    pending = operation.catch(() => {});
    return operation;
  }

  return {
    observe(records, at) {
      return edit((state) => {
        let changed = false;
        const baseline = !state.baseline_at;
        let count = Object.keys(state.devices).length;
        for (const record of records) {
          const mac = (record.mac ?? '').replace(/[:-]/g, '').toLowerCase();
          if (!/^[0-9a-f]{12}$/.test(mac) || mac === '000000000000' || (parseInt(mac.slice(0, 2), 16) & 1) ||
              !isIP(record.address) || !record.interface) continue;
          const id = createHash('sha256').update(record.interface + '|' + mac).digest('hex').slice(0, 24);
          let device = state.devices[id];
          if (!device) {
            if (count >= 2000) continue;
            device = state.devices[id] = { id, mac: record.mac, interface: record.interface, baseline,
              first_seen: at, last_seen: at, reviewed_at: null, addresses: [] };
            count += 1;
            changed = true;
          }
          if (device.last_seen !== at) { device.last_seen = at; changed = true; }
          if (!device.addresses.includes(record.address)) {
            device.addresses = [...device.addresses, record.address].slice(-12);
            changed = true;
          }
        }
        if (baseline && count) { state.baseline_at = at; changed = true; }
        return changed;
      });
    },
    async review(id, at) {
      let found = false;
      await edit((state) => {
        const device = state.devices[id];
        if (!device || device.baseline) return false;
        found = true;
        if (device.reviewed_at) return false;
        device.reviewed_at = at;
        return true;
      });
      return found;
    },
  };
}

module.exports = { deviceHistory };
