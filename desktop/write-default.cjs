const fs = require('node:fs');
const path = require('node:path');
const { workspaceOrigin } = require('./workspace.cjs');

if (process.env.NORTH_DESKTOP_DEFAULT_URL) {
  fs.writeFileSync(path.join(__dirname, 'ui', 'workspace-default.json'),
    JSON.stringify({ origin: workspaceOrigin(process.env.NORTH_DESKTOP_DEFAULT_URL) }));
}
