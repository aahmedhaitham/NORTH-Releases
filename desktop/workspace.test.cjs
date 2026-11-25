const assert = require('node:assert/strict');
const test = require('node:test');
const { workspaceOrigin } = require('./workspace.cjs');

test('accepts an HTTPS workspace origin only', () => {
  assert.equal(workspaceOrigin(' https://north.example.com/ '), 'https://north.example.com');
  for (const address of [
    'http://north.example.com', 'file:///secrets', 'https://user:pass@north.example.com',
    'https://north.example.com/api/cloud/status', 'https://north.example.com/?x=1', null,
  ]) assert.throws(() => workspaceOrigin(address));
});
