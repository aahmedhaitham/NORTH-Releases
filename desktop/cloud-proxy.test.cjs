const assert = require('node:assert/strict');
const test = require('node:test');
const { makeCloudProxy } = require('./cloud-proxy.cjs');

test('bundled client keeps sign-in in the bridge and forwards only workspace requests', async () => {
  const origin = 'https://north.example.com';
  const proxy = makeCloudProxy(origin, async (url, options) => {
    assert.ok(url.startsWith(origin + '/api/'));
    assert.equal(options.redirect, 'error');
    if (url.endsWith('/login')) {
      assert.equal(options.headers.Origin, origin);
      assert.equal(options.headers.Cookie, undefined);
      return Response.json({ signed_in: true }, { headers: { 'Set-Cookie': '__Host-north_session=example; HttpOnly; Secure' } });
    }
    assert.equal(options.headers.Cookie, '__Host-north_session=example');
    return Response.json({ events: [] });
  });
  const login = await proxy(new Request('north://app/api/cloud/login', { method: 'POST', body: '{"key":"example"}' }));
  assert.equal(login.status, 200);
  assert.equal(login.headers.has('Set-Cookie'), false);
  assert.equal((await proxy(new Request('north://app/api/cloud/snapshot', { method: 'POST' }))).status, 405);
  assert.deepEqual(await (await proxy(new Request('north://app/api/events'))).json(), { events: [] });
});

test('a cloud connection failure is returned to the local interface', async () => {
  const proxy = makeCloudProxy('https://north.example.com', async () => { throw new Error('offline'); });
  const response = await proxy(new Request('north://app/api/cloud/status'));
  assert.equal(response.status, 503);
  assert.match((await response.json()).detail, /could not be reached/);
});
