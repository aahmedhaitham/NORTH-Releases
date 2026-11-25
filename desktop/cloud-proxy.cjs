function makeCloudProxy(origin, fetcher = fetch) {
  let sessionCookie = '';

  return async (request) => {
    const { pathname, search } = new URL(request.url);
    if (!pathname.startsWith('/api/') || pathname === '/api/cloud/snapshot'
      || !['GET', 'POST'].includes(request.method)) {
      return Response.json({ detail: 'This route is unavailable in the desktop client.' }, { status: 405 });
    }
    const headers = { 'User-Agent': 'NORTH-Desktop/0.2', Accept: 'application/json, text/plain' };
    if (sessionCookie) headers.Cookie = sessionCookie;
    let body;
    if (request.method === 'POST') {
      headers.Origin = origin;
      headers['Content-Type'] = 'application/json';
      body = await request.text();
      if (body.length > 4096) return Response.json({ detail: 'Request too large.' }, { status: 413 });
    }
    try {
      const upstream = await fetcher(origin + pathname + search, {
        method: request.method, headers, body, redirect: 'error', signal: AbortSignal.timeout(12000),
      });
      const setCookie = upstream.headers.get('Set-Cookie');
      if (upstream.ok && pathname === '/api/cloud/login') {
        sessionCookie = setCookie?.match(/^(__Host-north_session=[^;]+)/)?.[1] ?? '';
        if (!sessionCookie || sessionCookie.endsWith('=')) {
          return Response.json({ detail: 'Cloud sign-in did not return a session.' }, { status: 502 });
        }
      } else if (upstream.status === 401 || (upstream.ok && pathname === '/api/cloud/logout')) {
        sessionCookie = '';
      }
      const responseHeaders = { 'Cache-Control': 'no-store' };
      for (const name of ['Content-Type', 'Content-Disposition']) {
        const value = upstream.headers.get(name);
        if (value) responseHeaders[name] = value;
      }
      return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
    } catch {
      return Response.json({ detail: 'The cloud workspace could not be reached over HTTPS.' }, { status: 503 });
    }
  };
}

module.exports = { makeCloudProxy };
