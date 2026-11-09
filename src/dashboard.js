import http from 'node:http';
import net from 'node:net';

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

const PAGE = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Router summary</title>
  <style>
    :root { color-scheme: light dark; font: 16px/1.5 system-ui, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; background: #101820; color: #e9f0f5; }
    main { width: min(900px, 100%); margin: 0 auto; padding: 2rem 1rem; }
    h1 { margin: 0 0 .25rem; font-size: clamp(1.6rem, 5vw, 2.2rem); }
    .muted { color: #aab9c5; }
    .toolbar { margin: 1.5rem 0; display: flex; flex-wrap: wrap; align-items: center; gap: .75rem; }
    select, button { font: inherit; color: inherit; background: #1b2a36; border: 1px solid #526674; border-radius: .45rem; padding: .65rem .8rem; }
    select { min-width: min(100%, 18rem); }
    button { cursor: pointer; }
    button:hover { background: #263b4b; }
    #status { min-height: 1.5em; }
    #cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .75rem; margin: 1rem 0 1.5rem; }
    .card, section { background: #17232d; border: 1px solid #2e414f; border-radius: .65rem; }
    .card { padding: 1rem; min-width: 0; }
    .card strong { display: block; margin-bottom: .3rem; color: #a9c9e0; font-size: .85rem; font-weight: 600; overflow-wrap: anywhere; }
    .card span { display: block; overflow-wrap: anywhere; }
    section { padding: 1rem; }
    h2 { margin: 0 0 .75rem; font-size: 1.15rem; }
    pre { margin: 0; max-height: 55vh; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; color: #d7e6f0; }
    @media (max-width: 480px) { main { padding: 1.25rem .8rem; } .toolbar { align-items: stretch; } select, button { width: 100%; } }
  </style>
</head>
<body>
  <main>
    <h1>Router summary</h1>
    <p class="muted">Local, read-only status view.</p>
    <div class="toolbar">
      <label for="device">Device</label>
      <select id="device" aria-label="Select device"><option value="">Loading devices…</option></select>
      <button id="refresh" type="button">Refresh</button>
    </div>
    <p id="status" class="muted" role="status" aria-live="polite"></p>
    <div id="cards" aria-label="Summary status cards"></div>
    <section aria-labelledby="summary-heading">
      <h2 id="summary-heading">Summary data</h2>
      <pre id="summary">Select a device to load its summary.</pre>
    </section>
  </main>
  <script>
    const selector = document.getElementById('device');
    const statusLine = document.getElementById('status');
    const summaryPanel = document.getElementById('summary');
    const cards = document.getElementById('cards');

    function listFrom(value) {
      if (Array.isArray(value)) return value;
      if (value && Array.isArray(value.devices)) return value.devices;
      return [];
    }
    function deviceId(item, index) {
      if (typeof item === 'string' || typeof item === 'number') return String(item);
      if (!item || typeof item !== 'object') return String(index);
      return String(item.id ?? item.deviceId ?? item.key ?? item.name ?? item['.id'] ?? index);
    }
    function deviceLabel(item, id) {
      if (item && typeof item === 'object') return String(item.name ?? item.label ?? item.identity ?? id);
      return id;
    }
    function renderCards(value) {
      cards.replaceChildren();
      let entries;
      if (value && typeof value === 'object' && !Array.isArray(value)) entries = Object.entries(value);
      else entries = [['Status', value]];
      for (const [key, item] of entries.slice(0, 8)) {
        const card = document.createElement('div');
        const title = document.createElement('strong');
        const detail = document.createElement('span');
        card.className = 'card';
        title.textContent = key;
        detail.textContent = item === null || item === undefined
          ? '—'
          : (typeof item === 'object' ? JSON.stringify(item) : String(item));
        card.append(title, detail);
        cards.append(card);
      }
    }
    async function loadSummary() {
      const id = selector.value;
      cards.replaceChildren();
      if (!id) {
        summaryPanel.textContent = 'No device selected.';
        statusLine.textContent = '';
        return;
      }
      statusLine.textContent = 'Loading summary…';
      summaryPanel.textContent = '';
      try {
        const response = await fetch('/api/summary?device=' + encodeURIComponent(id), { headers: { Accept: 'application/json' } });
        const value = await response.json();
        if (!response.ok) throw new Error(value.error || 'Unable to load summary.');
        summaryPanel.textContent = JSON.stringify(value, null, 2);
        renderCards(value);
        statusLine.textContent = 'Summary loaded.';
      } catch {
        summaryPanel.textContent = 'Unable to load this device summary.';
        statusLine.textContent = 'Request failed.';
      }
    }
    async function loadDevices() {
      statusLine.textContent = 'Loading devices…';
      try {
        const response = await fetch('/api/devices', { headers: { Accept: 'application/json' } });
        const value = await response.json();
        if (!response.ok) throw new Error('Unable to load devices.');
        const devices = listFrom(value);
        selector.replaceChildren();
        for (const [index, item] of devices.entries()) {
          const id = deviceId(item, index);
          const option = document.createElement('option');
          option.value = id;
          option.textContent = deviceLabel(item, id);
          selector.append(option);
        }
        if (devices.length === 0) {
          selector.add(new Option('No devices available', ''));
          summaryPanel.textContent = 'No devices are available.';
          statusLine.textContent = 'No devices found.';
          return;
        }
        statusLine.textContent = '';
        await loadSummary();
      } catch {
        selector.replaceChildren(new Option('Devices unavailable', ''));
        summaryPanel.textContent = 'Unable to load devices.';
        statusLine.textContent = 'Request failed.';
      }
    }
    selector.addEventListener('change', loadSummary);
    document.getElementById('refresh').addEventListener('click', loadSummary);
    loadDevices();
  </script>
</body>
</html>`;

function isLoopbackAddress(address) {
  const family = net.isIP(address);
  if (family === 4) return Number(address.split('.')[0]) === 127
    && address.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255);
  return family === 6 && address.toLowerCase() === '::1';
}

function normalizeBindHost(host) {
  if (typeof host !== 'string') throw new TypeError('Dashboard host must be localhost or a loopback address.');
  const normalized = host.toLowerCase();
  if (normalized === 'localhost' || isLoopbackAddress(normalized)) return normalized;
  throw new TypeError('Dashboard host must be localhost or a loopback address.');
}

function requestHostIsLocal(header) {
  if (typeof header !== 'string' || header.length > 300) return false;
  let hostname;
  let portPart = '';
  if (header.startsWith('[')) {
    const end = header.indexOf(']');
    if (end < 0) return false;
    hostname = header.slice(1, end).toLowerCase();
    portPart = header.slice(end + 1);
    if (portPart && !/^:\d+$/.test(portPart)) return false;
  } else {
    const colon = header.lastIndexOf(':');
    if (colon >= 0) {
      if (header.indexOf(':') !== colon) return false;
      hostname = header.slice(0, colon).toLowerCase();
      portPart = header.slice(colon);
      if (!/^:\d+$/.test(portPart)) return false;
    } else hostname = header.toLowerCase();
  }
  if (portPart) {
    const port = Number(portPart.slice(1));
    if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  }
  if (hostname === 'localhost') return true;
  return isLoopbackAddress(hostname);
}

function sendJson(response, status, value) {
  let body;
  try {
    body = JSON.stringify(value);
  } catch {
    status = 500;
    body = '{"error":"Unable to encode response."}';
  }
  response.writeHead(status, {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(body),
  });
  response.end(body);
}

function getDeviceId(device) {
  if (typeof device === 'string' || typeof device === 'number') return String(device);
  if (!device || typeof device !== 'object') return null;
  const id = device.id ?? device.deviceId ?? device.key ?? device.name ?? device['.id'];
  return id === undefined || id === null ? null : String(id);
}

function deviceListFrom(value) {
  if (Array.isArray(value)) return value;
  if (value && Array.isArray(value.devices)) return value.devices;
  if (value && typeof value === 'object') return Object.entries(value).map(([id, details]) => (
    details && typeof details === 'object' && !Array.isArray(details) ? { id, ...details } : { id, value: details }
  ));
  return [];
}

export async function startDashboard({ listDevices, readSummary, host = '127.0.0.1', port = 9090 }) {
  if (typeof listDevices !== 'function' || typeof readSummary !== 'function') {
    throw new TypeError('listDevices and readSummary must be functions.');
  }
  const bindHost = normalizeBindHost(host);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new RangeError('Dashboard port must be an integer from 1 to 65535.');
  }

  const server = http.createServer(async (request, response) => {
    if (!requestHostIsLocal(request.headers.host)) {
      sendJson(response, 400, { error: 'Invalid Host header.' });
      return;
    }
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      sendJson(response, 405, { error: 'Method not allowed.' });
      return;
    }

    let pathname;
    let searchParams;
    try {
      const url = new URL(request.url, 'http://localhost');
      pathname = url.pathname;
      searchParams = url.searchParams;
    } catch {
      sendJson(response, 400, { error: 'Invalid request URL.' });
      return;
    }

    if (pathname === '/') {
      response.writeHead(200, {
        ...SECURITY_HEADERS,
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'Content-Length': Buffer.byteLength(PAGE),
      });
      response.end(PAGE);
      return;
    }
    if (pathname === '/api/devices') {
      try {
        const devices = await listDevices();
        sendJson(response, 200, devices);
      } catch {
        sendJson(response, 500, { error: 'Unable to load devices.' });
      }
      return;
    }
    if (pathname === '/api/summary') {
      const requestedId = searchParams.get('device');
      if (!requestedId || requestedId.length > 256) {
        sendJson(response, 400, { error: 'A valid device parameter is required.' });
        return;
      }
      try {
        const devices = deviceListFrom(await listDevices());
        const device = devices.find((entry) => getDeviceId(entry) === requestedId);
        if (!device) {
          sendJson(response, 404, { error: 'Device not found.' });
          return;
        }
        const summary = await readSummary(requestedId);
        sendJson(response, 200, summary);
      } catch {
        sendJson(response, 500, { error: 'Unable to load summary.' });
      }
      return;
    }
    sendJson(response, 404, { error: 'Not found.' });
  });

  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, bindHost);
  });
  const urlHost = bindHost.includes(':') ? `[${bindHost}]` : bindHost;
  const url = `http://${urlHost}:${port}`;
  return {
    server,
    url,
    async close() {
      if (!server.listening) return;
      await new Promise((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    },
  };
}
