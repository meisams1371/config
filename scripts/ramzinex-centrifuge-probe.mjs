import { Centrifuge } from 'centrifuge';
import WebSocket from 'ws';
import { HttpsProxyAgent } from 'https-proxy-agent';

const ENDPOINT = 'wss://websocket.ramzinex.ir/websocket';
const CONNECT_TIMEOUT_MS = 20000;
const RAW_TIMEOUT_MS = 16000;
const SUBSCRIBE_TIMEOUT_MS = 12000;
const PUBLICATION_WINDOW_MS = 8000;
const CHANNELS = [
  { channel: 'orderbook:2', delta: false },
  { channel: 'orderbook:11', delta: false },
  { channel: 'last-trades:11', delta: true },
];

const proxyCandidates = (
  process.env.RAMZINEX_WS_HTTP_PROXIES ||
  process.env.RAMZINEX_WS_HTTP_PROXY ||
  ''
).split(/[\r\n,]+/).map((value) => value.trim()).filter(Boolean).slice(0, 3);

const routes = proxyCandidates.length
  ? proxyCandidates.map((url, index) => ({ url, label: 'verified-iran-proxy', index: index + 1 }))
  : [{ url: '', label: 'direct-or-no-proxy-configured', index: 0 }];

function safeMessage(value) {
  return String(value ?? '').replace(/[\r\n\t]+/g, ' ').slice(0, 220);
}

function withTimeout(promise, timeoutMs, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(label + ' timed out after ' + timeoutMs + 'ms')), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function summarizeData(data) {
  if (Array.isArray(data)) return { type: 'array', length: data.length };
  if (data && typeof data === 'object') {
    const summary = { type: 'object', keys: Object.keys(data).slice(0, 20) };
    if (Array.isArray(data.buys)) summary.buys_count = data.buys.length;
    if (Array.isArray(data.sells)) summary.sells_count = data.sells.length;
    return summary;
  }
  return { type: typeof data };
}

function makeWebSocketClass(proxyUrl) {
  const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : undefined;
  return class RamzinexWebSocket extends WebSocket {
    constructor(address, protocols, options = {}) {
      super(address, protocols, {
        ...(options && typeof options === 'object' ? options : {}),
        ...(agent ? { agent } : {}),
      });
    }
  };
}

// Raw diagnostic uses the documented Centrifuge JSON connect command.
// It distinguishes an HTTP upgrade failure from a successful Centrifuge handshake.
async function probeRawConnect(WSClass) {
  return new Promise((resolve) => {
    const result = {
      websocket_upgrade: false,
      connect_command_sent: false,
      connect_acknowledged: false,
      protocol: 'centrifuge-json',
    };
    let settled = false;
    let timer;
    const socket = new WSClass(ENDPOINT, 'centrifuge-json', { handshakeTimeout: 14000 });

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { socket.close(); } catch { /* ignore closing errors */ }
      resolve(result);
    };

    timer = setTimeout(() => {
      result.error = 'raw Centrifuge connect acknowledgement timed out';
      finish();
    }, RAW_TIMEOUT_MS);

    socket.on('open', () => {
      result.websocket_upgrade = true;
      result.negotiated_protocol = socket.protocol || null;
      socket.send(JSON.stringify({ connect: { name: 'js' }, id: 1 }));
      result.connect_command_sent = true;
    });

    socket.on('message', (raw) => {
      const body = raw.toString();
      if (body.trim() === '{}') {
        try { socket.send('{}'); } catch { /* connection may be closing */ }
        result.application_ping_seen = true;
        return;
      }
      try {
        const message = JSON.parse(body);
        if (message?.id === 1 && message?.connect) {
          result.connect_acknowledged = true;
          result.server_version_present = Boolean(message.connect.version);
          result.client_id_present = Boolean(message.connect.client);
          finish();
        } else if (message?.id === 1 && message?.error) {
          result.server_error = {
            code: Number.isFinite(message.error.code) ? message.error.code : null,
            message: safeMessage(message.error.message),
          };
          finish();
        }
      } catch {
        result.non_json_message_received = true;
      }
    });

    socket.on('unexpected-response', (_request, response) => {
      result.http_status = response.statusCode ?? null;
      result.error = 'WebSocket upgrade was rejected by the HTTP server';
      response.resume();
      finish();
    });

    socket.on('error', (error) => {
      result.error = (error?.name ?? 'Error') + ': ' + safeMessage(error?.message ?? error);
      finish();
    });

    socket.on('close', (code, reason) => {
      result.close_code = code;
      if (reason?.length) result.close_reason = safeMessage(reason.toString());
      if (!result.connect_acknowledged && !result.error) {
        result.error = 'Socket closed before connect acknowledgement';
      }
      finish();
    });
  });
}

async function probeSdk(WSClass) {
  const result = {
    connection: { connected: false, disconnected: [], errors: [] },
    channels: {},
    publication_window_ms: PUBLICATION_WINDOW_MS,
  };
  const client = new Centrifuge(ENDPOINT, { websocket: WSClass });

  client.on('error', (ctx) => {
    const err = ctx?.error ?? ctx;
    result.connection.errors.push({
      type: safeMessage(ctx?.type),
      code: Number.isFinite(err?.code) ? err.code : null,
      message: safeMessage(err?.message ?? err?.reason ?? 'client error'),
    });
  });
  client.on('connected', (ctx) => {
    result.connection.connected = true;
    result.connection.client_id_present = Boolean(ctx?.client);
  });
  client.on('disconnected', (ctx) => {
    result.connection.disconnected.push({
      code: Number.isFinite(ctx?.code) ? ctx.code : null,
      reason: safeMessage(ctx?.reason),
    });
  });

  const subscriptions = [];
  for (const item of CHANNELS) {
    const row = {
      channel: item.channel,
      delta_requested: item.delta ? 'fossil' : null,
      subscribed: false,
      publications: 0,
      errors: [],
    };
    result.channels[item.channel] = row;
    const sub = client.newSubscription(item.channel, item.delta ? { delta: 'fossil' } : {});
    sub.on('subscribed', (ctx) => {
      row.subscribed = true;
      row.recoverable = Boolean(ctx?.recoverable);
    });
    sub.on('publication', (ctx) => {
      row.publications += 1;
      row.last_publication = summarizeData(ctx?.data);
      row.last_offset_present = Number.isFinite(ctx?.offset);
    });
    sub.on('error', (ctx) => {
      const err = ctx?.error ?? ctx;
      row.errors.push({
        code: Number.isFinite(err?.code) ? err.code : null,
        message: safeMessage(err?.message ?? err?.reason ?? 'subscription error'),
      });
    });
    subscriptions.push({ sub });
  }

  try {
    client.connect();
    await withTimeout(client.ready(), CONNECT_TIMEOUT_MS, 'Centrifuge connection');
    result.connection.connected = true;
    for (const { sub } of subscriptions) sub.subscribe();
    await Promise.allSettled(
      subscriptions.map(({ sub }) => withTimeout(sub.ready(), SUBSCRIBE_TIMEOUT_MS, 'subscription')),
    );
    await new Promise((resolve) => setTimeout(resolve, PUBLICATION_WINDOW_MS));
  } catch (error) {
    result.connection.error = safeMessage(error?.message ?? error);
  } finally {
    client.disconnect();
    await new Promise((resolve) => setTimeout(resolve, 200));
  }

  const rows = Object.values(result.channels);
  const subscribed = rows.filter((row) => row.subscribed).length;
  const publications = rows.reduce((sum, row) => sum + row.publications, 0);
  result.summary = {
    connected: result.connection.connected,
    subscribed_channels: subscribed,
    total_channels: CHANNELS.length,
    publications_received: publications,
    subscription_protocol_confirmed: result.connection.connected && subscribed > 0,
    data_stream_confirmed: result.connection.connected && subscribed > 0 && publications > 0,
  };
  return result;
}

const report = {
  checked_at: new Date().toISOString(),
  endpoint: ENDPOINT,
  sdk: 'centrifuge-js',
  route_candidates: routes.length,
  routes_tested: [],
  channel_patterns_from_docs: CHANNELS.map((item) => item.channel),
};

for (const route of routes) {
  const WSClass = makeWebSocketClass(route.url);
  const routeResult = {
    route: route.label,
    route_index: route.index,
    proxy_configured: Boolean(route.url),
    raw_protocol_probe: await probeRawConnect(WSClass),
  };

  if (routeResult.raw_protocol_probe.connect_acknowledged) {
    routeResult.sdk_probe = await probeSdk(WSClass);
  } else {
    routeResult.sdk_probe = {
      skipped: true,
      reason: 'The raw WebSocket upgrade or documented Centrifuge connect acknowledgement did not succeed on this route.',
    };
  }

  report.routes_tested.push(routeResult);
  if (routeResult.sdk_probe?.summary?.subscription_protocol_confirmed) break;
}

const successfulRoute = report.routes_tested.find(
  (route) => route.sdk_probe?.summary?.subscription_protocol_confirmed,
);
const publications = report.routes_tested.reduce(
  (sum, route) => sum + (route.sdk_probe?.summary?.publications_received ?? 0),
  0,
);
report.summary = {
  routes_attempted: report.routes_tested.length,
  websocket_upgrade_confirmed: report.routes_tested.some((route) => route.raw_protocol_probe.websocket_upgrade),
  raw_connect_acknowledged: report.routes_tested.some((route) => route.raw_protocol_probe.connect_acknowledged),
  subscription_protocol_confirmed: Boolean(successfulRoute),
  successful_route_index: successfulRoute?.route_index ?? null,
  publications_received: publications,
  data_stream_confirmed: publications > 0,
  note: publications > 0
    ? 'At least one public market publication arrived through the official Centrifuge SDK; fossil decoding is handled by the SDK.'
    : successfulRoute
      ? 'Centrifuge connection and subscriptions were accepted, but no publication arrived during the observation window.'
      : 'No route completed the WebSocket upgrade and documented Centrifuge connect acknowledgement. This does not prove the service is unavailable from other networks.',
};

console.log(JSON.stringify(report, null, 2));
if (!successfulRoute) process.exitCode = 1;
