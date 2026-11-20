import { Centrifuge } from 'centrifuge';
import WebSocket from 'ws';

const ENDPOINT = 'wss://websocket.ramzinex.ir/websocket';
const CONNECT_TIMEOUT_MS = 15000;
const SUBSCRIBE_TIMEOUT_MS = 10000;
const PUBLICATION_WINDOW_MS = 8000;

// Channels and delta handling follow the uploaded Ramzinex documentation.
const CHANNELS = [
  { channel: 'orderbook:2', delta: false },
  { channel: 'orderbook:11', delta: false },
  { channel: 'last-trades:11', delta: true },
];

function withTimeout(promise, timeoutMs, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${timeoutMs}ms`)), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function safeMessage(value) {
  return String(value ?? '').replace(/[\\r\\n\\t]+/g, ' ').slice(0, 180);
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

const report = {
  checked_at: new Date().toISOString(),
  endpoint: ENDPOINT,
  sdk: 'centrifuge-js',
  channels: {},
  connection: { connected: false, disconnected: [] },
  publication_window_ms: PUBLICATION_WINDOW_MS,
};

const client = new Centrifuge(ENDPOINT, { websocket: WebSocket });

client.on('connecting', () => {
  report.connection.connecting_events = (report.connection.connecting_events ?? 0) + 1;
});
client.on('connected', (ctx) => {
  report.connection.connected = true;
  report.connection.client_id_present = Boolean(ctx?.client);
});
client.on('disconnected', (ctx) => {
  report.connection.disconnected.push({
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
  report.channels[item.channel] = row;

  const options = item.delta ? { delta: 'fossil' } : {};
  const sub = client.newSubscription(item.channel, options);
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
  subscriptions.push({ sub, row });
}

let connected = false;
try {
  client.connect();
  await withTimeout(client.ready(), CONNECT_TIMEOUT_MS, 'Centrifuge connection');
  connected = true;
  report.connection.connected = true;

  for (const { sub } of subscriptions) sub.subscribe();

  await Promise.allSettled(
    subscriptions.map(({ sub }) => withTimeout(sub.ready(), SUBSCRIBE_TIMEOUT_MS, 'subscription')),
  );

  await new Promise((resolve) => setTimeout(resolve, PUBLICATION_WINDOW_MS));
} catch (error) {
  report.connection.error = safeMessage(error?.message ?? error);
} finally {
  client.disconnect();
  await new Promise((resolve) => setTimeout(resolve, 250));
}

const rows = Object.values(report.channels);
const subscribedCount = rows.filter((row) => row.subscribed).length;
const publicationCount = rows.reduce((sum, row) => sum + row.publications, 0);
report.summary = {
  connected,
  subscribed_channels: subscribedCount,
  total_channels: CHANNELS.length,
  publications_received: publicationCount,
  data_stream_confirmed: connected && subscribedCount > 0 && publicationCount > 0,
  subscription_protocol_confirmed: connected && subscribedCount > 0,
  note: publicationCount === 0
    ? 'Subscriptions may be accepted, but no publication arrived during the observation window; this does not prove the market stream is inactive.'
    : 'At least one market publication was delivered through the official Centrifuge SDK; fossil delta payloads are handled by the SDK.',
};

console.log(JSON.stringify(report, null, 2));
if (!connected || subscribedCount === 0) process.exitCode = 1;
