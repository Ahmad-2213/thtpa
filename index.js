import { connect } from 'cloudflare:sockets'

/**
 * Default settings.
 */
const SETTINGS = {
  UUID: '', // vless UUID
  PROXY: '', // optional proxy hostname or IP
  LOG_LEVEL: 'none', // debug, info, error, none
  TIME_ZONE: '0', // time zone for logs (in hours)
  
  WS_PATH: '/ws', // path for websocket transport (enable by non‑empty string)
  DOH_QUERY_PATH: '', // path for DNS over HTTPS queries
  UPSTREAM_DOH: 'https://dns.google/dns-query',
  IP_QUERY_PATH: '',

  BUFFER_SIZE: '0', // in KiB; set to '0' to disable buffering
  XHTTP_PATH: '/xhttp',
  XPADDING_RANGE: '0',

  // We now use only the pipe relay so that we delegate most work to pipeTo().
  RELAY_SCHEDULER: 'pipe',

  // New setting: maximum allowed connection duration in milliseconds.
  // This helps abort requests that might otherwise build up CPU usage on the free plan.
  MAX_REQUEST_DURATION: '500',
};

// Cache for processed configuration
let cfgCache = null;

// A constant response for bad requests.
const BAD_REQUEST = new Response(null, {
  status: 404,
  statusText: 'Bad Request',
});

/* ─────────────────────────────────────────────────────────────────────────────
   Utility Functions
   ───────────────────────────────────────────────────────────────────────────── */

// Validate that two 16‑byte UUID arrays are equal.
function validate_uuid(left, right) {
  for (let i = 0; i < 16; i++) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}

// Concatenate Uint8Arrays.
function concat_typed_arrays(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function random_num(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function random_id() {
  const min = 10000, max = 99999;
  return random_num(min, max);
}

function random_str(len) {
  return Array.from({ length: len }, () => ((Math.random() * 36) | 0).toString(36)).join('');
}

function random_uuid() {
  const s4 = () =>
    Math.floor((1 + Math.random()) * 0x10000)
      .toString(16)
      .substring(1);
  return `${s4()}${s4()}-${s4()}-${s4()}-${s4()}-${s4()}${s4()}${s4()}`;
}

const MAX_PADDING_LENGTH = 1000;

function random_padding(range_str) {
  if (!range_str || range_str === '0' || typeof range_str !== 'string') return null;
  const range = range_str
    .split('-')
    .map(s => parseInt(s, 10))
    .filter(n => !isNaN(n))
    .slice(0, 2)
    .sort((a, b) => a - b);
  if (range.length === 0 || range[0] < 1) return null;
  // Pick a random length within the range.
  let len = range[0] === range[1] ? range[0] : random_num(range[0], range[1]);
  // Cap the padding length to avoid HTTP/2 header frame size issues.
  len = Math.min(len, MAX_PADDING_LENGTH);
  return '0'.repeat(len);
}

// Convert a UUID string (with dashes) into a Uint8Array.
function parse_uuid(uuid) {
  const hex = uuid.replace(/-/g, '');
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 32; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Decodes a modified Base64 string (URL‑friendly, using "-" and "_" instead of "+" and "/")
 * into an ArrayBuffer. Returns null on failure.
 * @param {string} base64Str 
 * @returns {ArrayBuffer|null}
 */
function base64ToArrayBuffer(base64Str) {
  try {
    base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const binaryStr = atob(base64Str);
    const len = binaryStr.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (err) {
    return null;
  }
}

/* ─────────────────────────────────────────────────────────────────────────────
   Logger
   ───────────────────────────────────────────────────────────────────────────── */

class Logger {
  constructor(log_level, time_zone) {
    this.inner_id = random_id();
    const tz = parseInt(time_zone);
    this.timeDrift = isNaN(tz) ? 0 : tz * 60 * 60 * 1000;
    // Levels: debug (0), info (1), error (2), none (3)
    const levels = ['debug', 'info', 'error', 'none'];
    this.level = levels.indexOf((log_level || 'info').toLowerCase());
  }
  debug(...args) {
    if (this.level <= 0) this.inner_log('DEBUG', ...args);
  }
  info(...args) {
    if (this.level <= 1) this.inner_log('INFO', ...args);
  }
  error(...args) {
    if (this.level <= 2) this.inner_log('ERROR', ...args);
  }
  inner_log(prefix, ...args) {
    const now = new Date(Date.now() + this.timeDrift).toISOString();
    console.log(now, prefix, `(${this.inner_id})`, ...args);
  }
}

/* ─────────────────────────────────────────────────────────────────────────────
   Reading and Parsing VLESS Header
   ───────────────────────────────────────────────────────────────────────────── */

/**
 * Reads the VLESS header from the client stream.
 * Throws if the header is too short or the UUID is invalid.
 */
async function read_vless_header(reader, cfg_uuid_str) {
  let capacity = 4096;
  let buffer = new Uint8Array(capacity);
  let offset = 0;
  const view = new DataView(buffer.buffer);
  
  async function ensureAvailable(n) {
    while (offset < n) {
      const { value, done } = await reader.read();
      if (done) throw new Error('header length too short');
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      if (offset + chunk.length > capacity) {
        capacity = Math.max(capacity * 2, offset + chunk.length);
        const newBuffer = new Uint8Array(capacity);
        newBuffer.set(buffer);
        buffer = newBuffer;
      }
      buffer.set(chunk, offset);
      offset += chunk.length;
    }
  }

  await ensureAvailable(1 + 16 + 1);
  const version = view.getUint8(0);
  const uuid = buffer.subarray(1, 17);
  const cfg_uuid = parse_uuid(cfg_uuid_str);
  if (!validate_uuid(uuid, cfg_uuid)) throw new Error('invalid UUID');

  const pb_len = buffer[17];
  const addr_plus1 = 18 + pb_len + 1 + 2 + 1;
  await ensureAvailable(addr_plus1 + 1);

  const cmd = buffer[18 + pb_len];
  if (cmd !== 1) throw new Error(`unsupported command: ${cmd}`);

  const port = (buffer[addr_plus1 - 3] << 8) | buffer[addr_plus1 - 2];
  const atype = buffer[addr_plus1 - 1];
  let header_len = -1;
  if (atype === 1) header_len = addr_plus1 + 4;
  else if (atype === 3) header_len = addr_plus1 + 16;
  else if (atype === 2) {
    await ensureAvailable(addr_plus1 + 1);
    header_len = addr_plus1 + 1 + buffer[addr_plus1];
  }
  if (header_len < 0) throw new Error('read address type failed');
  await ensureAvailable(header_len);

  let hostname = '';
  const idx = addr_plus1;
  if (atype === 1) {
    hostname = `${buffer[idx]}.${buffer[idx + 1]}.${buffer[idx + 2]}.${buffer[idx + 3]}`;
  } else if (atype === 2) {
    hostname = new TextDecoder().decode(buffer.subarray(idx + 1, idx + 1 + buffer[idx]));
  } else if (atype === 3) {
    hostname = Array.from(buffer.subarray(idx, idx + 16), byte => byte.toString(16).padStart(2, '0')).join(':');
  }
  if (!hostname) throw new Error('parse hostname failed');

  return {
    hostname,
    port,
    // Extra client data (if any) after the header.
    data: buffer.subarray(header_len, offset),
    // The response to send to the client.
    resp: new Uint8Array([version, 0]),
  };
}

async function parse_header(uuid_str, client) {
  const reader = client.readable.getReader();
  try {
    return await read_vless_header(reader, uuid_str);
  } finally {
    reader.releaseLock();
  }
}

/* ─────────────────────────────────────────────────────────────────────────────
   Connecting and Relaying
   ───────────────────────────────────────────────────────────────────────────── */

/**
 * A helper that always uses pipeTo() to relay data between two streams.
 * (This avoids the overhead of manually reading/writing small chunks.)
 */
async function pipeRelay(src, dest, initialData) {
  if (initialData && initialData.byteLength > 0) {
    const writer = dest.writable.getWriter();
    try {
      await writer.write(initialData);
    } finally {
      writer.releaseLock();
    }
  }
  const options = src.signal ? { signal: src.signal } : {};
  return src.readable.pipeTo(dest.writable, options);
}

async function relayConnections(cfg, log, client, remote, vless) {
  // Start piping in both directions concurrently.
  const upload = pipeRelay(client, remote, vless.data).catch(err => {
    if (err.name !== 'AbortError') log.error("Upload error:", err.message);
  });
  const download = pipeRelay(remote, client, vless.resp).catch(err => {
    if (err.name !== 'AbortError') log.error("Download error:", err.message);
  });
  await Promise.all([upload, download])
    .then(() => log.info("Connection closed."))
    .catch(err => log.error("Relay encountered an error:", err.message));
}

// When the client aborts the connection, close the remote.
function watch_abort_signal(log, signal, remote) {
  if (!signal || !remote) return;
  const handler = () => {
    log.debug("Aborted, closing remote connection.");
    remote.close().catch(err => log.error("Error closing remote:", err));
    signal.removeEventListener('abort', handler);
  };
  if (signal.aborted) return handler();
  signal.addEventListener('abort', handler, { once: true });
}

/**
 * Connect to the remote destination using a timeout.
 */
async function timed_connect(hostname, port, ms) {
  return new Promise((resolve, reject) => {
    const conn = connect({ hostname, port });
    const timeoutId = setTimeout(() => reject(new Error("connect timeout")), ms);
    conn.opened.then(() => {
      clearTimeout(timeoutId);
      resolve(conn);
    }).catch(err => {
      clearTimeout(timeoutId);
      reject(err);
    });
  });
}

// Precompiled IPv4 validation regex.
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

// Global object to record the last successful direct connection time (in ms) per hostname.
let connectionHistory = {};
// Cool‑down period during which direct connection is preferred (in milliseconds).
const DIRECT_SUCCESS_COOL_DOWN = 30000; // 30 seconds

// Record that a direct connection succeeded for the hostname.
function recordDirectSuccess(hostname) {
  connectionHistory[hostname] = Date.now();
}

// Returns true if a direct connection was successful for this hostname within the cool‑down period.
function directRecently(hostname) {
  return connectionHistory[hostname] && (Date.now() - connectionHistory[hostname] < DIRECT_SUCCESS_COOL_DOWN);
}

function isEpicGamesDomain(hostname) {
  return /(?:epicgames\.com|epicgamescdn\.com|riotgames\.com|api\.riotgames\.com|ddragon\.leagueoflegends\.com|riotstatic\.com|riotcdn\.net|akamaized\.net|fastly-download\.epicgames\.com|steamcontent(?:-a)?\.akamaihd\.net|steamcontent\.com|cdn\.steamstatic\.com|clashofclans\.com|ubisoft(?:connect)?\.com|ubisoftcdn\.com|uplay(?:cdn)?\.com|supercell(?:content)?\.net|d\d+\.[a-z0-9-]+\.cloudfront\.net)/i.test(hostname);
}

// Global dynamic blacklist for hostnames that have failed via proxy.
const proxyFailureBlacklist = {};
function markProxyForbidden(hostname) {
  proxyFailureBlacklist[hostname] = true;
}

// Modified connect_remote: if the hostname is either blacklisted or matches Epic Games domains, use direct.
async function connect_remote(log, hostname, port, cfg_proxy) {
  const timeout = 400; // overall connection timeout in ms
  const trimmedHost = hostname.trim();
  const portStr = port.toString();

  // For IPv4 addresses, always use direct.
  if (IPV4_REGEX.test(trimmedHost)) {
    log.info(`Direct IP connect [${trimmedHost}]:${portStr}`);
    return timed_connect(trimmedHost, portStr, timeout);
  }

  // If we have a recent direct connection, immediately use direct.
  if (directRecently(trimmedHost)) {
    log.info(`Recent direct connection recorded for [${trimmedHost}]. Using direct connection.`);
    return timed_connect(trimmedHost, portStr, timeout);
  }

  // If this hostname is already blacklisted due to proxy failures, use direct.
  if (proxyFailureBlacklist[trimmedHost]) {
    log.info(`Proxy is blacklisted for [${trimmedHost}]. Using direct connection.`);
    return timed_connect(trimmedHost, portStr, timeout);
  }

  // NEW APPROACH: if the hostname is known to be Epic Games–related, always use direct.
  if (isEpicGamesDomain(trimmedHost)) {
    log.info(`Epic Games domain detected for [${trimmedHost}]. Forcing direct connection.`);
    // Optionally mark it for future reference.
    markProxyForbidden(trimmedHost);
    return timed_connect(trimmedHost, portStr, timeout);
  }

  // Otherwise, if a proxy is configured, attempt to use it.
  const proxy = cfg_proxy?.trim();
  if (!proxy) {
    log.info(`No proxy configured for [${trimmedHost}]. Using direct connection.`);
    return timed_connect(trimmedHost, portStr, timeout);
  }
  
  log.info(`Attempting proxy connection for [${trimmedHost}]:${portStr} via [${proxy}]`);
  try {
    const conn = await timed_connect(proxy, portStr, timeout);
    log.info(`Proxy connection succeeded for [${trimmedHost}]:${portStr}`);
    return conn;
  } catch (err) {
    log.error(`Proxy connection failed for [${trimmedHost}]:${portStr}: ${err.message}. Falling back to direct.`);
    const directConn = await timed_connect(trimmedHost, portStr, timeout);
    // Record that direct succeeded so subsequent attempts use direct.
    recordDirectSuccess(trimmedHost);
    return directConn;
  }
}
async function handle_client(cfg, log, client) {
  try {
    const vless = await parse_header(cfg.UUID, client);
    const remote = await connect_remote(log, vless.hostname, vless.port, cfg.PROXY);
    relayConnections(cfg, log, client, remote, vless);
    watch_abort_signal(log, client.signal, remote);
    return true;
  } catch (err) {
    log.error("handle_client error:", err.message);
    client.close && client.close();
    return false;
  }
}

/**
 * Wraps handle_client() in a timeout so that if the connection lasts longer
 * than MAX_REQUEST_DURATION (in milliseconds), it is aborted. This is intended
 * to help avoid CPU time limit exceeded errors on the free plan.
 */
async function handle_client_with_timeout(cfg, log, client) {
  const maxDuration = parseInt(cfg.MAX_REQUEST_DURATION, 10) || 1000;
  let timeoutId;
  try {
    await Promise.race([
      handle_client(cfg, log, client),
      new Promise((_, reject) => {
        timeoutId = setTimeout(() => {
          log.error("Maximum connection duration exceeded. Aborting connection.");
          client.close && client.close();
          reject(new Error("Maximum connection duration exceeded"));
        }, maxDuration);
      })
    ]);
    return true;
  } catch (err) {
    log.error("handle_client_with_timeout error:", err.message);
    client.close && client.close();
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

/* ─────────────────────────────────────────────────────────────────────────────
   XHTTP and WebSocket Client Factories
   ───────────────────────────────────────────────────────────────────────────── */

function create_queuing_strategy(buff_size) {
  return buff_size > 0 ? new ByteLengthQueuingStrategy({ highWaterMark: buff_size }) : undefined;
}

function create_xhttp_client(cfg, buff_size, client_readable) {
  const transformStream = new TransformStream(
    {
      transform(chunk, controller) {
        controller.enqueue(chunk);
      },
    },
    create_queuing_strategy(buff_size)
  );

  const headers = {
    'X-Accel-Buffering': 'no',
    'Cache-Control': 'no-store',
    'User-Agent': 'Go-http-client/2.0',
    'Content-Type': 'application/grpc',
  };

  // Use the capped random padding.
  const padding = random_padding(cfg.XPADDING_RANGE);
  if (padding) headers['X-Padding'] = padding;

  const resp = new Response(transformStream.readable, { headers });
  return {
    readable: client_readable,
    writable: transformStream.writable,
    resp,
    // Added close function to ensure the writable stream is closed on errors.
    close: () => {
      try {
        const writer = transformStream.writable.getWriter();
        writer.close().catch(() => {});
      } catch (e) {
        // Ignore any errors during close.
      }
    }
  };
}

/**
 * Modified create_ws_client() to add early data support.
 * An extra parameter "earlyData" is now accepted.
 */
function create_ws_client(log, buff_size, ws_client, ws_server, earlyData) {
  const abort_ctrl = new AbortController();
  let wsRunning = true;
  let reading = true, writing = true;
  function close() {
    if (wsRunning) {
      wsRunning = false;
      try {
        ws_server.close();
      } catch (err) {
        log.error(`close ws server error: ${err}`);
      }
    }
  }
  function try_close() {
    if (!reading && !writing) close();
  }
  function reading_done() {
    reading = false;
    log.debug("ws reader closed");
    try_close();
  }
  const readable = new ReadableStream({
    start(controller) {
      // Add early data if provided.
      if (earlyData) {
        const earlyBuffer = base64ToArrayBuffer(earlyData);
        if (earlyBuffer) {
          log.info("Enqueuing early data, byteLength:", earlyBuffer.byteLength);
          controller.enqueue(earlyBuffer);
        } else {
          log.error("Failed to decode early data.");
        }
      }
      ws_server.addEventListener('message', ({ data }) => controller.enqueue(data));
      ws_server.addEventListener('error', (err) => {
        log.error(`ws server error: ${err.message}`);
        abort_ctrl.abort();
        controller.error(err);
      });
      ws_server.addEventListener('close', () => {
        log.debug("ws server closed");
        wsRunning = false;
        abort_ctrl.abort();
        controller.close();
      });
    }
  }, create_queuing_strategy(buff_size));
  const writable = new WritableStream({
    write(chunk) {
      if (!abort_ctrl.signal.aborted) ws_server.send(chunk);
    },
    close() {
      log.debug("ws writer closed");
      writing = false;
      try_close();
    }
  }, create_queuing_strategy(buff_size));
  return {
    readable,
    writable,
    resp: new Response(null, { status: 101, webSocket: ws_client }),
    signal: abort_ctrl.signal,
    close,
    reading_done,
  };
}

/* ─────────────────────────────────────────────────────────────────────────────
   Handling DoH and JSON Requests
   ───────────────────────────────────────────────────────────────────────────── */

function handle_doh(log, request, url, upstream) {
  const mime_dnsmsg = 'application/dns-message';
  const method = request.method;
  if (method === 'POST' && request.headers.get('content-type') === mime_dnsmsg) {
    log.info("handle DoH POST request");
    return fetch(upstream, {
      method,
      headers: {
        Accept: mime_dnsmsg,
        'Content-Type': mime_dnsmsg,
      },
      body: request.body,
    });
  }
  if (method !== 'GET') return BAD_REQUEST;
  const mime_json = 'application/dns-json';
  if (request.headers.get('Accept') === mime_json) {
    log.info("handle DoH GET json request");
    return fetch(upstream + url.search, {
      method,
      headers: { Accept: mime_json },
    });
  }
  const param = url.searchParams.get('dns');
  if (param) {
    log.info("handle DoH GET hex request");
    return fetch(upstream + '?dns=' + param, {
      method,
      headers: { Accept: mime_dnsmsg },
    });
  }
  return BAD_REQUEST;
}

function get_ip_info(request) {
  return {
    ip: request.headers.get('cf-connecting-ip') || '',
    userAgent: request.headers.get('user-agent') || '',
    asOrganization: request.cf?.asOrganization || '',
    city: request.cf?.city || '',
    continent: request.cf?.continent || '',
    country: request.cf?.country || '',
    latitude: request.cf?.latitude || '',
    longitude: request.cf?.longitude || '',
    region: request.cf?.region || '',
    regionCode: request.cf?.regionCode || '',
    timezone: request.cf?.timezone || '',
  };
}

function handle_json(cfg, url, request) {
  if (cfg.IP_QUERY_PATH && request.url.endsWith(cfg.IP_QUERY_PATH)) {
    return get_ip_info(request);
  }
  const path = append_slash(url.pathname);
  if (url.searchParams.get('uuid') === cfg.UUID) {
    if (cfg.XHTTP_PATH && path.endsWith(cfg.XHTTP_PATH)) {
      return create_config('xhttp', url, cfg.UUID);
    }
    if (cfg.WS_PATH && path.endsWith(cfg.WS_PATH)) {
      return create_config('ws', url, cfg.UUID);
    }
  }
  return null;
}

function append_slash(path) {
  return path.endsWith('/') ? path : path + '/';
}

function create_config(ctype, url, uuid) {
  const config = JSON.parse(JSON.stringify(config_template));
  const vless = config.outbounds[0].settings.vnext[0];
  const stream = config.outbounds[0].streamSettings;
  const host = url.hostname;
  vless.users[0].id = uuid;
  vless.address = host;
  stream.tlsSettings.serverName = host;
  const path = append_slash(url.pathname);
  if (ctype === 'ws') {
    delete stream.tlsSettings.alpn;
    stream.wsSettings = { path, host };
  } else if (ctype === 'xhttp') {
    stream.xhttpSettings = {
      mode: 'stream-one',
      host,
      path,
      noGRPCHeader: false,
      keepAlivePeriod: 300,
    };
  } else {
    return null;
  }
  if (url.searchParams.get('fragment') === 'true') {
    config.outbounds[0].proxySettings = {
      tag: 'direct',
      transportLayer: true,
    };
    config.outbounds.push({
      tag: 'direct',
      protocol: 'freedom',
      settings: {
        fragment: {
          packets: 'tlshello',
          length: '100-200',
          interval: '10-20',
        },
      },
    });
  }
  stream.network = ctype;
  return config;
}

const config_template = {
  log: { loglevel: "warning" },
  inbounds: [
    {
      tag: "agentin",
      port: 1080,
      listen: "127.0.0.1",
      protocol: "socks",
      settings: {}
    }
  ],
  outbounds: [
    {
      protocol: "vless",
      settings: {
        vnext: [
          {
            address: "localhost",
            port: 443,
            users: [
              { id: "", encryption: "none" }
            ]
          }
        ]
      },
      tag: "agentout",
      streamSettings: {
        network: "raw",
        security: "tls",
        tlsSettings: {
          serverName: "localhost",
          alpn: [ "h2" ]
        }
      }
    }
  ]
};

function example(url) {
  const ws_path = random_str(8);
  const xhttp_path = random_str(8);
  const uuid = random_uuid();
  return `Error: UUID is empty

Settings example:
UUID: ${uuid}
WS_PATH: /${ws_path}
XHTTP_PATH: /${xhttp_path}

WebSocket config.json:
${url.origin}/${ws_path}/?fragment=true&uuid=${uuid}

XHTTP config.json:
${url.origin}/${xhttp_path}/?fragment=true&uuid=${uuid}

Refresh this page to re‑generate a random settings example.`;
}

function isValidIP(ip) {
  return IPV4_REGEX.test(ip);
}

/**
 * If the URL path has two segments and the second is an IP address,
 * override cfg.PROXY with that IP and revert the pathname.
 */
function extractProxyAndRevertPath(url, cfg) {
  const pathParts = url.pathname.split('/').filter(Boolean);
  if (pathParts.length === 2 && isValidIP(pathParts[1])) {
    cfg.PROXY = pathParts[1];
    url.pathname = `/${pathParts[0]}`;
    return true;
  }
  return false;
}

/* ─────────────────────────────────────────────────────────────────────────────
   Main Request Handler
   ───────────────────────────────────────────────────────────────────────────── */

/**
 * The main request handler.
 * Note: The signature now includes a third parameter ctx (the execution context)
 * so that we can use ctx.waitUntil() to detach long‑lived connections.
 */
async function main(request, env, ctx) {
  const url = new URL(request.url);

  // Extract proxy IP from URL path (if provided).
  let proxyIP = '';
  const pathParts = url.pathname.split('/').filter(p => p.length > 0);
  if (pathParts.length === 2 && isValidIP(pathParts[1])) {
    proxyIP = pathParts[1];
    url.pathname = `/${pathParts[0]}/`;
  }

  // Load settings and override proxy if necessary.
  const cfg = load_settings(env, SETTINGS);
  if (proxyIP) {
    cfg.PROXY = proxyIP;
  }
  const log = new Logger(cfg.LOG_LEVEL, cfg.TIME_ZONE);
  if (proxyIP) {
    log.info(`Using proxy IP from URL path: ${cfg.PROXY}`);
  }

  // If UUID is not set, show an example configuration.
  if (!cfg.UUID) {
    return new Response(example(url));
  }

  const path = url.pathname;
  const buff_size = (parseInt(cfg.BUFFER_SIZE, 10) || 0) * 1024;

  // Handle WebSocket transport.
  if (
    cfg.WS_PATH &&
    request.headers.get('Upgrade') === 'websocket' &&
    path === cfg.WS_PATH
  ) {
    log.debug("Accepting WebSocket client");
    const wsPair = new WebSocketPair();
    const ws_client = wsPair[0];
    const ws_server = wsPair[1];
    // Extract early data from sec-websocket-protocol header.
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const client = create_ws_client(log, buff_size, ws_client, ws_server, earlyData);
    try {
      ws_server.accept();
      // Detach the long‑lived connection so the fetch event can return immediately.
      ctx.waitUntil(handle_client_with_timeout(cfg, log, client));
      return client.resp;
    } catch (err) {
      log.error(`WebSocket accept error: ${err.message}`);
      client.close && client.close();
      return BAD_REQUEST;
    }
  }

  // Handle XHTTP transport.
  if (
    cfg.XHTTP_PATH &&
    request.method === 'POST' &&
    path === cfg.XHTTP_PATH
  ) {
    log.debug("Accepting XHTTP client");
    const client = create_xhttp_client(cfg, buff_size, request.body);
    // Detach the long‑lived connection so that the fetch event returns immediately.
    ctx.waitUntil(handle_client_with_timeout(cfg, log, client));
    return client.resp;
  }

  // Handle DoH requests.
  if (cfg.DOH_QUERY_PATH && append_slash(path).endsWith(append_slash(cfg.DOH_QUERY_PATH))) {
    return handle_doh(log, request, url, cfg.UPSTREAM_DOH);
  }

  // Handle JSON and plain GET requests.
  if (request.method === 'GET' && !request.headers.get('Upgrade')) {
    const o = handle_json(cfg, url, request);
    if (o) {
      return new Response(JSON.stringify(o), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response("Hello World!");
  }

  return BAD_REQUEST;
}

function load_settings(env, settings) {
  if (cfgCache) return cfgCache;
  const cfg = Object.assign({}, settings, env);
  cfg.BUFFER_SIZE = parseInt(cfg.BUFFER_SIZE, 10) || 0;
  // The yield-related settings are no longer used.
  cfg.TIME_DRIFT = (parseInt(cfg.TIME_ZONE, 10) || 0) * 3600 * 1000;
  ['XHTTP_PATH', 'WS_PATH', 'DOH_QUERY_PATH'].forEach(feature => {
    if (cfg[feature]) cfg[feature] = append_slash(cfg[feature]);
  });
  cfgCache = cfg;
  return cfg;
}

export default {
  // Note: Cloudflare Workers will call fetch(request, env, ctx)
  fetch: main,
  // For unit testing:
  concat_typed_arrays,
  parse_uuid,
  random_id,
  random_padding,
  validate_uuid,
};
