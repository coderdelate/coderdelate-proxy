#!/usr/bin/env node
'use strict';

/**
 * Improved forward HTTP/HTTPS proxy with optional Basic auth, timeouts, and safer header handling.
 *
 * Run:
 *   PORT=8000 node index.js
 *   AUTH_REQUIRED=1 PROXY_USER=alice PROXY_PASS=secret PORT=8000 node index.js
 */

const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8000;
const AUTH_REQUIRED = !!process.env.AUTH_REQUIRED;
const PROXY_USER = process.env.PROXY_USER || '';
const PROXY_PASS = process.env.PROXY_PASS || '';
const REQUEST_TIMEOUT_MS = 120000; // 2 minutes

const LOG = (...args) => console.log(new Date().toISOString(), ...args);

function parseBasicAuth(header) {
  if (!header || typeof header !== 'string') return null;
  const m = header.match(/^Basic\s+(.+)$/i);
  if (!m) return null;
  try {
    const decoded = Buffer.from(m[1], 'base64').toString('utf8');
    const idx = decoded.indexOf(':');
    if (idx === -1) return { user: decoded, pass: '' };
    return { user: decoded.slice(0, idx), pass: decoded.slice(idx + 1) };
  } catch (e) {
    return null;
  }
}

function isAuthorized(header) {
  if (!AUTH_REQUIRED) return true;
  const creds = parseBasicAuth(header);
  if (!creds) return false;
  return creds.user === PROXY_USER && creds.pass === PROXY_PASS;
}

const HOP_BY_HOP = [
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailers',
  'transfer-encoding',
  'upgrade'
];

function stripHopByHopHeaders(headers) {
  for (const h of HOP_BY_HOP) delete headers[h];
  // Also remove headers listed in Connection header
  if (headers.connection) {
    const parts = headers.connection.split(',');
    for (const p of parts) {
      const k = p && p.trim().toLowerCase();
      if (k) delete headers[k];
    }
    delete headers.connection;
  }
}

const server = http.createServer();

server.on('request', (clientReq, clientRes) => {
  const start = Date.now();
  const remote = clientReq.socket && clientReq.socket.remoteAddress;
  const proxyAuth = clientReq.headers['proxy-authorization'];

  if (!isAuthorized(proxyAuth)) {
    clientRes.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Proxy"' });
    clientRes.end('Proxy authentication required');
    LOG('407', clientReq.method, clientReq.url, 'from', remote || '-', 'auth failed');
    return;
  }

  // parse target URL: clientReq.url should be absolute-form for proxies, but be defensive
  let targetUrl;
  try {
    targetUrl = new URL(clientReq.url);
  } catch (err) {
    const hostHeader = clientReq.headers['host'];
    if (!hostHeader) {
      clientRes.writeHead(400);
      clientRes.end('Bad request: no host');
      LOG('400 missing host', clientReq.method, clientReq.url, 'from', remote || '-');
      return;
    }
    const scheme = clientReq.socket.encrypted ? 'https:' : 'http:';
    try {
      targetUrl = new URL(`${scheme}//${hostHeader}${clientReq.url}`);
    } catch (err2) {
      clientRes.writeHead(400);
      clientRes.end('Bad request');
      LOG('400 url parse failed', clientReq.method, clientReq.url, 'from', remote || '-');
      return;
    }
  }

  const isTls = targetUrl.protocol === 'https:';
  const port = targetUrl.port ? parseInt(targetUrl.port, 10) : (isTls ? 443 : 80);

  const headers = Object.assign({}, clientReq.headers);
  stripHopByHopHeaders(headers);
  // ensure we don't forward proxy-specific headers
  delete headers['proxy-authorization'];

  const options = {
    protocol: targetUrl.protocol,
    hostname: targetUrl.hostname,
    port: port,
    method: clientReq.method,
    path: targetUrl.pathname + targetUrl.search,
    headers,
    agent: false
  };

  const proxyModule = isTls ? https : http;
  const proxyReq = proxyModule.request(options, (proxyRes) => {
    clientRes.writeHead(proxyRes.statusCode, proxyRes.statusMessage, proxyRes.headers);
    proxyRes.pipe(clientRes, { end: true });

    proxyRes.on('end', () => {
      const took = Date.now() - start;
      LOG('HTTP', clientReq.method, targetUrl.href, '->', proxyRes.statusCode, `${took}ms`, 'from', remote || '-');
    });
  });

  proxyReq.on('timeout', () => {
    proxyReq.abort();
  });

  proxyReq.setTimeout(REQUEST_TIMEOUT_MS);

  proxyReq.on('error', (err) => {
    if (!clientRes.headersSent) {
      clientRes.writeHead(502);
      clientRes.end('Bad gateway: ' + (err && err.message));
    } else {
      clientRes.end();
    }
    LOG('HTTP proxy request error', err && err.message, 'for', clientReq.url, 'from', remote || '-');
  });

  clientReq.on('error', (err) => {
    LOG('Client request error', err && err.message, 'from', remote || '-');
    proxyReq.abort();
  });

  // timeouts on client socket
  if (clientReq.socket && typeof clientReq.socket.setTimeout === 'function') {
    clientReq.socket.setTimeout(REQUEST_TIMEOUT_MS, () => {
      clientReq.destroy();
    });
  }

  clientReq.pipe(proxyReq, { end: true });
});

server.on('connect', (req, clientSocket, head) => {
  // CONNECT request for HTTPS tunneling. req.url is host:port
  const remote = clientSocket && clientSocket.remoteAddress;
  const proxyAuth = req.headers['proxy-authorization'];

  if (!isAuthorized(proxyAuth)) {
    // respond with 407 over the raw socket
    clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\n');
    clientSocket.write('Proxy-Authenticate: Basic realm="Proxy"\r\n');
    clientSocket.write('\r\n');
    clientSocket.end();
    LOG('CONNECT 407', req.url, 'from', remote || '-', 'auth failed');
    return;
  }

  const [hostPart, portPart] = req.url.split(':');
  const host = hostPart;
  const port = parseInt(portPart, 10) || 443;

  let serverSocket;
  let connected = false;

  serverSocket = net.connect({ host, port }, () => {
    connected = true;
    // inform client the tunnel is established
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n' +
      'Proxy-agent: coderdelate-proxy\r\n' +
      '\r\n');
    // if there is buffered data, send it
    if (head && head.length) serverSocket.write(head);
    // pipe bidirectionally
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
    LOG('CONNECT', req.url, 'established', 'from', remote || '-');
  });

  // set timeouts
  clientSocket.setTimeout(REQUEST_TIMEOUT_MS, () => {
    LOG('Client socket timeout', req.url, 'from', remote || '-');
    clientSocket.destroy();
    if (serverSocket) serverSocket.destroy();
  });

  serverSocket.setTimeout(REQUEST_TIMEOUT_MS, () => {
    LOG('Upstream socket timeout', req.url, 'to', host + ':' + port);
    serverSocket.destroy();
    clientSocket.destroy();
  });

  serverSocket.on('error', (err) => {
    if (!connected) {
      // failed to connect
      try {
        clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
      } catch (e) {}
      clientSocket.end();
    } else {
      clientSocket.destroy();
    }
    LOG('CONNECT tunnel error', err && err.message, 'to', req.url);
  });

  clientSocket.on('error', (err) => {
    LOG('Client socket error during CONNECT', err && err.message, 'from', remote || '-');
    if (serverSocket) serverSocket.destroy();
  });
});

server.on('clientError', (err, socket) => {
  LOG('Client error', err && err.message);
  try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch (e) {}
});

server.listen(PORT, () => {
  LOG(`Proxy server listening on port ${PORT} (AUTH_REQUIRED=${AUTH_REQUIRED ? 'yes' : 'no'})`);
});
