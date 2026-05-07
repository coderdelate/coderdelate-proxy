#!/usr/bin/env node
'use strict';

/**
 * Minimal forward HTTP/HTTPS proxy with optional Basic auth.
 *
 * Usage:
 *  PORT=8000 node index.js
 *  AUTH_REQUIRED=1 PROXY_USER=alice PROXY_PASS=secret PORT=8000 node index.js
 *
 * No external dependencies.
 */

const http = require('http');
const net = require('net');
const { URL } = require('url');

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8000;
const AUTH_REQUIRED = !!process.env.AUTH_REQUIRED;
const PROXY_USER = process.env.PROXY_USER || '';
const PROXY_PASS = process.env.PROXY_PASS || '';
const LOG = (msg, ...args) => {
  console.log(new Date().toISOString(), msg, ...args);
};

function parseBasicAuth(header) {
  if (!header) return null;
  const m = header.match(/Basic\s+(.+)/i);
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

function checkAuth(header) {
  if (!AUTH_REQUIRED) return true;
  const creds = parseBasicAuth(header);
  if (!creds) return false;
  return creds.user === PROXY_USER && creds.pass === PROXY_PASS;
}

const server = http.createServer();

// Handle regular HTTP requests (GET, POST, etc. using full URL from client)
server.on('request', (clientReq, clientRes) => {
  const proxyAuthHeader = clientReq.headers['proxy-authorization'] || clientReq.headers['proxy-authenticate'];
  if (!checkAuth(proxyAuthHeader)) {
    clientRes.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Proxy"' });
    clientRes.end('Proxy authentication required');
    LOG('407 Proxy auth required', clientReq.method, clientReq.url, clientReq.socket.remoteAddress);
    return;
  }

  // clientReq.url may be absolute-form (when talking to an HTTP proxy)
  let targetUrl;
  try {
    targetUrl = new URL(clientReq.url);
  } catch (e) {
    // fallback: build URL from Host header
    const host = clientReq.headers['host'];
    if (!host) {
      clientRes.writeHead(400);
      clientRes.end('Bad request: no host');
      return;
    }
    const scheme = clientReq.socket.encrypted ? 'https:' : 'http:';
    targetUrl = new URL(`${scheme}//${host}${clientReq.url}`);
  }

  const isTls = targetUrl.protocol === 'https:';
  const port = targetUrl.port || (isTls ? 443 : 80);

  const options = {
    protocol: targetUrl.protocol,
    hostname: targetUrl.hostname,
    port: port,
    method: clientReq.method,
    path: targetUrl.pathname + targetUrl.search,
    headers: Object.assign({}, clientReq.headers),
  };

  // Remove hop-by-hop headers that should not be forwarded
  delete options.headers['proxy-authorization'];
  delete options.headers['proxy-authenticate'];
  delete options.headers['proxy-connection'];
  options.headers['connection'] = 'close';

  const proxyReq = (isTls ? require('https') : require('http')).request(options, (proxyRes) => {
    // Copy status and headers
    clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(clientRes, { end: true });
  });

  proxyReq.on('error', (err) => {
    LOG('HTTP proxy request error', err && err.message);
    if (!clientRes.headersSent) {
      clientRes.writeHead(502);
      clientRes.end('Bad gateway: ' + (err && err.message));
    } else {
      clientRes.end();
    }
  });

  // Pipe request body
  clientReq.pipe(proxyReq, { end: true });

  LOG('HTTP proxy', clientReq.method, targetUrl.href, 'from', clientReq.socket.remoteAddress);
});

// Handle HTTPS CONNECT method for tunneling
server.on('connect', (req, clientSocket, head) => {
  // req.url is in the form "hostname:port"
  const proxyAuthHeader = req.headers['proxy-authorization'];
  if (!checkAuth(proxyAuthHeader)) {
    clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n');
    clientSocket.destroy();
    LOG('CONNECT 407 Proxy auth required', req.url, clientSocket.remoteAddress);
    return;
  }

  const [host, portStr] = req.url.split(':');
  const port = parseInt(portStr, 10) || 443;

  const serverSocket = net.connect(port, host, () => {
    // Write HTTP/1.1 200 Connection Established and pipe
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    // If any buffered data exists, pipe it
    if (head && head.length) serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });

  serverSocket.on('error', (err) => {
    LOG('CONNECT tunnel error', err && err.message);
    clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    clientSocket.destroy();
  });

  clientSocket.on('error', (err) => {
    LOG('Client socket error during CONNECT', err && err.message);
    serverSocket.destroy();
  });

  LOG('CONNECT', req.url, 'from', clientSocket.remoteAddress);
});

server.on('clientError', (err, socket) => {
  LOG('Client error', err && err.message);
  socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

server.listen(PORT, () => {
  LOG(`Proxy server listening on port ${PORT} (AUTH_REQUIRED=${AUTH_REQUIRED ? 'yes' : 'no'})`);
});
