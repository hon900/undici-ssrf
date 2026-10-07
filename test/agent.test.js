import assert from "node:assert/strict";
import dns from "node:dns";
import { once } from "node:events";
import { createServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFileSync } from "node:fs";
import { createSecureContext } from "node:tls";
import test from "node:test";
import { createSsrfAgent, HostfenceError } from "../src/index.js";

async function localServer(t) {
  const requests = [];
  let connections = 0;
  const server = createServer((req, res) => {
    requests.push({ host: req.headers.host, path: req.url });
    if (req.url === "/redirect") {
      res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
    }
    res.end("local response");
  });
  server.on("connection", () => connections++);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  return { port: server.address().port, requests, connections: () => connections };
}

test("pinned agent reaches only its checked address without an OS DNS lookup", async (t) => {
  const server = await localServer(t);
  const lookups = [];
  const dispatcher = createSsrfAgent({
    // This exception is scoped to the local test server; the default blocks it.
    allowLoopback: true,
    allowedHosts: ["xn--bcher-kva.invalid"],
    allowedPorts: [server.port],
    lookup: async (hostname) => {
      lookups.push(hostname);
      return ["127.0.0.1"];
    },
  }, { connections: 1, connectTimeout: 1000 });
  t.after(() => dispatcher.destroy());
  const originalLookup = dns.lookup;
  let osLookups = 0;
  dns.lookup = (...args) => {
    osLookups++;
    args.at(-1)(new Error("unexpected operating-system DNS lookup"));
  };
  try {
    const response = await dispatcher.request({
      origin: `HTTP://BÜCHER.invalid:${server.port}`,
      path: "/checked", method: "GET",
    });
    assert.equal(response.statusCode, 200);
    assert.equal(await response.body.text(), "local response");
    assert.deepEqual(server.requests, [{ host: `xn--bcher-kva.invalid:${server.port}`, path: "/checked" }]);
    assert.equal(server.connections(), 1);
    assert.deepEqual(lookups, ["xn--bcher-kva.invalid", "xn--bcher-kva.invalid"]);
    assert.equal(osLookups, 0);
  } finally {
    dns.lookup = originalLookup;
  }
});

test("a DNS rebind after preflight is blocked before a socket is opened", async (t) => {
  const server = await localServer(t);
  let lookups = 0;
  const dispatcher = createSsrfAgent({
    lookup: async () => ++lookups === 1 ? ["93.184.216.34"] : ["127.0.0.1"],
  });
  t.after(() => dispatcher.destroy());
  await assert.rejects(dispatcher.request({
    origin: `http://rebind.invalid:${server.port}`, path: "/", method: "GET",
  }), HostfenceError);
  assert.equal(lookups, 2, "the connector independently checks the actual connection hostname");
  assert.equal(server.connections(), 0);
  assert.deepEqual(server.requests, []);
});

test("private, metadata, and mixed DNS answers cannot reach a real socket", async (t) => {
  const server = await localServer(t);
  for (const addresses of [["127.0.0.1"], ["169.254.169.254"], ["93.184.216.34", "127.0.0.1"]]) {
    const dispatcher = createSsrfAgent({ lookup: async () => addresses });
    try {
      await assert.rejects(dispatcher.request({
        origin: `http://blocked.invalid:${server.port}`, path: "/", method: "GET",
      }), HostfenceError);
    } finally {
      await dispatcher.destroy();
    }
  }
  const dispatcher = createSsrfAgent();
  try {
    await assert.rejects(dispatcher.request({
      origin: `http://127.0.0.1:${server.port}`, path: "/", method: "GET",
    }), HostfenceError);
  } finally {
    await dispatcher.destroy();
  }
  assert.equal(server.connections(), 0);
  assert.deepEqual(server.requests, []);
});

test("pinned agent leaves redirects for the caller and rejects routing overrides", async (t) => {
  const server = await localServer(t);
  const dispatcher = createSsrfAgent({ allowLoopback: true, lookup: async () => ["127.0.0.1"] });
  t.after(() => dispatcher.destroy());
  const request = { origin: `http://redirect.invalid:${server.port}`, path: "/redirect", method: "GET" };
  const response = await dispatcher.request(request);
  assert.equal(response.statusCode, 302);
  assert.equal(response.headers.location, "http://169.254.169.254/latest/meta-data/");
  await response.body.text();
  for (const overrides of [
    { maxRedirections: 1 }, { connect: {} }, { servername: "other.invalid" },
    { headers: { Host: "other.invalid" } },
    { headers: [":authority", "other.invalid"] },
    { headers: new Headers({ host: "other.invalid" }) },
  ]) {
    await assert.rejects(dispatcher.request({ ...request, ...overrides }), TypeError);
  }
  assert.equal(server.requests.length, 1);
});

test("agent construction does not allow bypassing its connector or policy", () => {
  for (const options of [
    { connect: { lookup: dns.lookup } }, { factory: () => null },
    { interceptors: {} }, { socketPath: "/tmp/example.sock" },
    { maxRedirections: 1 }, { rejectUnauthorized: false },
  ]) {
    assert.throws(() => createSsrfAgent({}, options), /unsupported agent option/);
  }
  assert.throws(() => createSsrfAgent({}, null), /options must be an object/);
});

test("TLS keeps the origin SNI and rejects an untrusted certificate", async (t) => {
  // This key and self-signed certificate are public test fixtures, never credentials.
  const credentials = {
    key: readFileSync(new URL("./fixtures/localhost-key.pem", import.meta.url)),
    cert: readFileSync(new URL("./fixtures/localhost-cert.pem", import.meta.url)),
  };
  const names = [];
  let requests = 0;
  const server = createHttpsServer({
    ...credentials,
    SNICallback(name, callback) {
      names.push(name);
      callback(null, createSecureContext(credentials));
    },
  }, (_req, res) => { requests++; res.end("must not arrive"); });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  const dispatcher = createSsrfAgent({ allowLoopback: true, lookup: async () => ["127.0.0.1"] });
  t.after(() => dispatcher.destroy());
  await assert.rejects(dispatcher.request({
    origin: `https://pinned.invalid:${server.address().port}`, path: "/", method: "GET",
  }), { code: "DEPTH_ZERO_SELF_SIGNED_CERT" });
  assert.deepEqual(names, ["pinned.invalid"]);
  assert.equal(requests, 0);
});
