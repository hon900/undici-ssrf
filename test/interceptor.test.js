import assert from "node:assert/strict";
import { setImmediate as nextTurn } from "node:timers/promises";
import test from "node:test";
import { MockAgent } from "undici";
import { assertOrigin, createSsrfInterceptor, HostfenceError, ssrfInterceptor } from "../src/index.js";

const publicLookup = async () => ["93.184.216.34"];

test("blocked requests return a synchronous boolean and never dispatch", async () => {
  for (const origin of ["http://127.0.0.1", "http://169.254.169.254", "not a URL"]) {
    let calls = 0;
    let error;
    const intercepted = ssrfInterceptor(() => { calls++; return true; });
    const result = intercepted({ origin, path: "/", method: "GET" }, { onError(value) { error = value; } });
    assert.equal(result, true);
    assert.equal(error, undefined, "errors are delivered asynchronously");
    await nextTurn();
    assert.equal(calls, 0);
    assert.ok(error instanceof HostfenceError);
  }
});

test("allowed requests dispatch only after policy completes and preserve handler", async () => {
  let resolveLookup;
  const pendingLookup = new Promise((resolve) => { resolveLookup = resolve; });
  const lookup = () => pendingLookup;
  let received;
  const handler = { onError: assert.fail };
  const intercepted = createSsrfInterceptor({ lookup })((opts, actualHandler) => {
    received = { opts, handler: actualHandler };
    return false;
  });
  const opts = { origin: "https://public.example", path: "/resource", method: "POST", body: "hello" };
  assert.equal(intercepted(opts, handler), true, "async policy acceptance cannot forward later dispatch backpressure");
  assert.equal(received, undefined);
  resolveLookup(["93.184.216.34"]);
  await nextTurn();
  assert.equal(received.opts.origin, opts.origin);
  assert.equal(received.opts.path, opts.path);
  assert.equal(received.opts.method, opts.method);
  assert.equal(received.opts.body, opts.body);
  assert.equal(typeof received.opts.connect.lookup, "function");
  assert.equal(received.handler, handler);
});

test("mutating the options or URL during DNS cannot swap the checked origin", async () => {
  let resolveLookup;
  const pendingLookup = new Promise((resolve) => { resolveLookup = resolve; });
  const lookup = () => pendingLookup;
  const origin = new URL("https://public.example");
  const opts = { origin, path: "/", method: "GET" };
  let actualOrigin;
  const intercepted = createSsrfInterceptor({ lookup })((request) => { actualOrigin = request.origin; return true; });
  intercepted(opts, { onError: assert.fail });
  origin.hostname = "127.0.0.1";
  opts.origin = "http://169.254.169.254";
  resolveLookup(["93.184.216.34"]);
  await nextTurn();
  assert.equal(actualOrigin, "https://public.example");
});

test("dispatch uses the validated canonical origin while retaining the scheme and nondefault port", async () => {
  let request;
  const intercepted = createSsrfInterceptor({ lookup: publicLookup })((opts) => { request = opts; return true; });
  intercepted({ origin: "HTTPS://BÜCHER.example:8443/ignored?query=ignored", path: "/actual" }, { onError: assert.fail });
  await nextTurn();
  assert.equal(request.origin, "https://xn--bcher-kva.example:8443");
  assert.equal(request.path, "/actual", "request paths are passed through rather than policy-checked");
});

test("object headers, header array values, and query arrays are isolated while DNS is pending", async () => {
  let resolveLookup;
  const pendingLookup = new Promise((resolve) => { resolveLookup = resolve; });
  let request;
  const body = Buffer.from("payload");
  const headers = { host: "public.example", authorization: "Bearer original", "x-tags": ["original"] };
  const query = { action: "read", tags: ["one", "two"] };
  const intercepted = createSsrfInterceptor({ lookup: () => pendingLookup })((opts) => { request = opts; return true; });
  intercepted({ origin: "https://public.example", path: "/", headers, query, body }, { onError: assert.fail });
  headers.host = "private.example";
  headers.authorization = "Bearer changed";
  headers["x-tags"][0] = "changed";
  query.action = "delete";
  query.tags.push("three");
  resolveLookup(["93.184.216.34"]);
  await nextTurn();
  assert.deepEqual(request.headers, { host: "public.example", authorization: "Bearer original", "x-tags": ["original"] });
  assert.deepEqual(request.query, { action: "read", tags: ["one", "two"] });
  assert.equal(request.body, body, "body identity must be preserved");
});

test("flat header arrays and URLSearchParams are copied before DNS", async () => {
  let resolveLookup;
  const pendingLookup = new Promise((resolve) => { resolveLookup = resolve; });
  let request;
  const headers = ["host", "public.example", "authorization", "Bearer original", "x-tags", ["one"]];
  const query = new URLSearchParams("tag=one&tag=two");
  const intercepted = createSsrfInterceptor({ lookup: () => pendingLookup })((opts) => { request = opts; return true; });
  intercepted({ origin: "https://public.example", headers, query }, { onError: assert.fail });
  headers[1] = "private.example";
  headers[3] = "Bearer changed";
  headers[5].push("two");
  query.set("tag", "changed");
  resolveLookup(["93.184.216.34"]);
  await nextTurn();
  assert.deepEqual(request.headers, ["host", "public.example", "authorization", "Bearer original", "x-tags", ["one"]]);
  assert.notEqual(request.query, query);
  assert.equal(request.query.toString(), "tag=one&tag=two");
});

test("Headers instances become a stable flat array before DNS", async () => {
  let resolveLookup;
  const pendingLookup = new Promise((resolve) => { resolveLookup = resolve; });
  let request;
  const headers = new Headers({ host: "public.example", authorization: "Bearer original" });
  const intercepted = createSsrfInterceptor({ lookup: () => pendingLookup })((opts) => { request = opts; return true; });
  intercepted({ origin: "https://public.example", headers }, { onError: assert.fail });
  headers.set("host", "private.example");
  headers.set("authorization", "Bearer changed");
  resolveLookup(["93.184.216.34"]);
  await nextTurn();
  assert.deepEqual(request.headers, ["authorization", "Bearer original", "host", "public.example"]);
});

test("custom exact-host policy rejects a public but unlisted destination", async () => {
  let error;
  const intercepted = createSsrfInterceptor({ lookup: publicLookup, allowedHosts: ["approved.example"] })(() => assert.fail("must not dispatch"));
  intercepted({ origin: "https://other.example" }, { onError(value) { error = value; } });
  await nextTurn();
  assert.ok(error instanceof HostfenceError);
  assert.match(error.reasons.join(" "), /allow list/);
});

test("modern Undici handlers receive onResponseError with a null controller", async () => {
  let received;
  const intercepted = ssrfInterceptor(() => assert.fail("must not dispatch"));
  assert.equal(intercepted({ origin: "http://[::1]" }, {
    onResponseError(controller, error) { received = { controller, error }; },
  }), true);
  await nextTurn();
  assert.equal(received.controller, null);
  assert.ok(received.error instanceof HostfenceError);
});

test("downstream throws are delivered once to the error handler", async () => {
  const expected = new Error("dispatcher closed");
  const errors = [];
  const intercepted = createSsrfInterceptor({ lookup: publicLookup })(() => { throw expected; });
  assert.equal(intercepted({ origin: "https://public.example" }, { onError(error) { errors.push(error); } }), true);
  await nextTurn();
  assert.deepEqual(errors, [expected]);
});

test("failed DNS reaches the handler with no unhandled rejection", async () => {
  const unhandled = [];
  const listener = (error) => unhandled.push(error);
  process.on("unhandledRejection", listener);
  try {
    let error;
    const intercepted = createSsrfInterceptor({ lookup: async () => { throw new Error("offline"); } })(() => assert.fail("must not dispatch"));
    intercepted({ origin: "https://public.example" }, { onError(value) { error = value; } });
    await nextTurn();
    await nextTurn();
    assert.ok(error instanceof HostfenceError);
    assert.match(error.reasons.join(" "), /DNS lookup failed/);
    assert.deepEqual(unhandled, []);
  } finally {
    process.off("unhandledRejection", listener);
  }
});

test("missing origins fail closed and legacy hostname/protocol options work", async () => {
  let error;
  let origin;
  const intercepted = createSsrfInterceptor({ lookup: publicLookup })((opts) => { origin = opts.origin; return true; });
  intercepted({}, { onError(value) { error = value; } });
  await nextTurn();
  assert.ok(error instanceof HostfenceError);
  assert.equal(origin, undefined);
  intercepted({ protocol: "https:", hostname: "public.example" }, { onError: assert.fail });
  await nextTurn();
  assert.equal(origin, "https://public.example");
});

test("invalid dispatcher and error handlers fail synchronously", () => {
  assert.throws(() => ssrfInterceptor(null), /dispatch must be a function/);
  assert.throws(() => ssrfInterceptor(() => true)({ origin: "https://public.example" }, {}), /handler must provide/);
});

test("assertOrigin retains its existing public API", async () => {
  assert.equal((await assertOrigin("https://93.184.216.34")).href, "https://93.184.216.34/");
  await assert.rejects(assertOrigin("http://127.0.0.1"), HostfenceError);
});

test("Undici compose/request integration forwards allowed requests and rejects blocked requests", async (t) => {
  const mockAgent = new MockAgent();
  mockAgent.disableNetConnect();
  t.after(() => mockAgent.close());
  mockAgent.get("https://public.example").intercept({ path: "/health", method: "GET" }).reply(200, "healthy");
  const dispatcher = mockAgent.compose(createSsrfInterceptor({ lookup: publicLookup }));
  const response = await dispatcher.request({ origin: "https://public.example", path: "/health", method: "GET" });
  assert.equal(response.statusCode, 200);
  assert.equal(await response.body.text(), "healthy");
  await assert.rejects(dispatcher.request({ origin: "http://127.0.0.1", path: "/", method: "GET" }), HostfenceError);
  mockAgent.assertNoPendingInterceptors();
});

test("Undici request receives canonical origin and original Headers/query after pending DNS", async (t) => {
  const mockAgent = new MockAgent();
  mockAgent.disableNetConnect();
  t.after(() => mockAgent.close());
  mockAgent.get("https://public.example:8443").intercept({
    path: "/health?tag=one&tag=two",
    method: "GET",
    headers: { authorization: "Bearer original" },
  }).reply(200, "snapshot accepted");
  let resolveLookup;
  const pendingLookup = new Promise((resolve) => { resolveLookup = resolve; });
  const dispatcher = mockAgent.compose(createSsrfInterceptor({ lookup: () => pendingLookup }));
  const headers = new Headers({ authorization: "Bearer original" });
  const query = { tag: ["one", "two"] };
  const pending = dispatcher.request({ origin: "HTTPS://PUBLIC.example:8443", path: "/health", method: "GET", headers, query });
  headers.set("authorization", "Bearer changed");
  query.tag.push("three");
  resolveLookup(["93.184.216.34"]);
  const response = await pending;
  assert.equal(await response.body.text(), "snapshot accepted");
  mockAgent.assertNoPendingInterceptors();
});
