# undici-ssrf

[Undici](https://github.com/nodejs/undici) origin-policy checks and a socket-pinning
agent backed by [hostfence](https://github.com/hon900/hostfence). Check requests
before dispatch and bind new connections to an address validated at connection time.

Requires Node.js 18.18 or later and a compatible Undici release. Undici 7 has a
higher Node.js requirement; follow that release's engine constraints.

```sh
npm install github:hon900/undici-ssrf#v0.9.1 undici@6
```

## Pinned connections

```js
import { createSsrfAgent } from "undici-ssrf";

const dispatcher = createSsrfAgent();
try {
  const { body } = await dispatcher.request({
    origin: "https://example.com",
    path: "/",
    method: "GET",
  });
  console.log(await body.text());
} finally {
  await dispatcher.close();
}
```

`createSsrfAgent(policy, options)` returns an owned Undici dispatcher; close it
after consuming response bodies. It validates every request's explicit origin.
On each new socket it validates the actual connection hostname again, then gives
Undici's constructor-level connector a lookup function returning only the
selected validated address. There is no subsequent operating-system DNS lookup.
The original hostname remains the HTTP Host and TLS SNI/certificate identity;
normal certificate verification stays enabled. The initial connection therefore
does two policy lookups (preflight and connection); pooled sockets can be reused.

`options` supports `connections`, `pipelining`, `headersTimeout`, `bodyTimeout`,
`connectTimeout`, `keepAliveTimeout`, `keepAliveMaxTimeout`,
`keepAliveTimeoutThreshold`, `maxHeaderSize`, and `maxResponseSize`. Other options
are rejected, including custom connectors, factories, proxies, and interceptor
overrides. Requests cannot override `Host`, `:authority`, `servername`, or
`connect`. Automatic redirects are disabled; nonzero `maxRedirections` is
rejected. Submit each redirect destination as a new request through this dispatcher.

## Custom policy

```js
import { createSsrfAgent } from "undici-ssrf";

const dispatcher = createSsrfAgent({
  protocols: ["https"],
  allowedHosts: ["api.example.com"],
}, { connections: 4 });
```

Both factories accept hostfence policy options, including a
custom asynchronous `lookup(hostname)` returning an array of IP address strings.
An allowlist does not override address restrictions. Each factory call owns its
policy instance; the existing `ssrfInterceptor` export retains the default policy.

## Existing dispatcher: preflight only

```js
import { Agent } from "undici";
import { createSsrfInterceptor, ssrfInterceptor } from "undici-ssrf";

const dispatcher = new Agent().compose(ssrfInterceptor);
// Or: new Agent().compose(createSsrfInterceptor({ allowedHosts: ["api.example.com"] }))
```

`ssrfInterceptor` and `createSsrfInterceptor(policy)` preserve the original
preflight API. They do **not** configure the connector of an existing dispatcher.
Undici does not apply request-level `opts.connect.lookup` to Agent/Pool/Client
socket creation. Use `createSsrfAgent` when socket pinning is required. Include
`opts.origin` explicitly; a bound Client or Pool can otherwise omit its target,
which the interceptor cannot infer and will reject.

`assertOrigin(stringOrUrl)` remains available as a standalone default-policy
assertion. It resolves to a `URL` or rejects with the exported `HostfenceError`.

## Dispatch and error contract

- The intercepted function returns `true` **synchronously** when it accepts a
  request for asynchronous policy evaluation. It never returns a Promise.
- A blocked or malformed origin does not reach the downstream dispatcher.
  Policy failures, DNS failures, and synchronous downstream errors are delivered
  to `handler.onError(error)`, or `handler.onResponseError(null, error)` for a
  modern Undici handler. Handler error callbacks must not throw.
- The routing origin is copied before asynchronous validation, including when
  the caller passes a mutable `URL` object. Downstream dispatch receives the
  validated URL's canonical origin, retaining its scheme and nondefault port.
- Plain header objects, flat header arrays, `Headers` entry iterables, and query
  objects are copied before DNS, including array values. `URLSearchParams` is
  copied too; serialization still follows the installed Undici version. Use
  plain query objects with Undici 6. Request bodies retain their original
  identity: the guard does not consume, clone, or freeze a stream or buffer.
- Validation finishes after the return value has been sent. The interceptor
  cannot relay the downstream dispatcher's eventual `false`/`drain` backpressure
  signal. Use `request()`/`fetch()` with application-level concurrency limits;
  this is not suitable for a low-level producer that relies on dispatch return
  values for flow control. It does not add a bounded queue or cancellation of
  pending DNS work. Wait for outstanding requests before closing the dispatcher.

These choices follow the [Undici dispatch contract](https://github.com/nodejs/undici/blob/v6.21.3/docs/docs/api/Dispatcher.md#dispatcherdispatchoptions-handler)
and the asynchronous acceptance pattern used by its
[DNS interceptor](https://github.com/nodejs/undici/blob/main/lib/interceptor/dns.js).

## Security boundary

Policy checks cover `opts.origin`, not
request paths, query values, header contents, or bodies. Metadata snapshots
prevent later mutation during DNS. The pinned agent rejects custom routing
headers, while the standalone interceptor passes them through. Neither mode
protects secrets in an `Authorization` header. Applications must set their own
header and path policy.

The standalone interceptor does not pin the checked DNS answers to
the socket used by Undici; DNS changes between validation and connection remain
a time-of-check/time-of-use risk. Use connection-time enforcement or validated
address pinning with correct TLS/SNI handling, plus network egress controls when
required. Custom connectors and proxies can change the actual socket target and
must enforce the same policy themselves. `createSsrfAgent` provides direct
connection pinning and does not accept those overrides. It pins the first
validated answer rather than falling back to a fresh resolver when connection
fails. Network egress controls remain useful defense in depth.

Every redirect needs a fresh policy check. Interceptor composition order matters:
a redirect/retry interceptor that redispatches through an inner function can
bypass an outer guard. The conservative configuration disables automatic
redirects and submits each validated destination as a new request. This package
does not claim to make arbitrary interceptor chains safe.

## Development

```sh
npm install
npm test
```

Tests use deterministic DNS, Undici `MockAgent`, and actual local HTTP/TLS sockets.
They verify connection-time rebinding rejection, private/mixed-answer rejection,
canonical Host/SNI, certificate verification, and the absence of an OS DNS lookup.
The preflight suite checks synchronous return type, allowed dispatch,
mutable-origin isolation, and error delivery without unhandled rejections.
Local socket fixtures explicitly allow loopback; production defaults do not.
No remote HTTP service is contacted.

The dependency is pinned to `github:hon900/hostfence#v1.4.1`; the umbrella
workspace can explicitly link its local core checkout for integration testing.
