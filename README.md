# undici-ssrf

[Undici](https://github.com/nodejs/undici) origin-policy interceptor backed by
[hostfence](https://github.com/hon900/hostfence). Check a destination before
dispatching a request and deliver policy failures through Undici's error handler.

Requires Node.js 18.18 or later and a compatible Undici release. Undici 7 has a
higher Node.js requirement; follow that release's engine constraints.

```sh
npm install github:hon900/undici-ssrf#v0.9.0 undici@6
```

## Default policy

```js
import { Agent } from "undici";
import { ssrfInterceptor } from "undici-ssrf";

const dispatcher = new Agent().compose(ssrfInterceptor);
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

Use this on an `Agent` with an explicit request origin. A bound `Client` or
`Pool` may omit `opts.origin`; the interceptor cannot inspect the bound origin
from the dispatch function and will reject an absent target. Include the origin
explicitly if using such a dispatcher.

## Custom policy

```js
import { Agent } from "undici";
import { createSsrfInterceptor } from "undici-ssrf";

const dispatcher = new Agent().compose(createSsrfInterceptor({
  protocols: ["https"],
  allowedHosts: ["api.example.com"],
}));
```

`createSsrfInterceptor(policy)` accepts hostfence policy options, including a
custom asynchronous `lookup(hostname)` returning an array of IP address strings.
An allowlist does not override address restrictions. Each factory call owns its
policy instance; the existing `ssrfInterceptor` export retains the default policy.

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

This is an **origin preflight check**. Policy checks cover `opts.origin`, not
request paths, query values, header contents, or bodies. Metadata snapshots
prevent later mutation during DNS; they do not authorize a custom `Host` header
or protect secrets in an `Authorization` header. Applications must set their own
header and path policy.

The interceptor does not pin the checked DNS answers to
the socket used by Undici; DNS changes between validation and connection remain
a time-of-check/time-of-use risk. Use connection-time enforcement or validated
address pinning with correct TLS/SNI handling, plus network egress controls when
required. Custom connectors and proxies can change the actual socket target and
must enforce the same policy themselves.

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

Tests use deterministic DNS and Undici `MockAgent`, including a real
`compose()`/`request()` integration. They check pre-dispatch rejection, synchronous
return type, allowed dispatch, mutable-origin isolation, and error delivery
without unhandled rejections. No remote HTTP service is contacted.

The dependency remains pinned to `github:hon900/hostfence#v1.3.0`; the umbrella
workspace can explicitly link its local core checkout for integration testing.
