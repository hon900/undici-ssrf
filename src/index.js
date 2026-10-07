import { Hostfence, HostfenceError, pinLookup } from "hostfence";
import { isIP } from "node:net";
import { Agent, buildConnector } from "undici";

const fence = new Hostfence();

export { HostfenceError };

function copyArrayValues(value) {
  return Array.isArray(value) ? value.map(copyArrayValues) : value;
}

function copyHeaders(headers) {
  if (headers == null || typeof headers !== "object") return headers;
  if (Array.isArray(headers)) return headers.map(copyArrayValues);
  if (typeof headers[Symbol.iterator] === "function") {
    // Headers and other entry iterables become an independent flat array,
    // supported by both legacy and current Undici dispatchers.
    const entries = [];
    for (const entry of headers) {
      if (!Array.isArray(entry) || entry.length !== 2) throw new TypeError("headers must contain key-value pairs");
      entries.push(entry[0], copyArrayValues(entry[1]));
    }
    return entries;
  }
  return Object.fromEntries(Object.entries(headers).map(([name, value]) => [name, copyArrayValues(value)]));
}

function copyQuery(query) {
  if (query instanceof URLSearchParams) return new URLSearchParams(query);
  if (query == null || typeof query !== "object") return query;
  return Object.fromEntries(Object.entries(query).map(([name, value]) => [name, copyArrayValues(value)]));
}

function reportError(handler, error) {
  // Error callbacks run outside Promise reactions. As in Undici, handlers must
  // not throw; a caller bug must not become an unhandled Promise rejection.
  queueMicrotask(() => {
    if (typeof handler.onResponseError === "function") handler.onResponseError(null, error);
    else handler.onError(error);
  });
}

export function createSsrfInterceptor(policy = {}) {
  const policyFence = new Hostfence(policy);
  return function interceptor(dispatch) {
    if (typeof dispatch !== "function") throw new TypeError("dispatch must be a function");
    return function intercepted(opts, handler) {
      if (!handler || (typeof handler.onError !== "function" && typeof handler.onResponseError !== "function")) {
        throw new TypeError("handler must provide onError or onResponseError");
      }

      let request;
      try {
        // Copy common mutable request metadata before awaiting DNS. Body
        // streams/buffers retain identity and are not consumed by the guard.
        const origin = opts.origin ?? `${opts.protocol}//${opts.hostname}`;
        request = { ...opts, origin: String(origin) };
        if (opts.headers !== undefined) request.headers = copyHeaders(opts.headers);
        if (opts.query !== undefined) request.query = copyQuery(opts.query);
      } catch (error) {
        reportError(handler, error);
        return true;
      }
      void policyFence.assert(request.origin).then(
        (url) => {
          try {
            request.origin = url.origin;
            dispatch(request, handler);
          } catch (error) {
            reportError(handler, error);
          }
        },
        (error) => reportError(handler, error),
      );

      // Accepted for asynchronous validation, not a report of socket readiness.
      // The downstream dispatch result arrives too late to forward backpressure.
      return true;
    };
  };
}

export const ssrfInterceptor = createSsrfInterceptor();

const agentOptionNames = new Set([
  "connections", "pipelining", "headersTimeout", "bodyTimeout", "connectTimeout",
  "keepAliveTimeout", "keepAliveMaxTimeout", "keepAliveTimeoutThreshold",
  "maxHeaderSize", "maxResponseSize",
]);

function guardAgentOptions(dispatch) {
  return function guarded(opts, handler) {
    if (opts.maxRedirections != null && opts.maxRedirections !== 0) {
      throw new TypeError("createSsrfAgent requires manual redirect handling");
    }
    if (opts.servername !== undefined || opts.connect !== undefined) {
      throw new TypeError("createSsrfAgent does not accept request connection overrides");
    }
    const headers = opts.headers;
    const names = Array.isArray(headers)
      ? headers.filter((_, index) => index % 2 === 0)
      : Object.keys(headers ?? {});
    if (names.some((name) => /^(host|:authority)$/i.test(String(name)))) {
      throw new TypeError("createSsrfAgent sets Host and TLS servername from the validated origin");
    }
    return dispatch(opts, handler);
  };
}

/** An owned Undici dispatcher with policy enforcement at every new socket. */
export function createSsrfAgent(policy = {}, options = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("agent options must be an object");
  }
  for (const name of Object.keys(options)) {
    if (!agentOptionNames.has(name)) throw new TypeError(`unsupported agent option: ${name}`);
  }
  const connectionFence = new Hostfence(policy);
  const connectTimeout = options.connectTimeout;
  const agent = new Agent({
    ...options,
    maxRedirections: 0,
    connect(connection, callback) {
      // Undici calls a constructor-level connector for every new socket.
      // A request-level opts.connect is not used by Agent/Pool/Client.
      const hostname = isIP(connection.hostname) === 6
        ? `[${connection.hostname}]` : connection.hostname;
      const origin = `${connection.protocol}//${hostname}${connection.port ? `:${connection.port}` : ""}`;
      void connectionFence.assertPin(origin).then(({ url, pin }) => {
        try {
          if (connection.httpSocket) throw new TypeError("preconnected sockets are not supported");
          const connector = buildConnector({ lookup: pinLookup(pin), timeout: connectTimeout });
          connector({
            ...connection,
            host: url.host,
            hostname: pin.servername,
            port: String(pin.port),
            // Never use an alternate Host header as the certificate identity.
            servername: isIP(pin.servername) ? undefined : pin.servername,
          }, callback);
        } catch (error) {
          callback(error, null);
        }
      }, (error) => callback(error, null));
    },
  });
  // compose applies interceptors from inner to outer. The preflight guard
  // snapshots metadata and reports errors thrown by the inner options guard.
  return agent.compose(guardAgentOptions, createSsrfInterceptor(policy));
}

export async function assertOrigin(url) {
  return fence.assert(url);
}
