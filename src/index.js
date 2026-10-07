import { Hostfence, HostfenceError, pinLookup } from "hostfence";

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
      void policyFence.assertPin(request.origin).then(
        ({ url, pin }) => {
          try {
            request.origin = url.origin;
            request.connect = { ...(request.connect ?? {}), lookup: pinLookup(pin) };
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

export async function assertOrigin(url) {
  return fence.assert(url);
}
