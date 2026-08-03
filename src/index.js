import { Hostfence, HostfenceError } from "hostfence";

const fence = new Hostfence();

export { HostfenceError };

export function ssrfInterceptor(dispatch) {
  return async function intercepted(opts, handler) {
    const origin = opts.origin || `${opts.protocol}//${opts.hostname}`;
    await fence.assert(String(origin));
    return dispatch(opts, handler);
  };
}

export async function assertOrigin(url) {
  return fence.assert(url);
}
