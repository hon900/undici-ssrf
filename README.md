# undici-ssrf

[undici](https://github.com/nodejs/undici) interceptor backed by
[hostfence](https://github.com/hon900/hostfence). Compose it onto a pool or
agent so internally routed origins never leave the worker.

```js
import { Agent } from "undici";
import { ssrfInterceptor } from "undici-ssrf";

const agent = new Agent().compose(ssrfInterceptor);
```

Depends on `github:hon900/hostfence#v1.2.0`.
