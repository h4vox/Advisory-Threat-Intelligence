// Eval stub: every logger.<channel>(...) call is a no-op.
const noop = () => {};
export const logger = new Proxy({}, { get: () => noop });
