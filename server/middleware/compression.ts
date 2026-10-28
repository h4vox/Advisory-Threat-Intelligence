/**
 * Gzip for dynamic responses of the production server: server-function data (JSON) and pages
 * (HTML). Static files are pre-compressed at build time (vite.config.ts `compressPublicAssets`),
 * so they already carry Content-Encoding and are left alone. JSON shrinks about 10×, which is most
 * of what a Library page downloads. Nitro global middleware; names sort before the others, so this
 * wraps their responses.
 */
interface CompressionEvent {
  req: { method: string; headers: Headers };
}

const COMPRESSIBLE = /^(?:application\/(?:json|javascript|x-ndjson|xml)|text\/(?:html|plain|css|javascript|xml)|image\/svg\+xml)\b/i;
const MIN_BYTES = 1024;

export default async function compression(event: CompressionEvent, next: () => unknown | Promise<unknown>): Promise<unknown> {
  const result = await next();
  if (!(result instanceof Response) || !result.body) return result;
  if (!/\bgzip\b/i.test(event.req.headers.get("accept-encoding") ?? "")) return result;
  const h = result.headers;
  if (h.get("content-encoding") || result.status === 204 || result.status === 304 || result.status === 206) return result;
  if (!COMPRESSIBLE.test(h.get("content-type") ?? "")) return result;
  const length = Number(h.get("content-length") ?? NaN);
  if (Number.isFinite(length) && length < MIN_BYTES) return result;
  const headers = new Headers(h);
  headers.set("Content-Encoding", "gzip");
  headers.delete("Content-Length");
  headers.append("Vary", "Accept-Encoding");
  return new Response(result.body.pipeThrough(new CompressionStream("gzip")), { status: result.status, statusText: result.statusText, headers });
}
