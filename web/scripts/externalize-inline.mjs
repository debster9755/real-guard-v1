/**
 * Post-`next build` step: rewrite every inline <script> and <style> in the
 * exported HTML into a real, same-origin file.
 *
 * WHY THIS EXISTS
 *
 * app/main.py's `SecurityHeadersMiddleware` sends
 * `Content-Security-Policy: default-src 'self'` on every response, with no
 * `unsafe-inline` (SEC-008, SPEC.md §11.4). Next.js's App Router static
 * export inlines its React Flight payload as
 * `<script>self.__next_f.push(...)</script>` blocks directly in each HTML
 * document — a real browser refuses every one of them under that header, and
 * the app renders as a blank page. This is exactly the class of defect
 * docs/adr/0012 already caught once by hand (htmx's inline <style>), which is
 * why it was checked here with a real browser rather than assumed.
 *
 * The three alternatives were weighed and rejected:
 *   - loosening the CSP to `unsafe-inline` — weakens SEC-008 system-wide for
 *     a UI convenience;
 *   - per-build script hashes in the header — the header is static in
 *     Python; feeding it build artefact hashes couples the two badly;
 *   - a nonce — needs per-request server rendering, which `output: 'export'`
 *     deliberately does not have.
 *
 * Externalising is the only option that changes neither the security header
 * nor the deployment model. Execution order is preserved: each extracted
 * script becomes a plain (non-async, non-defer) `<script src>` at exactly the
 * position its inline original occupied, so the parser still runs them in
 * document order, before the async bundle chunks that consume `__next_f`.
 *
 * Idempotent, and a no-op on any document that has no inline blocks.
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const WEB_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT_DIR = join(WEB_ROOT, 'out');
// Kept under `_next/static/` so it inherits the same long-lived caching
// posture as every other build artefact, and is obviously build output.
const ASSET_SUBDIR = join('_next', 'static', 'csp');
const ASSET_DIR = join(OUT_DIR, ASSET_SUBDIR);
// Must match `basePath` in next.config.ts — these URLs are resolved by the
// browser against the site root, not against the document.
const URL_PREFIX = '/console/_next/static/csp';

const INLINE_SCRIPT = /<script(?![^>]*\ssrc=)([^>]*)>([\s\S]*?)<\/script>/gi;
const INLINE_STYLE = /<style(?![^>]*\shref=)([^>]*)>([\s\S]*?)<\/style>/gi;

function htmlFiles(dir) {
  const found = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) found.push(...htmlFiles(full));
    else if (entry.endsWith('.html')) found.push(full);
  }
  return found;
}

function writeAsset(contents, extension) {
  const hash = createHash('sha256').update(contents).digest('hex').slice(0, 16);
  const name = `${hash}.${extension}`;
  mkdirSync(ASSET_DIR, { recursive: true });
  writeFileSync(join(ASSET_DIR, name), contents, 'utf8');
  return `${URL_PREFIX}/${name}`;
}

/** Drop `type`/`nonce`; keep anything else the tag carried (e.g. `id`). */
function keepAttributes(raw) {
  return raw
    .replace(/\stype\s*=\s*("[^"]*"|'[^']*'|\S+)/gi, '')
    .replace(/\snonce\s*=\s*("[^"]*"|'[^']*'|\S+)/gi, '')
    .trim();
}

let scriptCount = 0;
let styleCount = 0;
let fileCount = 0;

for (const file of htmlFiles(OUT_DIR)) {
  const original = readFileSync(file, 'utf8');

  let html = original.replace(INLINE_SCRIPT, (match, attrs, body) => {
    if (body.trim() === '') return match;
    scriptCount += 1;
    const url = writeAsset(body, 'js');
    const kept = keepAttributes(attrs);
    return `<script${kept ? ` ${kept}` : ''} src="${url}"></script>`;
  });

  html = html.replace(INLINE_STYLE, (match, attrs, body) => {
    if (body.trim() === '') return match;
    styleCount += 1;
    const url = writeAsset(body, 'css');
    const kept = keepAttributes(attrs);
    return `<link rel="stylesheet"${kept ? ` ${kept}` : ''} href="${url}">`;
  });

  if (html !== original) {
    writeFileSync(file, html, 'utf8');
    fileCount += 1;
  }
}

// Fail loudly rather than shipping HTML the browser will refuse: if a future
// Next upgrade emits an inline block this regex does not match, the assertion
// below is what catches it — not a blank page in production.
const remaining = [];
for (const file of htmlFiles(OUT_DIR)) {
  const html = readFileSync(file, 'utf8');
  INLINE_SCRIPT.lastIndex = 0;
  INLINE_STYLE.lastIndex = 0;
  const hasScript = [...html.matchAll(INLINE_SCRIPT)].some((m) => m[2].trim() !== '');
  const hasStyle = [...html.matchAll(INLINE_STYLE)].some((m) => m[2].trim() !== '');
  if (hasScript || hasStyle) remaining.push(relative(OUT_DIR, file));
}

if (remaining.length > 0) {
  console.error(
    `CSP: inline blocks still present after rewriting: ${remaining.join(', ')}`,
  );
  process.exit(1);
}

console.log(
  `CSP: externalised ${scriptCount} inline script(s) and ${styleCount} inline style(s) ` +
    `across ${fileCount} HTML file(s) — SEC-008 default-src 'self' needs no unsafe-inline.`,
);
