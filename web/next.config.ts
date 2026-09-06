import type { NextConfig } from 'next';

/**
 * real-guard-v1 `/console` — docs/adr/0014-console-spa-frontend.md §1.
 *
 * `output: 'export'` — there is no Node server at runtime. `next build`
 * produces static HTML/JS/CSS at Docker *build* time and FastAPI serves the
 * result same-origin via `StaticFiles` (app/console_api.py), exactly the way
 * `/dashboard/static` already serves vendored htmx. Single container, single
 * port, no CORS, no third-party CDN at request time (SPEC.md §2.19).
 *
 * `basePath: '/console'` — resolved empirically, not assumed (ADR 0014 §1's
 * "path-prefix resolution" note). With a basePath the exported `out/` is
 * internally consistent: pages land at `out/index.html`, `out/login/…` and
 * assets are emitted as `/console/_next/…`, so mounting `out/` at `/console`
 * server-side makes every generated URL resolve with no rewriting. The
 * alternative (no basePath, pages nested under `app/console/…`) emits its
 * assets at `/_next/…` — root-absolute URLs that a `/console` mount does not
 * cover, which 404 silently in the browser while the HTML itself loads fine.
 *
 * `trailingSlash: true` — the exported tree is directory-per-route
 * (`out/login/index.html`). Starlette's `StaticFiles(html=True)` serves a
 * directory's `index.html` only for a path that already ends in `/`, and
 * otherwise issues a 307 redirect to add one. Emitting trailing-slash URLs
 * from Next's own `<Link>`s avoids that redirect round-trip entirely.
 *
 * `images.unoptimized` — required by `output: 'export'` (there is no image
 * optimisation server). This console ships no raster images anyway; the only
 * graphics are inline SVG icons.
 */
const nextConfig: NextConfig = {
  output: 'export',
  basePath: '/console',
  trailingSlash: true,
  reactStrictMode: true,
  images: { unoptimized: true },
};

export default nextConfig;
