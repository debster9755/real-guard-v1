/*
 * Pre-paint theme bootstrap for the real-guard-v1 console.
 *
 * This exists as a real, same-origin *file* rather than the conventional
 * inline <script> snippet because app/main.py sends
 * `Content-Security-Policy: default-src 'self'` with no `unsafe-inline`
 * (SEC-008) — a real browser refuses an inline script outright, and the
 * page would flash light-then-dark on every load for a dark-mode user.
 * Loaded synchronously (no defer/async) from <head>, so the class is on
 * <html> before the first paint.
 */
(function () {
  try {
    var stored = window.localStorage.getItem('rg-console-theme');
    var dark =
      stored === 'dark' ||
      (stored !== 'light' &&
        window.matchMedia &&
        window.matchMedia('(prefers-color-scheme: dark)').matches);
    if (dark) document.documentElement.classList.add('dark');
  } catch (e) {
    /* storage refused (private mode); fall back to the light default */
  }
})();
