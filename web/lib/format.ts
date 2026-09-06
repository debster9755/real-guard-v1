/**
 * Timestamp helpers.
 *
 * The API returns RFC 3339 UTC with a `Z` suffix (API-005). Reviewers care
 * about two things a raw timestamp answers badly: how long a request has
 * been waiting, and how long is left before it expires (APR-007 — an
 * approval that expires is never resumed). So the queue shows both
 * relatively, with the exact value kept in a `title` attribute for anyone
 * who needs to correlate against a log line.
 */

function parse(iso: string): Date | null {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** "just now" / "4m ago" / "3h ago" / "2d ago". */
export function timeAgo(iso: string, now: number = Date.now()): string {
  const date = parse(iso);
  if (!date) return iso;
  const seconds = Math.floor((now - date.getTime()) / 1000);
  if (seconds < 45) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}

/** "in 58m" / "in 3h" / "expired" — an elapsed deadline is stated plainly
 *  rather than shown as a negative duration. */
export function timeUntil(iso: string, now: number = Date.now()): string {
  const date = parse(iso);
  if (!date) return iso;
  const seconds = Math.floor((date.getTime() - now) / 1000);
  if (seconds <= 0) return 'expired';
  if (seconds < 60) return `in ${seconds}s`;
  if (seconds < 3600) return `in ${Math.floor(seconds / 60)}m`;
  if (seconds < 86_400) return `in ${Math.floor(seconds / 3600)}h`;
  return `in ${Math.floor(seconds / 86_400)}d`;
}

/** `2026-09-06 13:27Z` — compact, still unambiguous and still UTC. */
export function compactUtc(iso: string): string {
  const date = parse(iso);
  if (!date) return iso;
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)}Z`;
}
