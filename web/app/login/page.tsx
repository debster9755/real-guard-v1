'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useState, type FormEvent } from 'react';

import { useAuth } from '@/components/auth-provider';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ApiError } from '@/lib/api';

/**
 * `POST /console/api/login` with a reviewer key. SEC-006: a service key is
 * refused here by the server, and the real message it returns ("Service keys
 * cannot sign in to the reviewer console (SEC-006).") is shown verbatim
 * rather than flattened into a generic failure — telling the operator which
 * *class* of key they used is the whole point of that distinction.
 */
export default function LoginPage() {
  const { session, ready, signIn } = useAuth();
  const router = useRouter();
  const [reviewerKey, setReviewerKey] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (ready && session) router.replace('/');
  }, [ready, session, router]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await signIn(reviewerKey);
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : 'Sign-in failed. Please try again.',
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="grid min-h-screen place-items-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="text-lg font-semibold text-ink">real-guard-v1 console</h1>
          <p className="mt-1 text-sm text-muted">
            Sign in with a reviewer key to review held requests.
          </p>
        </div>

        <Card className="p-6">
          <form onSubmit={onSubmit} noValidate>
            <label htmlFor="reviewer_key" className="block text-xs font-medium text-muted">
              Reviewer key
            </label>
            <input
              id="reviewer_key"
              name="reviewer_key"
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={reviewerKey}
              onChange={(event) => setReviewerKey(event.target.value)}
              data-testid="reviewer-key-input"
              className="mt-1.5 w-full rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-sm text-ink placeholder:text-muted/60"
              placeholder="rev_…"
            />

            {error ? (
              <p
                role="alert"
                data-testid="login-error"
                className="mt-3 rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger"
              >
                {error}
              </p>
            ) : null}

            <Button
              type="submit"
              data-testid="login-submit"
              disabled={submitting || reviewerKey.length === 0}
              className="mt-4 w-full"
            >
              {submitting ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>
        </Card>

        <p className="mt-4 text-center text-xs text-muted">
          The minimal HTMX dashboard remains available at{' '}
          <a href="/dashboard" className="text-brand underline underline-offset-2">
            /dashboard
          </a>
          .
        </p>
      </div>
    </div>
  );
}
