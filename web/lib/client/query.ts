/**
 * The TanStack Query client for client components (one per browser tab, created by the providers).
 *
 * - Errors are ApiError everywhere (`Register.defaultError`), with the service's message and hint.
 * - A failed mutation toasts "title + message + hint" unless it opts out with `meta: { toast: false }` (pages that show
 *   the failure inline, next to the field it is about). `meta.errorTitle` sets the toast's title.
 * - A failed query does not toast: pages render it inline with a retry (Arc: an alert next to the cause).
 * - A 401 means the sign-in ended (the API proxy cleared it): the session keeper sends the Carbon to sign in again.
 * - Queries retry network blips and 5xx twice; mutations never retry on their own (send an Idempotency-Key and let the
 *   Carbon try again).
 *
 * Seed a query with what the Server Component already fetched, so the page paints without a second request:
 *
 *   const items = useQuery({ queryKey: ["items"], queryFn: ({ signal }) => api.get<Item[]>("/v1/items", { signal }), initialData });
 */
import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";
import { ApiError, isSignedOutError } from "../errors";
import { notifyError } from "../notify";
import { markSignedOut } from "./session";

export interface QueryMeta extends Record<string, unknown> {
  /** Title of the error toast (mutations). */
  errorTitle?: string;
  /** false: never toast this failure (the page shows it inline). */
  toast?: boolean;
}

declare module "@tanstack/react-query" {
  interface Register {
    defaultError: ApiError;
    queryMeta: QueryMeta;
    mutationMeta: QueryMeta;
  }
}

/** Retry only what may succeed on its own: the network, and the service having a moment. Never 4xx. */
function shouldRetry(failureCount: number, error: unknown): boolean {
  const failure = ApiError.from(error);
  if (failure.status === 0 && failure.code !== "network_error") return false;
  if (failure.status !== 0 && failure.status < 500) return false;
  return failureCount < 2;
}

export function createQueryClient(): QueryClient {
  return new QueryClient({
    queryCache: new QueryCache({
      onError: error => {
        if (isSignedOutError(error)) markSignedOut();
      },
    }),
    mutationCache: new MutationCache({
      onError: (error, _variables, _context, mutation) => {
        const failure = ApiError.from(error);
        if (isSignedOutError(failure)) {
          markSignedOut();
          return;
        }
        if (mutation.meta?.toast === false) return;
        notifyError(failure, mutation.meta?.errorTitle);
      },
    }),
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        gcTime: 5 * 60_000,
        retry: shouldRetry,
        retryDelay: attempt => Math.min(4000, 600 * 2 ** attempt),
        refetchOnWindowFocus: true,
      },
      mutations: { retry: false },
    },
  });
}
