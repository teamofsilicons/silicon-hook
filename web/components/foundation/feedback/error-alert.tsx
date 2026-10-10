/**
 * A failure shown where it happened, in the service's own words: what went wrong (message) and what to do (hint), with
 * the request id to quote. Pages pass what tryApiFetch() returned, or an ApiError from a query or mutation.
 *
 *   <ErrorAlert error={error} title="Items could not be loaded" action={<Button onClick={refetch}>Try again</Button>} />
 */
import type { ReactNode } from "react";
import { Alert } from "@/components/silicon-ui/alert/alert";
import type { ApiErrorInit } from "@/lib/errors";
import { readableTimes } from "@/lib/format";
import styles from "./error-alert.module.css";

export function ErrorAlert({ error, title, action }: { error: Pick<ApiErrorInit, "message" | "hint" | "requestId" | "status">; title?: string; action?: ReactNode }) {
  return (
    <Alert tone="danger" title={title ?? (error.status === 0 ? "The service could not be reached" : "That did not work")}>
      <span className={styles.body}>
        {readableTimes([error.message, error.hint].filter(Boolean).join(" "))}
        {error.requestId ? <span className={styles.reference}>Request {error.requestId}</span> : null}
      </span>
      {action ? <span className={styles.action}>{action}</span> : null}
    </Alert>
  );
}
