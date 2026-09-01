# Silicon Hook ↔ Silicon DM integration contract

**Contract version:** `silicon-hook-dm/v1`

**Status:** Hook implemented; the current local Silicon DM `0.2.0` alignment
worktree is incompatible and must not be deployed with this Hook contract.

Hook's product understanding requires every durably accepted webhook event to
reach the target Silicon through DM. This document fixes that boundary without
making WebSocket state part of Hook.

## Durable handoff

Hook sends the immutable minimal event to:

```http
POST /api/v1/internal/hook-events
Authorization: Bearer <Silicon Hook IAM service token>
Content-Type: application/json
Idempotency-Key: <stable Hook event UUID>
```

```json
{
  "event_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91e1",
  "org_id": "acme",
  "silicon_id": "support:acme",
  "type": "source.event",
  "trace_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91f1",
  "payload": {}
}
```

DM must authenticate the `silicon-hook` service identity, authorize its
dedicated delivery scope, deduplicate `event_id`, commit durable client-delivery
work, and return only `202 Accepted` for success. The canonical JSON encoding of
`payload` is limited to 1,048,576 bytes; the complete body is limited to
1,052,672 bytes.

Hook retries transient failures with the same event ID and exact bytes. It must
not treat a missing route or another non-202 response as delivery, discard the
outbox event, or reclassify the payload as a normal conversation message.

## Acknowledgment ownership

Hook's ingress `202` acknowledges local durable acceptance. DM's internal
`202` acknowledges durable handoff. DM then owns represented-actor WebSocket
authorization, delivery sequences, client ACK state, reconnect replay, and the
30-second ping / two-minute `4000 heartbeat-timeout` lifecycle. A client ACK is
not Hook delivery state and heartbeats are never Hook events.

## Compatibility audit

As audited on 2026-09-01, the current uncommitted Silicon DM product-alignment
worktree removes `/api/v1/internal/hook-events`, `SystemEvent`, the Hook service
authentication path, and realtime system-event frames under its proposed
D-049/D-051 decisions. Deploying that state would make DM return `404` for every
Hook delivery and strand accepted events in terminal failure, so end-to-end
WebSocket delivery and client acknowledgment would not occur.

Production release requires one explicit product decision:

1. DM restores and versions the durable Hook-event ingestion and system-event
   replay contract described above; or
2. Hook's understanding is revised to name another durable consumer and the
   replacement end-to-end acknowledgment protocol is designed and implemented.

Until then, Hook preserves its own explicit forwarding requirement and records
the incompatibility as a release gate rather than weakening durability.
