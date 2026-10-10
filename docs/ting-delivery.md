# Delivery through Ting

Hook receives, verifies and keeps provider webhooks. Ting carries each verified
event to the Silicon (and to Carbons who subscribed). The app that hosts the
Silicon handles receiving; nobody configures Hook or Ting by hand.

Delivery is optional. Without it Hook still receives, verifies and stores every
event for 14 days, and Silicons read them with `hook events` or the history API.

## Turning delivery on or off

| Variable | Meaning |
| --- | --- |
| `HOOK_TING_URL` | Ting's origin. Unset: delivery is off. Plain `http` only for loopback. |
| `HOOK_TING_TIMEOUT_SECONDS` | Deadline for one call to Ting, 1 to 15 seconds (default 10). |
| `HOOK_TING_POLL_MILLISECONDS` | How often the publisher looks for queued sends, 100 to 30000 ms (default 1000). |

With `HOOK_TING_URL` unset, Hook queues nothing (so turning delivery on later
does not flood Silicons with old events), logs that delivery is off at startup,
and says so everywhere a client can look: `/readyz` (`delivery.ting: disabled`),
`GET /api/v3/delivery`, `409 delivery_disabled` from enrolment and
subscriptions, and `state: delivery_disabled` in publication status.

Before setting `HOOK_TING_URL`, Ting must accept Silicon Accounts proofs from
Hook (Ting's own migration is outside Hook), and Ting's operator must register
the `hook.webhook.received` type. Until then keep it unset.

## How Hook talks to Ting

Hook signs every call to Ting with a Silicon Accounts proof made with Hook's own
app credentials:

| Call | Proof | Scope |
| --- | --- | --- |
| Send a notification, read its receipt | App verification (no user) | `tings.send`, `sent.query` |
| Enrol a recipient | User verification, from the recipient's own Hook access token | `tings.subscribe` |

App verification proofs are kept in memory and renewed one at a time; a User
verification proof is made for each enrolment while the recipient's request is
live. Hook stores no delegated tokens. Recipients are addressed by their Silicon
Accounts uuid and current id, `{"uuid", "id"}`.

## Event and acknowledgment flow

1. Hook verifies the provider's signature, then stores the original request and
   the exact outgoing Ting request in one transaction. The provider hears
   `webhook.ok` only after the commit.
2. The publisher sends each queued notification with a fresh proof, retrying with
   the same bytes and the same producer key
   (`hook:{event id}:{sha256(recipient uuid)}`) until Ting confirms it stored the
   send. An uncertain result never creates a second notification.
3. Ting receives the compact `new_event` envelope: the provider name and a
   reference (event id, `silicon: {uuid, id}`, hook id, original sequence and
   time, and a summary with the provider and receipt time in the hook's IANA time
   zone). Provider bodies and headers stay in Hook.
4. The receiving app fetches `GET /api/v3/silicons/{silicon uuid}/events/{event id}`
   with the recipient's own Hook token. Failed access checks and expired events
   must not become application work.
5. The app durably accepts and deduplicates the event before acknowledging Ting's
   local batch. Ting may replay or reorder; deduplicate on the event id.

Hook keeps events 14 days, even if Ting keeps the reference longer.

## Recipients

- **The Silicon** receives its own events. Its sends use Ting's required
  (automation) mode, which the Silicon opts into through its own app; until then
  they stay pending with `required_delivery_not_enabled`. Hook never downgrades
  the mode.
- **Carbons** with `view` (or more) on a Silicon, and its custodian, can subscribe
  to copies of its future events: `POST /api/v3/silicons/{silicon}/delivery/subscription`
  (`hook receiving subscribe`). Copies use ordinary delivery and follow the
  Carbon's notification preferences. Hook checks the Carbon's access again before
  every send, and drops the subscription when access ends (grant revoked,
  custodian changed, Hook's access removed, account deleted). At most 100
  observers per Silicon.

Enrolment (`POST /api/v3/delivery/recipient`, `hook receiving register`) grants
Hook's notifications to the caller in Ting. Attaching a destination is done in
Ting by the receiving app; Hook never stores the receiving URL.

## Publication status

`GET /api/v3/silicons/{silicon}/events/{event}/publication` reports
`delivery_disabled`, `not_queued`, `pending` (with `last_error_code`),
`accepted_by_ting`, `accepted_silently` (ordinary send while muted) or
`not_delivered_legacy`, plus `delivery`, `silent`, attempts and, when available,
Ting's receipt with per-destination delivery and read acknowledgments. A receipt
means a destination accepted the event, never that the Silicon finished its
work.

## From Hook before 1.0

Sends queued before 1.0 that Ting never accepted cannot be signed with Silicon
Accounts proofs; migration `0019` marks them `legacy_identity` and publication
shows `not_delivered_legacy` until the event expires. Earlier Carbon
subscriptions are not carried over: Carbons subscribe again. The publisher setup
and the separate Ting approval of earlier versions are gone.
