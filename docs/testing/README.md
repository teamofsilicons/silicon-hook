# Testing environments

A Hook environment is an empty sandbox owned by a production organization,
with the requesting Carbon or Silicon recorded as its creator. It binds to one
existing IAM testing environment. Hook tests always use test IAM; production
IAM is never a fallback for missing test identities or application credentials.

| Credential | Selects or authorizes |
|---|---|
| Production Hook/IAM identity | Creates environments and performs creator/admin lifecycle operations |
| IAM testing key | Selects the IAM sandbox for every outbound IAM request |
| Test IAM application secret | Authenticates Hook's application inside that IAM sandbox |
| Hook testing key | Selects the Hook sandbox; authorizes root operations |
| Test IAM actor token | Supplies the actor and ordinary permissions inside the Hook sandbox |
| Local relay token | Selects one CLI profile/environment at hook.localhost |

The Hook key is exactly 32 alphanumeric characters. It is stored encrypted and
is retrievable by the creator or owning organization's administrator/owner.
Keep it private. Anyone possessing it can inspect root metadata, configure the
test IAM application and clear the environment. Ordinary hook operations also
use a signed-in actor from the linked IAM test environment, preserving actual
production permission behavior for meaningful tests.

## Bootstrap order

1. Create an IAM testing environment and keep its key.
2. Create/import the Hook application inside that IAM environment. Keep the
   returned test application secret and configured webhook signing secret.
3. Sign in to Hook with a production identity in the organization that will own
   the Hook environment.
4. Create a Hook environment with name, optional description and IAM test key.
   Test application configuration may be supplied here or installed afterward.
5. Keep the returned Hook environment UUID and root key. A new environment has
   no hooks, history, blocked records or delivery positions.
6. Sign in through IAM inside that test world, mint a Hook application SLT,
   and exchange it with the Hook key attached.
7. Use ordinary Hook operations in the selected sandbox.

One IAM world may be linked to only one Hook environment, making incoming IAM
test webhook routing unambiguous. To create another Hook sandbox, create another
IAM testing environment. Cleaning Hook does not clean IAM or recreate actors.

## URLs and isolation

Production ingress: `/silicon/{silicon_id}/{8-uppercase-alphanumeric}`.
Test ingress: `/test/silicon/{silicon_id}/{8-uppercase-alphanumeric}`.
The public URL contains neither a root key nor an environment UUID. A durable
routing ledger maps the public URL to exactly one environment. Providers do
not attach the root key. Hook's ordinary API v1 routes use `X-Hook-Test-Key`.

Runtime storage uses a shared test database separate from production. Each
connection is pinned to one environment and generation. PostgreSQL row-level
policies scope hooks, history, blocks, idempotency, retired keys and delivery
state. Rotation/reset/deletion changes generation so old connections cannot
continue using stale authority. URL tombstones survive reset so an old provider
URL cannot accidentally become a new hook's URL in a reused test environment.

The 10-hook limit is per entire test environment, across all its Silicons.
Soft-deleted hooks still count until permanently purged or the environment is
cleaned. This limit applies only to testing.

## Lifecycle

| Action | Authority | Effect |
|---|---|---|
| Read metadata/list | Production identity in owning organization | Public environment metadata, no key |
| Retrieve key | Creator or owning-org admin/owner | Current root key |
| Rotate key | Creator or owning-org admin/owner | New key; old key and scoped sessions invalidated |
| Clean | Current Hook root key | Erases Hook data; retains environment, key, IAM binding and URL tombstones |
| Delete | Creator or owning-org admin/owner | Disables key/ingress/streams; contents remain recoverable |
| Restore | Creator or owning-org admin/owner | Recovers within 30 days; retained key works again |
| Inactivity cleanup | Worker | Soft-deletes after 15 days without activity |
| Permanent purge | Worker | Erases an environment after 30 days deleted |

Retries of lifecycle mutations use Idempotency-Key and are retained for 24
hours. Repeating a reset with the same key does not erase events created after
the original reset. Reusing that key with different content/action is a
conflict. The mutation ledger is control metadata and survives environment
cleaning; it is removed with permanent environment deletion.

Guides: [API](api.md), [Rust client](client.md), [CLI](cli.md).
