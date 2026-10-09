-- Silicon Accounts identity (Hook API v3).
--
-- Additive only: every IAM-era column, row and table is kept as it is. Accounts
-- uuids (short, case-sensitive text such as `zQo`, never RFC 4122 UUIDs) go into
-- new columns next to the IAM-era ones. Rows created from now on also store the
-- uuid in the legacy key columns (silicon_id, created_by_id, actor_id), so an
-- IAM public id (`si:...`/`c:...`, always with a colon) can only appear in rows
-- written before this migration. The operator command
-- `hook-migrate link-identities` fills the new uuid columns of those rows from a
-- reviewed mapping file; re-running it with another mapping overwrites them.
-- The organization column is no longer read: new rows get the constant
-- 'accounts' and child rows copy their parent's value.

-- ---------------------------------------------------------------------------
-- Endpoint keys become globally unique; ingress routes by key.
-- ---------------------------------------------------------------------------

DO $migration$
DECLARE duplicates text;
BEGIN
    SELECT string_agg(endpoint_key, ', ' ORDER BY endpoint_key) INTO duplicates
    FROM (
        SELECT endpoint_key FROM (
            SELECT environment_id, endpoint_key FROM hook.hooks
            UNION ALL
            SELECT environment_id, endpoint_key FROM hook_private.retired_endpoint_keys
        ) AS keys
        GROUP BY environment_id, endpoint_key
        HAVING count(*) > 1
    ) AS repeated;
    IF duplicates IS NOT NULL THEN
        RAISE EXCEPTION 'endpoint keys are used more than once (live or retired): %', duplicates
            USING ERRCODE = '23505',
                  HINT = 'Rotate the endpoint of one of the hooks that share each key before migrating.';
    END IF;
END;
$migration$;

CREATE UNIQUE INDEX hooks_endpoint_key_global
    ON hook.hooks (environment_id, endpoint_key);
CREATE UNIQUE INDEX retired_endpoint_keys_global
    ON hook_private.retired_endpoint_keys (environment_id, endpoint_key);

-- ---------------------------------------------------------------------------
-- Accounts identity columns next to the IAM-era ones.
-- ---------------------------------------------------------------------------

ALTER TABLE hook.hooks
    ADD COLUMN silicon_uuid text,
    ADD COLUMN created_by_uuid text,
    ADD COLUMN is_accounts_default boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT hooks_silicon_uuid_format CHECK (
        silicon_uuid IS NULL OR silicon_uuid ~ '^[A-Za-z0-9]{1,64}$'
    ),
    ADD CONSTRAINT hooks_created_by_uuid_format CHECK (
        created_by_uuid IS NULL OR created_by_uuid ~ '^[A-Za-z0-9]{1,64}$'
    );
ALTER TABLE hook.hooks ALTER COLUMN org_id SET DEFAULT 'accounts';
CREATE INDEX hooks_by_silicon_uuid
    ON hook.hooks (silicon_uuid, created_at DESC, id DESC)
    WHERE silicon_uuid IS NOT NULL;
-- One "Silicon Accounts updates" hook per Silicon, in any lifecycle state.
CREATE UNIQUE INDEX hooks_one_accounts_default_per_silicon
    ON hook.hooks (environment_id, silicon_uuid)
    WHERE is_accounts_default;
COMMENT ON COLUMN hook.hooks.silicon_id IS
    'Namespace key the hook was created under: the IAM-era public id for hooks created before Silicon Accounts, the owning Silicon''s Accounts uuid afterwards. Ingress accepts it in the URL forever.';
COMMENT ON COLUMN hook.hooks.silicon_uuid IS
    'Owning Silicon''s Silicon Accounts uuid; NULL for an IAM-era hook until link-identities maps it.';

ALTER TABLE hook.events
    ADD COLUMN silicon_uuid text,
    ADD CONSTRAINT events_silicon_uuid_format CHECK (
        silicon_uuid IS NULL OR silicon_uuid ~ '^[A-Za-z0-9]{1,64}$'
    );
CREATE INDEX events_per_account_history
    ON hook.events (silicon_uuid, received_at DESC, id DESC)
    WHERE silicon_uuid IS NOT NULL;

ALTER TABLE hook.blocked_requests
    ADD COLUMN silicon_uuid text,
    ADD CONSTRAINT blocked_requests_silicon_uuid_format CHECK (
        silicon_uuid IS NULL OR silicon_uuid ~ '^[A-Za-z0-9]{1,64}$'
    );
CREATE INDEX blocked_requests_per_account_history
    ON hook.blocked_requests (silicon_uuid, received_at DESC, id DESC)
    WHERE silicon_uuid IS NOT NULL;

ALTER TABLE hook_private.retired_endpoint_keys
    ADD COLUMN silicon_uuid text,
    ADD CONSTRAINT retired_endpoint_keys_silicon_uuid_format CHECK (
        silicon_uuid IS NULL OR silicon_uuid ~ '^[A-Za-z0-9]{1,64}$'
    );

ALTER TABLE hook_private.management_idempotency ALTER COLUMN org_id SET DEFAULT 'accounts';

ALTER TABLE hook_private.audit_log
    ADD COLUMN silicon_uuid text,
    ADD COLUMN actor_uuid text,
    ADD CONSTRAINT audit_log_silicon_uuid_format CHECK (
        silicon_uuid IS NULL OR silicon_uuid ~ '^[A-Za-z0-9]{1,64}$'
    ),
    ADD CONSTRAINT audit_log_actor_uuid_format CHECK (
        actor_uuid IS NULL OR actor_uuid ~ '^[A-Za-z0-9]{1,64}$'
    );
ALTER TABLE hook_private.audit_log ALTER COLUMN org_id SET DEFAULT 'accounts';
ALTER TABLE hook_private.audit_log DROP CONSTRAINT audit_log_action;
ALTER TABLE hook_private.audit_log ADD CONSTRAINT audit_log_action CHECK (
    action IN (
        'hook.created',
        'hook.updated',
        'hook.disabled',
        'hook.enabled',
        'hook.deleted',
        'hook.restored',
        'hook.secret_rotated',
        'hook.endpoint_rotated',
        'hook.iam_connected',
        'hook.accounts_connected',
        'access.granted',
        'access.revoked',
        'allow_list.added',
        'allow_list.removed',
        'account.deleted'
    )
);
CREATE INDEX audit_log_by_silicon_uuid
    ON hook_private.audit_log (silicon_uuid, occurred_at DESC, id DESC)
    WHERE silicon_uuid IS NOT NULL;

-- ---------------------------------------------------------------------------
-- What Hook knows about Silicon Accounts accounts.
-- ---------------------------------------------------------------------------

CREATE TABLE hook_private.accounts (
    uuid text PRIMARY KEY,
    -- NULL until Hook meets the account: a sign-out or deletion can arrive
    -- before the account ever used Hook, and must still apply to its tokens.
    kind text,
    -- Current public id (`c:...`/`si:...`); NULL once the account is deleted.
    public_id text,
    -- When public_id became current (token iat, lookup time or event time).
    public_id_at timestamptz,
    display_name text,
    pfp_url text,
    -- A Silicon's custodian (always a Carbon).
    custodian_uuid text,
    -- When the custodian was last confirmed (lookup, sign-in or webhook).
    custodian_checked_at timestamptz,
    -- occurred_at of the last applied silicon.custodian_changed.
    custodian_changed_at timestamptz,
    -- account.updated version last applied.
    profile_version bigint NOT NULL DEFAULT 0,
    -- Tokens issued before this instant are refused (sign-out, access removal).
    revoked_before timestamptz,
    deleted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT accounts_uuid_format CHECK (uuid ~ '^[A-Za-z0-9]{1,64}$'),
    CONSTRAINT accounts_kind CHECK (kind IN ('carbon', 'silicon')),
    CONSTRAINT accounts_public_id_format CHECK (
        public_id IS NULL OR (
            char_length(public_id) BETWEEN 3 AND 255 AND public_id ~ '^(c|si):[!-~]+$'
        )
    ),
    CONSTRAINT accounts_display_name_length CHECK (
        display_name IS NULL OR char_length(display_name) <= 200
    ),
    CONSTRAINT accounts_pfp_url_length CHECK (pfp_url IS NULL OR char_length(pfp_url) <= 2048),
    CONSTRAINT accounts_custodian_format CHECK (
        custodian_uuid IS NULL OR custodian_uuid ~ '^[A-Za-z0-9]{1,64}$'
    ),
    CONSTRAINT accounts_only_silicons_have_custodians CHECK (
        kind = 'silicon' OR custodian_uuid IS NULL
    ),
    CONSTRAINT accounts_profile_version_nonnegative CHECK (profile_version >= 0)
);
-- Not unique: a stale row may still name an id another account has taken since.
CREATE INDEX accounts_by_public_id ON hook_private.accounts (public_id)
    WHERE public_id IS NOT NULL;
CREATE INDEX accounts_by_custodian ON hook_private.accounts (custodian_uuid)
    WHERE custodian_uuid IS NOT NULL;
COMMENT ON TABLE hook_private.accounts IS
    'Silicon Accounts identities seen by Hook, keyed by uuid; filled from verified tokens, lookups and the Accounts webhook.';

-- Every public id Hook has seen an account use. Ingress accepts any of them in
-- a URL whose key belongs to that account's hook, so renames never break URLs.
CREATE TABLE hook_private.account_ids (
    account_uuid text NOT NULL REFERENCES hook_private.accounts (uuid) ON DELETE CASCADE,
    public_id text NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (account_uuid, public_id),
    CONSTRAINT account_ids_public_id_format CHECK (
        char_length(public_id) BETWEEN 3 AND 255 AND public_id ~ '^(c|si):[!-~]+$'
    )
);
CREATE INDEX account_ids_by_public_id ON hook_private.account_ids (public_id);

-- Explicit access to one Silicon's hooks.
CREATE TABLE hook_private.silicon_grants (
    silicon_uuid text NOT NULL,
    grantee_uuid text NOT NULL,
    level text NOT NULL,
    granted_by_uuid text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (silicon_uuid, grantee_uuid),
    CONSTRAINT silicon_grants_level CHECK (level IN ('view', 'manage')),
    CONSTRAINT silicon_grants_not_self CHECK (silicon_uuid <> grantee_uuid),
    CONSTRAINT silicon_grants_uuid_format CHECK (
        silicon_uuid ~ '^[A-Za-z0-9]{1,64}$'
        AND grantee_uuid ~ '^[A-Za-z0-9]{1,64}$'
        AND granted_by_uuid ~ '^[A-Za-z0-9]{1,64}$'
    )
);
CREATE INDEX silicon_grants_by_grantee ON hook_private.silicon_grants (grantee_uuid);

-- Accounts outside a Silicon's circle that may share hooks with it.
CREATE TABLE hook_private.silicon_allowances (
    silicon_uuid text NOT NULL,
    allowed_uuid text NOT NULL,
    added_by_uuid text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (silicon_uuid, allowed_uuid),
    CONSTRAINT silicon_allowances_not_self CHECK (silicon_uuid <> allowed_uuid),
    CONSTRAINT silicon_allowances_uuid_format CHECK (
        silicon_uuid ~ '^[A-Za-z0-9]{1,64}$'
        AND allowed_uuid ~ '^[A-Za-z0-9]{1,64}$'
        AND added_by_uuid ~ '^[A-Za-z0-9]{1,64}$'
    )
);

-- Accounts webhook deliveries already applied (retries and replays reuse event_id).
CREATE TABLE hook_private.accounts_events (
    event_id text PRIMARY KEY,
    event_type text NOT NULL,
    account_uuid text,
    occurred_at timestamptz,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accounts_events_id_length CHECK (char_length(event_id) BETWEEN 1 AND 200),
    CONSTRAINT accounts_events_type_length CHECK (char_length(event_type) BETWEEN 1 AND 100)
);
CREATE INDEX accounts_events_retention ON hook_private.accounts_events (received_at);

-- ---------------------------------------------------------------------------
-- Delivery through Ting in the Accounts era.
-- ---------------------------------------------------------------------------

-- A Carbon's request to receive copies of a Silicon's future events. Replaces
-- the IAM-era ting_recipient_bindings, which stay in place and unused.
CREATE TABLE hook_private.observer_subscriptions (
    id uuid PRIMARY KEY,
    silicon_uuid text NOT NULL,
    recipient_uuid text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT observer_subscriptions_unique UNIQUE (silicon_uuid, recipient_uuid),
    CONSTRAINT observer_subscriptions_not_self CHECK (silicon_uuid <> recipient_uuid),
    CONSTRAINT observer_subscriptions_uuid_format CHECK (
        silicon_uuid ~ '^[A-Za-z0-9]{1,64}$' AND recipient_uuid ~ '^[A-Za-z0-9]{1,64}$'
    )
);

ALTER TABLE hook_private.ting_outbox
    ADD COLUMN observer_subscription_id uuid
        REFERENCES hook_private.observer_subscriptions (id) ON DELETE CASCADE;
CREATE INDEX ting_outbox_by_observer ON hook_private.ting_outbox (observer_subscription_id)
    WHERE observer_subscription_id IS NOT NULL;

ALTER TABLE hook_private.ting_outbox DROP CONSTRAINT ting_outbox_error_safe;
ALTER TABLE hook_private.ting_outbox ADD CONSTRAINT ting_outbox_error_safe CHECK (last_error_code IN (
    'authorization_unavailable', 'consent_required', 'recipient_not_registered',
    'required_delivery_not_enabled',
    'transport_unavailable', 'rate_limited', 'ting_unavailable',
    'request_rejected', 'invalid_response', 'publisher_not_configured',
    'publisher_unavailable', 'publisher_unauthorized', 'ting_unauthorized',
    'type_not_registered', 'idempotency_conflict', 'environment_changed',
    'observer_authority_refresh_required', 'observer_authorization_unavailable',
    'legacy_identity', 'proof_unavailable'
));

-- Sends queued under Silicon IAM that Ting never accepted cannot be signed with
-- Silicon Accounts proofs. They stay as a record, parked until their event
-- expires, and publication status reports them as not delivered.
UPDATE hook_private.ting_outbox
SET next_attempt_at = expires_at,
    last_error_code = 'legacy_identity',
    lease_id = NULL,
    lease_until = NULL
WHERE accepted_at IS NULL;

-- ---------------------------------------------------------------------------
-- IAM-era identities and their Silicon Accounts links.
-- ---------------------------------------------------------------------------

CREATE TABLE hook_private.identity_links (
    iam_public_id text PRIMARY KEY,
    kind text NOT NULL,
    iam_principal_id text,
    accounts_uuid text,
    linked_at timestamptz,
    -- 'inventory' when this migration found the id in Hook's data,
    -- 'mapping:<sha256 of the file>' once link-identities applied a mapping.
    source text NOT NULL,
    -- Whether Hook's data references the id (found by this migration). Ids
    -- that only a mapping file named are false.
    in_hook_data boolean NOT NULL DEFAULT false,
    CONSTRAINT identity_links_public_id_format CHECK (
        char_length(iam_public_id) BETWEEN 3 AND 255 AND iam_public_id ~ '^(c|si):[!-~]+$'
    ),
    CONSTRAINT identity_links_kind CHECK (kind IN ('carbon', 'silicon')),
    CONSTRAINT identity_links_principal_length CHECK (
        iam_principal_id IS NULL OR char_length(iam_principal_id) BETWEEN 1 AND 255
    ),
    CONSTRAINT identity_links_uuid_format CHECK (
        accounts_uuid IS NULL OR accounts_uuid ~ '^[A-Za-z0-9]{1,64}$'
    ),
    CONSTRAINT identity_links_linked_together CHECK ((accounts_uuid IS NULL) = (linked_at IS NULL)),
    CONSTRAINT identity_links_source_length CHECK (char_length(source) BETWEEN 1 AND 100)
);
CREATE UNIQUE INDEX identity_links_one_iam_id_per_account
    ON hook_private.identity_links (accounts_uuid) WHERE accounts_uuid IS NOT NULL;
COMMENT ON TABLE hook_private.identity_links IS
    'Every IAM-era public id stored in Hook and the Silicon Accounts uuid an operator mapped it to.';

INSERT INTO hook_private.identity_links (iam_public_id, kind, source, in_hook_data)
SELECT DISTINCT id, CASE WHEN id LIKE 'si:%' THEN 'silicon' ELSE 'carbon' END, 'inventory', true
FROM (
    SELECT silicon_id AS id FROM hook.hooks
    UNION SELECT created_by_id FROM hook.hooks
    UNION SELECT silicon_id FROM hook_private.retired_endpoint_keys
    UNION SELECT silicon_id FROM hook_private.audit_log
    UNION SELECT actor_id FROM hook_private.audit_log
    UNION SELECT silicon_id FROM hook_private.ting_recipient_bindings
    UNION SELECT recipient_id FROM hook_private.ting_recipient_bindings
) AS stored
WHERE char_length(id) BETWEEN 3 AND 255 AND id ~ '^(c|si):[!-~]+$'
ON CONFLICT (iam_public_id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- API v3. v1 and v2 used Silicon IAM sign-in and end here.
-- ---------------------------------------------------------------------------

ALTER TABLE hook_private.contract_versions DROP CONSTRAINT contract_versions_major_check;
ALTER TABLE hook_private.contract_versions
    ADD CONSTRAINT contract_versions_major_check CHECK (major IN ('v1', 'v2', 'v3'));
UPDATE hook_private.contract_versions
SET status = 'sunset', sunset_at = COALESCE(sunset_at, clock_timestamp())
WHERE major IN ('v1', 'v2') AND status <> 'sunset';

CREATE OR REPLACE FUNCTION hook_private.contract_status(selected_major text, record_request boolean)
RETURNS TABLE (status text, deprecated_at timestamptz, last_requested_at timestamptz, request_count bigint, sunset_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE current_row hook_private.contract_versions%ROWTYPE;
BEGIN
    IF selected_major NOT IN ('v1', 'v2', 'v3') OR NOT hook_private.environment_is_available() THEN RETURN; END IF;
    INSERT INTO hook_private.contract_versions (environment_id, major, status, sunset_at)
        VALUES (hook_private.environment_id(), selected_major,
                CASE WHEN selected_major = 'v3' THEN 'active' ELSE 'sunset' END,
                CASE WHEN selected_major = 'v3' THEN NULL ELSE clock_timestamp() END)
        ON CONFLICT DO NOTHING;
    SELECT * INTO current_row FROM hook_private.contract_versions c
        WHERE c.environment_id = hook_private.environment_id() AND c.major = selected_major FOR UPDATE;
    IF current_row.status = 'deprecated' AND
        GREATEST(current_row.deprecated_at, current_row.last_requested_at) <= clock_timestamp() - INTERVAL '7 days' THEN
        current_row.status := 'sunset';
        current_row.sunset_at := clock_timestamp();
        UPDATE hook_private.contract_versions c SET status = 'sunset', sunset_at = current_row.sunset_at
            WHERE c.environment_id = current_row.environment_id AND c.major = selected_major;
    END IF;
    IF record_request AND current_row.status <> 'sunset' THEN
        UPDATE hook_private.contract_versions c SET last_requested_at = clock_timestamp(), request_count = c.request_count + 1
            WHERE c.environment_id = current_row.environment_id AND c.major = selected_major RETURNING * INTO current_row;
    END IF;
    RETURN QUERY SELECT current_row.status, current_row.deprecated_at, current_row.last_requested_at, current_row.request_count, current_row.sunset_at;
END $$;
REVOKE ALL ON FUNCTION hook_private.contract_status(text, boolean) FROM PUBLIC;

REVOKE ALL ON hook_private.accounts, hook_private.account_ids, hook_private.silicon_grants,
    hook_private.silicon_allowances, hook_private.accounts_events,
    hook_private.observer_subscriptions, hook_private.identity_links FROM PUBLIC;
