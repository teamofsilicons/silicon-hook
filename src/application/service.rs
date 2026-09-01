//! Hook management, ingress, history, and provisioning workflows.

use std::{collections::BTreeMap, sync::Arc};

use serde::Serialize;
use time::OffsetDateTime;

use super::{
    AcceptEventCommand, ApplicationError, Clock, CreateHookCommand, DeleteHookCommand, EventPage,
    HookMutationCommand, HookWithSecret, ListEventsCommand, ProvisionIamHookCommand,
    SetHooksEnabledCommand,
};
use crate::{
    dm_contract::DmRequestBodyError,
    domain::{
        Action, AuthorizationContext, AuthorizationDecision, EndpointKey, EventCursorScope,
        EventEnvelopeInput, EventFilter, EventId, EventRecord, EventType, Hook, HookDescription,
        HookId, HookName, HookStatus, NewHook, RequestDigest, SigningSecret, TraceId, authorize,
    },
    infrastructure::{
        crypto::{CursorCodec, SecretCipher, WebhookSignatureVerifier},
        postgres::{
            AuditContext, BatchHookActivation, CreateHook, CreateHookOutcome, EventPageRequest,
            HookMutation, IdempotencyScope, IngressAcceptance, NewEvent, PersistedResponse,
            PostgresStore, RestoreHook, RestoreHookOutcome, RotateSecret, RotateSecretOutcome,
            SECRET_REPLAY_WINDOW, StoreError,
        },
    },
};

const ENDPOINT_GENERATION_ATTEMPTS: usize = 16;
const MAX_HOOK_ACTIVATION_BATCH_SIZE: usize = 1_000;
const IAM_HOOK_NAME: &str = "Silicon IAM";
const IAM_HOOK_DESCRIPTION: &str = "Default Silicon IAM event hook";

/// Coordinates validated domain behavior with durable persistence.
#[derive(Clone)]
pub struct HookApplication {
    store: PostgresStore,
    secret_cipher: Arc<SecretCipher>,
    cursor_codec: Arc<CursorCodec>,
    signature_verifier: WebhookSignatureVerifier,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for HookApplication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HookApplication")
            .field("store", &self.store)
            .field("secret_cipher", &"[REDACTED]")
            .field("cursor_codec", &"[REDACTED]")
            .field("signature_verifier", &self.signature_verifier)
            .finish_non_exhaustive()
    }
}

impl HookApplication {
    /// Composes the application from its durable, cryptographic, and time boundaries.
    #[must_use]
    pub fn new(
        store: PostgresStore,
        secret_cipher: Arc<SecretCipher>,
        cursor_codec: Arc<CursorCodec>,
        signature_verifier: WebhookSignatureVerifier,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            secret_cipher,
            cursor_codec,
            signature_verifier,
            clock,
        }
    }

    /// Exposes the store for readiness without leaking it into handlers.
    #[must_use]
    pub const fn store(&self) -> &PostgresStore {
        &self.store
    }

    /// Lists hooks inside an IAM-authorized organization and Silicon scope.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, persistence, or invariant failure.
    pub async fn list_hooks(
        &self,
        authorization: &AuthorizationContext,
        silicon_id: &crate::domain::SiliconId,
        include_deleted: bool,
    ) -> Result<Vec<Hook>, ApplicationError> {
        authorize_action(authorization, Action::ListHooks, silicon_id, None)?;
        let retained_at = database_time(self.clock.now())?;
        self.store
            .list_hooks(
                authorization.organization_id(),
                silicon_id,
                include_deleted,
                retained_at,
            )
            .await
            .map_err(map_store_error)
    }

    /// Gets one hook inside an IAM-authorized tenant scope.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, not-found, persistence, or invariant failure.
    pub async fn get_hook(
        &self,
        authorization: &AuthorizationContext,
        silicon_id: &crate::domain::SiliconId,
        hook_id: HookId,
    ) -> Result<Hook, ApplicationError> {
        authorize_action(authorization, Action::ReadHook, silicon_id, None)?;
        let hook = self
            .store
            .get_hook(authorization.organization_id(), silicon_id, hook_id)
            .await
            .map_err(map_store_error)?
            .ok_or(ApplicationError::NotFound)?;
        let now = database_time(self.clock.now())?;
        if !hook.is_retained_at(now) {
            return Err(ApplicationError::NotFound);
        }
        Ok(hook)
    }

    /// Creates a normal hook and returns its signing secret once.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, idempotency, persistence, or cryptographic failure.
    pub async fn create_hook(
        &self,
        command: CreateHookCommand,
    ) -> Result<HookWithSecret, ApplicationError> {
        authorize_action(
            &command.context.authorization,
            Action::CreateHook,
            &command.silicon_id,
            None,
        )?;
        let request_digest =
            create_hook_request_digest(&command.name, command.description.as_ref())?;
        self.create_hook_inner(CreateHookParts {
            organization_id: command.context.authorization.organization_id().clone(),
            silicon_id: command.silicon_id,
            name: command.name,
            description: command.description,
            actor: command.context.authorization.actor().clone(),
            acting_application: command.context.authorization.acting_application().cloned(),
            idempotency_key: command.context.idempotency_key,
            request_digest,
            request_id: command.context.request_id,
            is_iam_default: false,
        })
        .await
    }

    /// Soft-deletes a hook while retaining it for recovery.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, not-found, persistence, or invariant failure.
    pub async fn delete_hook(&self, command: DeleteHookCommand) -> Result<(), ApplicationError> {
        authorize_action(
            &command.authorization,
            Action::ReadHook,
            &command.silicon_id,
            None,
        )?;
        let hook = self
            .store
            .get_hook(
                command.authorization.organization_id(),
                &command.silicon_id,
                command.hook_id,
            )
            .await
            .map_err(map_store_error)?
            .ok_or(ApplicationError::NotFound)?;
        authorize_action(
            &command.authorization,
            Action::DeleteHook,
            &command.silicon_id,
            hook.created_via_application(),
        )?;
        if hook.status() == HookStatus::Deleted {
            return Ok(());
        }

        let mutation = HookMutation {
            organization_id: command.authorization.organization_id().clone(),
            silicon_id: command.silicon_id,
            hook_id: command.hook_id,
            audit: audit_context(&command.authorization, command.request_id),
            occurred_at: database_time(self.clock.now())?,
        };
        match self.store.delete_hook(&mutation).await {
            Ok(_) | Err(StoreError::StateConflict { .. }) => Ok(()),
            Err(error) => Err(map_store_error(error)),
        }
    }

    /// Sets the desired ingress state of one or more retained hooks atomically.
    ///
    /// Repeating a request that already matches the desired state is a no-op.
    /// Deleted hooks must be restored rather than enabled, and any invalid
    /// target causes the complete batch to fail.
    ///
    /// # Errors
    ///
    /// Returns a validation, authorization, not-found, lifecycle, or
    /// persistence failure.
    pub async fn set_hooks_enabled(
        &self,
        mut command: SetHooksEnabledCommand,
    ) -> Result<Vec<Hook>, ApplicationError> {
        let requested_order = command.hook_ids.clone();
        validate_activation_hook_ids(&mut command.hook_ids)?;

        let hooks = self
            .store
            .get_hooks_by_ids(
                command.authorization.organization_id(),
                &command.silicon_id,
                &command.hook_ids,
            )
            .await
            .map_err(map_store_error)?;
        if hooks.len() != command.hook_ids.len() {
            return Err(ApplicationError::NotFound);
        }
        for hook in &hooks {
            if hook.status() == HookStatus::Deleted {
                return Err(ApplicationError::StateConflict);
            }
            authorize_action(
                &command.authorization,
                Action::SetHookEnabled,
                &command.silicon_id,
                hook.created_via_application(),
            )?;
        }

        let updated = self
            .store
            .set_hooks_enabled(&BatchHookActivation {
                organization_id: command.authorization.organization_id().clone(),
                silicon_id: command.silicon_id,
                hook_ids: command.hook_ids,
                enabled: command.enabled,
                audit: audit_context(&command.authorization, command.request_id),
                occurred_at: database_time(self.clock.now())?,
            })
            .await
            .map_err(map_store_error)?;
        let mut by_id = updated
            .into_iter()
            .map(|hook| (hook.id(), hook))
            .collect::<BTreeMap<_, _>>();
        if by_id.len() != requested_order.len() {
            return Err(ApplicationError::internal(anyhow::anyhow!(
                "activation persistence returned an incomplete hook set"
            )));
        }
        requested_order
            .into_iter()
            .map(|hook_id| {
                by_id.remove(&hook_id).ok_or_else(|| {
                    ApplicationError::internal(anyhow::anyhow!(
                        "activation persistence returned a mismatched hook set"
                    ))
                })
            })
            .collect()
    }

    /// Restores a soft-deleted hook while its recovery window remains open.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, lifecycle, idempotency, or persistence failure.
    pub async fn restore_hook(
        &self,
        command: HookMutationCommand,
    ) -> Result<Hook, ApplicationError> {
        let authorization = &command.context.authorization;
        authorize_action(authorization, Action::ReadHook, &command.silicon_id, None)?;
        let hook = self
            .store
            .get_hook(
                authorization.organization_id(),
                &command.silicon_id,
                command.hook_id,
            )
            .await
            .map_err(map_store_error)?
            .ok_or(ApplicationError::NotFound)?;
        authorize_action(
            authorization,
            Action::RestoreHook,
            &command.silicon_id,
            hook.created_via_application(),
        )?;
        let now = database_time(self.clock.now())?;
        if let Some(deleted_at) = hook.deleted_at() {
            let recovery = time::Duration::days(crate::domain::HOOK_RECOVERY_DAYS);
            if deleted_at
                .checked_add(recovery)
                .is_none_or(|deadline| now > deadline)
            {
                return Err(ApplicationError::RecoveryExpired);
            }
        }

        let persistence = RestoreHook {
            organization_id: authorization.organization_id().clone(),
            silicon_id: command.silicon_id,
            hook_id: command.hook_id,
            idempotency: idempotency_scope(
                "hook.restore",
                authorization,
                command.hook_id.to_string(),
                command.context.idempotency_key,
                empty_request_digest(),
            ),
            response: PersistedResponse {
                status: 200,
                resource_id: Some(command.hook_id),
                encrypted_secret: None,
                secret_replay_until: None,
            },
            audit: audit_context(authorization, command.context.request_id),
            occurred_at: now,
        };
        match self.store.restore_hook(&persistence).await {
            Ok(
                RestoreHookOutcome::Restored(restored)
                | RestoreHookOutcome::Replayed { hook: restored, .. },
            ) => Ok(restored),
            Err(error) => Err(map_store_error(error)),
        }
    }

    /// Replaces a hook signing secret and returns the new value once.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, lifecycle, idempotency, persistence, or crypto failure.
    pub async fn rotate_hook_secret(
        &self,
        command: HookMutationCommand,
    ) -> Result<HookWithSecret, ApplicationError> {
        let authorization = &command.context.authorization;
        authorize_action(authorization, Action::ReadHook, &command.silicon_id, None)?;
        let hook = self
            .store
            .get_hook(
                authorization.organization_id(),
                &command.silicon_id,
                command.hook_id,
            )
            .await
            .map_err(map_store_error)?
            .ok_or(ApplicationError::NotFound)?;
        authorize_action(
            authorization,
            Action::RotateSecret,
            &command.silicon_id,
            hook.created_via_application(),
        )?;

        let now = database_time(self.clock.now())?;
        let secret = SigningSecret::generate().map_err(ApplicationError::internal)?;
        let encrypted = self
            .secret_cipher
            .encrypt(command.hook_id, &secret)
            .map_err(ApplicationError::internal)?;
        let replay_until = secret_replay_until(now)?;
        let persistence = RotateSecret {
            organization_id: authorization.organization_id().clone(),
            silicon_id: command.silicon_id,
            hook_id: command.hook_id,
            encrypted_secret: encrypted.clone(),
            idempotency: idempotency_scope(
                "hook.secret.rotate",
                authorization,
                command.hook_id.to_string(),
                command.context.idempotency_key,
                empty_request_digest(),
            ),
            response: PersistedResponse {
                status: 200,
                resource_id: Some(command.hook_id),
                encrypted_secret: Some(encrypted),
                secret_replay_until: Some(replay_until),
            },
            audit: audit_context(authorization, command.context.request_id),
            occurred_at: now,
        };
        match self.store.rotate_hook_secret(&persistence).await {
            Ok(RotateSecretOutcome::Rotated(rotated)) => Ok(HookWithSecret {
                hook: rotated,
                signing_secret: secret,
            }),
            Ok(RotateSecretOutcome::Replayed { hook, response }) => {
                self.secret_result_from_replay(hook, response)
            }
            Err(error) => Err(map_store_error(error)),
        }
    }

    /// Provisions IAM's unique default hook after service authentication.
    ///
    /// # Errors
    ///
    /// Returns a service-authorization, uniqueness, idempotency, persistence, or crypto failure.
    pub async fn provision_iam_hook(
        &self,
        command: ProvisionIamHookCommand,
    ) -> Result<HookWithSecret, ApplicationError> {
        if !command.actor.is_service_named("silicon-iam") {
            return Err(ApplicationError::Forbidden);
        }
        let request_digest =
            provision_iam_request_digest(&command.organization_id, &command.silicon_id)?;
        self.create_hook_inner(CreateHookParts {
            organization_id: command.organization_id,
            silicon_id: command.silicon_id,
            name: HookName::new(IAM_HOOK_NAME).map_err(|_| ApplicationError::Validation {
                field: "iam_hook_name",
            })?,
            description: HookDescription::optional(Some(IAM_HOOK_DESCRIPTION.to_owned())).map_err(
                |_| ApplicationError::Validation {
                    field: "iam_hook_description",
                },
            )?,
            actor: command.actor,
            acting_application: None,
            idempotency_key: command.idempotency_key,
            request_digest,
            request_id: command.request_id,
            is_iam_default: true,
        })
        .await
    }

    /// Authenticates and durably accepts a public webhook event.
    ///
    /// # Errors
    ///
    /// Returns a not-found, signature, validation, idempotency, persistence, or crypto failure.
    pub async fn accept_event(
        &self,
        command: AcceptEventCommand,
    ) -> Result<EventId, ApplicationError> {
        let resolution = self
            .store
            .find_active_hook_by_endpoint(&command.silicon_id, &command.endpoint_key)
            .await
            .map_err(map_store_error)?
            .ok_or(ApplicationError::NotFound)?;
        let hook = resolution.hook;
        let expected_encrypted_secret = hook.encrypted_signing_secret().clone();
        let secret = self
            .secret_cipher
            .decrypt(hook.id(), hook.encrypted_signing_secret())
            .map_err(ApplicationError::internal)?;
        let now = database_time(resolution.database_time)?;
        self.signature_verifier
            .verify(
                &secret,
                &command.timestamp,
                &command.body,
                &command.signature,
                now,
            )
            .map_err(|_| ApplicationError::InvalidSignature)?;
        let input: EventEnvelopeInput =
            serde_json::from_slice(&command.body).map_err(|error| match error.classify() {
                serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                    ApplicationError::MalformedJson
                }
                serde_json::error::Category::Data => ApplicationError::Validation {
                    field: "event_body",
                },
                serde_json::error::Category::Io => ApplicationError::internal(error),
            })?;
        let trace_id =
            TraceId::new(command.request_id).map_err(|_| ApplicationError::Validation {
                field: "request_id",
            })?;
        let envelope =
            input
                .normalize(now, trace_id)
                .map_err(|_| ApplicationError::Validation {
                    field: "event_body",
                })?;
        let event = EventRecord::accept(
            EventId::new(),
            hook.organization_id().clone(),
            command.silicon_id,
            hook.id(),
            envelope,
            RequestDigest::sha256(&command.body),
            now,
        );
        let authenticated_request_digest =
            authenticated_ingress_digest(&command.timestamp, &command.body);
        let new_event = NewEvent::new(
            event,
            expected_encrypted_secret,
            authenticated_request_digest,
            command.idempotency_key,
        )
        .map_err(|error| match error {
            DmRequestBodyError::PayloadTooLarge { .. }
            | DmRequestBodyError::RequestTooLarge { .. } => ApplicationError::PayloadTooLarge,
            DmRequestBodyError::Serialization(_) => ApplicationError::internal(error),
        })?;
        match self.store.accept_event(&new_event).await {
            Ok(
                IngressAcceptance::Accepted { event_id } | IngressAcceptance::Replayed { event_id },
            ) => Ok(event_id),
            Err(StoreError::SecretSuperseded) => Err(ApplicationError::InvalidSignature),
            Err(error) => Err(map_store_error(error)),
        }
    }

    /// Lists retained events under a filter-bound authenticated cursor.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, validation, persistence, or cursor failure.
    pub async fn list_events(
        &self,
        command: ListEventsCommand,
    ) -> Result<EventPage, ApplicationError> {
        authorize_action(
            &command.authorization,
            Action::ReadEvents,
            &command.silicon_id,
            None,
        )?;
        if command.limit == 0 || command.limit > 10_000 {
            return Err(ApplicationError::Validation { field: "limit" });
        }
        let event_type = command
            .event_type
            .map(EventType::new)
            .transpose()
            .map_err(|_| ApplicationError::Validation {
                field: "event_type",
            })?;
        let filter = EventFilter::new(command.hook_id, event_type);
        let scope = EventCursorScope::new(
            command.authorization.organization_id().clone(),
            command.silicon_id.clone(),
            filter.clone(),
        );
        let cursor = command
            .cursor
            .as_deref()
            .map(|encoded| self.cursor_codec.decode(&scope, encoded))
            .transpose()
            .map_err(|_| ApplicationError::Validation { field: "cursor" })?;
        let page = self
            .store
            .list_events(&EventPageRequest {
                organization_id: command.authorization.organization_id().clone(),
                silicon_id: command.silicon_id,
                filter,
                cursor,
                limit: command.limit,
            })
            .await
            .map_err(map_store_error)?;
        let next_cursor = page
            .next_cursor
            .map(|boundary| self.cursor_codec.encode(&scope, boundary))
            .transpose()
            .map_err(ApplicationError::internal)?;
        Ok(EventPage {
            items: page.items,
            next_cursor,
        })
    }

    async fn create_hook_inner(
        &self,
        parts: CreateHookParts,
    ) -> Result<HookWithSecret, ApplicationError> {
        let now = database_time(self.clock.now())?;
        let replay_until = secret_replay_until(now)?;
        for _ in 0..ENDPOINT_GENERATION_ATTEMPTS {
            let hook_id = HookId::new();
            let endpoint_key = EndpointKey::generate().map_err(ApplicationError::internal)?;
            let secret = SigningSecret::generate().map_err(ApplicationError::internal)?;
            let encrypted = self
                .secret_cipher
                .encrypt(hook_id, &secret)
                .map_err(ApplicationError::internal)?;
            let hook = Hook::create(NewHook {
                id: hook_id,
                organization_id: parts.organization_id.clone(),
                silicon_id: parts.silicon_id.clone(),
                name: parts.name.clone(),
                description: parts.description.clone(),
                endpoint_key,
                created_by: parts.actor.clone(),
                created_via_application: parts.acting_application.clone(),
                created_at: now,
                encrypted_signing_secret: encrypted.clone(),
            });
            let idempotency = IdempotencyScope {
                operation: if parts.is_iam_default {
                    "hook.iam.provision"
                } else {
                    "hook.create"
                }
                .to_owned(),
                actor: parts.actor.clone(),
                calling_application_id: parts.acting_application.clone(),
                organization_id: parts.organization_id.clone(),
                target_id: parts.silicon_id.as_str().to_owned(),
                key: parts.idempotency_key.clone(),
                request_digest: *parts.request_digest.as_bytes(),
            };
            let persistence = CreateHook {
                hook,
                is_iam_default: parts.is_iam_default,
                idempotency,
                response: PersistedResponse {
                    status: 201,
                    resource_id: Some(hook_id),
                    encrypted_secret: Some(encrypted),
                    secret_replay_until: Some(replay_until),
                },
                audit: AuditContext {
                    actor: parts.actor.clone(),
                    calling_application_id: parts.acting_application.clone(),
                    request_id: parts.request_id.clone(),
                },
                recorded_at: now,
            };
            match self.store.create_hook(persistence).await {
                Ok(CreateHookOutcome::Created(created)) => {
                    return Ok(HookWithSecret {
                        hook: created,
                        signing_secret: secret,
                    });
                }
                Ok(CreateHookOutcome::Replayed { hook, response }) => {
                    return self.secret_result_from_replay(hook, response);
                }
                Err(StoreError::EndpointKeyConflict) => {}
                Err(error) => return Err(map_store_error(error)),
            }
        }
        Err(ApplicationError::internal(anyhow::anyhow!(
            "endpoint key collision budget exhausted"
        )))
    }

    fn secret_result_from_replay(
        &self,
        hook: Hook,
        response: PersistedResponse,
    ) -> Result<HookWithSecret, ApplicationError> {
        let encrypted = response.encrypted_secret.ok_or_else(|| {
            ApplicationError::internal(anyhow::anyhow!(
                "secret-bearing replay lacks encrypted secret"
            ))
        })?;
        let signing_secret = self
            .secret_cipher
            .decrypt(hook.id(), &encrypted)
            .map_err(ApplicationError::internal)?;
        Ok(HookWithSecret {
            hook,
            signing_secret,
        })
    }
}

#[derive(Clone, Debug)]
struct CreateHookParts {
    organization_id: crate::domain::OrganizationId,
    silicon_id: crate::domain::SiliconId,
    name: HookName,
    description: Option<HookDescription>,
    actor: crate::domain::ActorRef,
    acting_application: Option<crate::domain::ApplicationId>,
    idempotency_key: String,
    request_digest: RequestDigest,
    request_id: Option<String>,
    is_iam_default: bool,
}

#[derive(Serialize)]
struct CanonicalCreateHookRequest<'a> {
    name: &'a str,
    description: Option<&'a str>,
}

#[derive(Serialize)]
struct CanonicalIamProvisionRequest<'a> {
    org_id: &'a str,
    silicon_id: &'a str,
}

fn create_hook_request_digest(
    name: &HookName,
    description: Option<&HookDescription>,
) -> Result<RequestDigest, ApplicationError> {
    canonical_request_digest(&CanonicalCreateHookRequest {
        name: name.as_str(),
        description: description.map(HookDescription::as_str),
    })
}

fn provision_iam_request_digest(
    organization_id: &crate::domain::OrganizationId,
    silicon_id: &crate::domain::SiliconId,
) -> Result<RequestDigest, ApplicationError> {
    canonical_request_digest(&CanonicalIamProvisionRequest {
        org_id: organization_id.as_str(),
        silicon_id: silicon_id.as_str(),
    })
}

fn canonical_request_digest<T: Serialize>(value: &T) -> Result<RequestDigest, ApplicationError> {
    serde_json::to_vec(value)
        .map(|bytes| RequestDigest::sha256(&bytes))
        .map_err(ApplicationError::internal)
}

fn empty_request_digest() -> RequestDigest {
    RequestDigest::sha256(&[])
}

fn authenticated_ingress_digest(timestamp: &str, body: &[u8]) -> RequestDigest {
    RequestDigest::sha256_parts(&[timestamp.as_bytes(), b".", body])
}

fn validate_activation_hook_ids(hook_ids: &mut [HookId]) -> Result<(), ApplicationError> {
    if hook_ids.is_empty() || hook_ids.len() > MAX_HOOK_ACTIVATION_BATCH_SIZE {
        return Err(ApplicationError::Validation { field: "hook_ids" });
    }
    hook_ids.sort_unstable();
    if hook_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ApplicationError::Validation { field: "hook_ids" });
    }
    Ok(())
}

fn authorize_action(
    authorization: &AuthorizationContext,
    action: Action,
    silicon_id: &crate::domain::SiliconId,
    creator_application: Option<&crate::domain::ApplicationId>,
) -> Result<(), ApplicationError> {
    match authorize(authorization, action, silicon_id, creator_application) {
        AuthorizationDecision::Allowed => Ok(()),
        AuthorizationDecision::TargetNotVisible => Err(ApplicationError::NotFound),
        AuthorizationDecision::InsufficientPrivilege
        | AuthorizationDecision::ApplicationOwnershipMismatch => Err(ApplicationError::Forbidden),
    }
}

fn audit_context(authorization: &AuthorizationContext, request_id: Option<String>) -> AuditContext {
    AuditContext {
        actor: authorization.actor().clone(),
        calling_application_id: authorization.acting_application().cloned(),
        request_id,
    }
}

fn idempotency_scope(
    operation: &str,
    authorization: &AuthorizationContext,
    target_id: String,
    key: String,
    request_digest: RequestDigest,
) -> IdempotencyScope {
    IdempotencyScope {
        operation: operation.to_owned(),
        actor: authorization.actor().clone(),
        calling_application_id: authorization.acting_application().cloned(),
        organization_id: authorization.organization_id().clone(),
        target_id,
        key,
        request_digest: *request_digest.as_bytes(),
    }
}

fn secret_replay_until(now: OffsetDateTime) -> Result<OffsetDateTime, ApplicationError> {
    now.checked_add(SECRET_REPLAY_WINDOW).ok_or_else(|| {
        ApplicationError::internal(anyhow::anyhow!("secret replay deadline overflow"))
    })
}

fn database_time(value: OffsetDateTime) -> Result<OffsetDateTime, ApplicationError> {
    let nanosecond = value.nanosecond() / 1_000 * 1_000;
    value.replace_nanosecond(nanosecond).map_err(|error| {
        ApplicationError::internal(anyhow::anyhow!(
            "failed to normalize an authoritative timestamp: {error}"
        ))
    })
}

fn database_is_unavailable(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed => true,
        sqlx::Error::Database(database) => database.code().is_some_and(|code| {
            code.starts_with("08")
                || code.starts_with("53")
                || matches!(code.as_ref(), "57014" | "57P01" | "57P02" | "57P03")
        }),
        _ => false,
    }
}

fn map_store_error(error: StoreError) -> ApplicationError {
    match error {
        StoreError::NotFound { .. } => ApplicationError::NotFound,
        StoreError::StateConflict { .. } => ApplicationError::StateConflict,
        StoreError::IdempotencyConflict => ApplicationError::IdempotencyConflict,
        StoreError::SecretReplayExpired | StoreError::SecretSuperseded => {
            ApplicationError::SecretUnavailable
        }
        StoreError::IamDefaultExists => ApplicationError::IamHookAlreadyExists,
        StoreError::HookLimitReached => ApplicationError::HookLimitReached,
        StoreError::InvalidArgument { field, .. } => ApplicationError::Validation { field },
        StoreError::Database(source) if database_is_unavailable(&source) => {
            ApplicationError::unavailable(source)
        }
        StoreError::Database(source) => ApplicationError::internal(source),
        StoreError::Migration(_)
        | StoreError::SchemaNotReady { .. }
        | StoreError::CorruptData { .. }
        | StoreError::LeaseLost
        | StoreError::EndpointKeyConflict
        | StoreError::NumericRange { .. } => ApplicationError::internal(error),
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::{
        authenticated_ingress_digest, create_hook_request_digest, database_is_unavailable,
        database_time, validate_activation_hook_ids,
    };
    use crate::domain::{HookDescription, HookId, HookName};

    #[test]
    fn authoritative_timestamps_match_postgres_precision() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(
            database_time(datetime!(2026-08-31 12:00:00.123456789 UTC))?,
            datetime!(2026-08-31 12:00:00.123456 UTC)
        );
        Ok(())
    }

    #[test]
    fn only_transient_database_failures_are_unavailable() {
        assert!(database_is_unavailable(&sqlx::Error::PoolTimedOut));
        assert!(database_is_unavailable(&sqlx::Error::PoolClosed));
        assert!(!database_is_unavailable(&sqlx::Error::RowNotFound));
        assert!(!database_is_unavailable(&sqlx::Error::ColumnNotFound(
            "missing".to_owned()
        )));
    }

    #[test]
    fn authenticated_ingress_digest_hashes_timestamp_period_and_exact_body() {
        let digest = authenticated_ingress_digest(
            "1700000000",
            br#"{"type":"example.created","payload":{"ok":true}}"#,
        );

        assert_eq!(
            hex::encode(digest.as_bytes()),
            "8edaf142ac722308fe70e68d70205f261828ab307102c6cf79d6f3bf7538f24c"
        );
    }

    #[test]
    fn management_digest_is_derived_from_validated_semantics()
    -> Result<(), Box<dyn std::error::Error>> {
        let name = HookName::new("GitHub")?;
        let description = HookDescription::optional(Some("Delivery hook".to_owned()))?;

        let first = create_hook_request_digest(&name, description.as_ref())?;
        let second = create_hook_request_digest(&name, description.as_ref())?;
        let changed = create_hook_request_digest(&HookName::new("GitLab")?, description.as_ref())?;

        assert_eq!(first, second);
        assert_ne!(first, changed);
        assert_eq!(
            create_hook_request_digest(&name, None)?,
            create_hook_request_digest(
                &name,
                HookDescription::optional(Some(String::new()))?.as_ref()
            )?
        );
        assert_eq!(
            first,
            create_hook_request_digest(
                &HookName::new("  GitHub  ")?,
                HookDescription::optional(Some("  Delivery hook  ".to_owned()))?.as_ref()
            )?
        );
        Ok(())
    }

    #[test]
    fn activation_batches_are_non_empty_unique_bounded_and_sorted() {
        let first = HookId::new();
        let second = HookId::new();
        let mut valid = vec![second, first];
        let mut expected = valid.clone();
        expected.sort_unstable();
        assert!(validate_activation_hook_ids(&mut valid).is_ok());
        assert_eq!(valid, expected);

        assert!(validate_activation_hook_ids(&mut Vec::new()).is_err());
        assert!(validate_activation_hook_ids(&mut [first, first]).is_err());
        assert!(validate_activation_hook_ids(&mut vec![HookId::new(); 1_001]).is_err());
    }
}
