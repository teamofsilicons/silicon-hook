//! Hook lifecycle use cases: create, read, update, activate, delete, restore,
//! rotate secret, rotate endpoint, and connecting the Silicon's IAM hook.

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::{
    ApplicationError, BindIamHookSecretCommand, ConnectIamHookCommand, CreateHookCommand,
    DeleteHookCommand, HookApplication, HookMutationCommand, HookWithSecret,
    SetHooksEnabledCommand, SigningInput, UpdateHookCommand,
    service::{
        audit_context, authorize_action, database_time, idempotency_scope, map_store_error,
        secret_replay_until,
    },
};
use crate::{
    domain::{
        Action, ActorRef, AuthorizationContext, EndpointKey, Hook, HookDescription, HookId,
        HookName, HookStatus, HookTimeZone, HookUpdate, NewHook, OrganizationId, SigningPolicy,
        SigningSecret, SiliconId,
        signature::{Expression, SignatureAlgorithm, SignatureConfig, SignatureEncoding},
    },
    infrastructure::postgres::{
        AuditContext, BatchHookActivation, CreateHook, CreateHookOutcome, HookMutation,
        IdempotencyScope, PersistedResponse, RestoreHook, RestoreHookOutcome, RotateEndpoint,
        RotateEndpointOutcome, RotateSecret, RotateSecretOutcome, StoreError, UpdateHook,
    },
};

const ENDPOINT_GENERATION_ATTEMPTS: usize = 16;
const MAX_HOOK_ACTIVATION_BATCH_SIZE: usize = 1_000;
const IAM_HOOK_NAME: &str = "Silicon IAM";
const IAM_HOOK_DESCRIPTION: &str = "Silicon IAM events for this Silicon";
/// IAM signs `{timestamp}.{body}` with HMAC-SHA-256 over the UTF-8 bytes of the
/// `swhs_` secret and presents `v1=<lowercase hex>` in
/// `X-Silicon-IAM-Signature`; the timestamp travels in
/// `X-Silicon-IAM-Timestamp`. The verifier strips the `v1=` label itself.
const IAM_PAYLOAD_EXPRESSION: &str =
    r#"concat(request.headers["x-silicon-iam-timestamp"], ".", request.raw_body)"#;
const IAM_SIGNATURE_EXPRESSION: &str = r#"request.headers["x-silicon-iam-signature"]"#;

impl HookApplication {
    /// Lists hooks inside an IAM-authorized organization and Silicon scope.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, persistence, or invariant failure.
    pub async fn list_hooks(
        &self,
        authorization: &AuthorizationContext,
        silicon_id: &SiliconId,
        include_deleted: bool,
    ) -> Result<Vec<Hook>, ApplicationError> {
        authorize_action(authorization, Action::ListHooks, silicon_id)?;
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
        silicon_id: &SiliconId,
        hook_id: HookId,
    ) -> Result<Hook, ApplicationError> {
        authorize_action(authorization, Action::ReadHook, silicon_id)?;
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

    /// Creates a hook and returns its signing secret once.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, validation, idempotency, persistence,
    /// or cryptographic failure.
    pub async fn create_hook(
        &self,
        command: CreateHookCommand,
    ) -> Result<HookWithSecret, ApplicationError> {
        authorize_action(
            &command.context.authorization,
            Action::CreateHook,
            &command.silicon_id,
        )?;
        let signing = command.signing.resolve(&SignatureConfig::default(), true);
        validate_signing_input(&signing)?;
        let request_digest = create_hook_request_digest(
            &command.name,
            command.description.as_ref(),
            &command.time_zone,
            &signing,
        )?;
        self.create_hook_inner(CreateHookParts {
            organization_id: command.context.authorization.organization_id().clone(),
            silicon_id: command.silicon_id,
            name: command.name,
            description: command.description,
            time_zone: command.time_zone,
            signing,
            actor: command.context.authorization.actor().clone(),
            idempotency_key: command.context.idempotency_key,
            request_digest,
            request_id: command.context.request_id,
            is_iam_default: false,
        })
        .await
    }

    /// Changes metadata, activation, or signing policy of one hook.
    ///
    /// Activation and metadata changes are applied in that order; either may
    /// be omitted. Requesting the current activation state is a no-op.
    ///
    /// # Errors
    ///
    /// Returns a validation, authorization, not-found, lifecycle, or
    /// persistence failure.
    pub async fn update_hook(&self, command: UpdateHookCommand) -> Result<Hook, ApplicationError> {
        let authorization = &command.authorization;
        authorize_action(authorization, Action::ReadHook, &command.silicon_id)?;
        let existing = self
            .store
            .get_hook(
                authorization.organization_id(),
                &command.silicon_id,
                command.hook_id,
            )
            .await
            .map_err(map_store_error)?
            .ok_or(ApplicationError::NotFound)?;
        if existing.status() == HookStatus::Deleted {
            return Err(ApplicationError::StateConflict);
        }
        let signing =
            command.patch.signing.clone().map(|patch| {
                patch.resolve(&existing.signing().config, existing.signing().required)
            });
        if let Some(signing) = &signing {
            validate_signing_input(signing)?;
        }
        if command.patch.enabled.is_some() {
            authorize_action(authorization, Action::SetHookEnabled, &command.silicon_id)?;
        }
        if command.patch.changes_metadata() {
            authorize_action(authorization, Action::UpdateHook, &command.silicon_id)?;
        }

        let mut current = existing;
        if let Some(enabled) = command.patch.enabled {
            let mut updated = self
                .store
                .set_hooks_enabled(&BatchHookActivation {
                    organization_id: authorization.organization_id().clone(),
                    silicon_id: command.silicon_id.clone(),
                    hook_ids: vec![command.hook_id],
                    enabled,
                    audit: audit_context(authorization, command.request_id.clone()),
                    occurred_at: database_time(self.clock.now())?,
                })
                .await
                .map_err(map_store_error)?;
            current = updated.pop().ok_or_else(|| {
                ApplicationError::internal(anyhow::anyhow!(
                    "single-hook activation returned no hook"
                ))
            })?;
        }
        if !command.patch.changes_metadata() {
            return Ok(current);
        }
        let signing = signing
            .map(|signing| self.signing_policy(current.id(), signing, current.signing()))
            .transpose()?;
        self.store
            .update_hook(UpdateHook {
                organization_id: authorization.organization_id().clone(),
                silicon_id: command.silicon_id,
                hook_id: command.hook_id,
                update: HookUpdate {
                    name: command.patch.name,
                    description: command.patch.description,
                    time_zone: command.patch.time_zone,
                    signing,
                },
                audit: audit_context(authorization, command.request_id),
                occurred_at: database_time(self.clock.now())?,
            })
            .await
            .map_err(map_store_error)
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
        let hook = self
            .load_for_mutation(
                authorization,
                &command.silicon_id,
                command.hook_id,
                Action::RestoreHook,
            )
            .await?;
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

    /// Replaces a hook signing secret with a generated one and returns it once.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, lifecycle, idempotency, persistence, or crypto failure.
    pub async fn rotate_hook_secret(
        &self,
        command: HookMutationCommand,
    ) -> Result<HookWithSecret, ApplicationError> {
        let authorization = &command.context.authorization;
        let hook = self
            .load_for_mutation(
                authorization,
                &command.silicon_id,
                command.hook_id,
                Action::RotateSecret,
            )
            .await?;
        if hook.signing().config.algorithm.is_asymmetric() {
            return Err(ApplicationError::ValidationDetailed {
                field: "signature",
                detail: "an asymmetric signature algorithm has no shared secret to rotate"
                    .to_owned(),
            });
        }

        let secret = SigningSecret::generate().map_err(ApplicationError::internal)?;
        self.store_rotated_secret(
            command,
            secret,
            "hook.secret.rotate",
            empty_request_digest(),
        )
        .await
    }

    /// Finds the Silicon's IAM hook or creates it, restoring a soft-deleted
    /// one, so the caller can register its endpoint with IAM.
    ///
    /// The hook verifies IAM's own signing convention. Until
    /// [`Self::bind_iam_hook_secret`] stores the secret IAM issued, a freshly
    /// created hook carries a placeholder secret that verifies nothing.
    ///
    /// # Errors
    ///
    /// Returns an authorization, recovery, idempotency, or persistence failure.
    pub async fn prepare_iam_hook(
        &self,
        command: ConnectIamHookCommand,
    ) -> Result<Hook, ApplicationError> {
        let authorization = &command.context.authorization;
        authorize_action(authorization, Action::ConnectIamHook, &command.silicon_id)?;
        let existing = self
            .store
            .find_iam_hook(authorization.organization_id(), &command.silicon_id)
            .await
            .map_err(map_store_error)?;
        match existing {
            Some(hook) if hook.status() == HookStatus::Deleted => {
                self.restore_hook(HookMutationCommand {
                    context: command.context,
                    silicon_id: command.silicon_id,
                    hook_id: hook.id(),
                })
                .await
            }
            Some(hook) => Ok(hook),
            None => {
                let request_digest = connect_iam_request_digest(&command.silicon_id)?;
                let created = self
                    .create_hook_inner(CreateHookParts {
                        organization_id: authorization.organization_id().clone(),
                        silicon_id: command.silicon_id,
                        name: HookName::new(IAM_HOOK_NAME).map_err(|_| {
                            ApplicationError::Validation {
                                field: "iam_hook_name",
                            }
                        })?,
                        description: HookDescription::optional(Some(
                            IAM_HOOK_DESCRIPTION.to_owned(),
                        ))
                        .map_err(|_| ApplicationError::Validation {
                            field: "iam_hook_description",
                        })?,
                        time_zone: HookTimeZone::default(),
                        signing: iam_signing_input()?,
                        actor: authorization.actor().clone(),
                        idempotency_key: command.context.idempotency_key,
                        request_digest,
                        request_id: command.context.request_id,
                        is_iam_default: true,
                    })
                    .await?;
                Ok(created.hook)
            }
        }
    }

    /// Stores the `swhs_` secret IAM issued when the Hook endpoint was
    /// registered as the Silicon's webhook.
    ///
    /// # Errors
    ///
    /// Returns an authorization, lifecycle, idempotency, or persistence failure.
    pub async fn bind_iam_hook_secret(
        &self,
        command: BindIamHookSecretCommand,
    ) -> Result<Hook, ApplicationError> {
        let mutation = HookMutationCommand {
            context: command.context,
            silicon_id: command.silicon_id,
            hook_id: command.hook_id,
        };
        let hook = self
            .load_for_mutation(
                &mutation.context.authorization,
                &mutation.silicon_id,
                mutation.hook_id,
                Action::ConnectIamHook,
            )
            .await?;
        if hook.status() == HookStatus::Deleted {
            return Err(ApplicationError::StateConflict);
        }
        let request_digest = secret_digest(&command.signing_secret);
        let stored = self
            .store_rotated_secret(
                mutation,
                command.signing_secret,
                "hook.iam.bind",
                request_digest,
            )
            .await?;
        Ok(stored.hook)
    }

    async fn store_rotated_secret(
        &self,
        command: HookMutationCommand,
        secret: SigningSecret,
        operation: &str,
        request_digest: [u8; 32],
    ) -> Result<HookWithSecret, ApplicationError> {
        let authorization = &command.context.authorization;
        let now = database_time(self.clock.now())?;
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
                operation,
                authorization,
                command.hook_id.to_string(),
                command.context.idempotency_key,
                request_digest,
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
                signing_secret: Some(secret),
            }),
            Ok(RotateSecretOutcome::Replayed { hook, response }) => {
                self.secret_result_from_replay(hook, &response)
            }
            Err(error) => Err(map_store_error(error)),
        }
    }

    /// Replaces a hook's public endpoint with a fresh key and permanently
    /// retires the previous one for the Silicon.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, lifecycle, idempotency, or persistence failure.
    pub async fn rotate_hook_endpoint(
        &self,
        command: HookMutationCommand,
    ) -> Result<Hook, ApplicationError> {
        let authorization = &command.context.authorization;
        self.load_for_mutation(
            authorization,
            &command.silicon_id,
            command.hook_id,
            Action::RotateEndpoint,
        )
        .await?;
        let now = database_time(self.clock.now())?;
        for _ in 0..ENDPOINT_GENERATION_ATTEMPTS {
            let replacement = EndpointKey::generate().map_err(ApplicationError::internal)?;
            let persistence = RotateEndpoint {
                organization_id: authorization.organization_id().clone(),
                silicon_id: command.silicon_id.clone(),
                hook_id: command.hook_id,
                replacement,
                idempotency: idempotency_scope(
                    "hook.endpoint.rotate",
                    authorization,
                    command.hook_id.to_string(),
                    command.context.idempotency_key.clone(),
                    empty_request_digest(),
                ),
                response: PersistedResponse {
                    status: 200,
                    resource_id: Some(command.hook_id),
                    encrypted_secret: None,
                    secret_replay_until: None,
                },
                audit: audit_context(authorization, command.context.request_id.clone()),
                occurred_at: now,
            };
            match self.store.rotate_hook_endpoint(&persistence).await {
                Ok(
                    RotateEndpointOutcome::Rotated(hook)
                    | RotateEndpointOutcome::Replayed { hook, .. },
                ) => return Ok(hook),
                Err(StoreError::EndpointKeyConflict) => {}
                Err(error) => return Err(map_store_error(error)),
            }
        }
        Err(ApplicationError::internal(anyhow::anyhow!(
            "endpoint key collision budget exhausted"
        )))
    }

    async fn load_for_mutation(
        &self,
        authorization: &AuthorizationContext,
        silicon_id: &SiliconId,
        hook_id: HookId,
        action: Action,
    ) -> Result<Hook, ApplicationError> {
        authorize_action(authorization, Action::ReadHook, silicon_id)?;
        let hook = self
            .store
            .get_hook(authorization.organization_id(), silicon_id, hook_id)
            .await
            .map_err(map_store_error)?
            .ok_or(ApplicationError::NotFound)?;
        authorize_action(authorization, action, silicon_id)?;
        Ok(hook)
    }

    /// Turns validated input into a persisted policy, generating a secret when
    /// the scheme needs one and none was supplied or already stored.
    fn signing_policy(
        &self,
        hook_id: HookId,
        input: SigningInput,
        existing: &SigningPolicy,
    ) -> Result<SigningPolicy, ApplicationError> {
        let encrypted_secret = if input.config.algorithm.is_asymmetric() {
            None
        } else if let Some(secret) = &input.secret {
            Some(
                self.secret_cipher
                    .encrypt(hook_id, secret)
                    .map_err(ApplicationError::internal)?,
            )
        } else {
            existing.encrypted_secret.clone()
        };
        if input.required && input.config.algorithm.uses_secret() && encrypted_secret.is_none() {
            return Err(ApplicationError::ValidationDetailed {
                field: "signature",
                detail: "supply a secret or rotate the signing secret before requiring signatures"
                    .to_owned(),
            });
        }
        Ok(SigningPolicy {
            required: input.required,
            config: input.config,
            encrypted_secret,
        })
    }

    async fn create_hook_inner(
        &self,
        parts: CreateHookParts,
    ) -> Result<HookWithSecret, ApplicationError> {
        let now = database_time(self.clock.now())?;
        let secret = match (
            &parts.signing.secret,
            parts.signing.config.algorithm.uses_secret(),
        ) {
            (Some(secret), true) => Some(secret.clone()),
            (None, true) => Some(SigningSecret::generate().map_err(ApplicationError::internal)?),
            (_, false) => None,
        };
        for _ in 0..ENDPOINT_GENERATION_ATTEMPTS {
            let hook_id = HookId::new();
            let endpoint_key = EndpointKey::generate().map_err(ApplicationError::internal)?;
            let encrypted = secret
                .as_ref()
                .map(|secret| self.secret_cipher.encrypt(hook_id, secret))
                .transpose()
                .map_err(ApplicationError::internal)?;
            let hook = Hook::create(NewHook {
                id: hook_id,
                organization_id: parts.organization_id.clone(),
                silicon_id: parts.silicon_id.clone(),
                name: parts.name.clone(),
                description: parts.description.clone(),
                endpoint_key,
                signing: SigningPolicy {
                    required: parts.signing.required,
                    config: parts.signing.config.clone(),
                    encrypted_secret: encrypted.clone(),
                },
                time_zone: parts.time_zone.clone(),
                created_by: parts.actor.clone(),
                created_at: now,
            });
            let idempotency = IdempotencyScope {
                operation: if parts.is_iam_default {
                    "hook.iam.connect"
                } else {
                    "hook.create"
                }
                .to_owned(),
                actor: parts.actor.clone(),
                organization_id: parts.organization_id.clone(),
                target_id: parts.silicon_id.as_str().to_owned(),
                key: parts.idempotency_key.clone(),
                request_digest: parts.request_digest,
            };
            let persistence = CreateHook {
                hook,
                is_iam_default: parts.is_iam_default,
                idempotency,
                response: PersistedResponse {
                    status: 201,
                    resource_id: Some(hook_id),
                    encrypted_secret: encrypted.clone(),
                    secret_replay_until: encrypted
                        .as_ref()
                        .map(|_| secret_replay_until(now))
                        .transpose()?,
                },
                audit: AuditContext {
                    actor: parts.actor.clone(),
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
                    return self.secret_result_from_replay(hook, &response);
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
        response: &PersistedResponse,
    ) -> Result<HookWithSecret, ApplicationError> {
        let signing_secret = response
            .encrypted_secret
            .as_ref()
            .map(|encrypted| self.secret_cipher.decrypt(hook.id(), encrypted))
            .transpose()
            .map_err(ApplicationError::internal)?;
        Ok(HookWithSecret {
            hook,
            signing_secret,
        })
    }
}

fn iam_signing_input() -> Result<SigningInput, ApplicationError> {
    let build = || -> Result<SigningInput, crate::domain::signature::ParseError> {
        Ok(SigningInput {
            required: true,
            config: SignatureConfig {
                algorithm: SignatureAlgorithm::HmacSha256,
                payload: Expression::parse(IAM_PAYLOAD_EXPRESSION)?,
                signature: Expression::parse(IAM_SIGNATURE_EXPRESSION)?,
                signature_encoding: SignatureEncoding::Hex,
                secret_encoding: crate::domain::signature::SecretEncoding::Utf8,
                public_key: None,
            },
            secret: None,
        })
    };
    build().map_err(ApplicationError::internal)
}

fn validate_signing_input(input: &SigningInput) -> Result<(), ApplicationError> {
    input
        .config
        .validate()
        .map_err(|error| ApplicationError::ValidationDetailed {
            field: "signature",
            detail: error.to_string(),
        })?;
    if input.secret.is_some() && input.config.algorithm.is_asymmetric() {
        return Err(ApplicationError::ValidationDetailed {
            field: "signature",
            detail: "asymmetric algorithms verify with a public key and take no secret".to_owned(),
        });
    }
    if let Some(secret) = &input.secret {
        input
            .config
            .secret_encoding
            .decode(secret.as_str())
            .map_err(|error| ApplicationError::ValidationDetailed {
                field: "signature",
                detail: error.to_string(),
            })?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct CreateHookParts {
    organization_id: OrganizationId,
    silicon_id: SiliconId,
    name: HookName,
    description: Option<HookDescription>,
    time_zone: HookTimeZone,
    signing: SigningInput,
    actor: ActorRef,
    idempotency_key: String,
    request_digest: [u8; 32],
    request_id: Option<String>,
    is_iam_default: bool,
}

#[derive(Serialize)]
struct CanonicalCreateHookRequest<'a> {
    name: &'a str,
    description: Option<&'a str>,
    time_zone: &'a str,
    signature_required: bool,
    signature: &'a SignatureConfig,
    /// SHA-256 of the supplied secret so replays bind to it without storing it.
    secret_digest: Option<String>,
}

#[derive(Serialize)]
struct CanonicalConnectIamRequest<'a> {
    silicon_id: &'a str,
}

fn create_hook_request_digest(
    name: &HookName,
    description: Option<&HookDescription>,
    time_zone: &HookTimeZone,
    signing: &SigningInput,
) -> Result<[u8; 32], ApplicationError> {
    canonical_request_digest(&CanonicalCreateHookRequest {
        name: name.as_str(),
        description: description.map(HookDescription::as_str),
        time_zone: time_zone.as_str(),
        signature_required: signing.required,
        signature: &signing.config,
        secret_digest: signing
            .secret
            .as_ref()
            .map(|secret| hex::encode(Sha256::digest(secret.as_str().as_bytes()))),
    })
}

fn connect_iam_request_digest(silicon_id: &SiliconId) -> Result<[u8; 32], ApplicationError> {
    let canonical = serde_json::to_vec(&CanonicalConnectIamRequest {
        silicon_id: silicon_id.as_str(),
    })
    .map_err(ApplicationError::internal)?;
    Ok(Sha256::digest(canonical).into())
}

/// Binds a replay to the exact secret it stored without persisting the secret.
fn secret_digest(secret: &SigningSecret) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"silicon-hook/iam-bind/v1\0");
    digest.update(secret.as_str().as_bytes());
    digest.finalize().into()
}

fn canonical_request_digest<T: Serialize>(value: &T) -> Result<[u8; 32], ApplicationError> {
    serde_json::to_vec(value)
        .map(|bytes| Sha256::digest(&bytes).into())
        .map_err(ApplicationError::internal)
}

fn empty_request_digest() -> [u8; 32] {
    Sha256::digest([]).into()
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

#[cfg(test)]
mod tests {
    use super::{
        SigningInput, create_hook_request_digest, iam_signing_input, validate_activation_hook_ids,
        validate_signing_input,
    };
    use crate::domain::{
        HookDescription, HookId, HookName, HookTimeZone, SigningSecret,
        signature::{SignatureAlgorithm, SignatureConfig},
    };

    fn signing(secret: Option<&str>) -> Result<SigningInput, Box<dyn std::error::Error>> {
        Ok(SigningInput {
            required: true,
            config: SignatureConfig::default(),
            secret: secret.map(SigningSecret::from_text).transpose()?,
        })
    }

    #[test]
    fn management_digest_is_derived_from_validated_semantics()
    -> Result<(), Box<dyn std::error::Error>> {
        let name = HookName::new("GitHub")?;
        let description = HookDescription::optional(Some("Delivery hook".to_owned()))?;
        let zone = HookTimeZone::default();

        let first =
            create_hook_request_digest(&name, description.as_ref(), &zone, &signing(None)?)?;
        let second =
            create_hook_request_digest(&name, description.as_ref(), &zone, &signing(None)?)?;
        let changed = create_hook_request_digest(
            &HookName::new("GitLab")?,
            description.as_ref(),
            &zone,
            &signing(None)?,
        )?;
        let with_secret = create_hook_request_digest(
            &name,
            description.as_ref(),
            &zone,
            &signing(Some("s3cret"))?,
        )?;

        assert_eq!(first, second);
        assert_ne!(first, changed);
        assert_ne!(first, with_secret);
        assert_eq!(
            create_hook_request_digest(&name, None, &zone, &signing(None)?)?,
            create_hook_request_digest(
                &name,
                HookDescription::optional(Some(String::new()))?.as_ref(),
                &zone,
                &signing(None)?
            )?
        );
        Ok(())
    }

    #[test]
    fn signing_input_validation_matches_algorithm_families()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(validate_signing_input(&signing(Some("provider"))?).is_ok());
        let mut asymmetric = signing(Some("provider"))?;
        asymmetric.config.algorithm = SignatureAlgorithm::Ed25519;
        assert!(validate_signing_input(&asymmetric).is_err());
        let mut hex_secret = signing(Some("not-hex"))?;
        hex_secret.config.secret_encoding = crate::domain::signature::SecretEncoding::Hex;
        assert!(validate_signing_input(&hex_secret).is_err());
        assert!(iam_signing_input().is_ok());
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
