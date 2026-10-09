//! Hook's Silicon Accounts app webhook: verified events reduced to their effect.

use silicon_accounts_client::{AccountKind, AccountRef, WebhookEvent, WebhookPayload};
use time::OffsetDateTime;

use super::{ApplicationError, HookApplication, service::map_store_error};
use crate::{
    domain::{AccountUuid, ActorKind, PublicId},
    infrastructure::{
        accounts::WebhookRejection,
        postgres::{AccountsChange, AccountsEvent, EventOutcome},
    },
};

/// What the webhook did with a delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookOutcome {
    /// The event changed Hook's records (or was one Hook does not act on).
    Applied,
    /// The event id was handled before.
    Duplicate,
}

fn refused(status: u16, code: &'static str, message: impl Into<String>) -> ApplicationError {
    ApplicationError::refused(status, code, message)
}

fn uuid(value: &str) -> Result<AccountUuid, ApplicationError> {
    AccountUuid::new(value).map_err(|_| {
        refused(
            400,
            "invalid_event",
            format!("The event names `{value}`, which is not a Silicon Accounts uuid."),
        )
    })
}

fn kind(kind: AccountKind) -> ActorKind {
    match kind {
        AccountKind::Carbon => ActorKind::Carbon,
        AccountKind::Silicon => ActorKind::Silicon,
    }
}

fn custodian(reference: Option<&AccountRef>) -> Option<(AccountUuid, Option<PublicId>)> {
    reference.and_then(|reference| {
        AccountUuid::new(reference.uuid.clone())
            .ok()
            .map(|uuid| (uuid, PublicId::new(reference.id.clone()).ok()))
    })
}

fn change(event: &WebhookEvent) -> Result<AccountsChange, ApplicationError> {
    Ok(match &event.payload {
        WebhookPayload::AccountIdChanged(data) => AccountsChange::IdChanged {
            uuid: uuid(&data.uuid)?,
            kind: data.kind.map(kind),
            old_id: PublicId::new(data.old_id.clone()).ok(),
            new_id: PublicId::new(data.new_id.clone()).map_err(|_| {
                refused(
                    400,
                    "invalid_event",
                    "account.id_changed carries no valid new_id.",
                )
            })?,
        },
        WebhookPayload::AccountUpdated(data) => match &data.account {
            Some(account) => AccountsChange::Updated {
                uuid: uuid(&data.uuid)?,
                kind: kind(account.kind),
                public_id: PublicId::new(account.id.clone()).ok(),
                display_name: Some(account.display_name.clone()).filter(|name| !name.is_empty()),
                pfp_url: Some(account.pfp_url.clone()).filter(|url| !url.is_empty()),
                custodian: custodian(account.custodian.as_ref()),
                version: account.version,
            },
            None => AccountsChange::Nothing,
        },
        WebhookPayload::CustodianChanged(data) => AccountsChange::CustodianChanged {
            uuid: uuid(&data.uuid)?,
            from: data
                .from
                .as_ref()
                .and_then(|from| AccountUuid::new(from.uuid.clone()).ok()),
            to: custodian(data.to.as_ref()),
        },
        WebhookPayload::MembershipSignedOut(data) => AccountsChange::SignedOut {
            uuid: uuid(&data.uuid)?,
            reason: data.reason.clone(),
        },
        WebhookPayload::MembershipAccessRemoved(data) => AccountsChange::AccessRemoved {
            uuid: uuid(&data.uuid)?,
        },
        WebhookPayload::AccountDeleted(data) => AccountsChange::Deleted {
            uuid: uuid(&data.uuid)?,
        },
        _ => AccountsChange::Nothing,
    })
}

impl HookApplication {
    /// Verifies and applies one Silicon Accounts webhook delivery.
    ///
    /// # Errors
    ///
    /// Returns `401` for a delivery that cannot be trusted (missing or wrong
    /// signature, stale timestamp), `400` for a verified body that is not an
    /// Accounts event, `503` when no webhook secret is configured, and
    /// persistence failures (Accounts retries those).
    pub async fn receive_accounts_webhook(
        &self,
        timestamp: Option<&str>,
        signature: Option<&str>,
        body: &[u8],
    ) -> Result<WebhookOutcome, ApplicationError> {
        let event = self
            .accounts
            .verify_webhook(timestamp.unwrap_or_default(), signature.unwrap_or_default(), body)
            .map_err(|rejection| match rejection {
                WebhookRejection::NotConfigured => refused(
                    503,
                    "webhook_not_configured",
                    "Hook has no Silicon Accounts webhook secret (HOOK_ACCOUNTS_WEBHOOK_SECRET), so it cannot verify deliveries.",
                ),
                WebhookRejection::Signature(error) => {
                    refused(401, "webhook_signature_invalid", error.to_string())
                }
                WebhookRejection::Body(error) => refused(400, "invalid_event", error.to_string()),
            })?;
        let change = change(&event)?;
        if matches!(change, AccountsChange::Nothing) {
            tracing::info!(
                event_id = %event.event_id,
                event_type = %event.event_type,
                "Silicon Accounts event needs no action"
            );
        }
        let outcome = self
            .store
            .apply_accounts_event(&AccountsEvent {
                event_id: event.event_id.clone(),
                event_type: event.event_type.clone(),
                occurred_at: event.occurred_at.unwrap_or_else(OffsetDateTime::now_utc),
                change,
            })
            .await
            .map_err(map_store_error)?;
        tracing::info!(
            event_id = %event.event_id,
            event_type = %event.event_type,
            duplicate = outcome == EventOutcome::Duplicate,
            "Silicon Accounts event received"
        );
        Ok(match outcome {
            EventOutcome::Applied => WebhookOutcome::Applied,
            EventOutcome::Duplicate => WebhookOutcome::Duplicate,
        })
    }
}
