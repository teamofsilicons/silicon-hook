//! Public ingress: route, guard, capture, verify, and record one request.

use url::Url;

use super::{
    ApplicationError, HookApplication, ReceiveOutcome, ReceiveRequestCommand,
    service::{database_time, endpoint_url, map_store_error},
};
use crate::{
    domain::{
        BlockReason, BlockedRequestId, EventId, Hook, SigningSecret,
        request::{CaptureError, CapturedRequest, CapturedRequestParts},
        safety::BlockCheck,
        signature::{HookContext, VerificationOutcome, verify},
    },
    infrastructure::postgres::{AcceptEvent, EndpointResolution, RecordBlockedRequest, StoreError},
};

impl HookApplication {
    /// Receives one provider request on a public endpoint.
    ///
    /// The endpoint is routed first, then the client address is checked
    /// against the hook's block list, then the request is captured exactly.
    /// When the hook requires signatures the request is verified; a verified
    /// request joins the delivery stream and an unverified one is written to
    /// the blocked log and counted against the address.
    ///
    /// # Errors
    ///
    /// Returns not-found for unknown or inactive endpoints, a retired-endpoint
    /// failure for rotated keys, a blocked-address failure, a capture-bound
    /// failure, or a persistence failure.
    pub async fn receive_request(
        &self,
        command: ReceiveRequestCommand,
    ) -> Result<ReceiveOutcome, ApplicationError> {
        let (hook, now) = match self
            .store
            .resolve_endpoint(&command.silicon_id, &command.endpoint_key)
            .await
            .map_err(map_store_error)?
        {
            EndpointResolution::Active {
                hook,
                database_time: at,
            } => (*hook, database_time(at)?),
            EndpointResolution::Retired => return Err(ApplicationError::EndpointRetired),
            EndpointResolution::Inactive | EndpointResolution::Unknown => {
                return Err(ApplicationError::NotFound);
            }
        };
        match self
            .store
            .check_ip_block(hook.id(), command.remote_ip, now)
            .await
            .map_err(map_store_error)?
        {
            BlockCheck::Allowed => {}
            BlockCheck::BlockedUntil(until) => {
                return Err(ApplicationError::IpBlocked { until });
            }
        }

        let hook_url = endpoint_url(
            &self.public_base_url,
            &command.silicon_id,
            &command.endpoint_key,
        )?;
        let mut request = capture(&self.public_base_url, command, now)?;
        if request
            .content_type()
            .is_some_and(|media_type| media_type == "multipart/form-data")
        {
            // A malformed multipart body is not fatal; expressions that need
            // parts will report the body as unavailable.
            let _parts = request.parse_multipart().await;
        }

        if !hook.signing().is_required() {
            return self.accept(hook, request).await;
        }
        match self.verify(&hook, &hook_url, &request) {
            Ok(()) => self.accept(hook, request).await,
            Err(reason) => self.block(hook, request, reason).await,
        }
    }

    fn verify(
        &self,
        hook: &Hook,
        hook_url: &Url,
        request: &CapturedRequest,
    ) -> Result<(), BlockReason> {
        let secret = hook
            .encrypted_signing_secret()
            .map(|encrypted| self.secret_cipher.decrypt(hook.id(), encrypted))
            .transpose()
            .map_err(|error| BlockReason::material_unavailable(&error.to_string()))?;
        let material = hook
            .signing()
            .config
            .material(secret.as_ref().map(SigningSecret::as_str))
            .map_err(|error| BlockReason::material_unavailable(&error.to_string()))?;
        let hook_id = hook.id().to_string();
        let context = HookContext {
            id: &hook_id,
            url: hook_url.as_str(),
        };
        match verify(&hook.signing().config, request, context, &material) {
            VerificationOutcome::Verified => Ok(()),
            VerificationOutcome::Rejected(reason) => Err(BlockReason::signature(&reason)),
        }
    }

    async fn accept(
        &self,
        hook: Hook,
        request: CapturedRequest,
    ) -> Result<ReceiveOutcome, ApplicationError> {
        self.store
            .accept_event(AcceptEvent {
                event_id: EventId::new(),
                hook,
                request,
            })
            .await
            .map(ReceiveOutcome::Accepted)
            .map_err(map_store_error)
    }

    async fn block(
        &self,
        hook: Hook,
        request: CapturedRequest,
        reason: BlockReason,
    ) -> Result<ReceiveOutcome, ApplicationError> {
        let strike = self
            .store
            .record_unverified_request(hook.id(), request.remote_ip(), request.received_at())
            .await
            .map_err(map_store_error)?;
        tracing::info!(
            hook_id = %hook.id(),
            reason = reason.code(),
            strike = ?strike,
            "unverified webhook request withheld"
        );
        match self
            .store
            .record_blocked_request(RecordBlockedRequest {
                id: BlockedRequestId::new(),
                hook,
                request,
                reason,
            })
            .await
        {
            Ok(blocked) => Ok(ReceiveOutcome::Blocked(blocked)),
            Err(StoreError::NotFound { .. }) => Err(ApplicationError::NotFound),
            Err(error) => Err(map_store_error(error)),
        }
    }
}

fn capture(
    public_base_url: &Url,
    command: ReceiveRequestCommand,
    received_at: time::OffsetDateTime,
) -> Result<CapturedRequest, ApplicationError> {
    let mut url = public_base_url.clone();
    url.set_query(command.query.as_deref());
    url.set_fragment(None);
    url.set_path(&command.path);
    CapturedRequest::new(CapturedRequestParts {
        method: command.method,
        url,
        headers: command.headers,
        body: command.body,
        remote_ip: command.remote_ip,
        received_at,
    })
    .map_err(|error| match error {
        CaptureError::BodyTooLarge
        | CaptureError::HeadersTooLarge
        | CaptureError::TooManyHeaders => ApplicationError::PayloadTooLarge,
        CaptureError::InvalidMethod => ApplicationError::Validation { field: "method" },
    })
}
