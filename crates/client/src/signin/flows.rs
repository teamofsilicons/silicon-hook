//! The sign-in calls: device flow, short-lived token exchange, refresh, revoke.

use std::time::Duration;

use reqwest::Url;
use silicon_accounts_client::{DevicePoll as AccountsPoll, TokenResponse};

use super::{
    DeviceCode, DeviceEvent, DevicePoll, SLT_GRANT_TYPE, SignIn, SignInError, SignInErrorKind,
    SltRefusal, Step, Tokens,
};
use crate::{Error, Result, models::Secret};

impl SignIn {
    /// Starts a Carbon's device sign-in for Hook. `client_label` names this
    /// machine on the approval page; `scope` asks for optional details
    /// (space separated).
    ///
    /// # Errors
    /// [`Error::SignIn`] when Silicon Accounts refuses (for example
    /// [`SignInErrorKind::NotEnabled`]) or cannot be reached.
    pub async fn start_device(
        &self,
        client_label: Option<&str>,
        scope: Option<&str>,
    ) -> Result<DeviceCode> {
        let device = self
            .accounts
            .app_device_authorize(&self.app_id, scope, client_label)
            .await
            .map_err(|error| SignInError::from_accounts(Step::Device, &error))?;
        Ok(DeviceCode {
            device_code: Secret::new(device.device_code.expose()),
            user_code: device.user_code,
            verification_uri: device.verification_uri,
            verification_uri_complete: device.verification_uri_complete,
            expires_in: device.expires_in,
            interval: device.interval,
        })
    }

    /// Polls a device sign-in once.
    ///
    /// # Errors
    /// [`SignInErrorKind::Denied`], [`SignInErrorKind::Expired`], and failures.
    pub async fn poll_device(&self, device: &DeviceCode) -> Result<DevicePoll> {
        let poll = self
            .accounts
            .app_device_poll(&self.app_id, device.device_code.expose())
            .await
            .map_err(|error| SignInError::from_accounts(Step::Device, &error))?;
        match poll {
            AccountsPoll::Pending => Ok(DevicePoll::Pending),
            AccountsPoll::SlowDown => Ok(DevicePoll::SlowDown),
            AccountsPoll::Tokens(tokens) => Ok(DevicePoll::Approved(Box::new((*tokens).into()))),
            AccountsPoll::Denied => Err(SignInError::oauth(
                Step::Device,
                400,
                "access_denied",
                Some(&format!(
                    "The sign-in request {} was denied on the account site.",
                    device.user_code
                )),
            )
            .into()),
            AccountsPoll::Expired => Err(expired(device)),
            #[allow(unreachable_patterns)]
            _ => Err(Error::Protocol(
                "Silicon Accounts answered the device poll with an unknown state".into(),
            )),
        }
    }

    /// Polls until the Carbon approves the device sign-in, honouring the
    /// interval, `slow_down` (5 seconds more each time) and the code's expiry.
    /// Transient failures are retried; `on_event` reports progress.
    ///
    /// # Errors
    /// [`SignInErrorKind::Denied`], [`SignInErrorKind::Expired`], and
    /// non-transient failures.
    pub async fn wait_for_device(
        &self,
        device: &DeviceCode,
        mut on_event: impl FnMut(DeviceEvent<'_>),
    ) -> Result<Tokens> {
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_secs(device.expires_in.clamp(1, 1800));
        let mut interval = Duration::from_secs(device.interval.clamp(1, 60));
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(expired(device));
            }
            tokio::time::sleep(interval.min(deadline - now)).await;
            match self.poll_device(device).await {
                Ok(DevicePoll::Approved(tokens)) => return Ok(*tokens),
                Ok(DevicePoll::Pending) => on_event(DeviceEvent::Pending),
                Ok(DevicePoll::SlowDown) => {
                    interval += Duration::from_secs(5);
                    on_event(DeviceEvent::SlowDown(interval));
                }
                Err(error) if transient(&error) => on_event(DeviceEvent::Retrying {
                    error: &error,
                    retry_in: interval,
                }),
                Err(error) => return Err(error),
            }
        }
    }

    /// Exchanges a short-lived token (`slt_…`, from
    /// `silicon-accounts login --app hook -q`) for Hook tokens, with Hook's
    /// `client_id` alone. The token is consumed even when the exchange is
    /// refused.
    ///
    /// # Errors
    /// [`SignInErrorKind::SltRefused`] with the exact reason, and failures.
    pub async fn exchange_slt(&self, slt: &str) -> Result<Tokens> {
        let slt = slt.trim();
        if !slt.starts_with("slt_") || !slt.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(SignInError::new(
                SignInErrorKind::SltRefused(SltRefusal::NotAnSlt),
                "not_an_slt",
                "This is not a Silicon Accounts short-lived token (they start with slt_). Nothing was sent.",
                format!("Mint one for Hook with `{}`.", super::SLT_COMMAND),
                None,
            )
            .into());
        }
        // `silicon-accounts-client` 0.4.0 on crates.io has no public-client SLT
        // exchange yet; this is the same form POST its later releases send.
        let response = self
            .post_form(
                &["v1", "oauth", "token"],
                &[
                    ("grant_type", SLT_GRANT_TYPE),
                    ("slt", slt),
                    ("client_id", &self.app_id),
                ],
            )
            .await?;
        if response.0.is_success() {
            let tokens: TokenResponse = serde_json::from_slice(&response.1).map_err(|_| {
                SignInError::new(
                    SignInErrorKind::Unavailable {
                        maybe_processed: true,
                    },
                    "invalid_response",
                    "Silicon Accounts accepted the short-lived token but its answer could not be read; the token is spent.",
                    format!("Mint a new one with `{}` and retry; check ACCOUNTS_URL.", super::SLT_COMMAND),
                    Some(response.0.as_u16()),
                )
            })?;
            return Ok(tokens.into());
        }
        Err(refusal(Step::Slt, response.0.as_u16(), &response.1).into())
    }

    /// Rotates the refresh token: the one you send is spent, store the new pair
    /// before using it. Refresh one at a time per sign-in (a spent token
    /// presented again ends the whole sign-in).
    ///
    /// # Errors
    /// [`SignInErrorKind::SessionEnded`] when the sign-in is over, and failures
    /// ([`SignInErrorKind::Unavailable`] says whether the token may be spent).
    pub async fn refresh(&self, refresh_token: &str) -> Result<Tokens> {
        self.accounts
            .refresh_app_public_client(&self.app_id, refresh_token)
            .await
            .map(Tokens::from)
            .map_err(|error| SignInError::from_accounts(Step::Refresh, &error).into())
    }

    /// Signs out: revokes the refresh token's whole sign-in at Silicon
    /// Accounts. Unknown or already revoked tokens succeed.
    ///
    /// # Errors
    /// Failures to reach Silicon Accounts and refusals.
    pub async fn revoke(&self, refresh_token: &str) -> Result<()> {
        // `revoke_public_client` in silicon-accounts-client 0.4.0 accepts only
        // Silicon Accounts' own client ids, so the form POST is sent directly.
        let token = refresh_token.trim();
        let hint = if token.starts_with("sar_") {
            "refresh_token"
        } else {
            "access_token"
        };
        let response = self
            .post_form(
                &["v1", "oauth", "revoke"],
                &[
                    ("token", token),
                    ("token_type_hint", hint),
                    ("client_id", &self.app_id),
                ],
            )
            .await?;
        if response.0.is_success() {
            return Ok(());
        }
        Err(refusal(Step::Revoke, response.0.as_u16(), &response.1).into())
    }

    async fn post_form(
        &self,
        path: &[&str],
        form: &[(&str, &str)],
    ) -> Result<(reqwest::StatusCode, zeroize::Zeroizing<Vec<u8>>)> {
        let url = endpoint(&self.url, path)?;
        let response = self
            .http
            .post(url)
            .form(form)
            .send()
            .await
            .map_err(|error| Error::from(SignInError::transport(&error)))?;
        let status = response.status();
        let body = crate::client::bounded_body(response).await?;
        Ok((status, body))
    }
}

fn endpoint(base: &Url, path: &[&str]) -> Result<Url> {
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|()| Error::Invalid("the Silicon Accounts URL cannot carry a path".into()))?
        .pop_if_empty()
        .extend(path);
    Ok(url)
}

fn expired(device: &DeviceCode) -> Error {
    SignInError::oauth(
        Step::Device,
        400,
        "expired_token",
        Some(&format!(
            "The sign-in code {} expired before it was approved.",
            device.user_code
        )),
    )
    .into()
}

fn transient(error: &Error) -> bool {
    matches!(error, Error::SignIn(sign_in) if matches!(sign_in.kind, SignInErrorKind::Unavailable { .. }))
}

/// Reads an OAuth error (`{"error": "...", "error_description": "..."}`) or the
/// service's standard error body.
fn refusal(step: Step, status: u16, body: &[u8]) -> SignInError {
    let value: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    if let Some(error) = value["error"].as_str() {
        return SignInError::oauth(step, status, error, value["error_description"].as_str());
    }
    let error = &value["error"];
    let code = error["code"].as_str().unwrap_or("unexpected_status");
    let message = error["message"].as_str().map_or_else(
        || format!("Silicon Accounts answered HTTP {status}."),
        str::to_owned,
    );
    let kind = if status >= 500 || status == 429 {
        SignInErrorKind::Unavailable {
            maybe_processed: false,
        }
    } else {
        SignInErrorKind::Rejected
    };
    SignInError::new(
        kind,
        code,
        message,
        error["hint"]
            .as_str()
            .unwrap_or("Check ACCOUNTS_URL and retry.")
            .to_owned(),
        Some(status),
    )
}
