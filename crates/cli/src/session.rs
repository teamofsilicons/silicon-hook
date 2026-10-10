//! Which URLs and Silicon a command uses, and a usable access token.
//!
//! Tokens are refreshed under the state lock when less than 60 seconds remain,
//! so concurrent `hook` processes share one refresh: the first refreshes and
//! saves the new pair, the others find it fresh after taking the lock. Silicon
//! Accounts treats a spent refresh token presented again as theft, so a refresh
//! whose outcome is unknown is never retried with the same token: the sign-in
//! is ended (its refresh token revoked, which only ends this sign-in) and the
//! account signs in again.

use silicon_hook_client::{
    Client, DEFAULT_URL, Error as ClientError,
    models::AccountKind,
    signin::{DEFAULT_ACCOUNTS_URL, SignIn, SignInErrorKind, Tokens},
};

use crate::{
    args::Cli,
    output::{CliError, CliResult, EXIT_AUTH, EXIT_FAILURE},
    store::{self, Locked, Profile, Session, SessionAccount, now},
};

/// Refresh when less than this many seconds remain.
pub const REFRESH_MARGIN: i64 = 60;

/// The Hook API and Silicon Accounts URLs in effect, and where each came from.
#[derive(Clone, Debug)]
pub struct Urls {
    pub hook: String,
    pub hook_source: &'static str,
    pub accounts: String,
    pub accounts_source: &'static str,
}

pub fn urls(cli: &Cli, profile: &Profile) -> Urls {
    let pick = |explicit: &Option<String>, saved: &Option<String>, default: &str| match (
        explicit.as_deref().map(str::trim).filter(|v| !v.is_empty()),
        saved,
    ) {
        (Some(value), _) => (
            value.trim_end_matches('/').to_owned(),
            "flag or environment",
        ),
        (None, Some(value)) => (value.trim_end_matches('/').to_owned(), "profile"),
        (None, None) => (default.to_owned(), "default"),
    };
    let (hook, hook_source) = pick(&cli.url, &profile.url, DEFAULT_URL);
    let (accounts, accounts_source) = pick(
        &cli.accounts_url,
        &profile.accounts_url,
        DEFAULT_ACCOUNTS_URL,
    );
    Urls {
        hook,
        hook_source,
        accounts,
        accounts_source,
    }
}

fn same(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

pub fn sign_in(accounts_url: &str) -> CliResult<SignIn> {
    SignIn::new(accounts_url).map_err(|error| {
        CliError::invalid(
            error.to_string(),
            "Set ACCOUNTS_URL (or --accounts-url, or `hook config set accounts-url`) to the Silicon Accounts origin.",
        )
    })
}

pub fn hook_client(url: &str, telemetry: bool) -> CliResult<Client> {
    Client::new(url)
        .map(|client| client.with_telemetry(telemetry))
        .map_err(|error| {
            CliError::invalid(
                error.to_string(),
                "Set SILICON_HOOK_URL (or --url, or `hook config set url`) to the Hook API origin.",
            )
        })
}

/// Why a saved session cannot be used with the URLs in effect.
pub fn binding_problem(session: &Session, urls: &Urls) -> Option<CliError> {
    if !same(&session.accounts_url, &urls.accounts) {
        return Some(CliError::new(
            EXIT_AUTH,
            "signed_in_elsewhere",
            format!(
                "This profile signed in with the Silicon Accounts at {}, but {} is in effect ({}).",
                session.accounts_url, urls.accounts, urls.accounts_source
            ),
            "Sign in again for this Silicon Accounts (`hook login`), or use another --profile.",
        ));
    }
    if !same(&session.url, &urls.hook) {
        return Some(CliError::new(
            EXIT_AUTH,
            "signed_in_elsewhere",
            format!(
                "This profile signed in for the Hook at {}, but {} is in effect ({}); its token is only sent to the Hook it signed in for.",
                session.url, urls.hook, urls.hook_source
            ),
            "Sign in again with this URL (`hook login`), or use another --profile.",
        ));
    }
    None
}

pub fn previous_version_error(profile_name: &str) -> CliError {
    CliError::new(
        EXIT_AUTH,
        "previous_version_session",
        format!(
            "Profile `{profile_name}` was signed in with Hook before 1.0. Hook now signs in with Silicon Accounts, and that sign-in was not carried over."
        ),
        "Carbons: `hook login`. Silicons: `silicon-accounts login --app hook -q | hook login --slt-stdin`.",
    )
}

/// Turns fresh tokens into a saved session.
pub fn session_from(
    tokens: Tokens,
    urls: &Urls,
    app_id: &str,
    method: &str,
    previous: Option<&Session>,
) -> CliResult<Session> {
    let account = match (tokens.account, previous) {
        (Some(account), _) => SessionAccount {
            uuid: account.uuid,
            kind: account.kind,
            id: account.id,
            display_name: account.display_name,
        },
        (None, Some(previous)) => previous.account.clone(),
        (None, None) => {
            return Err(CliError::new(
                EXIT_FAILURE,
                "missing_account",
                "Silicon Accounts returned tokens without the account they belong to.",
                "Retry; if it persists, report it with `hook report`.",
            ));
        }
    };
    let issued = now();
    Ok(Session {
        app_id: app_id.to_owned(),
        accounts_url: urls.accounts.clone(),
        url: urls.hook.clone(),
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_at: issued.saturating_add(i64::try_from(tokens.expires_in).unwrap_or(1800)),
        refresh_expires_at: tokens.refresh_expires_at.map(|at| at.unix_timestamp()),
        scope: tokens.scope,
        account,
        method: method.to_owned(),
        signed_in_at: previous.map_or(issued, |p| p.signed_in_at),
        refresh_started_at: None,
    })
}

/// The profile's session with at least a minute left, refreshed if needed.
/// `force` refreshes even a fresh token (after Hook refused it).
pub async fn fresh_session(cli: &Cli, force: bool) -> CliResult<(Session, Profile)> {
    let folder = store::folder()?;
    let loaded = store::read(&folder)?;
    if let Some(problem) = &loaded.unreadable {
        return Err(CliError::new(
            EXIT_FAILURE,
            "state_unreadable",
            problem.clone(),
            "Move the file aside, then sign in again with `hook login`.",
        ));
    }
    let profile = loaded.profile(&cli.profile);
    let urls = urls(cli, &profile);
    let Some(seen) = profile.session.clone() else {
        return Err(if profile.previous_version_session {
            previous_version_error(&cli.profile)
        } else {
            CliError::not_signed_in(&cli.profile)
        });
    };
    if let Some(problem) = binding_problem(&seen, &urls) {
        return Err(problem);
    }
    if !force && seen.refresh_started_at.is_none() && seen.expires_at - now() >= REFRESH_MARGIN {
        return Ok((seen, profile));
    }
    let (mut locked, _) = Locked::open(false)?;
    let current = locked.profile(&cli.profile).session.clone();
    let Some(mut session) = current else {
        return Err(CliError::not_signed_in(&cli.profile));
    };
    let refreshed_meanwhile = session.access_token != seen.access_token;
    if session.refresh_started_at.is_none()
        && session.expires_at - now() >= REFRESH_MARGIN
        && (!force || refreshed_meanwhile)
    {
        let profile = locked.profile(&cli.profile).clone();
        return Ok((session, profile));
    }
    let client = sign_in(&session.accounts_url)?.with_app_id(&session.app_id);
    if session.refresh_started_at.is_some() {
        return Err(end_uncertain(
            &mut locked,
            cli,
            &client,
            &session,
            "A token refresh by an earlier hook command did not finish",
        )
        .await);
    }
    let Some(refresh_token) = session.refresh_token.clone() else {
        locked.profile(&cli.profile).session = None;
        locked.save()?;
        return Err(CliError::new(
            EXIT_AUTH,
            "session_ended",
            "The saved sign-in has no refresh token and its access token has expired.",
            "Sign in again with `hook login` (Carbons) or `hook login --slt-stdin` (Silicons).",
        ));
    };
    session.refresh_started_at = Some(now());
    locked.profile(&cli.profile).session = Some(session.clone());
    locked.save()?;
    match client.refresh(refresh_token.expose()).await {
        Ok(tokens) => {
            let next = session_from(
                tokens,
                &urls_of(&session),
                &session.app_id,
                &session.method,
                Some(&session),
            )?;
            locked.profile(&cli.profile).session = Some(next.clone());
            locked.save()?;
            let profile = locked.profile(&cli.profile).clone();
            Ok((next, profile))
        }
        Err(ClientError::SignIn(error)) => match error.kind {
            SignInErrorKind::SessionEnded => {
                locked.profile(&cli.profile).session = None;
                locked.save()?;
                Err(CliError::new(
                    EXIT_AUTH,
                    "session_ended",
                    format!(
                        "The sign-in as {} has ended: {}",
                        session.who(),
                        error.message
                    ),
                    error.hint.clone(),
                ))
            }
            SignInErrorKind::Unavailable {
                maybe_processed: true,
            } => Err(end_uncertain(
                &mut locked,
                cli,
                &client,
                &session,
                "The token refresh request was sent but its answer never arrived",
            )
            .await),
            _ => {
                session.refresh_started_at = None;
                locked.profile(&cli.profile).session = Some(session);
                locked.save()?;
                Err(ClientError::SignIn(error).into())
            }
        },
        Err(other) => {
            session.refresh_started_at = None;
            locked.profile(&cli.profile).session = Some(session);
            locked.save()?;
            Err(other.into())
        }
    }
}

fn urls_of(session: &Session) -> Urls {
    Urls {
        hook: session.url.clone(),
        hook_source: "session",
        accounts: session.accounts_url.clone(),
        accounts_source: "session",
    }
}

/// Ends a sign-in whose refresh token may already be spent: presenting it
/// again would look like theft and end every Hook sign-in of the account, so
/// it is revoked instead (which ends only this sign-in) and forgotten.
async fn end_uncertain(
    locked: &mut Locked,
    cli: &Cli,
    client: &SignIn,
    session: &Session,
    what: &str,
) -> CliError {
    if let Some(token) = &session.refresh_token {
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.revoke(token.expose()),
        )
        .await;
    }
    locked.profile(&cli.profile).session = None;
    if let Err(error) = locked.save() {
        return error;
    }
    CliError::new(
        EXIT_AUTH,
        "refresh_interrupted",
        format!(
            "{what}, so the saved refresh token of {} may already be spent. Hook does not present a possibly spent token (Silicon Accounts would end every Hook sign-in of the account); this sign-in was ended instead.",
            session.who()
        ),
        "Sign in again: `hook login` (Carbons) or `silicon-accounts login --app hook -q | hook login --slt-stdin` (Silicons).",
    )
}

/// A Hook client for the profile's session, refreshed if needed.
pub async fn signed_in_client(cli: &Cli, force: bool) -> CliResult<(Client, Session, Profile)> {
    let (session, profile) = fresh_session(cli, force).await?;
    let client =
        hook_client(&session.url, profile.telemetry)?.with_token(session.access_token.expose());
    Ok((client, session, profile))
}

/// The Silicon a command acts on: `--silicon`, the profile's setting, or the
/// signed-in Silicon (by uuid).
pub fn target(cli: &Cli, profile: &Profile, session: &Session) -> CliResult<String> {
    let chosen = cli
        .silicon
        .clone()
        .or_else(|| profile.silicon.clone())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    match chosen {
        Some(value) => validate_silicon(&value).map(|()| value),
        None if session.account.kind == AccountKind::Silicon => Ok(session.account.uuid.clone()),
        None => Err(CliError::invalid(
            format!(
                "Which Silicon? You are signed in as {}, a Carbon, and no Silicon was chosen.",
                session.who()
            ),
            "Add --silicon si:<id> (or its uuid); `hook silicons` lists the ones you can open, and `hook config set silicon si:<id>` saves a default.",
        )),
    }
}

pub fn validate_silicon(value: &str) -> CliResult<()> {
    if value.starts_with("c:") {
        return Err(CliError::invalid(
            format!("`{value}` is a Carbon id; hooks belong to Silicons."),
            "Give the Silicon's si:<id> or uuid; `hook silicons` lists the ones you can open.",
        ));
    }
    if value.contains(['/', '\\', '?', '#', ' ']) || value.len() > 120 {
        return Err(CliError::invalid(
            format!("`{value}` is not a Silicon id or uuid."),
            "Silicon ids look like si:scout; uuids are short case-sensitive strings like zQo.",
        ));
    }
    Ok(())
}
