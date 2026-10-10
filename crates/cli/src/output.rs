//! Output and errors. Results are JSON on stdout. Next-step hints go to stderr
//! unless `--json`. Errors say exactly what failed and why, with a stable code,
//! and exit with:
//! 0 success, 1 failure, 2 invalid input, 3 sign-in required or refused,
//! 4 not found, 5 conflict, 6 rate limited, 130 interrupted.

use std::fmt;

use serde::Serialize;
use serde_json::{Value, json};
use silicon_hook_client::{Error as ClientError, signin::SignInErrorKind};

pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_INVALID: i32 = 2;
pub const EXIT_AUTH: i32 = 3;
pub const EXIT_NOT_FOUND: i32 = 4;
pub const EXIT_CONFLICT: i32 = 5;
pub const EXIT_RATE_LIMITED: i32 = 6;
pub const EXIT_INTERRUPTED: i32 = 130;

/// An error ready to show. Boxed so results stay small.
#[derive(Debug)]
pub struct CliError(Box<Body>);

#[derive(Debug)]
pub struct Body {
    pub code: String,
    pub message: String,
    pub hint: Option<String>,
    pub exit: i32,
    pub status: Option<u16>,
    pub request_id: Option<String>,
    pub details: Option<Value>,
}

pub type CliResult<T> = Result<T, CliError>;

impl std::ops::Deref for CliError {
    type Target = Body;
    fn deref(&self) -> &Body {
        &self.0
    }
}

impl CliError {
    pub fn new(exit: i32, code: &str, message: impl Into<String>, hint: impl Into<String>) -> Self {
        let hint = hint.into();
        Self(Box::new(Body {
            code: code.to_owned(),
            message: message.into(),
            hint: (!hint.is_empty()).then_some(hint),
            exit,
            status: None,
            request_id: None,
            details: None,
        }))
    }

    pub fn invalid(message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self::new(EXIT_INVALID, "invalid_input", message, hint)
    }

    pub fn not_signed_in(profile: &str) -> Self {
        Self::new(
            EXIT_AUTH,
            "not_signed_in",
            format!("Profile `{profile}` is not signed in to Hook."),
            "Carbons: `hook login` (approve the code in a browser). Silicons: `silicon-accounts login --app hook -q | hook login --slt-stdin`.",
        )
    }

    pub fn io(action: &str, path: &std::path::Path, error: &std::io::Error) -> Self {
        let hint = match error.kind() {
            std::io::ErrorKind::PermissionDenied => format!(
                "Check the permissions of {}, or choose another base with `hook config home <dir>` or SILICON_HOOK_HOME.",
                path.display()
            ),
            _ => "Check the path and the disk, then retry.".to_owned(),
        };
        Self::new(
            EXIT_FAILURE,
            "io_error",
            format!("Could not {action} {}: {error}.", path.display()),
            hint,
        )
    }

    pub fn exit_code(&self) -> i32 {
        self.exit
    }

    pub fn to_json(&self) -> Value {
        let mut error = json!({"code": self.code, "message": self.message, "exit_code": self.exit});
        if let Some(hint) = &self.hint {
            error["hint"] = json!(hint);
        }
        if let Some(status) = self.status {
            error["status"] = json!(status);
        }
        if let Some(id) = &self.request_id {
            error["request_id"] = json!(id);
        }
        if let Some(details) = &self.details {
            error["details"] = details.clone();
        }
        json!({ "error": error })
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, "\nHint: {hint}")?;
        }
        Ok(())
    }
}

fn exit_for_status(status: u16) -> i32 {
    match status {
        400 | 410 | 413 | 415 | 422 => EXIT_INVALID,
        401 | 403 => EXIT_AUTH,
        404 => EXIT_NOT_FOUND,
        409 => EXIT_CONFLICT,
        429 => EXIT_RATE_LIMITED,
        _ => EXIT_FAILURE,
    }
}

impl From<ClientError> for CliError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Api(api) => {
                let hint = api
                    .hint
                    .clone()
                    .unwrap_or_else(|| api_hint(&api.code, api.status));
                let mut cli = Self::new(exit_for_status(api.status), &api.code, &api.message, hint);
                cli.0.status = Some(api.status);
                cli.0.request_id.clone_from(&api.request_id);
                if let Some(details) = &api.details {
                    cli.0.details = Some(json!(details));
                }
                cli
            }
            ClientError::SignIn(sign_in) => {
                let exit = match sign_in.kind {
                    SignInErrorKind::SltRefused(_)
                    | SignInErrorKind::SessionEnded
                    | SignInErrorKind::Denied
                    | SignInErrorKind::Expired
                    | SignInErrorKind::NotEnabled => EXIT_AUTH,
                    SignInErrorKind::Unavailable { .. } => EXIT_FAILURE,
                    _ => sign_in.status.map_or(EXIT_FAILURE, exit_for_status),
                };
                let mut cli = Self::new(exit, &sign_in.code, &sign_in.message, &sign_in.hint);
                cli.0.status = sign_in.status;
                if let SignInErrorKind::SltRefused(reason) = sign_in.kind {
                    cli.0.details = Some(json!({"reason": reason.as_str()}));
                }
                cli
            }
            ClientError::Transport(error) => Self::new(
                EXIT_FAILURE,
                "hook_unreachable",
                format!("Hook could not be reached: {error}."),
                "Check the network and the Hook URL (`hook config show`; SILICON_HOOK_URL or --url), then retry.",
            ),
            ClientError::Protocol(message) => Self::new(
                EXIT_FAILURE,
                "incompatible_response",
                message,
                "Check that the Hook URL points at a Hook 1.x API (`hook system version`).",
            ),
            ClientError::Invalid(message) => Self::invalid(message, ""),
            other => Self::new(EXIT_FAILURE, "client_error", other.to_string(), ""),
        }
    }
}

fn api_hint(code: &str, status: u16) -> String {
    match (code, status) {
        ("forbidden" | "no_access", _) => "You need access to this Silicon's hooks: be the Silicon, its custodian, or an account it granted access to (`hook access list --silicon <si:id>` shows who). Creating and changing hooks needs manage access.".into(),
        ("delivery_disabled", _) => "This Hook does not deliver through Ting; it still receives and stores every event. Read them with `hook events`.".into(),
        ("api_version_sunset", _) => "Use a Hook 1.x CLI against a Hook 1.x API.".into(),
        ("account_not_found", _) => "Check the c:/si: id (ids can change), or use the account's uuid.".into(),
        ("silicon_not_found" | "not_a_silicon", _) => "Check the Silicon's si:<id> or uuid; `hook silicons` lists the ones you can open.".into(),
        ("silicon_not_reachable", _) => "That Silicon only accepts grants from accounts on its allow-list: ask it (or its custodian) to run `hook allow-list add <your id>`.".into(),
        ("already_has_access", _) => "The Silicon itself and its custodian always have full access; grants are for other accounts.".into(),
        (_, 401) => "Sign in again: `hook login` (Carbons) or `silicon-accounts login --app hook -q | hook login --slt-stdin` (Silicons).".into(),
        (_, 404) => "Check the id; `hook list` shows the Silicon's hooks and `hook silicons` the Silicons you can open.".into(),
        _ => String::new(),
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::new(EXIT_FAILURE, "io_error", error.to_string(), "")
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self::new(EXIT_FAILURE, "json_error", error.to_string(), "")
    }
}

/// Prints a result on stdout as pretty JSON.
pub fn print<T: Serialize>(value: &T) -> CliResult<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Prints one JSON object on one line (progress lines with `--json`).
pub fn print_line(value: &Value) {
    println!("{value}");
}

/// A hint or notice on stderr, unless `--json`.
pub fn hint(json: bool, text: &str) {
    if !json {
        eprintln!("{text}");
    }
}

/// Shows an error: JSON on stderr with `--json`, prose otherwise.
pub fn error(json: bool, error: &CliError, command: &str) {
    if json {
        eprintln!("{}", error.to_json());
    } else {
        eprintln!("error[{}]: {error}", error.code);
        if !command.is_empty() {
            eprintln!("Usage: hook {command} --help · all commands: hook commands");
        }
    }
}
