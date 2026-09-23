use clap::{Args, Parser, Subcommand};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "hook",
    version,
    about = "Manage signed provider webhooks and their delivery status.",
    long_about = "Manage Silicon Hook through its official Rust client. Sign in with an IAM short-lived token. Applications handle receiving internally; this CLI does not run a delivery daemon. Use the same commands in a sandbox with --test <environment-id>.",
    after_help = "Start: hook iam --json; hook login <slt> --org tos\nThen: hook --silicon cos:tos create GitHub\nInspect: hook events; hook publication <event-id>\nExplore: hook commands; hook <command> --help\nDocs: https://docs.hook.teamofsilicons.com · Source: https://github.com/teamofsilicons/silicon-hook\nRust: https://crates.io/crates/silicon-hook-client · Bugs: hook report --help"
)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        default_value = "default",
        help = "Independent local identity/profile"
    )]
    pub profile: String,
    #[arg(
        long,
        global = true,
        env = "SILICON_HOOK_URL",
        help = "Backend origin; defaults to backend.hook.teamofsilicons.com"
    )]
    pub url: Option<String>,
    #[arg(
        long,
        global = true,
        env = "SILICON_HOOK_ORG",
        help = "Organization handle in the selected production/test plane"
    )]
    pub org: Option<String>,
    #[arg(
        long,
        global = true,
        help = "Target Silicon, e.g. cos:tos; defaults to the signed-in Silicon"
    )]
    pub silicon: Option<String>,
    #[arg(
        long,
        global = true,
        help = "Test environment UUID; its root key is stored separately"
    )]
    pub test: Option<Uuid>,
    #[arg(
        long,
        global = true,
        conflicts_with = "test",
        help = "Use the separate production session for this command"
    )]
    pub production: bool,
    #[arg(
        long,
        global = true,
        help = "Structured JSON output without next-step prose"
    )]
    pub json: bool,
    #[arg(
        long,
        global = true,
        help = "Reuse this key when retrying the same mutation"
    )]
    pub idempotency_key: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Submit a bug report to GitHub using an already authenticated gh CLI. No logs or credentials are collected.
    Report {
        message: String,
        #[arg(
            long,
            help = "Optional silicon-hook GitHub pull request URL containing a fix"
        )]
        pr: Option<String>,
    },
    /// Show source, online docs and published package links.
    About,
    /// Sign in with an IAM short-lived token, or check login status.
    Login(Login),
    /// Discover the IAM app_id needed to request a short-lived token; no login needed.
    Iam,
    /// Revoke the saved refresh-token family and remove the local session.
    Logout,
    /// Show local session metadata without exposing tokens.
    Whoami,
    /// Create a named provider webhook. Signing is enabled by default.
    Create {
        name: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        time_zone: Option<String>,
        #[arg(
            long,
            help = "Signature policy JSON or @file; see hook docs signatures"
        )]
        signature: Option<String>,
        #[arg(
            long,
            help = "BYOS secret file; '-' reads stdin. Preserves spaces; removes one trailing line ending"
        )]
        secret_file: Option<String>,
        #[arg(long, help = "Accept unsigned requests for this hook")]
        unsigned: bool,
    },
    /// Set or replace a BYOS secret without changing the hook URL or other settings.
    SetSecret {
        id: Uuid,
        #[arg(
            long,
            help = "Secret file; '-' reads stdin. Preserves spaces; removes one trailing line ending"
        )]
        secret_file: String,
        #[arg(long, value_parser = ["utf8", "ascii", "hex", "base64", "base64url", "raw"])]
        secret_encoding: Option<String>,
    },
    /// List provider URLs, lifecycle state and latest receipt timestamps.
    List {
        #[arg(long)]
        include_deleted: bool,
    },
    /// Read one hook's metadata and signing policy.
    Show { id: Uuid },
    /// Update metadata/signature policy with a JSON merge patch.
    Update {
        id: Uuid,
        #[arg(
            long,
            help = "JSON or @file: name, description, time_zone, enabled, signature"
        )]
        patch: String,
    },
    /// Soft-delete a hook; recover it with restore within 45 days.
    Delete { id: Uuid },
    /// Recover a deleted hook within its 45-day retention window.
    Restore { id: Uuid },
    /// Resume ingress for one or more hooks atomically.
    Enable {
        #[arg(required = true)]
        ids: Vec<Uuid>,
    },
    /// Pause ingress for one or more hooks while preserving their URLs and history.
    Disable {
        #[arg(required = true)]
        ids: Vec<Uuid>,
    },
    /// Rotate a hook URL or signing secret.
    Rotate {
        #[command(subcommand)]
        kind: Rotate,
    },
    /// Read verified request history; omit --hook for account-wide history.
    Events(History),
    /// Read withheld request history, retained for 14 days.
    Blocked(History),
    /// Fetch one retained event and its original provider request.
    Event { id: Uuid },
    /// Inspect publication and available recipient receipts for one event.
    Publication { event_id: Uuid },
    /// Administer the organization's dedicated internal delivery publisher.
    Publisher {
        #[command(subcommand)]
        action: Publisher,
    },
    /// Manage internal receiving registration and the current Carbon's interest.
    Receiving {
        #[command(subcommand)]
        action: Receiving,
    },
    /// Register this Silicon's IAM notifications as a Hook connection.
    ConnectIam,
    /// Create, configure, reset and recover isolated testing environments.
    Env {
        #[command(subcommand)]
        action: Environment,
    },
    /// Read or change local profile settings.
    Config {
        #[command(subcommand)]
        action: Config,
    },
    /// Inspect backend readiness and API compatibility.
    System {
        #[command(subcommand)]
        action: System,
    },
    /// Discover every command and its complete usage, without signing in.
    Commands,
    /// Read bundled guides: overview, api, client, cli, iam, signatures, testing, testing-api, testing-client, testing-cli, delivery, delivery-issues, relay, contracts, configuration, telemetry, deployment.
    Docs {
        #[arg(default_value = "overview")]
        topic: String,
    },
}

#[derive(Debug, Args)]
#[command(
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    after_help = "Next: hook login status --json to verify your identity; hook list to inspect provider webhooks. Applications handle receiving internally."
)]
pub struct Login {
    #[command(subcommand)]
    pub action: Option<LoginAction>,
    #[arg(
        value_name = "SLT",
        conflicts_with_all = ["slt", "slt_file"],
        help = "IAM short-lived token (use --slt-file to avoid shell history)"
    )]
    pub token: Option<String>,
    #[arg(
        long,
        conflicts_with_all = ["slt_file", "token"],
        help = "Short-lived IAM token; --slt-file avoids shell history"
    )]
    pub slt: Option<String>,
    #[arg(
        long,
        required_unless_present_any = ["slt", "token"],
        help = "File containing only the short-lived token; '-' reads stdin"
    )]
    pub slt_file: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum LoginAction {
    /// Verify the selected identity online with IAM; does not expose tokens.
    Status,
}

#[derive(Debug, Subcommand)]
pub enum Rotate {
    Endpoint { id: Uuid },
    Secret { id: Uuid },
}
#[derive(Debug, Args)]
pub struct History {
    #[arg(long)]
    pub hook: Option<Uuid>,
    #[arg(long, default_value_t = 100, help = "Number of requests, 1–10000")]
    pub limit: u32,
    #[arg(long, help = "Opaque next_cursor returned by a prior page")]
    pub cursor: Option<String>,
}
#[derive(Debug, Subcommand)]
pub enum Publisher {
    /// Provision the publisher as a Carbon owner/admin; prints only safe metadata.
    #[command(
        after_help = "Internal application setup. Requires --idempotency-key; reuse the same key and SLT file after an interrupted request. No --silicon selection is needed."
    )]
    Provision {
        #[arg(long, help = "Dedicated publisher's Hook SLT file; '-' reads stdin")]
        slt_file: String,
        #[arg(
            long,
            help = "Explicitly recover an existing rejected publisher family"
        )]
        replace_rejected: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum Receiving {
    /// Print the validated non-secret scope for an internal testing receiver.
    Scope,
    /// Write a scoped testing capability to a new private file; starts no receiver.
    #[command(
        after_help = "Requires a selected test environment and --idempotency-key. Save `hook receiving scope` to a file first. Retry uncertainty with the same scope file and key. Renew explicitly with --receiver-id and a new key. The output file must not already exist; no token is printed and no daemon is started. Windows uses a verified owner-only ACL and may retain an empty reservation after failure; retry with a new output path and the original scope and key."
    )]
    Bootstrap {
        #[arg(long, help = "Pinned JSON scope file, retained unchanged for retries")]
        scope_file: String,
        #[arg(long, help = "New private 0600 capability file; never overwritten")]
        output: String,
        #[arg(
            long,
            help = "Existing receiver ID to renew explicitly with a new operation key"
        )]
        receiver_id: Option<String>,
    },
    /// Register the authenticated actor for internal application delivery; starts no receiver.
    Register,
    /// Read this Carbon's subscription for the selected --silicon.
    Status,
    /// Receive future events for the selected --silicon, subject to current IAM visibility.
    Subscribe,
    /// Stop this Carbon's future and queued observer sends for the selected --silicon.
    Unsubscribe,
}
#[derive(Debug, Subcommand)]
pub enum Environment {
    /// Select a sandbox with its IAM app_secret. Then run `hook login <test-slt-or-id>`.
    Use {
        #[arg(long, help = "File containing the IAM app_secret; '-' reads stdin")]
        app_secret_file: String,
    },
    /// Leave testing mode and return to the separately saved production session.
    Exit,
    /// Create an empty Hook sandbox linked to an existing IAM test environment.
    Create {
        name: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        iam_key_file: String,
        #[arg(
            long,
            help = "Optional JSON file with test app_id, app_secret, webhook_secret, webhook_secret_version"
        )]
        iam_config: Option<String>,
    },
    /// Store a root key for an existing environment, without changing backend data.
    Attach {
        id: Uuid,
        #[arg(long)]
        key_file: String,
    },
    /// List environments owned by the production organization.
    List {
        #[arg(long,default_value="active",value_parser=["active","deleted","all"])]
        status: String,
        #[arg(long, default_value_t = 100, help = "Page size, 1–1000")]
        limit: u32,
        #[arg(long, help = "Last environment UUID from the previous descending page")]
        after: Option<Uuid>,
    },
    Show {
        id: Uuid,
    },
    /// Retrieve a key as creator/org administrator; JSON output includes the secret.
    Key {
        id: Uuid,
    },
    /// Invalidate an environment root key and store the replacement locally.
    RotateKey {
        id: Uuid,
    },
    /// Soft-delete the environment; recoverable for 30 days.
    Delete {
        id: Uuid,
    },
    Restore {
        id: Uuid,
    },
    /// Read the selected test environment. Requires --test.
    Current,
    /// Erase Hook data while retaining the environment and IAM binding. Requires --test.
    Clean,
    /// Install test-only IAM application credentials from a JSON file. Requires --test.
    ConfigureIam {
        #[arg(long)]
        file: String,
    },
}
#[derive(Debug, Subcommand)]
pub enum Config {
    /// Show configuration and identity metadata; credentials are redacted.
    Show,
    /// List locally configured profile names.
    Profiles,
    /// Set the base home directory; Hook stores state below .silicon-hook.
    Home { location: String },
    /// Set url, org, silicon or telemetry for the selected profile.
    Set {
        #[arg(value_parser=["url","org","silicon","telemetry"])]
        key: String,
        value: String,
    },
}
#[derive(Debug, Subcommand)]
pub enum System {
    Version,
    Health,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_supports_token_only_and_status_without_tokens() {
        let cli = Cli::try_parse_from(["hook", "login", "opaque-slt"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Login(Login { token: Some(_), .. })
        ));
        let cli = Cli::try_parse_from(["hook", "login", "status", "--json"]).unwrap();
        assert!(cli.json);
        assert!(matches!(
            cli.command,
            Command::Login(Login {
                action: Some(LoginAction::Status),
                ..
            })
        ));
        assert!(Cli::try_parse_from(["hook", "login"]).is_err());
        assert!(Cli::try_parse_from(["hook", "login", "status", "--slt", "secret"]).is_err());
    }

    #[test]
    fn receiving_and_discovery_support_test_context() {
        for command in [
            vec!["iam", "--json"],
            vec!["receiving", "register"],
            vec!["receiving", "status"],
            vec!["receiving", "subscribe"],
            vec!["receiving", "unsubscribe"],
            vec!["event", "00000000-0000-4000-8000-000000000001"],
            vec!["publication", "00000000-0000-4000-8000-000000000001"],
        ] {
            let mut args = vec![
                "hook",
                "--profile",
                "reviewer",
                "--test",
                "00000000-0000-4000-8000-000000000001",
            ];
            args.extend(command);
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(cli.test.is_some());
            assert_eq!(cli.profile, "reviewer");
        }
    }

    #[test]
    fn retired_transports_and_login_destination_flags_are_not_accepted() {
        for command in [
            vec!["webhook", "http://127.0.0.1/events"],
            vec!["unhook"],
            vec!["daemon", "start"],
            vec!["listen"],
            vec!["deliveries", "cursor"],
            vec!["deliveries", "ack", "1"],
            vec!["login", "slt", "--webhook-url", "http://127.0.0.1/events"],
            vec!["--isi", "internal-id", "iam"],
        ] {
            let mut args = vec!["hook"];
            args.extend(command);
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn byos_commands_support_files_stdin_and_test_context() {
        let id = "00000000-0000-4000-8000-000000000001";
        for command in [
            vec!["create", "Stripe", "--secret-file", "-"],
            vec![
                "set-secret",
                id,
                "--secret-file",
                "provider.txt",
                "--secret-encoding",
                "hex",
            ],
        ] {
            let mut args = vec!["hook", "--test", id];
            args.extend(command);
            assert!(Cli::try_parse_from(args).is_ok());
        }
        assert!(Cli::try_parse_from(["hook", "set-secret", id]).is_err());
        assert!(
            Cli::try_parse_from([
                "hook",
                "set-secret",
                id,
                "--secret-file",
                "-",
                "--secret-encoding",
                "invalid"
            ])
            .is_err()
        );
    }
}
