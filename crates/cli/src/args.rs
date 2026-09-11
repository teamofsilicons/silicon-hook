use clap::{Args, Parser, Subcommand};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "hook",
    version,
    about = "Signed webhooks for Silicons, with reliable local delivery.",
    long_about = "Manage Silicon Hook through its official Rust client. Sign in with an IAM short-lived token, then configure your delivery URL with hook webhook. Use the same commands in a sandbox with --test <environment-id>.",
    after_help = "Start: hook iam --json; hook login <slt> --org tos\nDelivery: hook webhook http://127.0.0.1:9000/events\nThen: hook --silicon cos:tos create GitHub\nExplore: hook commands; hook <command> --help"
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
        help = "Test environment UUID; its root key is stored separately",
        env = "SILICON_HOOK_TEST"
    )]
    pub test: Option<Uuid>,
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
    /// Sign in with an IAM short-lived token, or check login status.
    Login(Login),
    /// Discover the IAM app_id needed to request a short-lived token; no login needed.
    Iam,
    /// Configure or replace this identity's local delivery URL and start its relay.
    Webhook { webhook_url: String },
    /// Detach this identity's local delivery URL, retaining login and pending events.
    Unhook,
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
        #[arg(long, help = "Accept unsigned requests for this hook")]
        unsigned: bool,
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
    /// Pull, acknowledge or inspect durable delivery positions.
    Deliveries {
        #[command(subcommand)]
        action: Deliveries,
    },
    /// Register this Silicon's IAM notifications as a Hook connection.
    ConnectIam,
    /// Read a live WebSocket stream; answer heartbeats automatically.
    Listen {
        #[arg(long, help = "Acknowledge each event after it is written to stdout")]
        ack: bool,
    },
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
    /// Manage the persistent local relay and identity-specific subscriptions.
    Daemon {
        #[command(subcommand)]
        action: Daemon,
    },
    /// Inspect backend readiness and API compatibility.
    System {
        #[command(subcommand)]
        action: System,
    },
    /// Discover every command and its complete usage, without signing in.
    Commands,
    /// Read bundled guides: overview, api, client, cli, iam, signatures, testing, testing-api, testing-client, testing-cli, relay.
    Docs {
        #[arg(default_value = "overview")]
        topic: String,
    },
}

#[derive(Debug, Args)]
#[command(
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    after_help = "Next: hook webhook <webhook-url> to receive events; hook login status --json to verify your identity."
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
    #[arg(
        long,
        help = "Local recipient URL; retained locally and never sent to the backend"
    )]
    pub webhook_url: Option<String>,
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
pub enum Deliveries {
    /// Pull pending events without acknowledging them.
    List {
        #[arg(long, default_value_t = 100)]
        limit: u32,
        #[arg(long)]
        after: Option<i64>,
    },
    /// Confirm all deliveries through this contiguous sequence.
    Ack { through: i64 },
    /// Read this identity's stored acknowledgment cursor.
    Cursor,
}
#[derive(Debug, Subcommand)]
pub enum Environment {
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
    /// Set url, org, silicon, auto-update, or the local relay port.
    Set {
        #[arg(value_parser=["url","org","silicon","auto-update","relay-port"])]
        key: String,
        value: String,
    },
}
#[derive(Debug, Subcommand)]
pub enum System {
    Version,
    Health,
}

#[derive(Debug, Subcommand)]
pub enum Daemon {
    /// Start the background relay, if it is not already running.
    Start,
    /// Run in the foreground; useful under a service manager.
    Run,
    /// Show daemon health and number of configured identities.
    Status,
    /// Stop the relay; backend events remain pending for replay.
    Stop,
    /// Replace the selected identity's subscribed Silicons. No IDs unsubscribes all.
    Subscribe { silicons: Vec<String> },
    /// Print the selected identity's local API token. Treat the output as a secret.
    Token,
    /// Send a LocalRequest JSON file through this identity and echo the exact receipt.
    Request {
        #[arg(long)]
        file: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_supports_token_only_and_status_without_tokens() {
        let cli = Cli::try_parse_from(["hook", "login", "opaque-slt"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Login(Login {
                token: Some(_),
                webhook_url: None,
                ..
            })
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
    fn delivery_and_discovery_support_test_context() {
        for command in [
            vec!["iam", "--json"],
            vec!["webhook", "http://127.0.0.1/events"],
            vec!["unhook"],
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
}
