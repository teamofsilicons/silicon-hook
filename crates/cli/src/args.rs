use clap::{Args, Parser, Subcommand};
use uuid::Uuid;

const AFTER_HELP: &str = "\
Start:
  hook accounts --json                      what signing in needs (works offline)
  hook login                                Carbons: approve a code in the browser
  silicon-accounts login --app hook -q | hook login --slt-stdin
                                            Silicons: sign in with a short-lived token
  hook login status --json                  who you are signed in as
Then:
  hook create GitHub                        a hook for the signed-in Silicon
  hook --silicon si:scout list              a Silicon you look after
  hook events                               verified requests, newest first
Explore: hook commands · hook <command> --help · hook docs <topic>
Docs: https://docs.hook.teamofsilicons.com · Source: https://github.com/teamofsilicons/silicon-hook
Rust: https://crates.io/crates/silicon-hook-client · Bugs: hook report --help";

#[derive(Debug, Parser)]
#[command(
    name = "hook",
    version,
    about = "Signed provider webhooks for Silicons: create the URLs providers call, verify every request, read the history.",
    long_about = "Silicon Hook gives each Silicon its own signed webhook URLs. Providers (GitHub, Stripe, ...) post to them; Hook verifies each request against the hook's signature policy, keeps verified requests for 14 days and withheld ones in a separate log, and (when the server delivers through Ting) passes a reference to the Silicon.\n\nA Silicon's hooks belong to it. The Silicon and its custodian (the Carbon who looks after it) can do everything; they can give other Carbons and Silicons view or manage access.\n\nSign in with Silicon Accounts: Carbons run `hook login`; Silicons pipe a short-lived token from `silicon-accounts login --app hook -q` into `hook login --slt-stdin`. Results print as JSON on stdout; hints go to stderr (silenced by --json).",
    after_help = AFTER_HELP
)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        default_value = "default",
        help = "Saved profile: its own sign-in and settings, in the same state directory"
    )]
    pub profile: String,
    #[arg(
        long,
        global = true,
        env = "SILICON_HOOK_URL",
        help = "Hook API origin [default: https://backend.hook.teamofsilicons.com]"
    )]
    pub url: Option<String>,
    #[arg(
        long,
        global = true,
        env = "ACCOUNTS_URL",
        help = "Silicon Accounts origin [default: https://accounts.teamofsilicons.com]"
    )]
    pub accounts_url: Option<String>,
    #[arg(
        long,
        global = true,
        value_name = "SI:ID|UUID",
        help = "The Silicon to act on; defaults to `hook config set silicon`, else the signed-in Silicon"
    )]
    pub silicon: Option<String>,
    #[arg(
        long,
        global = true,
        help = "JSON only: no hints on stderr; errors as JSON on stderr"
    )]
    pub json: bool,
    #[arg(
        long,
        global = true,
        help = "Reuse this key when retrying the same change after an uncertain result"
    )]
    pub idempotency_key: Option<String>,
    /// Removed in 1.0; kept only to explain the change.
    #[arg(long, global = true, hide = true)]
    pub org: Option<String>,
    /// Removed in 1.0; kept only to explain the change.
    #[arg(long, global = true, hide = true)]
    pub test: Option<String>,
    /// Removed in 1.0; kept only to explain the change.
    #[arg(long, global = true, hide = true)]
    pub production: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Sign in with Silicon Accounts (Carbons: device code; Silicons: short-lived token), or check the sign-in with `login status`.
    Login(Login),
    /// Sign out: revoke this profile's sign-in at Silicon Accounts and forget it locally.
    Logout,
    /// Show the saved sign-in without contacting any service.
    Whoami,
    /// What signing in to Hook needs: app id, Silicon Accounts URL, API URL, version. Works offline, signed out.
    Accounts,
    #[command(hide = true)]
    Iam,
    /// List the Silicons you can open: yourself, the Silicons you look after, and the ones shared with you.
    Silicons,
    /// Create a provider webhook for the Silicon. Signing is on by default; the generated secret prints once.
    #[command(
        after_help = "Examples:\n  hook create GitHub --signature @github-policy.json\n  hook create Stripe --secret-file stripe-secret.txt\n  hook create LocalDemo --unsigned\nThe URL to give the provider is endpoint_url. See `hook docs signatures` for policies."
    )]
    Create {
        /// Provider name, used in event summaries (e.g. GitHub).
        name: String,
        #[arg(long, help = "Free text")]
        description: Option<String>,
        #[arg(long, help = "IANA time zone for event summaries [default: UTC]")]
        time_zone: Option<String>,
        #[arg(
            long,
            help = "Signature policy as JSON or @file; see hook docs signatures"
        )]
        signature: Option<String>,
        #[arg(
            long,
            help = "Bring your own secret from a file ('-' reads stdin); spaces kept, one trailing line ending removed"
        )]
        secret_file: Option<String>,
        #[arg(long, help = "Accept unsigned requests (no verification)")]
        unsigned: bool,
    },
    /// Set or replace a hook's secret (bring your own secret); the URL and policy stay.
    SetSecret {
        id: Uuid,
        #[arg(
            long,
            help = "Secret file; '-' reads stdin. Spaces kept; one trailing line ending removed"
        )]
        secret_file: String,
        #[arg(long, value_parser = ["utf8", "ascii", "hex", "base64", "base64url", "raw"])]
        secret_encoding: Option<String>,
    },
    /// List the Silicon's hooks: provider URL, state, last request.
    List {
        #[arg(long, help = "Also show deleted hooks that can still be restored")]
        include_deleted: bool,
    },
    /// Show one hook's settings and signing policy (never its secret).
    Show { id: Uuid },
    /// Change a hook with a JSON patch: name, description, time_zone, enabled, signature.
    Update {
        id: Uuid,
        #[arg(
            long,
            help = "JSON or @file, e.g. '{\"description\":null}' clears the description"
        )]
        patch: String,
    },
    /// Delete a hook; restore it within 45 days.
    Delete { id: Uuid },
    /// Restore a deleted hook with its URL and secret.
    Restore { id: Uuid },
    /// Resume ingress for one or more hooks (all or nothing).
    Enable {
        #[arg(required = true)]
        ids: Vec<Uuid>,
    },
    /// Pause ingress for one or more hooks; URLs and history stay.
    Disable {
        #[arg(required = true)]
        ids: Vec<Uuid>,
    },
    /// Rotate a hook's URL (the old one is retired for good) or its signing secret.
    Rotate {
        #[command(subcommand)]
        kind: Rotate,
    },
    /// Read verified requests, newest first; --hook for one hook, else the whole Silicon.
    Events(History),
    /// Read withheld (unverified) requests, kept 14 days.
    Blocked(History),
    /// Fetch one retained event with its original provider request.
    Event { id: Uuid },
    /// Where one event's delivery through Ting stands.
    Publication { event_id: Uuid },
    /// Who can see and manage the Silicon's hooks: list, grant, revoke, leave.
    Access {
        #[command(subcommand)]
        action: Access,
    },
    /// Accounts the Silicon accepts access grants from although their custodian is not its custodian.
    AllowList {
        #[command(subcommand)]
        action: AllowList,
    },
    /// Receive the Silicon's own Silicon Accounts events (sign-outs, id changes...) in a hook.
    #[command(
        after_help = "Flow:\n  1. hook connect-accounts                     prints the hook URL and the silicon-accounts command\n  2. silicon-accounts webhook set <url>        (the Silicon) prints a whsec_ secret once\n     silicon-accounts silicon webhook set <si:id> <url>   (its custodian)\n  3. hook connect-accounts --secret-file -     stores that secret on the hook\nUntil the secret is stored, deliveries are withheld as unverified."
    )]
    ConnectAccounts {
        #[arg(
            long,
            help = "Store the whsec_ secret Silicon Accounts printed ('-' reads stdin)"
        )]
        secret_file: Option<String>,
    },
    /// Delivery through Ting: enrol yourself, and (Carbons) subscribe to a Silicon's events.
    Receiving {
        #[command(subcommand)]
        action: Receiving,
    },
    /// Read or change local settings: URLs, default Silicon, telemetry, home directory.
    Config {
        #[command(subcommand)]
        action: Config,
    },
    /// Check the Hook API: version, readiness, delivery.
    System {
        #[command(subcommand)]
        action: System,
    },
    /// List every command path; --json adds each command's full help. No sign-in needed.
    Commands,
    /// Read the bundled guides offline: overview, signin, cli, client, receiving, signatures, delivery, contracts, configuration, telemetry, deployment, releases.
    Docs {
        #[arg(default_value = "overview")]
        topic: String,
    },
    /// File a bug report on GitHub with your authenticated gh CLI (only your text and the version are sent).
    Report {
        message: String,
        #[arg(long, help = "A silicon-hook pull request with a fix")]
        pr: Option<String>,
    },
    /// Show the source repository, docs, packages and version.
    About,
}

#[derive(Debug, Args)]
#[command(
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    after_help = "Carbons:  hook login            prints a code and a URL; approve it in a browser (10 minutes)\nSilicons: silicon-accounts login --app hook -q | hook login --slt-stdin\n          hook login <SLT> and --slt <SLT> also work (the token is single use, two minutes)\nThen:     hook login status --json"
)]
pub struct Login {
    #[command(subcommand)]
    pub action: Option<LoginAction>,
    #[arg(
        value_name = "SLT",
        conflicts_with_all = ["slt", "slt_stdin", "slt_file"],
        help = "Short-lived token from `silicon-accounts login --app hook -q` (prefer --slt-stdin)"
    )]
    pub token: Option<String>,
    #[arg(long, conflicts_with_all = ["slt_stdin", "slt_file"], help = "Short-lived token; visible to other processes, prefer --slt-stdin")]
    pub slt: Option<String>,
    #[arg(
        long,
        conflicts_with = "slt_file",
        help = "Read the short-lived token from stdin"
    )]
    pub slt_stdin: bool,
    #[arg(
        long,
        hide = true,
        help = "File holding the short-lived token; '-' reads stdin"
    )]
    pub slt_file: Option<String>,
    #[arg(
        long,
        help = "Device sign-in: also open the approval page in a browser"
    )]
    pub open: bool,
    #[arg(long, help = "Device sign-in: name this machine on the approval page")]
    pub label: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum LoginAction {
    /// Who this profile is signed in as. Refreshes the sign-in when needed and asks Hook to confirm it; --offline reads only the saved file.
    #[command(
        after_help = "With --json the exit code is always 0: {\"authenticated\":false} when signed out; when signed in: uuid, id, kind, display_name, expires_at, refresh_expires_at, verified. Without --json it exits 1 when signed out."
    )]
    Status {
        #[arg(long, help = "Read only the saved sign-in; contact no service")]
        offline: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum Rotate {
    /// Retire the hook's URL for good and issue a new one.
    Endpoint { id: Uuid },
    /// Generate a new signing secret (prints once); the old one stops verifying.
    Secret { id: Uuid },
}

#[derive(Debug, Args)]
pub struct History {
    #[arg(long, help = "Only this hook")]
    pub hook: Option<Uuid>,
    #[arg(long, default_value_t = 100, help = "How many, 1 to 10000")]
    pub limit: u32,
    #[arg(long, help = "next_cursor from the previous page")]
    pub cursor: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Access {
    /// Who has access to the Silicon's hooks, and your own access.
    List,
    /// Give a Carbon or Silicon view or manage access (the Silicon or its custodian only).
    Grant {
        #[arg(value_name = "C:ID|SI:ID|UUID")]
        account: String,
        #[arg(long, value_parser = ["view", "manage"], help = "view: read hooks and history; manage: also create and change hooks")]
        level: String,
    },
    /// Remove an account's access (the Silicon or its custodian only).
    Revoke {
        #[arg(value_name = "C:ID|SI:ID|UUID")]
        account: String,
    },
    /// Give up your own access to the Silicon.
    Leave,
}

#[derive(Debug, Subcommand)]
pub enum AllowList {
    /// The accounts on the Silicon's allow-list.
    List,
    /// Allow an account (and its Silicons' grants) to give this Silicon access.
    Add {
        #[arg(value_name = "C:ID|SI:ID|UUID")]
        account: String,
    },
    /// Remove an account; grants it already gave stay until revoked.
    Remove {
        #[arg(value_name = "C:ID|SI:ID|UUID")]
        account: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum Receiving {
    /// Enrol yourself with Ting to receive Hook's notifications (when the server delivers through Ting).
    Register,
    /// Your (a Carbon's) subscription to the Silicon's events.
    Status,
    /// Receive copies of the Silicon's future events (Carbons with access).
    Subscribe,
    /// Stop receiving copies of the Silicon's events.
    Unsubscribe,
}

#[derive(Debug, Subcommand)]
pub enum Config {
    /// Show the settings in effect and where each comes from; tokens are never shown.
    Show,
    /// List the saved profiles.
    Profiles,
    /// Keep state under `<location>/.silicon-hook` from now on (the directory must exist).
    Home { location: String },
    /// Set url, accounts-url, silicon or telemetry (on|off) for the profile.
    Set {
        #[arg(value_parser = ["url", "accounts-url", "silicon", "telemetry"])]
        key: String,
        value: String,
    },
    /// Go back to the default for url, accounts-url or silicon.
    Unset {
        #[arg(value_parser = ["url", "accounts-url", "silicon"])]
        key: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum System {
    /// The Hook API's version and the API major it serves (no sign-in).
    Version,
    /// Whether the Hook API is ready (no sign-in).
    Health,
    /// Whether this Hook delivers events through Ting (needs sign-in).
    Delivery,
}
