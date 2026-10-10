//! Unit tests: argument parsing, state storage, legacy state, target selection
//! and secret files. The binary's behaviour end to end is in `tests/`.

use clap::Parser as _;
use silicon_hook_client::{Secret, models::AccountKind};

use crate::{
    args::{Access, Cli, Command, LoginAction},
    commands::read_secret,
    session,
    store::{self, Locked, Profile, Session, SessionAccount},
};

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    let mut all = vec!["hook"];
    all.extend_from_slice(args);
    Cli::try_parse_from(all)
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("hook-unit-{name}-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn session(kind: AccountKind) -> Session {
    Session {
        app_id: "hook".into(),
        accounts_url: "http://localhost:9590".into(),
        url: "http://127.0.0.1:4201".into(),
        access_token: Secret::new("at"),
        refresh_token: Some(Secret::new("sar_1")),
        expires_at: store::now() + 1800,
        refresh_expires_at: None,
        scope: None,
        account: SessionAccount {
            uuid: "Sx1".into(),
            kind,
            id: "si:scout".into(),
            display_name: String::new(),
        },
        method: "slt".into(),
        signed_in_at: store::now(),
        refresh_started_at: None,
    }
}

#[test]
fn login_without_arguments_is_the_device_flow_and_status_is_a_subcommand() {
    let cli = parse(&["login"]).expect("device flow");
    let Command::Login(login) = &cli.command else {
        panic!()
    };
    assert!(
        login.action.is_none() && login.token.is_none() && login.slt.is_none() && !login.slt_stdin
    );
    let cli = parse(&["login", "status", "--json"]).expect("status");
    assert!(cli.json);
    let Command::Login(login) = &cli.command else {
        panic!()
    };
    assert!(matches!(
        login.action,
        Some(LoginAction::Status { offline: false })
    ));
    let cli = parse(&["login", "status", "--offline"]).expect("offline");
    let Command::Login(login) = &cli.command else {
        panic!()
    };
    assert!(matches!(
        login.action,
        Some(LoginAction::Status { offline: true })
    ));
}

#[test]
fn a_short_lived_token_is_accepted_positionally_by_flag_or_on_stdin_but_only_once() {
    for args in [
        vec!["login", "slt_abc"],
        vec!["login", "--slt", "slt_abc"],
        vec!["login", "--slt-stdin"],
        vec!["login", "--slt-file", "-"],
    ] {
        assert!(parse(&args).is_ok(), "{args:?}");
    }
    for args in [
        vec!["login", "slt_abc", "--slt", "slt_def"],
        vec!["login", "--slt", "slt_abc", "--slt-stdin"],
        vec!["login", "slt_abc", "--slt-stdin"],
        vec!["login", "status", "--slt", "slt_abc"],
    ] {
        assert!(parse(&args).is_err(), "{args:?}");
    }
}

#[test]
fn discovery_and_hidden_compatibility_commands_parse() {
    assert!(matches!(
        parse(&["accounts", "--json"]).expect("accounts").command,
        Command::Accounts
    ));
    assert!(matches!(
        parse(&["iam", "--json"]).expect("iam").command,
        Command::Iam
    ));
    let help = <Cli as clap::CommandFactory>::command()
        .render_long_help()
        .to_string();
    let words: Vec<String> = help
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        .map(str::to_ascii_lowercase)
        .collect();
    for word in [
        "iam",
        "org",
        "orgs",
        "honeycomb",
        "organization",
        "organisation",
        "human",
        "team",
    ] {
        assert!(!words.iter().any(|w| w == word), "help mentions {word}");
    }
    assert!(!help.contains("test environment"));
}

#[test]
fn retired_commands_are_rejected_and_retired_flags_explain_themselves() {
    for args in [
        vec!["env", "list"],
        vec!["publisher", "provision", "--slt-file", "-"],
        vec!["connect-iam"],
        vec!["receiving", "authorize"],
        vec![
            "receiving",
            "bootstrap",
            "--scope-file",
            "a",
            "--output",
            "b",
        ],
        vec!["webhook", "http://127.0.0.1/events"],
        vec!["unhook"],
        vec!["daemon", "start"],
        vec!["listen"],
        vec!["config", "set", "org", "tos"],
    ] {
        assert!(parse(&args).is_err(), "{args:?}");
    }
    let cli = parse(&["--org", "tos", "list"]).expect("hidden flag parses");
    let error = crate::removed_flags(&cli).expect_err("--org is refused");
    assert_eq!(error.code, "invalid_input");
    assert!(
        error
            .hint
            .as_deref()
            .unwrap_or_default()
            .contains("--silicon")
    );
    let cli = parse(&["--test", "00000000-0000-4000-8000-000000000001", "list"]).expect("parses");
    assert!(crate::removed_flags(&cli).is_err());
    assert!(crate::removed_flags(&parse(&["list"]).expect("plain")).is_ok());
}

#[test]
fn access_grants_need_a_level() {
    assert!(parse(&["access", "grant", "c:ada"]).is_err());
    assert!(parse(&["access", "grant", "c:ada", "--level", "admin"]).is_err());
    let cli = parse(&[
        "--silicon",
        "si:scout",
        "access",
        "grant",
        "c:ada",
        "--level",
        "manage",
    ])
    .expect("grant");
    let Command::Access {
        action: Access::Grant { account, level },
    } = &cli.command
    else {
        panic!()
    };
    assert_eq!((account.as_str(), level.as_str()), ("c:ada", "manage"));
}

#[test]
fn the_target_is_the_flag_then_the_profile_then_the_signed_in_silicon() {
    let silicon = session(AccountKind::Silicon);
    let carbon = session(AccountKind::Carbon);
    let mut profile = Profile::default();
    let plain = parse(&["list"]).expect("list");
    assert_eq!(
        session::target(&plain, &profile, &silicon).expect("own uuid"),
        "Sx1"
    );
    let error = session::target(&plain, &profile, &carbon).expect_err("a Carbon must choose");
    assert!(
        error
            .hint
            .as_deref()
            .unwrap_or_default()
            .contains("hook silicons")
    );
    profile.silicon = Some("si:saved".into());
    assert_eq!(
        session::target(&plain, &profile, &carbon).expect("saved"),
        "si:saved"
    );
    let flagged = parse(&["--silicon", "Zq7", "list"]).expect("flag");
    assert_eq!(
        session::target(&flagged, &profile, &carbon).expect("flag wins"),
        "Zq7"
    );
    let wrong = parse(&["--silicon", "c:ada", "list"]).expect("parses");
    assert!(
        session::target(&wrong, &profile, &carbon).is_err(),
        "a Carbon id is not a Silicon"
    );
    let odd = parse(&["--silicon", "si:a/b", "list"]).expect("parses");
    assert!(session::target(&odd, &profile, &carbon).is_err());
}

#[test]
fn a_session_is_bound_to_its_accounts_and_hook_urls() {
    let stored = session(AccountKind::Silicon);
    let profile = Profile::default();
    let matching = parse(&[
        "--url",
        "http://127.0.0.1:4201/",
        "--accounts-url",
        "http://localhost:9590",
        "list",
    ])
    .expect("parse");
    assert!(session::binding_problem(&stored, &session::urls(&matching, &profile)).is_none());
    let other_hook = parse(&[
        "--url",
        "http://127.0.0.1:9999",
        "--accounts-url",
        "http://localhost:9590",
        "list",
    ])
    .expect("parse");
    let problem =
        session::binding_problem(&stored, &session::urls(&other_hook, &profile)).expect("bound");
    assert_eq!(problem.code, "signed_in_elsewhere");
    let other_accounts = parse(&[
        "--url",
        "http://127.0.0.1:4201",
        "--accounts-url",
        "https://accounts.teamofsilicons.com",
        "list",
    ])
    .expect("parse");
    assert!(session::binding_problem(&stored, &session::urls(&other_accounts, &profile)).is_some());
}

#[cfg(unix)]
fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn state_is_private_atomic_and_round_trips() {
    let base = temp_dir("state");
    let folder = base.join(".silicon-hook");
    let (mut locked, notice) = Locked::open_in(folder.clone(), false).expect("open");
    assert!(notice.is_none());
    locked.profile("default").session = Some(session(AccountKind::Silicon));
    locked.profile("default").telemetry = false;
    locked.save().expect("save");
    drop(locked);
    #[cfg(unix)]
    {
        assert_eq!(mode(&folder), 0o700);
        assert_eq!(mode(&folder.join(store::STATE_FILE)), 0o600);
        assert_eq!(mode(&folder.join(store::LOCK_FILE)), 0o600);
    }
    let leftovers: Vec<_> = std::fs::read_dir(&folder)
        .expect("dir")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "no temporary files remain");
    let loaded = store::read(&folder).expect("read");
    let profile = loaded.profile("default");
    assert!(!profile.telemetry);
    assert_eq!(profile.session.expect("session").account.uuid, "Sx1");
    std::fs::remove_dir_all(base).ok();
}

#[test]
fn the_lock_serializes_changes() {
    let base = temp_dir("lock");
    let folder = base.join(".silicon-hook");
    let (first, _) = Locked::open_in(folder.clone(), false).expect("first");
    let (sender, receiver) = std::sync::mpsc::channel();
    let other = folder.clone();
    let waiter = std::thread::spawn(move || {
        let (_second, _) = Locked::open_in(other, false).expect("second");
        sender.send(()).expect("send");
    });
    assert!(
        receiver
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_err(),
        "a second holder must wait for the lock"
    );
    drop(first);
    receiver
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the second holder proceeds once the first unlocks");
    waiter.join().expect("join");
    std::fs::remove_dir_all(base).ok();
}

#[test]
fn an_unreadable_state_file_is_reported_and_only_a_sign_in_moves_it_aside() {
    let base = temp_dir("corrupt");
    let folder = base.join(".silicon-hook");
    std::fs::create_dir_all(&folder).expect("dir");
    std::fs::write(folder.join(store::STATE_FILE), b"{not json").expect("write");
    let loaded = store::read(&folder).expect("read never fails on content");
    assert!(loaded.unreadable.is_some());
    let error = Locked::open_in(folder.clone(), false)
        .err()
        .expect("refused");
    assert_eq!(error.code, "state_unreadable");
    let (locked, notice) = Locked::open_in(folder.clone(), true).expect("recovered");
    assert!(notice.expect("notice").contains("moved to"));
    drop(locked);
    let kept = std::fs::read_dir(&folder)
        .expect("dir")
        .filter_map(Result::ok)
        .any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("profiles.json.unreadable-")
        });
    assert!(kept, "the unreadable file is kept for inspection");
    std::fs::remove_dir_all(base).ok();
}

#[test]
fn pre_1_0_state_contributes_settings_but_never_credentials() {
    let base = temp_dir("legacy");
    let folder = base.join(".silicon-hook");
    std::fs::create_dir_all(&folder).expect("dir");
    let legacy = serde_json::json!({"profiles": {
        "default": {"url": "https://api.hook.teamofsilicons.com", "org": "tos", "silicon": "si:cos",
            "telemetry": false, "session": {"tokens": {"access_token": "oat_secret", "refresh_token": "ort_secret"}}},
        "lab": {"url": "http://127.0.0.1:8080", "org": null, "silicon": null, "session": null,
            "test_sessions": {"00000000-0000-4000-8000-000000000001": {}}},
        "fresh": {"url": "https://api.hook.teamofsilicons.com", "session": null}
    }});
    let bytes = serde_json::to_vec(&legacy).expect("json");
    std::fs::write(folder.join(store::LEGACY_FILE), &bytes).expect("write");
    let loaded = store::read(&folder).expect("read");
    let default = loaded.profile("default");
    assert!(default.previous_version_session && default.session.is_none());
    assert_eq!(default.silicon.as_deref(), Some("si:cos"));
    assert!(!default.telemetry, "an opt-out survives the upgrade");
    assert_eq!(default.url, None, "the production URL is the default again");
    let lab = loaded.profile("lab");
    assert!(lab.previous_version_session);
    assert_eq!(lab.url.as_deref(), Some("http://127.0.0.1:8080"));
    assert!(!loaded.profile("fresh").previous_version_session);
    let saved = serde_json::to_string(&loaded.state).expect("json");
    assert!(
        !saved.contains("oat_secret") && !saved.contains("ort_secret") && !saved.contains("tos")
    );
    assert_eq!(
        std::fs::read(folder.join(store::LEGACY_FILE)).expect("read"),
        bytes,
        "untouched"
    );
    std::fs::write(folder.join(store::LEGACY_FILE), b"garbage").expect("write");
    assert!(
        store::read(&folder)
            .expect("tolerated")
            .state
            .profiles
            .is_empty()
    );
    std::fs::remove_dir_all(base).ok();
}

#[test]
fn secret_files_keep_spaces_and_refuse_empty_multiline_or_control_characters() {
    let path = std::env::temp_dir().join(format!("hook-byos-{}", uuid::Uuid::now_v7()));
    let text = path.to_str().expect("utf-8 path").to_owned();
    for ending in ["", "\n", "\r\n"] {
        std::fs::write(&path, format!(" provider secret {ending}")).expect("write");
        assert_eq!(
            read_secret(&text).expect("secret").expose(),
            " provider secret "
        );
    }
    for value in ["", "\n", "first\nsecond", "first\n\n", "tab\there"] {
        std::fs::write(&path, value).expect("write");
        assert!(read_secret(&text).is_err(), "{value:?}");
    }
    std::fs::write(&path, "x".repeat(4097)).expect("write");
    assert!(read_secret(&text).is_err());
    std::fs::remove_file(path).ok();
}
