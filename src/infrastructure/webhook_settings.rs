//! Whether Silicon Accounts delivers Hook's app webhook the way Hook needs it.
//!
//! Hook acts on six account events. They arrive only while the app webhook
//! points at Hook's `/webhook`, holds a signing secret, is active, and includes
//! the updates that carry them. Update picks made elsewhere survive setting the
//! URL again (Silicon Apps' recommended set leaves out `custodian_change`), so
//! `hook-api` reads the settings once at startup and warns about anything that
//! would make it miss events. Nothing here blocks startup.

use serde_json::Value;

/// The updates Hook acts on, each with what is lost without it.
pub const REQUIRED_UPDATES: &[(&str, &str)] = &[
    (
        "id_change",
        "new c:/si: ids show up only when Hook next sees a token or looks the account up",
    ),
    (
        "custodian_change",
        "a Silicon's new custodian gains access to its hooks, and the previous one loses it, only when Hook checks the custodian again (up to 5 minutes later)",
    ),
    (
        "access_removed",
        "sign-outs and removed access go unseen, so earlier tokens keep working until they expire on routes that do not ask Silicon Accounts",
    ),
    (
        "account_deleted",
        "a deleted Silicon's hooks keep accepting requests until Hook next looks it up",
    ),
];

/// What is wrong with Hook's webhook settings as Silicon Accounts returned
/// them (`GET /v1/apps/{app_id}/webhook`), one sentence each; empty when
/// nothing is. `expected_url` is this Hook's own `/webhook` URL.
#[must_use]
pub fn findings(settings: &Value, expected_url: &str) -> Vec<String> {
    let mut found = Vec::new();
    let Some(url) = settings.get("url").and_then(Value::as_str) else {
        found.push(format!(
            "Hook's Silicon Accounts webhook is not set, so account changes never reach Hook: point it at {expected_url} with every update (\"events\": null)"
        ));
        return found;
    };
    if url.trim_end_matches('/') != expected_url.trim_end_matches('/') {
        found.push(format!(
            "Silicon Accounts sends Hook's account events to {url}, not to this Hook ({expected_url})"
        ));
    }
    if settings.get("secret_set").and_then(Value::as_bool) == Some(false) {
        found.push(
            "Hook's Silicon Accounts webhook has no signing secret, so Hook refuses every delivery"
                .to_owned(),
        );
    }
    if let Some(status) = settings.get("status").and_then(Value::as_str)
        && status != "active"
    {
        found.push(format!(
            "Hook's Silicon Accounts webhook is {status}: nothing is delivered until it is active again"
        ));
    }
    if let Some(picked) = settings.get("events").and_then(Value::as_array) {
        let picked: Vec<&str> = picked.iter().filter_map(Value::as_str).collect();
        for (update, consequence) in REQUIRED_UPDATES {
            if !picked.contains(update) {
                found.push(format!(
                    "Hook's Silicon Accounts webhook does not receive the `{update}` update: {consequence}. Set it again with \"events\": null (every update)"
                ));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::findings;

    const URL: &str = "https://api.hook.teamofsilicons.com/webhook";

    #[test]
    fn every_update_to_this_hook_needs_no_warning() {
        let settings = json!({"url": URL, "secret_set": true, "events": null, "status": "active"});
        assert!(findings(&settings, URL).is_empty());
        let trailing = json!({"url": format!("{URL}/"), "secret_set": true, "events": null});
        assert!(findings(&trailing, URL).is_empty());
        let all = json!({"url": URL, "secret_set": true, "status": "active",
            "events": ["id_change", "custodian_change", "access_removed", "account_deleted", "pfp_change"]});
        assert!(findings(&all, URL).is_empty());
    }

    #[test]
    fn the_recommended_picks_miss_custodian_changes() {
        let recommended = json!({"url": URL, "secret_set": true, "status": "active",
            "events": ["id_change", "display_name_change", "pfp_change", "access_removed", "account_deleted"]});
        let found = findings(&recommended, URL);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("`custodian_change`"), "{found:?}");
    }

    #[test]
    fn unset_elsewhere_secretless_or_paused_webhooks_are_named() {
        assert!(findings(&json!({"url": null, "secret_set": false}), URL)[0].contains("not set"));
        let elsewhere =
            json!({"url": "https://old.example/webhook", "secret_set": false, "status": "paused"});
        let found = findings(&elsewhere, URL);
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(found[0].contains("https://old.example/webhook"));
        assert!(found[1].contains("no signing secret"));
        assert!(found[2].contains("paused"));
    }
}
