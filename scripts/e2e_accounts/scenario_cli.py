"""Scenario 2 (a Silicon on the CLI) and scenario 3 (a Carbon's device-flow sign-in)."""

import time

from scenario_api import silicon_token


def slt_for(h, silicon):
    return h.mint("slt", "--silicon", silicon.id, "--stk", silicon.stk, "--app", h.app_id)["slt"]


def wait_events(h, home, hook_id, count, seconds=40):
    deadline = time.time() + seconds
    items = []
    while time.time() < deadline:
        code, events, _ = h.hook(home, "events", "--hook", hook_id, "--limit", "20")
        items = events.get("items", []) if code == 0 and isinstance(events, dict) else []
        if len(items) >= count:
            return items
        time.sleep(1)
    return items


def scenario_2(h):
    h.begin(2, "a Silicon signs in to the hook CLI with a short-lived token and uses it")
    s1 = h.s1
    s1.home = h.home("s1-hook-cli")
    code, out, err = h.hook(s1.home, "login", "--slt-stdin", stdin=slt_for(h, s1))
    h.check("printf %s \"$SLT\" | hook login --slt-stdin (fresh SILICON_HOME)",
            code == 0 and out.get("authenticated") is True and out.get("uuid") == s1.uuid and out.get("kind") == "silicon",
            out or err, critical=True)
    code, status, err = h.hook(s1.home, "login", "status", "--json")
    h.check("hook login status --json: authenticated, confirmed by Hook",
            code == 0 and status.get("authenticated") is True and status.get("uuid") == s1.uuid
            and status.get("id") == s1.id and status.get("kind") == "silicon", status or err)

    code, created, err = h.hook(s1.home, "create", "LocalDemo", "--unsigned", "--description", "made by the Silicon")
    h.check("hook create LocalDemo --unsigned", code == 0 and created.get("created_by", {}).get("uuid") == s1.uuid,
            {k: created.get(k) for k in ("name", "silicon", "created_by")} if code == 0 else err, critical=True)
    h.local_demo = created
    status, answer = h.provider_post(created["endpoint_url"], {"ref": "refs/heads/main"})
    h.check("a provider posts to it", status == 200 and answer.get("status") == "webhook.ok", answer)
    items = wait_events(h, s1.home, created["id"], 1, seconds=5)
    h.check("hook events --hook <id> shows the request", len(items) == 1 and
            items[0]["request"]["body"] == '{"ref": "refs/heads/main"}', [(e["provider"], e["summary"]) for e in items])
    code, updated, err = h.hook(s1.home, "update", created["id"], "--patch", '{"description":"changed by the Silicon"}')
    code_show, shown, _ = h.hook(s1.home, "show", created["id"])
    h.check("hook update --patch, then hook show reflects it",
            code == 0 and code_show == 0 and shown.get("description") == "changed by the Silicon",
            {"description": shown.get("description")} if code_show == 0 else err)
    code, rotated, err = h.hook(s1.home, "rotate", "endpoint", created["id"])
    old_status, old_answer = h.provider_post(created["endpoint_url"], {"to": "old"})
    new_status, _ = h.provider_post(rotated.get("endpoint_url", ""), {"to": "new"}) if code == 0 else (0, None)
    h.check("hook rotate endpoint: the old URL is retired (410), the new one works",
            code == 0 and old_status == 410 and (old_answer or {}).get("error", {}).get("code") == "endpoint_retired"
            and new_status == 200, {"old": old_status, "new": new_status})
    if code == 0:
        h.local_demo = rotated
    code, listed, err = h.hook(s1.home, "list")
    names = sorted(item["name"] for item in listed.get("items", [])) if code == 0 else []
    h.check("hook list shows the custodian's GitHub hook and the Silicon's own",
            {"GitHub", "LocalDemo"} <= set(names), names or err)

    connect_accounts(h, s1)

    # One machine's logout must not end the Silicon's other sign-ins (membership.signed_out, app_revoked).
    s1.token = silicon_token(h, s1)
    before = h.delivery_ids()
    code, out, err = h.hook(s1.home, "logout")
    h.check("hook logout revokes the sign-in at Silicon Accounts", code == 0 and out.get("revoked") is True, out or err)
    delivery = h.wait_delivery("membership.signed_out", s1.uuid, before)
    reason = delivery.get("payload", {}).get("data", {}).get("reason")
    status, body = h.call("GET", "auth/status", s1)
    h.check("Hook hears membership.signed_out (app_revoked) and keeps the Silicon's other sign-in working",
            reason == "app_revoked" and status == 200, {"reason": reason, "other_token_status": status})
    code, out, err = h.hook(s1.home, "login", "status", "--json")
    h.check("hook login status --json after logout: {\"authenticated\": false}, exit 0",
            code == 0 and out == {"authenticated": False}, out or err)
    code, out, err = h.hook(s1.home, "login", slt_for(h, s1))
    h.check("the Silicon runtime's positional form, hook login <SLT>, signs it in again",
            code == 0 and out.get("authenticated") is True, out or err)


def connect_accounts(h, s1):
    """"Connect Silicon Accounts updates": the Silicon's own Accounts events, verified by a hook."""
    code, connected, err = h.hook(s1.home, "connect-accounts")
    command = (connected or {}).get("next_steps", {}).get("set_webhook", "") if code == 0 else ""
    h.check("hook connect-accounts prepares the hook and names the exact silicon-accounts command",
            command.startswith("silicon-accounts webhook set ") and connected.get("secret_stored_now") is False,
            {"set_webhook": command, "secret_stored_now": (connected or {}).get("secret_stored_now")}, critical=True)
    url = connected["hook"]["endpoint_url"]
    h.accounts_hook = connected["hook"]
    s1.accounts_home = h.home("s1-accounts-cli")
    code, out, err = h.accounts_cli(s1.accounts_home, "login", "--silicon", s1.id, "--stk-stdin", stdin=s1.stk)
    h.check("the Silicon signs in to the Silicon Accounts CLI (silicon-accounts login --silicon)", code == 0,
            out or err, critical=True)
    code, out, err = h.accounts_cli(s1.accounts_home, "webhook", "set", url)
    secret = (out.get("webhook_secret") or out.get("secret")) if isinstance(out, dict) else None
    h.check("silicon-accounts webhook set <hook URL> prints a whsec_ secret once",
            code == 0 and str(secret).startswith("whsec_"), out or err, critical=True)
    code, stored, err = h.hook(s1.home, "connect-accounts", "--secret-file", "-", stdin=secret)
    h.check("hook connect-accounts --secret-file - stores it on the same hook",
            code == 0 and stored.get("secret_stored_now") is True and stored["hook"]["id"] == connected["hook"]["id"],
            {"secret_stored_now": (stored or {}).get("secret_stored_now")} if code == 0 else err)
    code, out, err = h.accounts_cli(s1.accounts_home, "webhook", "test")
    h.check("silicon-accounts webhook test queues a signed ping", code == 0, out or err)
    items = wait_events(h, s1.home, connected["hook"]["id"], 1)
    body = items[0]["request"]["body"] if items else ""
    h.check("the ping arrives at Hook and verifies with the x-accounts-signature policy",
            '"type":"ping"' in body.replace(" ", ""), [(e["provider"], e["summary"]) for e in items])
    code, blocked, _ = h.hook(s1.home, "blocked", "--hook", connected["hook"]["id"])
    h.check("…and nothing from Silicon Accounts was withheld",
            code == 0 and blocked.get("items") == [], [b.get("reason_code") for b in (blocked or {}).get("items", [])])


def scenario_3(h):
    h.begin(3, "a Carbon signs in to the hook CLI with the device flow")
    c1 = h.c1
    c1.home = h.home("c1-hook-cli")
    device, approval, code, final, err = h.device_login(c1.home, c1.email)
    h.note(f"hook login --json printed: {{\"event\": \"{device.get('event')}\", \"user_code\": \"{device.get('user_code')}\", "
           f"\"verification_uri\": \"{device.get('verification_uri')}\"}}; approved: {approval}")
    h.check("hook login (device flow) finishes after the Carbon approves the code",
            code == 0 and (final or {}).get("kind") == "carbon" and (final or {}).get("uuid") == c1.uuid,
            final or err, critical=True)
    code, status, err = h.hook(c1.home, "login", "status", "--json")
    h.check("hook login status --json: the Carbon, confirmed by Hook",
            code == 0 and status.get("authenticated") is True and status.get("kind") == "carbon", status or err)
    code, silicons, err = h.hook(c1.home, "silicons")
    entry = [i for i in (silicons or {}).get("items", []) if i["silicon"]["uuid"] == h.s1.uuid] if code == 0 else []
    h.check("hook silicons lists S1 as looked after by this Carbon", entry and entry[0]["access"] == "custodian",
            silicons or err)
    code, events, err = h.hook(c1.home, "--silicon", h.s1.id, "events", "--limit", "10")
    h.check("hook --silicon <S1> events reads the Silicon's history",
            code == 0 and len(events.get("items", [])) >= 3, [(e["provider"], e["summary"]) for e in (events or {}).get("items", [])][:5] if code == 0 else err)
