"""Scenario 5 (Silicon Accounts webhook events) and scenario 8 (restart safety)."""

import base64
import datetime
import json
import time
import uuid

from support import Stop

from scenario_cli import slt_for, wait_events
from scenario_api import silicon_token


def now_ms():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def harmful_duplicate(h, event_id):
    """A delivery that reuses an applied event_id but would sign C1 out if Hook applied it."""
    return {"event_id": event_id, "type": "membership.signed_out", "occurred_at": now_ms(), "app_id": h.app_id,
            "silicon": None, "data": {"uuid": h.c1.uuid, "membership_id": f"{h.app_id}:{h.c1.uuid}",
                                       "reason": "session_revoked"}}


def scenario_5(h):
    h.begin(5, "Silicon Accounts webhook events: id change, profile, sign-outs, custodian change, deletion, access removal")
    h.load_webhook_secret()
    h.c1.first_party = h.mint("carbon", "--email", h.c1.email)["access_token"]
    h.c2.first_party = h.mint("carbon", "--email", h.c2.email)["access_token"]
    status, body = h.call("GET", "auth/status", token=h.c1.first_party)
    h.check("Silicon Accounts' own (first-party) token is refused: token_wrong_audience",
            status == 401 and body["error"]["code"] == "token_wrong_audience", body)
    id_change(h)
    replays(h)
    forgeries(h)
    profile_update(h)
    stk_rotation(h)
    same_second_sign_in(h)
    custodian_change(h)
    deletion(h)
    access_removed(h)


def id_change(h):
    s1 = h.s1
    old_id, new_id = s1.id, f"si:hook-e2e-s1r-{h.suffix}"
    before = h.delivery_ids()
    status, body = h.accounts("POST", f"/v1/me/silicons/{s1.uuid}/id", h.c1, body={"id": new_id})
    h.check("the custodian changes S1's id (POST /v1/me/silicons/{uuid}/id, first-party token)",
            status == 200, {"status": status, "id": (body or {}).get("id")}, critical=True)
    h.id_change_delivery = h.wait_delivery("account.id_changed", s1.uuid, before)
    s1.old_id, s1.id = old_id, new_id
    status, silicons = h.call("GET", "silicons", h.c1)
    entry = [i for i in silicons.get("items", []) if i["silicon"]["uuid"] == s1.uuid]
    h.check("Hook shows the new id in GET /silicons", entry and entry[0]["silicon"]["id"] == new_id,
            entry[0]["silicon"] if entry else silicons)
    status, hooks = h.call("GET", f"silicons/{new_id}/hooks", h.c1)
    items = hooks.get("items", []) if status == 200 else []
    h.check("the Silicon's hooks answer to the new id and show URLs with it",
            items and all(i["silicon"]["id"] == new_id and f"/silicon/{new_id}/" in i["endpoint_url"] for i in items),
            [(i["name"], i["endpoint_url"].rsplit("/", 2)[-2]) for i in items])
    github = [i for i in items if i["id"] == h.github["id"]][0]
    secret = h.github["signing_secret"]
    old_status, _ = h.provider_post(h.github["endpoint_url"], {"via": "old id"}, secret=secret)
    new_status, _ = h.provider_post(github["endpoint_url"], {"via": "new id"}, secret=secret)
    status, events = h.call("GET", f"silicons/{s1.uuid}/hooks/{github['id']}/events", h.c1)
    bodies = [e["request"]["body"] for e in events.get("items", [])]
    h.check("a URL a provider already holds (old id) keeps working, and so does the new one",
            old_status == 200 and new_status == 200 and '{"via": "old id"}' in bodies and '{"via": "new id"}' in bodies,
            {"old_id_url": old_status, "new_id_url": new_status, "verified_events": len(bodies)})
    code, listed, err = h.hook(s1.home, "list")
    h.check("the Silicon's CLI session from before the rename keeps working (uuid-keyed)",
            code == 0 and listed["items"] and all(i["silicon"]["id"] == new_id for i in listed["items"]),
            {"exit": code, "ids": sorted({i["silicon"]["id"] for i in (listed or {}).get("items", [])})} if code == 0 else err)
    items = wait_events(h, s1.home, h.accounts_hook["id"], 2)
    types = [e["request"]["body"].split('"type":"', 1)[-1].split('"', 1)[0] for e in items]
    h.check("the Silicon's own Accounts hook received silicon.id_changed, verified", "silicon.id_changed" in types, types)


def replays(h):
    delivery = h.id_change_delivery
    event_id = delivery["event_id"]
    status, body = h.accounts("POST", f"/v1/apps/{h.app_id}/webhook/replay", basic=True,
                              body={"delivery_ids": [delivery["id"]]}, idempotent=True)
    h.check("the stack replays the id-change delivery (same event_id, fresh signature)",
            status == 200 and delivery["id"] in body.get("replayed", []), body)
    deadline = time.time() + 30
    duplicates = []
    while time.time() < deadline and not duplicates:
        duplicates = [l for l in h.hook_log_lines(event_id) if "duplicate=true" in l]
        time.sleep(0.5)
    rows = h.sql(f"SELECT count(*) FROM hook_private.accounts_events WHERE event_id = '{event_id}'")
    h.check("Hook acknowledges the replay and ignores it (logged duplicate, one dedupe row)",
            duplicates and rows == "1", {"log": duplicates[-1][-160:] if duplicates else None, "rows": rows})
    status, _ = h.signed_delivery(harmful_duplicate(h, event_id))
    status_after, _ = h.call("GET", "auth/status", h.c1)
    h.check("a delivery reusing that event_id with a sign-out payload changes nothing",
            status == 204 and status_after == 200, {"delivery": status, "c1_token_after": status_after})


def forgeries(h):
    payload = harmful_duplicate(h, str(uuid.uuid4()))
    status, body = h.signed_delivery(payload, secret="whsec_not-the-real-secret-0000000000")
    h.check("a delivery signed with another secret is refused (401)", status == 401 and
            body["error"]["code"] == "webhook_signature_invalid", body)
    status, body = h.signed_delivery(payload, signature=False)
    h.check("an unsigned delivery is refused (401)", status == 401, body)
    status, body = h.signed_delivery(payload, timestamp=time.time() - 600)
    h.check("a correctly signed but 10-minute-old delivery is refused (401)", status == 401, body)
    status_after, _ = h.call("GET", "auth/status", h.c1)
    h.check("none of them signed C1 out", status_after == 200, {"c1_token": status_after})


def profile_update(h):
    s1 = h.s1
    before = h.delivery_ids()
    status, body = h.accounts("PATCH", f"/v1/me/silicons/{s1.uuid}", h.c1, body={"display_name": f"Renamed {h.suffix}"})
    h.check("the custodian renames S1's display name", status == 200, {"status": status})
    delivery = h.wait_delivery("account.updated", s1.uuid, before)
    stored = h.sql(f"SELECT display_name FROM hook_private.accounts WHERE uuid = '{s1.uuid}'")
    h.check("Hook applies account.updated to its account cache", stored == f"Renamed {h.suffix}",
            {"changed": delivery.get("payload", {}).get("data", {}).get("changed"), "stored": stored})


def stk_rotation(h):
    s3 = h.s3
    before = h.delivery_ids()
    status, body = h.accounts("POST", f"/v1/me/silicons/{s3.uuid}/stk", h.c1, body={}, idempotent=True)
    h.check("the custodian rotates S3's STK", status in (200, 201), {"status": status})
    if isinstance(body, dict) and body.get("stk"):
        s3.stk = body["stk"]
    delivery = h.wait_delivery("membership.signed_out", s3.uuid, before)
    reason = delivery.get("payload", {}).get("data", {}).get("reason")
    status, error = h.call("GET", "auth/status", s3)
    h.check("membership.signed_out (stk_rotated) ends S3's earlier Hook tokens (401 session_ended)",
            reason == "stk_rotated" and status == 401 and error["error"]["code"] == "session_ended",
            {"reason": reason, "status": status, "code": (error or {}).get("error", {}).get("code")})


def public_client_token(h, silicon, stk):
    """A Silicon signing straight back in (STK -> short-lived token -> Hook's public-client exchange), fast."""
    import urllib.parse
    status, session = h.accounts("POST", "/v1/silicons/login",
                                 body={"id": silicon.id, "stk": stk, "client_label": "hook e2e"})
    if status != 200:
        raise Stop(f"silicon login answered {status}: {session}")
    status, slt = h.accounts("POST", "/v1/me/short-lived-tokens", body={"app_id": h.app_id},
                             token=session["access_token"])
    form = urllib.parse.urlencode({"grant_type": "urn:silicon:params:oauth:grant-type:slt", "slt": slt["slt"],
                                   "client_id": h.app_id}).encode()
    import urllib.request
    request = urllib.request.Request(f"{h.accounts_api}/v1/oauth/token", data=form, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())["access_token"]


def token_iat(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["iat"]


def same_second_sign_in(h):
    """A Silicon that signs in again right after its STK is rotated keeps working once Hook hears the sign-out."""
    s2 = h.s2
    old_token = s2.token
    while time.time() % 1 > 0.05:  # start at the top of a second, so the new token shares it
        time.sleep(0.01)
    before = h.delivery_ids()
    status, rotated = h.accounts("POST", f"/v1/me/silicons/{s2.uuid}/stk", h.c2, body={}, idempotent=True)
    new_token = public_client_token(h, s2, rotated["stk"])
    s2.stk = rotated["stk"]
    delivery = h.wait_delivery("membership.signed_out", s2.uuid, before)
    occurred = delivery.get("payload", {}).get("occurred_at", "")
    same_second = occurred[:19] == datetime.datetime.fromtimestamp(token_iat(new_token), datetime.timezone.utc) \
        .strftime("%Y-%m-%dT%H:%M:%S")
    status_new, _ = h.call("GET", "auth/status", token=new_token)
    status_old, _ = h.call("GET", "auth/status", token=old_token)
    h.check("a Silicon that signs in again in the very second its STK was rotated is accepted after the sign-out "
            "lands; its earlier token is refused",
            status_new == 200 and status_old == 401,
            {"sign_out_at": occurred, "new_token_same_second": same_second, "new": status_new, "old": status_old})


def custodian_change(h):
    s3 = h.s3
    before = h.delivery_ids()
    status, body = h.accounts("POST", f"/v1/me/silicons/{s3.uuid}/transfer", h.c1, body={"to": h.c2.id})
    request_id = (body or {}).get("request", {}).get("id")
    h.check("C1 offers S3 to C2", status == 201 and request_id, {"status": status})
    status, _ = h.accounts("POST", f"/v1/me/custodian-requests/{request_id}/accept", h.c2)
    h.check("C2 accepts and becomes S3's custodian", status == 204, {"status": status})
    delivery = h.wait_delivery("silicon.custodian_changed", s3.uuid, before)
    to = delivery.get("payload", {}).get("data", {}).get("to") or {}
    status_c2, hooks = h.call("GET", f"silicons/{s3.id}/hooks", h.c2)
    status_c1, _ = h.call("GET", f"silicons/{s3.id}/hooks", h.c1)
    h.check("after silicon.custodian_changed the new custodian manages S3's hooks and the old one is refused",
            to.get("uuid") == h.c2.uuid and status_c2 == 200 and [i["name"] for i in hooks["items"]] == ["S3Demo"]
            and status_c1 == 403, {"new_custodian": status_c2, "old_custodian": status_c1})
    _, listed_c2 = h.call("GET", "silicons", h.c2)
    _, listed_c1 = h.call("GET", "silicons", h.c1)
    in_c2 = [i["access"] for i in listed_c2.get("items", []) if i["silicon"]["uuid"] == s3.uuid]
    in_c1 = [i for i in listed_c1.get("items", []) if i["silicon"]["uuid"] == s3.uuid]
    h.check("GET /silicons moves S3 from C1's list to C2's", in_c2 == ["custodian"] and not in_c1,
            {"c2": in_c2, "c1": len(in_c1)})


def deletion(h):
    s3 = h.s3
    before = h.delivery_ids()
    status, _ = h.accounts("DELETE", f"/v1/me/silicons/{s3.uuid}", h.c2, body={"confirm": s3.id})
    h.check("S3's new custodian deletes S3's account", status == 204, {"status": status})
    h.wait_delivery("account.deleted", s3.uuid, before)
    status, body = h.provider_post(h.s3_hook["endpoint_url"], {"after": "account deleted"})
    h.check("account.deleted: S3's hook URL answers 410 account_deleted at once",
            status == 410 and (body or {}).get("error", {}).get("code") == "account_deleted", body)
    deleted_at = h.sql(f"SELECT count(*) FROM hook.hooks WHERE silicon_uuid = '{s3.uuid}' AND deleted_at IS NOT NULL")
    h.check("…its hooks are soft-deleted (kept for the 45-day purge, not dropped)", deleted_at == "1",
            {"soft_deleted_hooks": deleted_at})


def access_removed(h):
    s1 = h.s1
    other_token = s1.token
    before = h.delivery_ids()
    code, out, err = h.accounts_cli(s1.accounts_home, "apps", "remove", h.app_id)
    h.check("the Silicon removes Hook's access (silicon-accounts apps remove hook)", code == 0, out or err)
    removed = h.wait_delivery("membership.access_removed", s1.uuid, before)
    status, body = h.call("GET", "auth/status", token=other_token)
    h.check("after membership.access_removed its old access token is refused (401 session_ended)",
            status == 401 and body["error"]["code"] == "session_ended", body)
    code, out, err = h.hook(s1.home, "login", "status", "--json")
    h.check("its CLI says it is signed out (exit 0)", code == 0 and out.get("authenticated") is False, out or err)
    status, hooks = h.call("GET", f"silicons/{s1.uuid}/hooks", h.c1)
    h.check("the custodian still manages the Silicon's hooks", status == 200 and len(hooks["items"]) >= 3,
            {"status": status, "hooks": len(hooks.get("items", []))})
    code, out, err = h.hook(s1.home, "login", "--slt-stdin", stdin=slt_for(h, s1))
    code_list, listed, err_list = h.hook(s1.home, "list")
    h.check("signing in again right away works and the Silicon's hooks are all still there",
            code == 0 and out.get("authenticated") is True and code_list == 0 and len(listed["items"]) >= 3,
            {"login": out if code == 0 else err, "hooks": len((listed or {}).get("items", []))})
    h.note(f"access removed at {removed.get('payload', {}).get('occurred_at')}; new sign-in "
           f"{'accepted' if code == 0 else 'refused'}")
    s1.token = silicon_token(h, s1)


def cli_refresh(h):
    """The CLI refreshes its sign-in at the real stack when the access token is about to expire."""
    import hashlib
    profiles = h.s1.home / ".silicon-hook" / "profiles.json"

    def session():
        data = json.loads(profiles.read_text())
        return data, data["profiles"]["default"]["session"]

    def digest(value):
        text = value if isinstance(value, str) else json.dumps(value)
        return hashlib.sha256(text.encode()).hexdigest()[:12]

    data, before = session()
    old = (digest(before["access_token"]), digest(before["refresh_token"]))
    before["expires_at"] = int(time.time()) + 10
    profiles.write_text(json.dumps(data))
    code, listed, err = h.hook(h.s1.home, "list")
    _, after = session()
    new = (digest(after["access_token"]), digest(after["refresh_token"]))
    h.check("the hook CLI refreshes at Silicon Accounts when its token is about to expire (both tokens rotate)",
            code == 0 and new[0] != old[0] and new[1] != old[1] and after["expires_at"] > time.time() + 1500
            and not after.get("refresh_started_at"),
            {"exit": code, "access_rotated": new[0] != old[0], "refresh_rotated": new[1] != old[1],
             "expires_in": after["expires_at"] - int(time.time())})


def scenario_8(h):
    h.begin(8, "restart safety: stateless sessions, kept keys, persistent webhook dedupe")
    _, before = h.call("GET", f"silicons/{h.s1.uuid}/events?limit=100", h.c1)
    count_before = len(before.get("items", []))
    result = h.dev_command("restart")
    h.check("scripts/dev-accounts.sh restart (same database, keys and webhook secret)",
            result.get("ready") and result.get("webhook") == "kept", {k: result.get(k) for k in ("ready", "webhook", "webhook_ping")})
    code, listed, err = h.hook(h.s1.home, "list")
    h.check("the Silicon's CLI session works without signing in again", code == 0 and listed["items"], err or None)
    status, _ = h.call("GET", "auth/status", h.c1)
    h.check("the Carbon's access token is still accepted", status == 200, {"status": status})
    cli_refresh(h)
    event_id = h.id_change_delivery["event_id"]
    status, _ = h.signed_delivery(harmful_duplicate(h, event_id))
    status_after, _ = h.call("GET", "auth/status", h.c1)
    rows = h.sql(f"SELECT count(*) FROM hook_private.accounts_events WHERE event_id = '{event_id}'")
    h.check("a duplicate of an event applied before the restart is still ignored",
            status == 204 and status_after == 200 and rows == "1", {"delivery": status, "c1": status_after, "rows": rows})
    status, _ = h.provider_post(h.github["endpoint_url"], {"after": "restart"}, secret=h.github["signing_secret"])
    _, after = h.call("GET", f"silicons/{h.s1.uuid}/events?limit=100", h.c1)
    bodies = [e["request"]["body"] for e in after.get("items", [])]
    h.check("a hook secret stored before the restart still verifies, and the history is intact",
            status == 200 and '{"after": "restart"}' in bodies and len(bodies) == count_before + 1,
            {"before": count_before, "after": len(bodies)})
