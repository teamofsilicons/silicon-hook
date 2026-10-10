"""Identities, scenario 1 (a Carbon on the API) and scenario 4 (custodian circle and sharing)."""

from support import Identity


def setup(h):
    """Two unrelated Carbons; C1 looks after S1 and S3 (siblings), C2 looks after S2."""
    h.begin("0", "test identities on the shared stack")
    n = h.suffix
    h.c1 = Identity("C1", email=f"hook-e2e-c1-{n}@example.test", kind="carbon")
    h.c2 = Identity("C2", email=f"hook-e2e-c2-{n}@example.test", kind="carbon")
    minted = {}
    for label, carbon, handle in (("S1", h.c1, f"hook-e2e-s1-{n}"), ("S3", h.c1, f"hook-e2e-s3-{n}"),
                                  ("S2", h.c2, f"hook-e2e-s2-{n}")):
        result = h.mint("silicon", "--custodian-email", carbon.email, "--handle", handle)
        minted[label] = Identity(label, **result)
        carbon.uuid, carbon.id = result["custodian"]["uuid"], result["custodian"]["id"]
    h.s1, h.s3, h.s2 = minted["S1"], minted["S3"], minted["S2"]
    for who in (h.c1, h.c2, h.s1, h.s2, h.s3):
        h.note(f"{who.label}: {who.id} (uuid {who.uuid})")
    h.check("S1 and S3 are looked after by C1, S2 by C2",
            h.s1.custodian["uuid"] == h.c1.uuid == h.s3.custodian["uuid"] and h.s2.custodian["uuid"] == h.c2.uuid)


def sign_in_web(h, carbon):
    """The web's sign-in: hosted pages, code + PKCE verifier exchanged with Hook's app secret."""
    result = h.mint("app-signin", "--app", h.app_id, "--email", carbon.email, "--redirect", h.web_redirect, "--exchange")
    tokens = result["tokens"]
    carbon.token = tokens["access_token"]
    return tokens


def scenario_1(h):
    h.begin(1, "a Carbon signs in like the web does and manages its Silicon's hooks over the API")
    status, info = h.call("GET", "auth/accounts")
    h.check("GET /api/v3/auth/accounts (public) names Hook's app id and the stack as the token issuer",
            status == 200 and info.get("app_id") == h.app_id and info["token"]["issuer"] == h.accounts_url
            and info.get("delivery") == "disabled", {k: info.get(k) for k in ("app_id", "accounts_url", "delivery")}
            if status == 200 else info)
    tokens = sign_in_web(h, h.c1)
    account = tokens.get("account", {})
    h.check("code exchange with Hook's app secret returns C1's access and refresh tokens",
            account.get("uuid") == h.c1.uuid and account.get("kind") == "carbon" and tokens.get("refresh_token"),
            {"account": {k: account.get(k) for k in ("uuid", "id", "kind")}, "expires_in": tokens.get("expires_in")},
            critical=True)
    status, body = h.call("GET", "auth/status", h.c1)
    h.check("Hook accepts the token (JWKS, audience hook, issuer the stack)",
            status == 200 and body.get("uuid") == h.c1.uuid and body.get("kind") == "carbon", body, critical=True)

    # Create
    status, created = h.call("POST", f"silicons/{h.s1.id}/hooks", h.c1, idempotent=True,
                             body={"name": "GitHub", "description": "made by S1's custodian over the API",
                                   "time_zone": "Asia/Kolkata"})
    ok = status == 201 and created.get("silicon", {}).get("uuid") == h.s1.uuid
    h.check("create: the custodian makes a signed hook for its Silicon (201, secret returned once)",
            ok and str(created.get("signing_secret", "")).startswith("v1."),
            {"status": status, "silicon": created.get("silicon"), "created_by": created.get("created_by"),
             "endpoint_url": created.get("endpoint_url")} if isinstance(created, dict) else created, critical=True)
    h.check("the hook is recorded as made by the custodian, never as the Silicon",
            created["created_by"] == {"uuid": h.c1.uuid, "kind": "carbon", "id": h.c1.id}, created["created_by"])
    h.github = created
    secret = created["signing_secret"]

    # Provider traffic: one signed (verified) and one unsigned (withheld) request.
    status, answer = h.provider_post(created["endpoint_url"], {"action": "opened", "number": 1}, secret=secret)
    h.check("a provider request signed with the hook's secret is accepted", status == 200 and
            answer.get("status") == "webhook.ok", answer)
    unsigned = h.provider_post(created["endpoint_url"], {"action": "unsigned"})
    unsigned_id = h.provider_post(created["endpoint_url"], {"action": "no signature"},
                                  extra_headers={"webhook-id": "msg_e2e", "webhook-timestamp": "1700000000"})
    forged = h.provider_post(created["endpoint_url"], {"action": "forged"},
                             extra_headers={"webhook-id": "msg_e2e", "webhook-timestamp": "1700000000",
                                            "webhook-signature": "v1,bm90IHRoZSBzaWduYXR1cmU="})
    h.check("unverifiable requests get the identical answer (no signature oracle)",
            all(status == 200 and answer.get("status") == "webhook.ok" for status, answer in (unsigned, unsigned_id, forged)),
            [answer for _, answer in (unsigned, unsigned_id, forged)])

    # List and read
    status, listed = h.call("GET", f"silicons/{h.s1.id}/hooks", h.c1)
    h.check("list: the hook is in its Silicon's list", status == 200 and
            any(item["id"] == created["id"] for item in listed.get("items", [])),
            [(i["name"], i["status"]) for i in listed.get("items", [])] if status == 200 else listed)
    status, shown = h.call("GET", f"silicons/{h.s1.uuid}/hooks/{created['id']}", h.c1)
    h.check("read: by the Silicon's uuid, without any secret material",
            status == 200 and shown.get("time_zone") == "Asia/Kolkata" and "signing_secret" not in shown
            and "secret" not in shown.get("signature", {}),
            {k: shown.get(k) for k in ("name", "time_zone", "status")} if status == 200 else shown)
    status, events = h.call("GET", f"silicons/{h.s1.id}/hooks/{created['id']}/events", h.c1)
    items = events.get("items", []) if status == 200 else []
    h.check("the verified request is in the history with its exact body",
            len(items) == 1 and items[0]["request"]["body"] == '{"action": "opened", "number": 1}',
            [(e["provider"], e["summary"]) for e in items] if items else events)
    h.first_event = items[0] if items else None
    status, blocked = h.call("GET", f"silicons/{h.s1.id}/hooks/{created['id']}/blocked-requests", h.c1)
    reasons = sorted(b["reason_code"] for b in blocked.get("items", [])) if status == 200 else blocked
    h.check("they are withheld with exact reasons: payload_unavailable, signature_missing, signature_mismatch",
            reasons == ["payload_unavailable", "signature_mismatch", "signature_missing"], reasons)

    # Update
    status, updated = h.call("PATCH", f"silicons/{h.s1.id}/hooks/{created['id']}", h.c1,
                             body={"description": "updated by the custodian", "time_zone": "UTC"})
    h.check("update: description and time zone change", status == 200 and
            updated.get("description") == "updated by the custodian" and updated.get("time_zone") == "UTC",
            {k: updated.get(k) for k in ("description", "time_zone")} if status == 200 else updated)

    # Delete, check, restore, delete for good (a separate hook, so GitHub stays for later scenarios)
    status, scratch = h.call("POST", f"silicons/{h.s1.id}/hooks", h.c1, idempotent=True,
                             body={"name": "Scratch", "signature": {"required": False}})
    h.check("a second hook for the delete/restore cycle", status == 201, {"status": status})
    scratch_id = scratch["id"]
    status, _ = h.call("DELETE", f"silicons/{h.s1.id}/hooks/{scratch_id}", h.c1)
    h.check("delete: soft-deletes the hook", status in (200, 204), {"status": status})
    status, _ = h.provider_post(scratch["endpoint_url"], {"after": "delete"})
    h.check("a deleted hook's URL answers 404", status == 404, {"status": status})
    status, listed = h.call("GET", f"silicons/{h.s1.id}/hooks?include_deleted=true", h.c1)
    deleted = [i for i in listed.get("items", []) if i["id"] == scratch_id]
    h.check("include_deleted shows it inside its 45-day recovery window",
            deleted and deleted[0].get("deleted_at"), deleted[0] if deleted else listed)
    status, restored = h.call("POST", f"silicons/{h.s1.id}/hooks/{scratch_id}/restore", h.c1, idempotent=True)
    status_after, _ = h.provider_post(scratch["endpoint_url"], {"after": "restore"})
    h.check("restore: the same URL works again", status == 200 and status_after == 200,
            {"restore": status, "ingress": status_after})
    status, _ = h.call("DELETE", f"silicons/{h.s1.id}/hooks/{scratch_id}", h.c1)
    h.check("delete again", status in (200, 204), {"status": status})

    status, silicons = h.call("GET", "silicons", h.c1)
    entry = [i for i in silicons.get("items", []) if i["silicon"]["uuid"] == h.s1.uuid]
    h.check("GET /silicons lists S1 for C1 with access `custodian`",
            entry and entry[0]["access"] == "custodian", silicons)

    # Hook 1.0 retires API v1/v2 management, while every ingress URL form a provider may hold keeps working.
    status, body = h.call("GET", f"{h.api}/api/v2/silicons/{h.s1.id}/hooks", h.c1)
    h.check("API v2 management answers 410 api_version_sunset with a pointer to v3",
            status == 410 and body["error"]["code"] == "api_version_sunset", body)
    key = created["endpoint_key"]
    aliases = {prefix: h.provider_post(f"{h.api}{prefix}/silicon/{h.s1.id}/{key}", {"via": prefix or "/"},
                                       secret=secret)[0] for prefix in ("/api/v1", "/api/v2")}
    h.check("ingress under /api/v1/silicon/... and /api/v2/silicon/... still verifies and accepts",
            all(status == 200 for status in aliases.values()), aliases)


def silicon_token(h, silicon):
    """What a Silicon's own server-side integration does: an SLT exchanged with Hook's app secret."""
    slt = h.mint("slt", "--silicon", silicon.id, "--stk", silicon.stk, "--app", h.app_id)["slt"]
    return h.mint("app-token", "--app", h.app_id, "--slt", slt)["access_token"]


def scenario_4(h):
    h.begin(4, "the custodian circle, sharing by id, and Silicons that are not open to the world")
    sign_in_web(h, h.c2)
    h.s3.token = silicon_token(h, h.s3)
    hooks = f"silicons/{h.s1.id}/hooks"
    status, body = h.call("GET", hooks, h.c1)
    h.check("the custodian sees its Silicon's hooks", status == 200 and len(body["items"]) >= 2,
            [(i["name"], i["created_by"]["kind"]) for i in body.get("items", [])])
    status, body = h.call("GET", hooks, h.c2)
    h.check("an unrelated Carbon is refused (403)", status == 403, body)
    event_path = f"silicons/{h.s1.id}/events/{h.first_event['id']}" if h.first_event else None
    if event_path:
        status, body = h.call("GET", event_path, h.c2)
        h.check("…and cannot read one of its events by id", status == 403, body)
    status, body = h.call("GET", hooks, h.s3)
    h.check("a sibling Silicon (same custodian) is refused too", status == 403, body)

    # The custodian prepares a hook for S3 (used by the custodian-change and deletion steps).
    status, s3_hook = h.call("POST", f"silicons/{h.s3.id}/hooks", h.c1, idempotent=True,
                             body={"name": "S3Demo", "signature": {"required": False}})
    h.check("the custodian makes a hook for its other Silicon S3", status == 201, {"status": status})
    h.s3_hook = s3_hook

    # Sharing by c: id, through C1's CLI (device-flow session from scenario 3).
    code, granted, err = h.hook(h.c1.home, "--silicon", h.s1.id, "access", "grant", h.c2.id, "--level", "view")
    h.check("C1 grants C2 `view` by its c: id (hook access grant)", code == 0 and
            granted.get("grant", {}).get("level") == "view", granted or err)
    status, body = h.call("GET", hooks, h.c2)
    h.check("C2 now lists the hooks", status == 200 and body.get("items"), {"status": status})
    if event_path:
        status, body = h.call("GET", event_path, h.c2)
        h.check("C2 now reads the event", status == 200, {"status": status})
    status, body = h.call("POST", hooks, h.c2, idempotent=True, body={"name": "ByViewer"})
    h.check("`view` cannot create a hook (403)", status == 403, body)
    code, granted, err = h.hook(h.c1.home, "--silicon", h.s1.id, "access", "grant", h.c2.id, "--level", "manage")
    status, body = h.call("POST", hooks, h.c2, idempotent=True,
                          body={"name": "ByManager", "signature": {"required": False}})
    h.check("after an upgrade to `manage` C2 creates one, recorded as C2",
            code == 0 and status == 201 and body["created_by"]["uuid"] == h.c2.uuid,
            body.get("created_by") if status == 201 else body)
    code, listed, err = h.hook(h.c1.home, "--silicon", h.s1.id, "access", "list")
    grants = {g["account"]["id"]: g["level"] for g in (listed or {}).get("grants", [])} if code == 0 else {}
    h.check("hook access list shows the custodian and C2's grant by current id",
            grants.get(h.c2.id) == "manage" and listed["custodian"]["uuid"] == h.c1.uuid,
            {"you": listed.get("you"), "grants": grants} if code == 0 else err)
    code, revoked, err = h.hook(h.c1.home, "--silicon", h.s1.id, "access", "revoke", h.c2.id)
    status, body = h.call("GET", hooks, h.c2)
    h.check("unsharing removes access at once", code == 0 and status == 403, {"revoke_exit": code, "c2_list": status})
    h.hook(h.c1.home, "--silicon", h.s1.id, "access", "grant", h.c2.id, "--level", "view")
    status_leave, _ = h.call("DELETE", f"silicons/{h.s1.id}/access/me", h.c2)
    status, _ = h.call("GET", hooks, h.c2)
    h.check("a grantee can leave on its own", status_leave == 204 and status == 403,
            {"leave": status_leave, "c2_list_after": status})

    # Silicons are not open to the world: S2 (looked after by C2) accepts a grant only once it allowed C1.
    code, refused, err = h.hook(h.c1.home, "--json", "--silicon", h.s1.id, "access", "grant", h.s2.id, "--level", "view")
    error = h.hook_json_error(err)
    h.check("granting S2 (another custodian's Silicon) is refused until S2 allows it",
            code != 0 and error.get("code") == "silicon_not_reachable", {"exit": code, "error": error})
    status, allowed = h.call("PUT", f"silicons/{h.s2.id}/allow-list/{h.c1.id}", h.c2)
    h.check("S2's custodian adds C1 to S2's allow-list", status == 200, allowed)
    code, granted, err = h.hook(h.c1.home, "--silicon", h.s1.id, "access", "grant", h.s2.id, "--level", "view")
    h.check("now the grant to S2 goes through", code == 0, granted or err)
    h.s2.token = silicon_token(h, h.s2)
    status, body = h.call("GET", hooks, h.s2)
    h.check("S2 reads S1's hooks with its own token", status == 200, {"status": status})
    status, body = h.call("POST", hooks, h.s2, idempotent=True, body={"name": "ByS2"})
    h.check("…but cannot create one with `view` (403)", status == 403, body)
