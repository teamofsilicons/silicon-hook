#!/usr/bin/env python3
"""Disposable real IAM/Ting delivery fixture. Never reads existing credentials.

Uses an existing local IAM image, a fresh isolated Docker network/database, and
the checksum-pinned published Ting server. Only fixture identity/type rows are
seeded; SLT issuance, app login, OBO, subscription, send, and ACK are real APIs.
"""
import argparse
import base64
import contextlib
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid

IAM_IMAGE = os.environ.get("HOOK_E2E_IAM_IMAGE", "silicon-iam:id-schema")
TING_COMMIT = "a86971a08089bd212810b2df49f3f13bd41e83ac"
TING_SHA256 = "2f4b0c8fb06fceebae344fcf330aa2665bbe0fac67f474b75f4f01089021e58b"
TING_ARCHIVE = f"ting-server-{TING_COMMIT}.tar.gz"
ORG_UUID = "a044c552-2e3f-4012-9672-72d1b1518401"
ACTORS = {"admin": ("c:ting_e2e_admin", "carbon", "owner"),
          "recipient": ("si:ting-e2e", "silicon", "member"),
          "publisher": ("si:ting-publisher", "silicon", "member")}
HOOK_SCOPES = ["self.identity.read", "self.profile.read", "self.organizations.read",
               "self.membership.read", "self.silicon_access.read", "directory.silicons.read"]
TING_SCOPES = ["self.identity.read", "self.organizations.read", "self.membership.read"]
ENDPOINTS = {"tings.send": "/v1/tings", "subscriptions.register": "/v1/subscriptions",
             "subscriptions.query": "/v1/subscriptions/query", "subscriptions.revoke": "/v1/subscriptions/revoke",
             "sent.query": "/v1/sent/query"}


def private(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(path, "w", opener=lambda name, flags: os.open(name, flags, 0o600)) as out:
        out.write(value if isinstance(value, str) else json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def command(args, *, stdin=None, env=None, log=None, timeout=180):
    result = subprocess.run(args, input=stdin, capture_output=True, env=env, timeout=timeout)
    if result.returncode:
        if log:
            private(log, (result.stdout + result.stderr).decode(errors="replace"))
        raise RuntimeError(f"{Path(args[0]).name} failed with exit {result.returncode}; private diagnostic: {log}")
    return result.stdout


def request(origin, method, path, body=None, token=None, headers=None, expected=(200,)):
    values = {"Content-Type": "application/json", **(headers or {})}
    if token:
        values["Authorization"] = "Bearer " + token
    raw = body if isinstance(body, bytes) else json.dumps(body, separators=(",", ":")).encode() if body is not None else None
    req = urllib.request.Request(origin + path, data=raw, method=method, headers=values)
    try:
        with urllib.request.urlopen(req, timeout=35) as response:
            status, data = response.status, response.read(1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        status, data = error.code, error.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise RuntimeError("oversized fixture API response")
    try:
        value = json.loads(data)
    except ValueError:
        raise RuntimeError(f"{method} {path} returned non-JSON HTTP {status}") from None
    if status not in expected:
        code = value.get("error", {}).get("code", "unknown")
        safe = code if code.replace("_", "").isalnum() and len(code) < 80 else "unknown"
        raise RuntimeError(f"{method} {path} returned HTTP {status}, code={safe}")
    return value


def psql(state, sql, database="iam"):
    return command(["docker", "exec", "-i", state["postgres"], "psql", "-U", "postgres", "-d", database,
                    "-X", "-v", "ON_ERROR_STOP=1", "-At"], stdin=sql.encode(), log=Path(state["directory"]) / "sql-error.log")


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def digest(pepper, purpose, value):
    material = b"silicon-iam:v1:digest" + struct.pack(">h", 1) + b"\0" + purpose.encode() + b"\0" + value.encode()
    return hmac.new(pepper, material, hashlib.sha256).hexdigest()


def token(prefix):
    return prefix + secrets.token_urlsafe(32)


def state_path(directory):
    return Path(directory) / "fixture.private.json"


def save(state):
    private(state_path(state["directory"]), state)


def load(directory):
    state = json.loads(state_path(directory).read_text())
    if not state.get("fixture_owned") or not state["network"].startswith("hook-ting-e2e-"):
        raise RuntimeError("not an owned fixture")
    return state


def cli(state, actor, args, raw=None):
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(("SILICON_IAM_", "IAM_TEST_")) or key == "SILICON_ORG":
            env.pop(key)
    env["SILICON_HOME"] = str(Path(state["directory"]) / "profiles" / actor)
    result = command([state["iam_cli"], "--url", state["iam_url"], "--no-org", "--json", *args],
                     stdin=raw, env=env, log=Path(state["directory"]) / "iam-cli-error.log", timeout=50)
    return json.loads(result)


def slt(state, actor, app="hook"):
    result = cli(state, actor, ["login", "--app-id", app, "--grant-org", "tos", "--approve-scopes"])
    return result["slt"]


def exchange(state, actor, app):
    return cli(state, actor, ["app", "token", "exchange", app, "--slt", slt(state, actor, app),
                              "--app-secret", state["app_secrets"][app]])


def proof(state, endpoint, raw, subject=None):
    return cli(state, "recipient", ["app", "obo", "exchange", "ting", endpoint,
        "--as-app-id", "hook", "--app-secret", state["app_secrets"]["hook"],
        "--subject-token", subject or state["hook_recipient"]["access_token"],
        "--org-context", "tos", "--method", "POST", "--body-file", "-"], raw)["access_proof"]


def seed(state, pepper):
    owner = ACTORS["admin"][0]
    q = quote
    parts = ["BEGIN;", "INSERT INTO iam.cryptographic_key_versions(purpose,key_version,status) VALUES ('token_hmac',1,'active'),('contact_aead',1,'active') ON CONFLICT DO NOTHING;"]
    for actor, kind, _ in ACTORS.values():
        parts.append(f"INSERT INTO iam.principals(id,kind,status,activated_at) VALUES({q(actor)},{q(kind)},'active',now());")
    parts += [f"INSERT INTO iam.carbons(id,carbon_id,display_name) VALUES({q(owner)},{q(owner)},'Ting E2E administrator');",
              f"INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name) VALUES('{ORG_UUID}','tos',{q(owner)},'Isolated Ting E2E');"]
    # Contact ciphertext is deliberately opaque fixture data, as in IAM's own
    # SQL fixtures; no contact scopes are requested and no email/SMS is sent.
    for kind in ("email", "phone"):
        parts.append(f"INSERT INTO iam.carbon_contacts(id,carbon_id,kind,ciphertext,nonce,encryption_key_version,verified_at) VALUES('{uuid.uuid4()}',{q(owner)},{q(kind)},decode('{secrets.token_hex(17)}','hex'),decode('{secrets.token_hex(12)}','hex'),1,now());")
    for label, (actor, kind, role) in ACTORS.items():
        membership, session, access_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        direct = token("cat_" if kind == "carbon" else "sat_")
        state["direct"][label] = {"access_token": direct, "membership_id": membership, "session_id": session}
        parts.append(f"INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES('{membership}','{ORG_UUID}',{q(actor)},{q(kind)},{q(role)});")
        if kind == "silicon":
            parts.append(f"INSERT INTO iam.silicons(id,organization_id,membership_id,organization_handle,silicon_handle,display_name,provisioning_status) VALUES({q(actor)},'{ORG_UUID}','{membership}','tos',{q(actor.removeprefix('si:'))},{q(label)},'active');")
        parts.append(f"INSERT INTO iam.authentication_sessions(id,subject_principal_id,subject_kind,authentication_method,subject_auth_epoch,idle_expires_at,absolute_expires_at) VALUES('{session}',{q(actor)},{q(kind)},{q('email_otp' if kind == 'carbon' else 'silicon_credential')},1,now()+interval '1 day',now()+interval '2 days');")
        parts.append(f"INSERT INTO iam.access_tokens(id,token_class,token_digest,digest_key_version,token_prefix,authentication_session_id,subject_principal_id,subject_kind,audience,subject_auth_epoch,expires_at) VALUES('{access_id}',{q(kind+'_access')},decode('{digest(pepper, kind+'-access-token', direct)}','hex'),1,{q(direct[:12])},'{session}',{q(actor)},{q(kind)},'silicon-iam',1,now()+interval '1 day');")
        parts.append(f"INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES('{access_id}','iam.self');")
    for app, secret in state["app_secrets"].items():
        parts.append(f"INSERT INTO iam.principals(id,kind,status,activated_at) VALUES({q(app)},'application','active',now());")
        iam_scopes = HOOK_SCOPES if app == "hook" else TING_SCOPES
        external = [{"app_id": "ting", "endpoint_id": e} for e in ENDPOINTS] if app == "hook" else []
        parts.append(f"INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,app_name,review_status,visibility,base_url,app_scope) VALUES({q(app)},{q(app)},'{ORG_UUID}',{q(owner)},{q(app)},'verified','public','https://fixture.invalid',{q(json.dumps({'iam':iam_scopes,'external':external}))}::jsonb);")
        parts.append(f"INSERT INTO iam.application_secrets(id,application_id,secret_version,secret_prefix,secret_digest,pepper_key_version,created_by_carbon_id) VALUES('{uuid.uuid4()}',{q(app)},1,{q(secret[:12])},decode('{digest(pepper,'application-secret',secret)}','hex'),1,{q(owner)});")
        scopes = iam_scopes + [f"obo:ting:{e}" for e in ENDPOINTS] if app == "hook" else iam_scopes
        for scope in scopes:
            parts += [f"INSERT INTO iam.oauth_scope_catalog(scope,description,sensitive) VALUES({q(scope)},'Isolated integration fixture',false) ON CONFLICT DO NOTHING;",
                      f"INSERT INTO iam.application_requested_scopes(application_id,scope) VALUES({q(app)},{q(scope)});",
                      f"INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES({q(app)},{q(scope)},{q(owner)});"]
    for endpoint, path in ENDPOINTS.items():
        parts.append(f"INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical,ttl_seconds) VALUES('{ORG_UUID}','ting',{q(endpoint)},{q(path)},'{{}}',true,60);")
    parts.append("COMMIT;")
    psql(state, "\n".join(parts))
    expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=12)).isoformat().replace("+00:00", "Z")
    for label, (actor, kind, _) in ACTORS.items():
        store = Path(state["directory"]) / "profiles" / label / ".silicon-iam"
        private(store / "config.json", {"telemetry":False,"auto_update":False,"current_profile":"default",
                "profiles":{"default":{"url":state["iam_url"]}}})
        private(store / "credentials.json", {"sessions":{"default":{"access_token":state["direct"][label]["access_token"],
                "refresh_token":"", "expires_at":expiry,"actor_type":kind,"actor_id":actor}}})
    save(state)


def port(container, number):
    raw = command(["docker", "port", container, f"{number}/tcp"]).decode().strip()
    host, value = raw.rsplit(":",1)
    if host != "127.0.0.1":
        raise RuntimeError("fixture listener is not restricted to loopback")
    return int(value)


def wait_health(url, path="/healthz"):
    for _ in range(60):
        try:
            request(url, "GET", path)
            return
        except (OSError, RuntimeError):
            time.sleep(.5)
    raise RuntimeError("isolated fixture failed its health check")


def setup(args):
    directory = Path(tempfile.mkdtemp(prefix="hook-ting-e2e-")).resolve()
    os.chmod(directory, 0o700)
    name = directory.name
    state = {"fixture_owned":True, "directory":str(directory), "network":name,
             "postgres":name+"-postgres", "iam":name+"-iam", "ting":name+"-ting",
             "containers":[], "iam_cli":args.iam_cli, "iam_image":args.iam_image,
             "ting_commit":TING_COMMIT, "org_id":"tos", "org_uuid":ORG_UUID,
             "actor_id":ACTORS["recipient"][0],"direct":{},
             "app_secrets":{"hook":token("ask_"),"ting":token("ask_")},
             "coverage":{"identity_setup":"synthetic rows in disposable IAM only", "type_management_bootstrap":False,
                         "real_iam_testing_plane":False, "external_service_mutations":False}}
    save(state)
    print(f"Fixture directory: {directory}", flush=True)
    command(["docker","network","create",name], log=directory/"setup-error.log")
    db_password, runtime_password = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    private(directory/"postgres.env", f"POSTGRES_PASSWORD={db_password}\nPOSTGRES_DB=iam\n")
    command(["docker","run","-d","--name",state["postgres"],"--network",name,"--network-alias","database",
             "--env-file",str(directory/"postgres.env"),"postgres:16.15-bookworm"], log=directory/"setup-error.log")
    state["containers"].append(state["postgres"]); save(state)
    for _ in range(60):
        if subprocess.run(["docker","exec",state["postgres"],"pg_isready","-U","postgres"],capture_output=True).returncode == 0:
            break
        time.sleep(.5)
    psql(state, f"CREATE ROLE silicon_iam_api NOLOGIN; CREATE ROLE silicon_iam_worker NOLOGIN; CREATE ROLE silicon_iam_key_operator NOLOGIN; CREATE ROLE fixture_api LOGIN PASSWORD {quote(runtime_password)} IN ROLE silicon_iam_api;")
    pepper = secrets.token_bytes(32)
    b64 = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
    env = {"IAM_ENVIRONMENT":"development", "IAM_BIND_ADDR":"0.0.0.0:8080", "IAM_ALLOW_LOCAL_PROVIDERS":"true",
           "IAM_EXPOSE_LOCAL_OTPS":"true", "IAM_LOG_FILTER":"error", "IAM_TELEMETRY":"off",
           "IAM_DATABASE_URL":f"postgres://fixture_api:{runtime_password}@database:5432/iam",
           "IAM_MIGRATOR_DATABASE_URL":f"postgres://postgres:{db_password}@database:5432/iam",
           "IAM_TOKEN_PEPPER_CURRENT_VERSION":"1", "IAM_TOKEN_PEPPER_KEYRING":json.dumps({"1":b64(pepper)}),
           "IAM_BLIND_INDEX_CURRENT_VERSION":"1", "IAM_BLIND_INDEX_KEYRING":json.dumps({"1":b64(secrets.token_bytes(32))}),
           "IAM_ENCRYPTION_CURRENT_VERSION":"1", "IAM_ENCRYPTION_KEYRING":json.dumps({"1":b64(secrets.token_bytes(32))}),
           "IAM_COOKIE_KEY":b64(secrets.token_bytes(32)), "IAM_PUBLIC_BASE_URL":"http://127.0.0.1:8080",
           "IAM_AUTH_BASE_URL":"http://127.0.0.1:8080", "IAM_CORS_ALLOWED_ORIGINS":"http://127.0.0.1:8080"}
    private(directory/"iam.env", "".join(f"{k}={v}\n" for k,v in env.items()))
    command(["docker","run","--rm","--network",name,"--env-file",str(directory/"iam.env"),args.iam_image,"iam-migrate"],log=directory/"migration-error.log")
    grants=command(["docker","run","--rm","--entrypoint","cat",args.iam_image,"/opt/silicon-iam/postgres/runtime-grants.sql"])
    psql(state,grants.decode())
    command(["docker","run","-d","--name",state["iam"],"--network",name,"--network-alias","iam",
             "-p","127.0.0.1::8080","-p","127.0.0.1::8082","--env-file",str(directory/"iam.env"),args.iam_image,"iam-api"],log=directory/"setup-error.log")
    state["containers"].append(state["iam"]); save(state)
    state["iam_url"]=f"http://127.0.0.1:{port(state['iam'],8080)}"; save(state)
    seed(state,pepper)
    wait_health(state["iam_url"])
    print("Real IAM running with isolated synthetic identities.",flush=True)
    for actor in ("admin","recipient"):
        state["hook_"+actor]=exchange(state,actor,"hook")
    save(state)
    archive=directory/TING_ARCHIVE
    urllib.request.urlretrieve(f"https://github.com/teamofsilicons/silicon-ting/releases/download/server-{TING_COMMIT}/{TING_ARCHIVE}",archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=TING_SHA256:
        raise RuntimeError("Ting server archive checksum mismatch")
    artifact=directory/"artifact"; artifact.mkdir()
    with tarfile.open(archive) as bundle:
        for member in bundle.getmembers():
            target=(artifact/member.name).resolve()
            if not target.is_relative_to(artifact) or member.issym() or member.islnk():
                raise RuntimeError("unexpected release archive entry")
        bundle.extractall(artifact,filter="data")
    binaries=list(artifact.rglob("ting-server"))
    if len(binaries)!=1:
        raise RuntimeError("release did not contain one Ting server")
    binary=binaries[0]; binary.chmod(0o755)
    store=directory/"ting-data";store.mkdir(mode=0o700)
    tenv={"TING_BIND":"0.0.0.0:8082","TING_PUBLIC_ORIGIN":"http://127.0.0.1:8082",
          "TING_DATABASE_PATH":"/data/ting.sqlite","TING_ENCRYPTION_KEY":secrets.token_hex(32),
          "TING_IAM_URL":"http://127.0.0.1:8080","TING_IAM_APP_SECRET":state["app_secrets"]["ting"],
          "TING_HONEYCOMB_URL":"http://127.0.0.1:1","TING_SPACESTATION_URL":"http://127.0.0.1:1",
          "TING_SPACESTATION_KEY":"table-fixture-"+secrets.token_hex(16),"TING_SPACESTATION_TABLE":"fixture",
          "TING_DOCS_URL":"http://127.0.0.1:8080/docs","RUST_LOG":"error"}
    private(directory/"ting.env","".join(f"{k}={v}\n" for k,v in tenv.items()))
    command(["docker","run","-d","--name",state["ting"],"--network","container:"+state["iam"],
             "--env-file",str(directory/"ting.env"),"-v",f"{binary}:/app/ting-server:ro","-v",f"{store}:/data",
             "-v",f"{args.ca_bundle}:/etc/ssl/certs/ca-certificates.crt:ro",
             "--entrypoint","/app/ting-server","debian:bookworm-slim"],log=directory/"setup-error.log")
    state["containers"].append(state["ting"]);state["ting_url"]=f"http://127.0.0.1:{port(state['iam'],8082)}";save(state)
    wait_health(state["ting_url"])
    # Never mix host and Linux SQLite WAL writers through a Docker file share.
    command(["docker", "stop", state["ting"]])
    with contextlib.closing(sqlite3.connect(store/"ting.sqlite")) as db:
        with db:
            db.execute("INSERT INTO types(ctx,org,app,name,description) VALUES(?,?,?,?,?)",
                       ("production",ORG_UUID,"hook","hook.webhook.received","Isolated Hook integration fixture"))
    command(["docker", "start", state["ting"]])
    wait_health(state["ting_url"])
    state["ting_session"]=request(state["ting_url"],"POST","/v1/session",{"slt":slt(state,"recipient","ting")},
                                    headers={"Idempotency-Key":str(uuid.uuid4())},expected=(200,201))["session_token"]
    save(state)
    verify(state)
    print(f"READY {state_path(directory)}",flush=True)


def verify(state):
    import websocket
    health = request(state["ting_url"], "GET", "/healthz")
    if health.get("version") != state.get("ting_version", "0.1.2"):
        raise RuntimeError("fixture requires its pinned Ting server version")
    raw=json.dumps({"org_id":"tos","app_id":"hook","for":state["actor_id"]},separators=(",",":")).encode()
    grant=request(state["ting_url"],"POST","/v1/subscriptions",raw,
                  token=proof(state,"subscriptions.register",raw),expected=(200,201))
    if grant["for"]!=state["actor_id"] or not grant["active"]:
        raise RuntimeError("recipient grant mismatch")
    url=state["ting_url"].replace("http://","ws://")+"/v1/ws?protocol=v1"
    ws=websocket.create_connection(url,timeout=20,suppress_origin=True)
    ready=json.loads(ws.recv()); receiver=ready["receiver_id"]
    def ws_call(op,**body):
        key=str(uuid.uuid4());ws.send(json.dumps({"op":op,"request_id":key,**body}))
        while True:
            value=json.loads(ws.recv())
            if value.get("op")=="ping":
                ws.send(json.dumps({"op":"pong"}));continue
            if value.get("request_id")==key:
                if value.get("op")=="error":raise RuntimeError("Ting websocket operation failed")
                return value
            pending.append(value)
    pending=[]
    ws_call("subscribe",org_id="tos",session_token=state["ting_session"],webhook_ids=[])
    endpoint="/v1/orgs/tos/webhooks"
    hook=request(state["ting_url"],"POST",endpoint,{"receiver_id":receiver},token=state["ting_session"],
                 headers={"Idempotency-Key":str(uuid.uuid4())},expected=(200,201))
    key="fixture-"+str(uuid.uuid4())
    body={"org_id":"tos","type":"hook.webhook.received","for":state["actor_id"],"key":key,
          "data":{"type":"new_event","data":{"sender":"fixture","metadata":{"run":key}}},"metadata":{}}
    raw=json.dumps(body,separators=(",",":")).encode()
    accepted=request(state["ting_url"],"POST","/v1/tings",raw,token=proof(state,"tings.send",raw),expected=(202,))
    replay=request(state["ting_url"],"POST","/v1/tings",raw,token=proof(state,"tings.send",raw),expected=(200,))
    if accepted!=replay:raise RuntimeError("fresh-proof send retry changed accepted identity")
    while True:
        value=pending.pop(0) if pending else json.loads(ws.recv())
        if value.get("op")=="ping":ws.send(json.dumps({"op":"pong"}));continue
        if value.get("op")=="tings" and value.get("webhook_id")==hook["id"]:
            items=value.get("tings",[])
            if any(item.get("id")==accepted["id"] and item.get("data")==body["data"] for item in items):break
    ws_call("ack",org_id="tos",webhook_id=hook["id"],message_ids=[accepted["id"]],kind="delivery")
    detail=request(state["ting_url"],"GET",f"/v1/orgs/tos/inbox/{accepted['id']}",token=state["ting_session"])
    if detail["read"]:raise RuntimeError("delivery ACK incorrectly marked read")
    ws_call("ack",org_id="tos",webhook_id=hook["id"],message_ids=[accepted["id"]],kind="read")
    detail=request(state["ting_url"],"GET",f"/v1/orgs/tos/inbox/{accepted['id']}",token=state["ting_session"])
    if not detail["read"]:raise RuntimeError("read ACK did not persist")
    ws.close()
    report={"real_iam":True,"real_ting":True,"iam_url":state["iam_url"],"ting_url":state["ting_url"],
            "ting_commit":state["ting_commit"],"ting_version":health["version"],"ting_archive_sha256":state.get("ting_archive_sha256", TING_SHA256),
            "checks":["official IAM CLI SLT and application login","recipient OBO registration",
                      "fresh request-bound OBO send proof","HTTP202 durable acceptance",
                      "fresh-proof idempotent replay returns same Ting ID","real websocket receives exact event",
                      "delivery ACK leaves notification unread","read ACK marks notification read"],
            "limitations":["Ting type definition is fixture seeded; Honeycomb management bootstrap not exercised",
                           "Uses disposable IAM normal data plane; cross-testing-environment isolation not exercised",
                           "Websocket receiver is test harness; native daemon/local webhook acceptance not yet exercised"],
            "ting_id":accepted["id"],"complete":True}
    private(Path(state["directory"])/"verification.json",report)
    print("PASS real IAM/Ting registration, send, replay, websocket receipt, delivery ACK, read ACK",flush=True)


def cleanup(state):
    for name in reversed(state["containers"]):
        if not name.startswith(state["network"]+"-"):raise RuntimeError("unowned container")
        subprocess.run(["docker","rm","-f",name],capture_output=True,check=False)
    subprocess.run(["docker","network","rm",state["network"]],capture_output=True,check=False)
    state["cleaned_at"]=datetime.datetime.now(datetime.timezone.utc).isoformat();save(state)
    print("Removed only this fixture's containers and network; private evidence retained.")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="operation",required=True)
    create=sub.add_parser("setup");create.add_argument("--iam-image",default=IAM_IMAGE);create.add_argument("--iam-cli",default="iam")
    create.add_argument("--ca-bundle",type=Path,default=Path("/etc/ssl/cert.pem"))
    for operation in ("verify","cleanup","slt"):
        p=sub.add_parser(operation);p.add_argument("directory",type=Path)
        if operation=="slt":
            p.add_argument("--actor",choices=ACTORS,default="publisher");p.add_argument("--app",default="hook");p.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    if args.operation=="setup":setup(args)
    else:
        state=load(args.directory)
        if args.operation=="cleanup":cleanup(state)
        elif args.operation=="verify":verify(state)
        else:
            private(args.output,{"slt":slt(state,args.actor,args.app)})
            print(f"Fresh SLT written privately to {args.output}")


if __name__=="__main__":
    os.umask(0o077)
    try:main()
    except Exception as error:
        # Never print subprocess arguments, raw API bodies, or credential files.
        if isinstance(error,RuntimeError):print(str(error),file=sys.stderr)
        else:print(f"Fixture failed: {type(error).__name__}",file=sys.stderr)
        sys.exit(1)
