use super::*;
use crate::domain::EncryptionKeyId;
use crate::infrastructure::{
    crypto::{SecretKey, SecretKeyring},
    postgres::migrate,
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, method, path},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(crate) struct Harness {
    _container: ContainerAsync<Postgres>,
    pub iam: IamClient,
    pub owner: PgPool,
}
pub(crate) fn pair(endpoint: &str, grant: Uuid, seconds: i64, testing: bool) -> Result<Value> {
    Ok(
        json!({"actor":{"type":"silicon","public_id":"si:worker"},"grant_id":grant,"access_token":format!("oba_{endpoint}"),"refresh_token":format!("obr_{endpoint}"),"token_type":"Bearer","expires_in":seconds,"expires_at":(OffsetDateTime::now_utc()+time::Duration::seconds(seconds)).format(&time::format_description::well_known::Rfc3339)?,"audience":"ting","endpoint_id":endpoint,"org_id":"tos","scope":format!("obo:ting:{endpoint}"),"testing_context":testing.then(||json!({"app_id":"ting","app_secret":"ask_ting_audience_secret","iam_test_key":"TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT"}))}),
    )
}
/// Transport fixtures start with already approved dedicated grants.
pub(crate) async fn approved(
    iam: IamClient,
    server: &MockServer,
    environment: Option<(Uuid, i64)>,
    organization: Uuid,
) -> Result<Harness> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let url = format!(
        "postgres://postgres:postgres@{}:{}/postgres",
        container.get_host().await?,
        container.get_host_port_ipv4(5432).await?
    );
    let owner = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await?;
    migrate(&owner).await?;
    if let Some((id, generation)) = environment {
        sqlx::query("INSERT INTO hook_control.environments(id,org_id,creator_kind,creator_id,name,key_hash,iam_key_hash,creation_request_hash,creation_input_hash,encrypted_credentials,generation) VALUES($1,'tos','silicon','si:worker','fixture',$2,$2,$2,$2,'{}',$3)").bind(id).bind(vec![7_u8;32]).bind(generation).execute(&owner).await?;
        Mock::given(method("GET")).and(path("/api/v1/application/testing-context")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"environment_id":id,"application":{"app_id":"ting","org_id":"tos","base_url":"http://127.0.0.1","app_scope":{"iam":[],"external":[]},"webhook_scope":[],"testing_idle_days":7}}))).mount(server).await;
    }
    Mock::given(method("POST")).and(path("/api/v1/oauth/introspect")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"active":true,"authorization":{"actor_type":"silicon","public_id":"si:worker","organization_id":organization,"org_id":"tos","membership_id":"si:worker[tos]","membership_version":1,"authorization_epoch":1,"audience":"hook","testing_environment_id":environment.map(|(id,_)|id),"scopes":[],"org_role":null,"tags":null}}))).mount(server).await;
    sqlx::raw_sql("CREATE ROLE grant_runtime; GRANT USAGE ON SCHEMA hook_private,hook_control TO grant_runtime; GRANT SELECT,UPDATE ON hook_control.environments TO grant_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON hook_private.ting_authorizations,hook_private.ting_obo_credentials TO grant_runtime; GRANT EXECUTE ON FUNCTION hook_private.environment_id(),hook_private.environment_is_available() TO grant_runtime;").execute(&owner).await?;
    let pool=PgPoolOptions::new().max_connections(5).after_connect(move |c,_|Box::pin(async move {
        sqlx::query("SET ROLE grant_runtime").execute(&mut *c).await?;
        if let Some((id,generation))=environment {sqlx::query("SELECT set_config('hook.environment_id',$1,false),set_config('hook.environment_generation',$2,false)").bind(id.to_string()).bind(generation.to_string()).execute(c).await?;} Ok(())
    })).connect(&url).await?;
    let key = EncryptionKeyId::new("fixture")?;
    let cipher = Arc::new(SecretCipher::new(SecretKeyring::new(
        key.clone(),
        [(key, SecretKey::from_bytes([71; 32]))],
    )?));
    let iam = iam.with_ting_grants(PostgresStore::new(pool), cipher);
    let broker = iam.ting_grants.as_ref().ok_or("broker missing")?;
    let token = SecretString::from("oat_fixture");
    let scope = broker.scope(&iam, &token, "tos").await?;
    let mut tx = broker.store.pool().begin().await?;
    broker.lock(&mut tx, &scope).await?;
    for root in TingGrants::roots(&iam) {
        let value =
            serde_json::from_value(pair(root, Uuid::new_v4(), 3600, environment.is_some())?)?;
        broker.save(&mut tx, &scope, &value).await?;
    }
    tx.commit().await?;
    Ok(Harness {
        _container: container,
        iam,
        owner,
    })
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "single fixture exercises persisted grant transitions and independent production/testing planes"
)]
async fn explicit_approval_encryption_retry_revocation_and_generation_fencing() -> Result {
    for testing in [false, true] {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/api/version")).respond_with(ResponseTemplate::new(200).insert_header("silicon-iam-api-version","v1").set_body_json(json!({"service":"silicon-iam","selected_api_version":"v1","supported_api_versions":["v1"],"build":"test","commit":"test"}))).mount(&server).await;
        let sdk = silicon_iam_client::Client::builder(&server.uri())?
            .credential(Credential::application("hook", "ask_fixture"))
            .auto_update(false)
            .build()?;
        let environment = testing.then(|| (Uuid::new_v4(), 7));
        let sdk = if testing {
            sdk.with_environment(EnvironmentKey::new("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")?)
        } else {
            sdk
        };
        let iam = IamClient {
            ting_grants: None,
            inner: Arc::new(super::super::Inner {
                sdk: Some(sdk),
                base_url: server.uri().parse()?,
                app_id: Some("hook".into()),
                accept_local_tokens: false,
                webhook_verifier: None,
                testing_id: environment.map(|v| v.0),
                webhook_key_digest: None,
            }),
        };
        let harness = approved(iam, &server, environment, Uuid::new_v4()).await?;
        let iam = &harness.iam;
        let token = SecretString::from("oat_fixture");
        assert_eq!(
            iam.ting_authorization_status(&token, "tos", true).await?["status"],
            "authorization_required"
        );
        assert!(matches!(
            iam.ting_proof(&token, "tos", "tings.send", "/v1/tings", b"{}")
                .await,
            Err(IamError::TingAuthorizationRequired)
        ));
        let id = Uuid::new_v4();
        let detail = json!({"id":id,"app_id":"hook","app_name":"Hook","actor":{"type":"silicon","public_id":"si:worker"},"org_id":"tos","status":"pending","version":1,"expires_at":(OffsetDateTime::now_utc()+time::Duration::minutes(10)).format(&time::format_description::well_known::Rfc3339)?,"endpoints":[],"authorization_url":"https://iam.example/consent","providers":[{"app_id":"ting","app_name":"Ting","actor":{"type":"silicon","public_id":"si:worker"},"org_id":"tos"}]});
        let start_attempt = std::sync::atomic::AtomicUsize::new(0);
        let start_reply = detail.clone();
        Mock::given(method("POST"))
            .and(path("/api/v1/obo-access/authorizations"))
            .respond_with(move |_: &wiremock::Request| {
                if start_attempt.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(503)
                } else {
                    ResponseTemplate::new(200).set_body_json(&start_reply)
                }
            })
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/obo-access/authorizations/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&detail))
            .mount(&server)
            .await;
        let grant = Uuid::new_v4();
        let mut pairs = Vec::new();
        for root in TingGrants::roots(iam) {
            pairs.push(pair(
                root,
                if root == "tings.send" {
                    grant
                } else {
                    Uuid::new_v4()
                },
                3600,
                testing,
            )?);
        }
        Mock::given(method("POST"))
            .and(path("/api/v1/obo-access/tokens"))
            .and(body_partial_json(
                json!({"authorization_code":"approved-code"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items":pairs})))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            iam.authorize_ting(&token, "tos", "stable-start-key")
                .await
                .is_err()
        );
        let retained: Value = sqlx::query_scalar("SELECT start_payload FROM hook_private.ting_authorizations WHERE start_key='stable-start-key'")
            .fetch_one(&harness.owner).await?;
        assert!(!retained.to_string().contains("oat_"));
        assert_eq!(
            iam.ting_authorization_status(&token, "tos", false).await?["status"],
            "authorization_required"
        );
        // Simulate a restarted caller with a rotated current OAuth login.
        let rotated = SecretString::from("oat_rotated_login");
        iam.clone()
            .authorize_ting(&rotated, "tos", "stable-start-key")
            .await?;
        let starts: Vec<_> = server
            .received_requests()
            .await
            .ok_or("missing starts")?
            .into_iter()
            .filter(|r| r.url.path() == "/api/v1/obo-access/authorizations")
            .collect();
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[0].body, starts[1].body);
        assert_eq!(
            starts[0].headers.get("idempotency-key"),
            starts[1].headers.get("idempotency-key")
        );
        assert_eq!(
            starts[1].body_json::<Value>()?["subject_token"],
            "oat_fixture"
        );
        assert_eq!(
            iam.complete_ting(&token, "tos", id, "approved-code")
                .await?["status"],
            "authorized"
        );
        iam.complete_ting(&token, "tos", id, "approved-code")
            .await?;
        assert!(
            iam.complete_ting(&token, "tos", id, "changed-code")
                .await
                .is_err()
        );
        assert!(
            iam.complete_ting(&token, "other-org", id, "approved-code")
                .await
                .is_err()
        );
        let stored: Vec<Value> =
            sqlx::query_scalar("SELECT sealed FROM hook_private.ting_obo_credentials")
                .fetch_all(&harness.owner)
                .await?;
        assert!(
            stored
                .iter()
                .all(|v| !v.to_string().contains("obr_") && !v.to_string().contains("oba_"))
        );
        let broker = iam.ting_grants.as_ref().ok_or("broker missing")?;
        let scope = broker.scope(iam, &token, "tos").await?;
        let mut expiring: models::OboTokenPair =
            serde_json::from_value(pair("tings.send", grant, 1, testing)?)?;
        let mut tx = broker.store.pool().begin().await?;
        broker.save(&mut tx, &scope, &expiring).await?;
        tx.commit().await?;
        let failure = Mock::given(method("POST"))
            .and(path("/api/v1/obo-access/tokens"))
            .and(body_partial_json(json!({"refresh_token":"obr_tings.send"})))
            .respond_with(ResponseTemplate::new(503))
            .mount_as_scoped(&server)
            .await;
        assert!(
            iam.ting_proof(&token, "tos", "tings.send", "/v1/tings", b"{}")
                .await
                .is_err()
        );
        drop(failure);
        let mut renewed = pair("tings.send", grant, 3600, testing)?;
        renewed["refresh_token"] = json!("obr_rotated");
        Mock::given(method("POST"))
            .and(path("/api/v1/obo-access/tokens"))
            .and(body_partial_json(json!({"refresh_token":"obr_tings.send"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items":[renewed]})))
            .expect(1)
            .mount(&server)
            .await;
        let (one, two) = tokio::join!(
            iam.ting_proof(&token, "tos", "tings.send", "/v1/tings", b"{}"),
            iam.ting_proof(&token, "tos", "tings.send", "/v1/tings", b"{}")
        );
        one?;
        two?;
        let requests = server.received_requests().await.ok_or("requests missing")?;
        let refreshes: Vec<_> = requests
            .iter()
            .filter(|r| {
                serde_json::from_slice::<Value>(&r.body)
                    .is_ok_and(|b| b["refresh_token"] == "obr_tings.send")
            })
            .collect();
        assert_eq!(refreshes.len(), 2);
        assert_eq!(
            refreshes[0].headers["idempotency-key"],
            refreshes[1].headers["idempotency-key"]
        );
        expiring.refresh_token = "obr_revoked".into();
        let mut tx = broker.store.pool().begin().await?;
        broker.save(&mut tx, &scope, &expiring).await?;
        tx.commit().await?;
        Mock::given(method("POST"))
            .and(path("/api/v1/obo-access/tokens"))
            .and(body_partial_json(json!({"refresh_token":"obr_revoked"})))
            .respond_with(ResponseTemplate::new(401).set_body_json(
                json!({"error":{"code":"invalid_refresh_token","message":"revoked"}}),
            ))
            .mount(&server)
            .await;
        assert!(matches!(
            iam.ting_proof(&token, "tos", "tings.send", "/v1/tings", b"{}")
                .await,
            Err(IamError::TingAuthorizationRequired)
        ));
        assert_eq!(
            iam.ting_authorization_status(&token, "tos", false).await?["endpoints"]
                .as_array()
                .ok_or("endpoints")?
                .len(),
            TingGrants::roots(iam).len() - 1
        );
        if let Some((environment, _)) = environment {
            sqlx::query("SELECT hook_control.clean_environment($1)")
                .bind(environment)
                .execute(&harness.owner)
                .await?;
            assert!(
                iam.ting_authorization_status(&token, "tos", false)
                    .await
                    .is_err()
            );
            let count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM hook_private.ting_obo_credentials")
                    .fetch_one(&harness.owner)
                    .await?;
            assert_eq!(count, 0);
        }
    }
    Ok(())
}
