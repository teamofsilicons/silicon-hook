use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, patch, post},
};
use serde_json::{Value, json};
use silicon_hook_client::{
    Client, Mutation, Secret,
    models::{CreateHook, Signature},
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::test]
async fn bring_your_own_secret_on_creation_and_replacement_sends_only_the_secret_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
    async fn record(
        State(calls): State<Arc<Mutex<Vec<Value>>>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        assert_eq!(headers["authorization"], "Bearer test-token");
        assert_eq!(headers["silicon-hook-api-version"], "v3");
        assert!(headers.contains_key("idempotency-key"));
        assert!(!headers.contains_key("x-org-id"));
        calls.lock().await.push(body);
        // An intentional refusal keeps this test about the request only.
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":{"code":"fixture","message":"recorded"}})),
        )
    }
    let app = Router::new()
        .route(
            "/api/version",
            get(|| async { Json(json!({"service":"silicon-hook", "selected_api_version":"v3"})) }),
        )
        .route("/api/v3/silicons/si:cos/hooks", post(record))
        .route("/api/v3/silicons/si:cos/hooks/{id}", patch(record))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let client = Client::new(&format!("http://{}", listener.local_addr()?))?
        .with_telemetry(false)
        .with_token("test-token");
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let creation = CreateHook {
        name: "Provider".into(),
        signature: Some(Signature {
            secret: Some(Secret::new(" first secret ")),
            ..Signature::default()
        }),
        ..CreateHook::default()
    };
    assert!(!format!("{creation:?}").contains("first secret"));
    let refused = client
        .create_hook("si:cos", &creation, &Mutation::default())
        .await
        .expect_err("the fixture refuses");
    assert_eq!(refused.code(), Some("fixture"));
    assert_eq!(refused.status(), Some(422));
    assert!(
        client
            .set_secret(
                "si:cos",
                uuid::Uuid::new_v4(),
                Secret::new("736563726574"),
                Some("hex".into()),
                &Mutation::default()
            )
            .await
            .is_err()
    );
    let recorded = calls.lock().await;
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0]["signature"], json!({"secret":" first secret "}));
    assert_eq!(
        recorded[1],
        json!({"signature":{"secret":"736563726574","secret_encoding":"hex"}})
    );
    server.abort();
    Ok(())
}
