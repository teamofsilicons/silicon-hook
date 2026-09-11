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
async fn byos_creation_and_replacement_keep_test_routing_and_policy_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
    async fn record(
        State(calls): State<Arc<Mutex<Vec<Value>>>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        assert_eq!(
            headers["x-hook-test-key"],
            "ABCDEFGHIJKLMNOPQRSTUVWX12345678"
        );
        assert_eq!(headers["x-org-id"], "tos");
        assert_eq!(headers["authorization"], "Bearer test-token");
        assert_eq!(headers["silicon-hook-api-version"], "v1");
        calls.lock().await.push(body);
        // An intentional API error avoids coupling this request contract test to hook response fields.
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":{"code":"fixture","message":"recorded"}})),
        )
    }
    let app = Router::new()
        .route(
            "/api/version",
            get(|| async { Json(json!({"service":"silicon-hook", "selected_api_version":"v1"})) }),
        )
        .route("/api/v1/silicons/cos:tos/hooks", post(record))
        .route("/api/v1/silicons/cos:tos/hooks/{id}", patch(record))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let client = Client::new(&format!("http://{}", listener.local_addr()?))?
        .with_auto_update(false)
        .with_organization("tos")
        .with_token("test-token")
        .with_test_key("ABCDEFGHIJKLMNOPQRSTUVWX12345678")?;
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
    assert!(
        client
            .create_hook("cos:tos", &creation, &Mutation::default())
            .await
            .is_err()
    );
    assert!(
        client
            .set_secret(
                "cos:tos",
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
