//! Per-request dependency scoping and contract admission.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use http::HeaderMap;

use super::state::ApiState;

/// Makes the API state available to handlers and admits versioned requests
/// against the persisted contract lifecycle.
pub(super) async fn scope(
    State(state): State<ApiState>,
    mut request: Request,
    next: Next,
) -> Response {
    let contract_headers =
        if let Some((major, _)) = super::version::split_path(request.uri().path()) {
            match super::contracts::admit_major(&state, major).await {
                Ok(headers) => headers,
                Err(error) => return error.into_response(),
            }
        } else {
            HeaderMap::new()
        };
    request.extensions_mut().insert(state);
    let mut response = next.run(request).await;
    response.headers_mut().extend(contract_headers);
    response
}
