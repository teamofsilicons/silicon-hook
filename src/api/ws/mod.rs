//! WebSocket delivery of verified provider requests.
//!
//! A client authenticates the upgrade request exactly like a management call
//! and names the Silicon streams it wants with repeated `silicon_id` query
//! parameters. Unacknowledged events are replayed first, then live events
//! follow in stream order. The server pings every 30 seconds and closes with
//! code 4000 after two minutes without a valid pong.

mod protocol;
mod session;

use axum::{
    Extension,
    extract::{RawQuery, ws::WebSocketUpgrade},
    http::HeaderMap,
    response::Response,
};

pub use protocol::{
    ClientFrame, HEARTBEAT_CLOSE_CODE, HEARTBEAT_CLOSE_REASON, PROTOCOL_VERSION, ServerFrame,
};

use super::{
    handlers::{authorize_management, map_application_error},
    state::ApiState,
};
use crate::{domain::SiliconId, error::AppError};

pub(super) async fn upgrade(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    upgrade: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let silicon_ids = parse_silicon_ids(
        query.as_deref().unwrap_or_default(),
        state.realtime.max_silicons_per_connection.get(),
    )?;
    let authorization_epoch = state.wakeups.authorization_epoch();
    let authorization = authorize_management(&state, &headers, &silicon_ids).await?;
    let streams = silicon_ids
        .iter()
        .map(|silicon_id| {
            state
                .application
                .authorize_stream(&authorization, silicon_id)
                .map_err(map_application_error)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let authority = session::SessionAuthority {
        epoch: authorization_epoch,
        iam: state.iam.clone(),
        request: crate::infrastructure::iam::AuthorizationRequest {
            token: super::extractors::bearer_token(&headers)?,
            org_id: super::extractors::organization_id(&headers)?,
            targets: silicon_ids,
        },
    };
    let application = state.application.clone();
    let wakeups = state.wakeups.clone();
    let settings = state.realtime;
    Ok(upgrade
        .max_message_size(64 * 1024)
        .on_upgrade(move |socket| {
            session::serve_socket(socket, application, wakeups, settings, streams, authority)
        }))
}

fn parse_silicon_ids(query: &str, maximum: usize) -> Result<Vec<SiliconId>, AppError> {
    let mut silicon_ids = Vec::new();
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        if key != "silicon_id" {
            return Err(AppError::validation("invalid_query"));
        }
        let silicon_id = SiliconId::new(value.into_owned())
            .map_err(|_| AppError::validation("invalid_silicon_id"))?;
        if !silicon_ids.contains(&silicon_id) {
            silicon_ids.push(silicon_id);
        }
        if silicon_ids.len() > maximum {
            return Err(AppError::validation_with_details(
                "invalid_silicon_id",
                format!("at most {maximum} Silicon streams per connection"),
            ));
        }
    }
    if silicon_ids.is_empty() {
        return Err(AppError::validation("invalid_silicon_id"));
    }
    Ok(silicon_ids)
}

#[cfg(test)]
mod tests {
    use super::parse_silicon_ids;

    #[test]
    fn repeated_silicon_ids_are_deduplicated_and_bounded() -> Result<(), Box<dyn std::error::Error>>
    {
        let ids = parse_silicon_ids(
            "silicon_id=cos:tos&silicon_id=ops:tos&silicon_id=cos:tos",
            4,
        )?;
        assert_eq!(ids.len(), 2);
        assert!(parse_silicon_ids("", 4).is_err());
        assert!(parse_silicon_ids("other=1", 4).is_err());
        assert!(parse_silicon_ids("silicon_id=a&silicon_id=b&silicon_id=c", 2).is_err());
        Ok(())
    }
}
