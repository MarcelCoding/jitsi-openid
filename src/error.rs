use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub(crate) enum AppError {
  InvalidSession,
  InvalidCode,
  InvalidState,
  InvalidIdTokenNonce,
  MissingIdToken,
  InvalidAccessToken,
  MissingAccessTokenHash,
  UnsupportedSigningAlgorithm,
  InternalServerError,
}

impl IntoResponse for AppError {
  fn into_response(self) -> Response {
    match self {
      Self::InvalidSession => (StatusCode::BAD_REQUEST, "Invalid Session"),
      Self::InvalidCode => (StatusCode::BAD_REQUEST, "Invalid Code"),
      Self::InvalidState => (StatusCode::BAD_REQUEST, "Invalid State"),
      Self::InvalidIdTokenNonce => (StatusCode::BAD_REQUEST, "Invalid Id Token Nonce"),
      Self::MissingIdToken => (StatusCode::BAD_REQUEST, "Missing Id Token - if you can't configure your IDP to provide an id token, reach out to me to implement some kind of workaround: https://github.com/MarcelCoding/jitsi-openid/issues/new"),
      Self::InvalidAccessToken => (StatusCode::BAD_REQUEST, "Invalid Access Token"),
      Self::MissingAccessTokenHash => (StatusCode::BAD_REQUEST, "Missing Access Token Hash - if you can't configure your IDP to provide an access token hash (delivered using the id token), reach out to me to implement some kind of workaround: https://github.com/MarcelCoding/jitsi-openid/issues/new"),
      Self::UnsupportedSigningAlgorithm => (StatusCode::BAD_REQUEST, "Unsupported Signing Algorithm"),
      Self::InternalServerError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"),
    }.into_response()
  }
}
