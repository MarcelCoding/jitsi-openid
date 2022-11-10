use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use openidconnect::ClaimsVerificationError;

pub(crate) enum AppError {
  InvalidSession,
  InvalidCode,
  InvalidState,
  InvalidIdTokenNonce(ClaimsVerificationError),
  MissingIdTokenAndUserInfoEndpoint,
  IdTokenRequired,
  InvalidAccessToken,
  MissingAccessTokenHash,
  UnsupportedSigningAlgorithm,
  InternalServerError,
  UnableToQueryUserInfo,
  AuthenticationContextWasNotFulfilled,
}

impl IntoResponse for AppError {
  fn into_response(self) -> Response {
    match self {
      Self::InvalidSession => (StatusCode::BAD_REQUEST, "Invalid Session").into_response(),
      Self::InvalidCode => (StatusCode::BAD_REQUEST, "Invalid Code").into_response(),
      Self::InvalidState => (StatusCode::BAD_REQUEST, "Invalid State").into_response(),
      Self::InvalidIdTokenNonce(err) => (StatusCode::BAD_REQUEST, format!("Invalid Id Token Nonce: {}", err)).into_response(),
      Self::MissingIdTokenAndUserInfoEndpoint => (StatusCode::BAD_REQUEST, "Missing Id Token And User Info Endpoint - at least one is missing, you may create an issue to find an workaround if you can't configure your idp to provide either of them: https://github.com/MarcelCoding/jitsi-openid/issues/new").into_response(),
      Self::InvalidAccessToken => (StatusCode::BAD_REQUEST, "Invalid Access Token").into_response(),
      Self::MissingAccessTokenHash => (StatusCode::BAD_REQUEST, "Missing Access Token Hash - if you can't configure your IDP to provide an access token hash (delivered using the id token), reach out to me to implement some kind of workaround: https://github.com/MarcelCoding/jitsi-openid/issues/new").into_response(),
      Self::UnsupportedSigningAlgorithm => (StatusCode::BAD_REQUEST, "Unsupported Signing Algorithm").into_response(),
      Self::InternalServerError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response(),
      Self::UnableToQueryUserInfo => (StatusCode::INTERNAL_SERVER_ERROR, "Unable to Query User Info").into_response(),
      Self::IdTokenRequired => (StatusCode::INTERNAL_SERVER_ERROR, "An authentication context requirement is configured. To validate this requirement an id token is required ... no id token was provided").into_response(),
      Self::AuthenticationContextWasNotFulfilled => (StatusCode::BAD_REQUEST, "An authentication context requirement is configured. No one or not the correct one was fulfilled.").into_response(),
    }
  }
}
