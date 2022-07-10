use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub(crate) enum AppError {
  InvalidSession,
  InvalidCode,
  InvalidState,
  InvalidIdTokenNonce,
  MissingIdTokenAndUserInfoEndpoint,
  IdTokenRequired,
  InvalidAccessToken,
  MissingAccessTokenHash,
  UnsupportedSigningAlgorithm,
  InternalServerError,
  UnableToQueryUserInfo,
  AuthenticationContextWasNtFulfilled,
}

impl IntoResponse for AppError {
  fn into_response(self) -> Response {
    match self {
      Self::InvalidSession => (StatusCode::BAD_REQUEST, "Invalid Session"),
      Self::InvalidCode => (StatusCode::BAD_REQUEST, "Invalid Code"),
      Self::InvalidState => (StatusCode::BAD_REQUEST, "Invalid State"),
      Self::InvalidIdTokenNonce => (StatusCode::BAD_REQUEST, "Invalid Id Token Nonce"),
      Self::MissingIdTokenAndUserInfoEndpoint => (StatusCode::BAD_REQUEST, "Missing Id Token And User Info Endpoint - at least one is missing, you may create an issue to find an workaround if you can't configure your idp to provide either of them: https://github.com/MarcelCoding/jitsi-openid/issues/new "),
      Self::InvalidAccessToken => (StatusCode::BAD_REQUEST, "Invalid Access Token"),
      Self::MissingAccessTokenHash => (StatusCode::BAD_REQUEST, "Missing Access Token Hash - if you can't configure your IDP to provide an access token hash (delivered using the id token), reach out to me to implement some kind of workaround: https://github.com/MarcelCoding/jitsi-openid/issues/new"),
      Self::UnsupportedSigningAlgorithm => (StatusCode::BAD_REQUEST, "Unsupported Signing Algorithm"),
      Self::InternalServerError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"),
      Self::UnableToQueryUserInfo => (StatusCode::INTERNAL_SERVER_ERROR, "Unable to Query User Info"),
      Self::IdTokenRequired => (StatusCode::INTERNAL_SERVER_ERROR, "An authentication context requirement is configured. To validate this requirement an id token is required ... no id token was provided"),
      Self::AuthenticationContextWasNtFulfilled => (StatusCode::BAD_REQUEST, "An authentication context requirement is configured. No one or not the correct one was fulfilled."),
    }.into_response()
  }
}
