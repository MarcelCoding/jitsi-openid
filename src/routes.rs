use axum::body::Body;
use axum::extract::{Path, Query};
use axum::response::{IntoResponse, Redirect};
use axum::routing::get;
use axum::{headers, Extension, Router, TypedHeader};
use axum_extra::extract::CookieJar;
use cookie::Cookie;
use jsonwebtoken::{EncodingKey, Header};
use openidconnect::core::{CoreAuthenticationFlow, CoreGenderClaim};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
  AccessTokenHash, AuthorizationCode, ConfigurationError, CsrfToken, IdTokenClaims, Nonce,
  OAuth2TokenResponse, PkceCodeChallenge, Scope, TokenResponse,
};
use serde::{self, Serializer};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tracing::error;
use uuid::Uuid;

use crate::AppError::{AuthenticationContextWasNotFulfilled, IdTokenRequired};
use crate::{
  AppError, Cfg, InternalServerError, InvalidAccessToken, InvalidCode, InvalidIdTokenNonce,
  InvalidSession, InvalidState, MissingAccessTokenHash, MissingIdTokenAndUserInfoEndpoint,
  MyClaims, MyClient, MyTokenResponse, MyUserInfoClaims, Session, Store, UnableToQueryUserInfo,
  UnsupportedSigningAlgorithm,
};

const COOKIE_NAME: &str = "JITSI_OPENID_SESSION";

pub(crate) fn build_routes() -> Router<Body> {
  Router::new()
    .route("/room/:name", get(room))
    .route("/callback", get(callback))
}

async fn room(
  Path(room): Path<String>,
  Extension(client): Extension<MyClient>,
  Extension(store): Extension<Store>,
  Extension(config): Extension<Cfg>,
  jar: CookieJar,
) -> impl IntoResponse {
  let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

  let mut request = client
    .authorize_url(
      CoreAuthenticationFlow::AuthorizationCode,
      CsrfToken::new_random,
      Nonce::new_random,
    )
    .set_pkce_challenge(pkce_challenge)
    .add_scope(Scope::new("profile".to_string()))
    .add_scope(Scope::new("email".to_string()));

  if let Some(acr_values) = config.acr_values {
    for class in acr_values {
      request = request.add_auth_context_value(class);
    }
  }

  let (auth_url, csrf_token, nonce) = request.url();

  let session_id = Uuid::new_v4();
  store.write().await.insert(
    session_id,
    Session {
      room,
      csrf_token,
      nonce,
      pkce_verifier,
    },
  );

  // Build the cookie
  let cookie = Cookie::build(COOKIE_NAME, session_id.to_string())
    .domain(
      config
        .base_url
        .host()
        .expect("Missing host in base url")
        .to_string(),
    )
    .path(config.base_url.path().to_string())
    .secure(config.base_url.scheme() == "https")
    .http_only(true)
    .max_age(Duration::minutes(30))
    .finish();

  (jar.add(cookie), Redirect::to(auth_url.as_str()))
}

#[derive(Deserialize)]
struct Callback {
  state: String,
  // session_state: String,
  code: AuthorizationCode,
}

async fn callback(
  Query(callback): Query<Callback>,
  TypedHeader(cookies): TypedHeader<headers::Cookie>,
  Extension(client): Extension<MyClient>,
  Extension(store): Extension<Store>,
  Extension(config): Extension<Cfg>,
) -> Result<impl IntoResponse, AppError> {
  let session_id = match cookies.get(COOKIE_NAME).map(Uuid::parse_str) {
    Some(Ok(session_id)) => session_id,
    Some(Err(_)) => return Err(InvalidSession),
    None => return Err(InvalidSession),
  };

  let session = match store.write().await.remove(&session_id) {
    Some(session) => session,
    None => return Err(InvalidSession),
  };

  if &callback.state != session.csrf_token.secret() {
    return Err(InvalidState);
  }

  let response = client
    .exchange_code(callback.code)
    .set_pkce_verifier(session.pkce_verifier)
    .request_async(async_http_client)
    .await
    .map_err(|_| InvalidCode)?;

  let jitsi_user = match id_token_claims(&config, &client, &response, &session.nonce)? {
    None => match user_info_claims(&client, &response).await? {
      None => return Err(MissingIdTokenAndUserInfoEndpoint),
      Some(user) => user,
    },
    Some(user) => user,
  };

  let jwt = create_jitsi_jwt(
    jitsi_user,
    "jitsi".to_string(),
    "jitsi".to_string(),
    config.jitsi_sub,
    "*".to_string(),
    config.jitsi_secret,
  )
  .map_err(|err| {
    error!("Unable to create jwt: {}", err);
    InternalServerError
  })?;

  let mut url = config.jitsi_url.join(&session.room).unwrap();
  url.query_pairs_mut().append_pair("jwt", &jwt);
  Ok(Redirect::to(url.as_str()))
}

fn id_token_claims(
  config: &Cfg,
  client: &MyClient,
  response: &MyTokenResponse,
  nonce: &Nonce,
) -> Result<Option<JitsiUser>, AppError> {
  let id_token = match response.id_token() {
    Some(id_token) => id_token,
    None => {
      return if config.acr_values.is_none() {
        Ok(None)
      } else {
        Err(IdTokenRequired)
      };
    }
  };

  let claims = id_token
    .claims(&client.id_token_verifier(), nonce)
    .map_err(|_| InvalidIdTokenNonce)?;

  if let Some(acr_values) = &config.acr_values {
    if let Some(auth_context) = claims.auth_context_ref() {
      if !acr_values.contains(auth_context) {
        return Err(AuthenticationContextWasNotFulfilled);
      }
    } else {
      return Err(AuthenticationContextWasNotFulfilled);
    }
  }

  match claims.access_token_hash() {
    Some(expected_access_token_hash) => {
      let algorithm = id_token
        .signing_alg()
        .map_err(|_| UnsupportedSigningAlgorithm)?;

      let actual_access_token_hash =
        AccessTokenHash::from_token(response.access_token(), &algorithm)
          .map_err(|_| UnsupportedSigningAlgorithm)?;

      if &actual_access_token_hash != expected_access_token_hash {
        return Err(InvalidAccessToken);
      }
    }
    None => return Err(MissingAccessTokenHash),
  };

  let uid = match claims.preferred_username() {
    Some(name) => name.to_string(),
    None => claims.subject().to_string(),
  };

  Ok(Some(JitsiUser {
    id: uid,
    email: claims.email().map(|email| email.to_string()),
    affiliation: claims.additional_claims().affiliation.clone(),
    name: get_display_name_id_token(claims),
    avatar: None,
  }))
}

async fn user_info_claims(
  client: &MyClient,
  response: &MyTokenResponse,
) -> Result<Option<JitsiUser>, AppError> {
  match client.user_info(response.access_token().clone(), None) {
    Ok(request) => {
      let claims: MyUserInfoClaims = request
        .request_async(async_http_client)
        .await
        .map_err(|_| UnableToQueryUserInfo)?;

      Ok(Some(JitsiUser {
        id: match claims.preferred_username() {
          Some(name) => name.to_string(),
          None => claims.subject().to_string(),
        },
        email: claims.email().map(|email| email.to_string()),
        affiliation: claims.additional_claims().affiliation.clone(),
        name: get_display_name(&claims),
        avatar: None,
      }))
    }
    Err(ConfigurationError::MissingUrl(_)) => Ok(None),
    Err(err) => {
      error!("Unable to find user info url: {}", err);
      Err(InternalServerError)
    }
  }
}

#[derive(Serialize)]
struct JitsiClaims {
  context: JitsiContext,
  aud: String,
  iss: String,
  sub: String,
  room: String,
  #[serde(serialize_with = "jwt_numeric_date")]
  iat: OffsetDateTime,
  #[serde(serialize_with = "jwt_numeric_date")]
  exp: OffsetDateTime,
}

#[derive(Serialize)]
struct JitsiContext {
  user: JitsiUser,
  group: Option<String>,
}

#[derive(Serialize)]
struct JitsiUser {
  id: String,
  email: Option<String>,
  affiliation: Option<String>,
  name: Option<String>,
  avatar: Option<String>,
}

fn create_jitsi_jwt(
  user: JitsiUser,
  aud: String,
  iss: String,
  sub: String,
  room: String,
  secret: String,
) -> anyhow::Result<String> {
  let iat = OffsetDateTime::now_utc();
  let exp = iat + Duration::days(1);

  let context = JitsiContext { user, group: None };
  let claims = JitsiClaims {
    context,
    aud,
    iss,
    sub,
    room,
    iat,
    exp,
  };

  let token = jsonwebtoken::encode(
    &Header::default(),
    &claims,
    &EncodingKey::from_secret(secret.as_bytes()),
  )?;

  Ok(token)
}

/// Serializes an OffsetDateTime to a Unix timestamp (milliseconds since 1970/1/1T00:00:00T)
pub fn jwt_numeric_date<S: Serializer>(
  date: &OffsetDateTime,
  serializer: S,
) -> Result<S::Ok, S::Error> {
  let timestamp = date.unix_timestamp();
  serializer.serialize_i64(timestamp)
}

fn get_display_name_id_token(claims: &IdTokenClaims<MyClaims, CoreGenderClaim>) -> Option<String> {
  if let Some(name) = claims
    .name()
    .or_else(|| claims.name())
    .and_then(|name| name.get(None))
    .map(|name| name.to_string())
  {
    return Some(name);
  }

  let name = [
    claims
      .given_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
    claims
      .middle_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
    claims
      .family_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
  ];

  if !name.is_empty() {
    return Some(
      name
        .into_iter()
        .flatten()
        .collect::<Vec<String>>()
        .join(" "),
    );
  }

  claims.preferred_username().map(|name| name.to_string())
}

fn get_display_name(claims: &MyUserInfoClaims) -> Option<String> {
  if let Some(name) = claims
    .name()
    .or_else(|| claims.name())
    .and_then(|name| name.get(None))
    .map(|name| name.to_string())
  {
    return Some(name);
  }

  let name = [
    claims
      .given_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
    claims
      .middle_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
    claims
      .family_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
  ];

  if !name.is_empty() {
    return Some(
      name
        .into_iter()
        .flatten()
        .collect::<Vec<String>>()
        .join(" "),
    );
  }

  claims.preferred_username().map(|name| name.to_string())
}
