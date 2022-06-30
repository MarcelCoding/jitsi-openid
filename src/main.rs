use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::response::{IntoResponse, Redirect};
use axum::routing::get;
use axum::{headers, Extension, Router, Server, TypedHeader};
use axum_extra::extract::CookieJar;
use config::{Config, Environment};
use cookie::Cookie;
use jsonwebtoken::{EncodingKey, Header};
use openidconnect::core::{
  CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType, CoreGenderClaim,
  CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
  CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreRevocableToken, CoreRevocationErrorResponse,
  CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
  AccessTokenHash, AdditionalClaims, AuthorizationCode, Client, ClientSecret, ConfigurationError,
  CsrfToken, EmptyExtraTokenFields, IdTokenFields, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
  PkceCodeVerifier, RedirectUrl, Scope, StandardErrorResponse, StandardTokenResponse,
  TokenResponse, UserInfoClaims,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{error, info};
use uuid::Uuid;

use crate::cfg::Cfg;
use crate::error::AppError;
use crate::error::AppError::{InvalidCode, InvalidSession};
use crate::AppError::{
  InternalServerError, InvalidAccessToken, InvalidIdTokenNonce, InvalidState,
  MissingAccessTokenHash, MissingIdTokenAndUserInfoEndpoint, UnableToQueryUserInfo,
  UnsupportedSigningAlgorithm,
};

mod cfg;
mod error;

const COOKIE_NAME: &str = "JITSI_OPENID_SESSION";

type Store = Arc<RwLock<HashMap<Uuid, Session>>>;

struct Session {
  room: String,
  csrf_token: CsrfToken,
  nonce: Nonce,
  pkce_verifier: PkceCodeVerifier,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct MyClaims {
  affiliation: Option<String>,
}

impl AdditionalClaims for MyClaims {}

type MyUserInfoClaims = UserInfoClaims<MyClaims, CoreGenderClaim>;

type MyIdTokenFields = IdTokenFields<
  MyClaims,
  EmptyExtraTokenFields,
  CoreGenderClaim,
  CoreJweContentEncryptionAlgorithm,
  CoreJwsSigningAlgorithm,
  CoreJsonWebKeyType,
>;

type MyTokenResponse = StandardTokenResponse<MyIdTokenFields, CoreTokenType>;

type MyClient = Client<
  MyClaims,
  CoreAuthDisplay,
  CoreGenderClaim,
  CoreJweContentEncryptionAlgorithm,
  CoreJwsSigningAlgorithm,
  CoreJsonWebKeyType,
  CoreJsonWebKeyUse,
  CoreJsonWebKey,
  CoreAuthPrompt,
  StandardErrorResponse<CoreErrorResponseType>,
  MyTokenResponse,
  CoreTokenType,
  CoreTokenIntrospectionResponse,
  CoreRevocableToken,
  CoreRevocationErrorResponse,
>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  tracing_subscriber::fmt::init();

  let config = Config::builder()
    .add_source(Environment::default().try_parsing(true))
    .build()?
    .try_deserialize::<Cfg>()?;

  let store = Store::new(RwLock::new(HashMap::new()));

  info!(
    "Using identity provider: {} and client-id: {}",
    &config.issuer_url.url(),
    *config.client_id
  );

  let provider_metadata: CoreProviderMetadata =
    CoreProviderMetadata::discover_async(config.issuer_url.clone(), async_http_client).await?;

  let client = MyClient::from_provider_metadata(
    provider_metadata,
    config.client_id.clone(),
    Some(config.client_secret.clone()),
  )
  .set_redirect_uri(RedirectUrl::from_url(config.base_url.join("callback")?));
  // TODO: .set_revocation_uri ?

  info!("Successfully queried identity provider metadata");

  let app = Router::new()
    .route("/room/:name", get(room))
    .route("/callback", get(callback))
    .layer(Extension(store))
    .layer(Extension(client))
    .layer(Extension(config.clone()));

  info!(
    "Listening on {}, have a try on: {}/{{name}}",
    config.listen_addr,
    config.base_url.join("room")?
  );

  Server::bind(&config.listen_addr)
    .serve(app.into_make_service())
    .with_graceful_shutdown(shutdown_signal())
    .await?;

  Ok(())
}

async fn shutdown_signal() {
  let ctrl_c = async {
    signal::ctrl_c()
      .await
      .expect("failed to install Ctrl+C handler");
  };

  #[cfg(unix)]
  {
    let terminate = async {
      signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("failed to install signal handler")
        .recv()
        .await;
    };

    tokio::select! {
      _ = ctrl_c => {},
      _ = terminate => {},
    }
  }

  #[cfg(not(unix))]
  ctrl_c.await;

  info!("signal received, starting graceful shutdown");
}

async fn room(
  Path(room): Path<String>,
  Extension(client): Extension<MyClient>,
  Extension(store): Extension<Store>,
  Extension(config): Extension<Cfg>,
  jar: CookieJar,
) -> impl IntoResponse {
  let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

  let (auth_url, csrf_token, nonce) = client
    .authorize_url(
      CoreAuthenticationFlow::AuthorizationCode,
      CsrfToken::new_random,
      Nonce::new_random,
    )
    .set_pkce_challenge(pkce_challenge)
    .add_scope(Scope::new("profile".to_string()))
    .add_scope(Scope::new("email".to_string()))
    .url();

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

  (jar.add(cookie), Redirect::to(&auth_url.to_string()))
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

  let jitsi_user = match id_token_claims(&client, &response, &session.nonce)? {
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
  client: &MyClient,
  response: &MyTokenResponse,
  nonce: &Nonce,
) -> Result<Option<JitsiUser>, AppError> {
  let id_token = match response.id_token() {
    Some(id_token) => id_token,
    None => return Ok(None),
  };

  let claims = id_token
    .claims(&client.id_token_verifier(), nonce)
    .map_err(|_| InvalidIdTokenNonce)?;

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
    name: claims
      .name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
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
        name: claims
          .name()
          .and_then(|name| name.get(None))
          .map(|name| name.to_string()),
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
  #[serde(with = "jwt_numeric_date")]
  iat: OffsetDateTime,
  #[serde(with = "jwt_numeric_date")]
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

mod jwt_numeric_date {
  //! Custom serialization of OffsetDateTime to conform with the JWT spec (RFC 7519 section 2, "Numeric Date")
  use serde::{self, Serializer};
  use time::OffsetDateTime;

  /// Serializes an OffsetDateTime to a Unix timestamp (milliseconds since 1970/1/1T00:00:00T)
  pub fn serialize<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let timestamp = date.unix_timestamp();
    serializer.serialize_i64(timestamp)
  }
}
