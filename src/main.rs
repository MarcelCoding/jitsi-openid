use std::collections::HashMap;
use std::sync::Arc;

use axum::Extension;
use config::{Config, Environment};
use openidconnect::core::{
  CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
  CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
  CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreRevocableToken, CoreRevocationErrorResponse,
  CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
  AdditionalClaims, Client, ClientSecret, CsrfToken, EmptyExtraTokenFields, IdTokenFields, Nonce,
  PkceCodeVerifier, RedirectUrl, StandardErrorResponse, StandardTokenResponse, UserInfoClaims,
};
use serde::{self};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use uuid::Uuid;

use crate::cfg::Cfg;
use crate::error::AppError;
use crate::error::AppError::{InvalidCode, InvalidSession};
use crate::routes::build_routes;
use crate::AppError::{
  InternalServerError, InvalidAccessToken, InvalidIdTokenNonce, InvalidState,
  MissingAccessTokenHash, MissingIdTokenAndUserInfoEndpoint, UnableToQueryUserInfo,
  UnsupportedSigningAlgorithm,
};

mod cfg;
mod error;
mod routes;

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
  let subscriber = FmtSubscriber::builder()
    .with_max_level(Level::INFO)
    .compact()
    .finish();

  tracing::subscriber::set_global_default(subscriber)?;

  info!(concat!(
    "Booting ",
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "..."
  ));

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

  let app = build_routes()
    .layer(Extension(store))
    .layer(Extension(client))
    .layer(Extension(config.clone()));

  let listener = TcpListener::bind(config.listen_addr).await?;

  info!(
    "Listening on {}, have a try on: {}/{{name}}",
    config.listen_addr,
    config.base_url.join("room")?
  );

  axum::serve(listener, app.into_make_service()).await?;

  Ok(())
}

// async fn shutdown_signal() {
//   let ctrl_c = async {
//     signal::ctrl_c()
//       .await
//       .expect("failed to install Ctrl+C handler");
//   };
//
//   #[cfg(unix)]
//   {
//     let terminate = async {
//       signal::unix::signal(signal::unix::SignalKind::terminate())
//         .expect("failed to install signal handler")
//         .recv()
//         .await;
//     };
//
//     tokio::select! {
//       _ = ctrl_c => {},
//       _ = terminate => {},
//     }
//   }
//
//   #[cfg(not(unix))]
//   ctrl_c.await;
//
//   info!("signal received, starting graceful shutdown");
// }
