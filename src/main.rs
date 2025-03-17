use std::collections::HashMap;
use std::sync::Arc;

use config::{Config, Environment};
use openidconnect::core::{
  CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
  CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
  CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
  AdditionalClaims, Client, ClientSecret, CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet,
  EndpointNotSet, EndpointSet, IdTokenFields, Nonce, PkceCodeVerifier, RedirectUrl,
  StandardErrorResponse, StandardTokenResponse, UserInfoClaims,
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
#[derive(Clone)]
pub(crate) struct JitsiSecret(pub(crate) String);

struct Session {
  room: String,
  csrf_token: CsrfToken,
  nonce: Nonce,
  pkce_verifier: PkceCodeVerifier,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct MyClaims {
  affiliation: Option<String>,
  moderator: Option<bool>,
}

impl AdditionalClaims for MyClaims {}

type MyUserInfoClaims = UserInfoClaims<MyClaims, CoreGenderClaim>;

type MyIdTokenFields = IdTokenFields<
  MyClaims,
  EmptyExtraTokenFields,
  CoreGenderClaim,
  CoreJweContentEncryptionAlgorithm,
  CoreJwsSigningAlgorithm,
>;

type MyTokenResponse = StandardTokenResponse<MyIdTokenFields, CoreTokenType>;

type MyClient = Client<
  MyClaims,
  CoreAuthDisplay,
  CoreGenderClaim,
  CoreJweContentEncryptionAlgorithm,
  CoreJsonWebKey,
  CoreAuthPrompt,
  StandardErrorResponse<CoreErrorResponseType>,
  MyTokenResponse,
  CoreTokenIntrospectionResponse,
  CoreRevocableToken,
  CoreRevocationErrorResponse,
  EndpointSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointMaybeSet,
  EndpointMaybeSet,
>;

#[derive(Clone)]
pub(crate) struct JitsiState {
  store: Store,
  client: MyClient,
  config: Cfg,
  jitsi_secret: JitsiSecret,
  http_client: reqwest::Client,
}

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

  let http_client = reqwest::ClientBuilder::new()
    // Following redirects opens the client up to SSRF vulnerabilities.
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .expect("Client should build");

  let provider_metadata: CoreProviderMetadata =
    CoreProviderMetadata::discover_async(config.issuer_url.clone(), &http_client).await?;

  let client_secret = config
    .client_secret
    .clone()
    .or(
      config
        .client_secret_file
        .clone()
        .map(|path| ClientSecret::new(std::fs::read_to_string(path).unwrap())),
    )
    .expect("Client secret not specified.");

  let client = MyClient::from_provider_metadata(
    provider_metadata,
    config.client_id.clone(),
    Some(client_secret),
  )
  .set_redirect_uri(RedirectUrl::from_url(config.base_url.join("callback")?));
  // TODO: .set_revocation_uri ?

  info!("Successfully queried identity provider metadata");

  let jitsi_secret = JitsiSecret(
    config
      .jitsi_secret
      .clone()
      .or(
        config
          .jitsi_secret_file
          .clone()
          .map(|path| std::fs::read_to_string(path).unwrap()),
      )
      .expect("Jitsi secret not specified."),
  );

  let app = build_routes().with_state(JitsiState {
    store,
    client,
    config: config.clone(),
    jitsi_secret: jitsi_secret.clone(),
    http_client,
  });

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
