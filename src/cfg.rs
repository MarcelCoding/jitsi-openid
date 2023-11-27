use std::net::SocketAddr;

use openidconnect::{AuthenticationContextClass, ClientId, IssuerUrl};
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::ClientSecret;

#[derive(Deserialize, Clone)]
pub(crate) struct Cfg {
  pub(crate) jitsi_secret: String,
  pub(crate) jitsi_url: Url,
  pub(crate) jitsi_sub: String,
  #[serde(alias = "issuer_base_url")]
  pub(crate) issuer_url: IssuerUrl,
  pub(crate) base_url: Url,
  pub(crate) client_id: ClientId,
  #[serde(alias = "secret")]
  pub(crate) client_secret: ClientSecret,
  #[serde(default = "default_listen_addr")]
  pub(crate) listen_addr: SocketAddr,
  #[serde(default)]
  #[serde(deserialize_with = "string_array")]
  pub(crate) acr_values: Option<Vec<AuthenticationContextClass>>,
  #[serde(default)]
  #[serde(deserialize_with = "string_array2")]
  pub(crate) scopes: Option<Vec<String>>,
  #[serde(default)]
  pub(crate) verify_access_token_hash: Option<bool>,
  #[serde(default)]
  pub(crate) skip_prejoin_screen: Option<bool>,
  #[serde(default)]
  pub(crate) group: String,

}

fn default_listen_addr() -> SocketAddr {
  ([127, 0, 0, 1], 3000).into()
}

/// Serializes an OffsetDateTime to a Unix timestamp (milliseconds since 1970/1/1T00:00:00T)
pub fn string_array2<'a, D: Deserializer<'a>>(
  deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
  let input: String = Deserialize::deserialize(deserializer)?;

  let values = input.split(' ').map(|acr| acr.to_string()).collect();

  Ok(Some(values))
}

/// Serializes an OffsetDateTime to a Unix timestamp (milliseconds since 1970/1/1T00:00:00T)
pub fn string_array<'a, D: Deserializer<'a>>(
  deserializer: D,
) -> Result<Option<Vec<AuthenticationContextClass>>, D::Error> {
  let input: String = Deserialize::deserialize(deserializer)?;

  let values = input
    .split(' ')
    .map(|acr| AuthenticationContextClass::new(acr.to_string()))
    .collect();

  Ok(Some(values))
}
