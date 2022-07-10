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
  #[serde(deserialize_with = "string_array")]
  pub(crate) acr_values: Vec<AuthenticationContextClass>,
}

fn default_listen_addr() -> SocketAddr {
  ([127, 0, 0, 1], 3000).into()
}

/// Serializes an OffsetDateTime to a Unix timestamp (milliseconds since 1970/1/1T00:00:00T)
pub fn string_array<'a, D: Deserializer<'a>>(
  deserializer: D,
) -> Result<Vec<AuthenticationContextClass>, D::Error> {
  let input: String = Deserialize::deserialize(deserializer)?;

  let values = input
    .split(' ')
    .map(|acr| AuthenticationContextClass::new(acr.to_string()))
    .collect();

  Ok(values)
}
