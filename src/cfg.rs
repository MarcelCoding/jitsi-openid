use std::net::{  SocketAddr};

use openidconnect::{ClientId, IssuerUrl};
use serde::Deserialize;
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
}

fn default_listen_addr() -> SocketAddr {
  ([127, 0, 0, 1], 3000).into()
}
