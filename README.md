# Jitsi OpenID

Jitsi OpenID is an authentication adapter to provide [jitsi](https://jitsi.org/) the ability to use single sign on
via [OpenID Connect](https://openid.net/connect/).

## Deployment

**This guide is based of the [docker setup from jitsi](https://github.com/jitsi/docker-jitsi-meet/).**

This image is available in the
[GitHub Container Registry](https://github.com/users/MarcelCoding/packages/container/package/jitsi-openid):

```
ghcr.io/marcelcoding/jitsi-openid:latest
```

### Docker "run" Command

```bash
docker run \
  -p 3000:3000 \
  -e JITSI_SECRET=SECURE_SECRET \
  -e JITSI_URL=https://meet.example.com \
  -e JITSI_SUB=meet.example.com \
  -e ISSUER_URL=https://id.example.com \
  -e BASE_URL=https://auth.meet.example.com \
  -e CLIENT_ID=meet.example.com \
  -e CLIENT_SECRET=SECURE_SECRET \
  --rm \
  ghcr.io/marcelcoding/jitsi-openid:latest
```

### Docker Compose

```yaml
# docker-compose.yaml

# ...

services:
  # ...

  jitsi-openid:
    image: ghcr.io/marcelcoding/jitsi-openid:latest
    restart: always
    environment:
      - "JITSI_SECRET=SECURE_SECRET" # <- shared with jitsi (JWT_APP_SECRET -> see .env from jitsi),
      #    secret to sign jwt tokens
      - "JITSI_URL=https://meet.example.com" # <- external url of jitsi
      - "JITSI_SUB=meet.example.com" # <- shared with jitsi (JWT_APP_ID -> see .env from jitsi),
      #    id of jitsi
      - "ISSUER_URL=https://id.example.com" # <- base URL of your OpenID Connect provider
      #    Keycloak: https://id.example.com/auth/realms/<realm>
      - "BASE_URL=https://auth.meet.example.com" # <- base URL of this application
      - "CLIENT_ID=meet.example.com" # <- OpenID Connect Client ID
      - "CLIENT_SECRET=SECURE_SECRET" # <- OpenID Connect Client secret
        # - 'ACR_VALUES=password email'              # <- OpenID Context Authentication Context Requirements,
        #    space separated list of allowed actions (OPTIONAL), see
        #    https://github.com/MarcelCoding/jitsi-openid/issues/122
        # - 'SCOPES=openid email jitsi'              # <- OpenID Scopes, space separated list of scopes (OPTIONAL),
        #    default: openid email
        # - 'VERIFY_ACCESS_TOKEN_HASH=false          # <- explicitly disable access token hash verification (OPTIONAL),
        #    default: true                                See https://github.com/MarcelCoding/jitsi-openid/issues/372#issuecomment-2730510228
        # - 'SKIP_PREJOIN_SCREEN=false'              # <- skips the jitsi prejoin screen after login (default: true)
        # - 'GROUP=example'                          # <- Value for the 'group' field in the token
      #    default: ''
    ports:
      - "3000:3000"
# ...
```

To generate the `JITSI_SECRET` you can use one of the following command:

```bash
cat /dev/urandom | tr -dc a-zA-Z0-9 | head -c128; echo
```

### NixOS

```nix
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";
    jitsi-openid = {
      url = "github:MarcelCoding/jitsi-openid";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, jitsi-openid, ... }: {
    nixosConfigurations = {
      hostname = nixpkgs.lib.nixosSystem {
        modules = [
          jitsi-openid.nixosModules.default
          { nixpkgs.overlays = [ jitsi-openid.overlays.default ]; }
        ];
      };
    };
  };
}
```

```nix
# for an explanation see docker compose setup
services.jitsi-openid = {
  enable = true;
  settings = {
    package = pkgs.jitsi-openid;
    enable = true;
    listen = {
      addr = "::1";
      port = 6031;
    };
    jitsiSecretFile = "/run/secrets/jitsi-secret-file";
    jitsiUrl = "https://meet.domain.tld";
    jitsiSub = "meet.domain.tld";
    issuerUrl = "https://auth.domain.tld";
    baseUrl = "https://auth.meet.domain.tld";
    clientId = "auth.meet.domain.tld";
    clientSecretFile = "/run/secrets/client-secret-file";
    openFirewall = false;
  };
};
```

### Jitsi Configuration

If you have problems understating this have a look here: https://github.com/MarcelCoding/jitsi-openid/issues/80

```bash
# for more information see:
# https://github.com/jitsi/docker-jitsi-meet/blob/master/env.example

# weather to allow users to join a room without requiring to authenticate
#ENABLE_GUESTS=1

# fixed
ENABLE_AUTH=1
AUTH_TYPE=jwt

# should be the same as JITSI_ID of jitsi-openid environment variables
JWT_APP_ID=meet.example.com
# should be the same as JITSI_SECRET of jitsi-openid environment variables
JWT_APP_SECRET=SECRET

# fixed values
JWT_ACCEPTED_ISSUERS=jitsi
JWT_ACCEPTED_AUDIENCES=jitsi

# auth.meet.example.com should be the domain name of jitsi-openid,
# `/room/{room}` is the endpoint that's jitsi redirecting the user to
# `{room}` is is a placeholder, where jitsi inserts the room name
# jitsi-openid should redirect the user after a successfully authentication
# !! it is recommend to use ALWAYS https e.g. using a reverse proxy !!
TOKEN_AUTH_URL=https://auth.meet.example.com/room/{room}
```

### Jitsi Configuration NixOS

The following NixOS config shows how to use JWT Auth with the jitsi NixOS module.
The necessary steps where extracted form [docker-jitsi-meet](https://github.com/jitsi/docker-jitsi-meet):

```nix
{
  pkgs,
  config,
  ...
}:

let
  hostName = "meet.example.com";
  ssoHostName = "auth-meet.example.com";
  ssoPort = 3000;
  ssoAddress = "127.0.0.1";
  cfg = config.services.jitsi-meet;
in
{
  networking.firewall.allowedUDPPorts = [ 10000 ]; # required for more then 2 participants

  # this assumes jitsi openid is already running on the server on port 3000
  # you could run it with e.g. virtualisation.oci-containers.containers
  services.nginx.virtualHosts.${ssoHostName} = {
    forceSSL = true;
    enableACME = true;
    locations = {
      "/" = {
        proxyPass = "http://${ssoAddress}:${toString ssoPort}";
      };
    };
  };

  nixpkgs.config.permittedInsecurePackages = [
    "jitsi-meet-1.0.8043"
  ];

  services.jitsi-meet = {
    enable = true;

    inherit hostName;
    nginx.enable = true;
    secureDomain = {
      enable = true;
      authentication = "token";
    };

    config.tokenAuthUrl = "https://${ssoHostName}/room/{room}";
  };

  services.prosody = {
    extraModules = [
      "token_verification"
    ];

    extraConfig = ''
      asap_accepted_issuers = "jitsi"
      asap_accepted_audiences = "jitsi"
    '';

    virtualHosts.${cfg.hostName} = {
      # a secure secret should be used for production
      extraConfig = ''
        app_secret = "insecure_secret"
        app_id = "jitsi"
      '';
    };
  };

  systemd.services.prosody.environment = {
    # the token_verification module has some more lua dependencies
    LUA_PATH = "${pkgs.lua52Packages.basexx}/share/lua/5.2/?.lua;${pkgs.lua52Packages.cjson}/share/lua/5.2/?.lua;${pkgs.lua52Packages.luaossl}/share/lua/5.2/?.lua;${pkgs.lua52Packages.inspect}/share/lua/5.2/?.lua";
    LUA_CPATH = "${pkgs.lua52Packages.cjson}/lib/lua/5.2/?.so;${pkgs.lua52Packages.luaossl}/lib/lua/5.2/?.so";
  };
}
```

### Jitsi JWTs

The JWTs are populated using the data returned by your IDP.
This includes the user id, email and name.

The `sub` extracted from the `prefered_username` field, if that isn't preset the `sub` field is used.

The `name` is extracted from the `name` field, if that isn't preset a concatenation of `given_name`, `middle_name`
and `family_name` is used. If all tree of them are also not present the `prefered_username` is used.

The `affiliation` is straight up passed, without any modifications or alternatives. It can be used to restrict the
permissions a user has in a specific room in jitsi.
See https://github.com/jitsi-contrib/prosody-plugins/tree/main/token_affiliation for more information.

The picture (avatar) URL is delegated from the IDP to Jitsi.

Translations aren't respected: https://github.com/MarcelCoding/jitsi-openid/issues/117#issuecomment-1172406703

## License

[LICENSE](LICENSE)
