{ config, pkgs, lib, ... }:

let
  cfg = config.services.jitsi-openid;
in
{
  options = {
    services.jitsi-openid = {
      package = lib.mkOption {
        type = lib.types.package;
        default = pkgs.jitsi-openid;
        defaultText = lib.literalExpression "pkgs.jitsi-openid";
        description = lib.mdDoc "Which Jitsi OpenID derivation to use.";
      };
      enable = lib.mkEnableOption (lib.mdDoc "Jitsi OpenID");
      listen = {
        addr = lib.mkOption {
          type = lib.types.str;
          description = lib.mdDoc "The ip address Jitsi OpenID should be listening on.";
          default = "0.0.0.0";
        };
        port = lib.mkOption {
          type = lib.types.port;
          description = lib.mdDoc "The port Jitsi OpenID shuld be listening on.";
          default = 6031;
        };
      };
      jitsiSecretFile = lib.mkOption {
        type = lib.types.str;
        description = lib.mdDoc "The socket address of the udp upstream zia should redirect all traffic to.";
        default = null;
      };
      jitsiUrl = lib.mkOption {
        type = lib.types.str;
        description = lib.mdDoc "The socket address of the udp upstream zia should redirect all traffic to.";
        default = null;
      };
      jitsiSub = lib.mkOption {
        type = lib.types.str;
        description = lib.mdDoc "The socket address of the udp upstream zia should redirect all traffic to.";
        default = null;
      };
      issuerUrl = lib.mkOption {
        type = lib.types.str;
        description = lib.mdDoc "The socket address of the udp upstream zia should redirect all traffic to.";
        default = null;
      };
      baseUrl = lib.mkOption {
        type = lib.types.str;
        description = lib.mdDoc "The socket address of the udp upstream zia should redirect all traffic to.";
        default = null;
      };
      clientId = lib.mkOption {
        type = lib.types.str;
        description = lib.mdDoc "The socket address of the udp upstream zia should redirect all traffic to.";
        default = null;
      };
      clientSecretFile = lib.mkOption {
        type = lib.types.str;
        description = lib.mdDoc "The socket address of the udp upstream zia should redirect all traffic to.";
        default = null;
      };
      openFirewall = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = lib.mdDoc "Whether to open ports in the firewall for the server.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.listen.port ];

    systemd.services.jitsi-openid = {
      description = "Jitsi OpenID";

      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/jitsi-openid";
        DynamicUser = true;
        User = "jitsi-openid";

        Environment = [
          "JITSI_OPENID_LISTEN_ADDR=${cfg.listen.addr}:${toString cfg.listen.port}"
          "JITSI_OPENID_JITSI_SECRET_FILE=${cfg.jitsiSecretFile}"
          "JITSI_OPENID_JITSI_URL=${cfg.jitsiUrl}"
          "JITSI_OPENID_JITSI_SUB=${cfg.jitsiSub}"
          "JITSI_OPENID_ISSUER_URL=${cfg.issuerUrl}"
          "JITSI_OPENID_BASE_URL=${cfg.baseUrl}"
          "JITSI_OPENID_CLIENT_ID=${cfg.clientId}"
          "JITSI_OPENID_CLIENT_SECRET_FILE=${cfg.clientSecretFile}"
        ];
      };
    };
  };
}
