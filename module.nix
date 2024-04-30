{ config, pkgs, lib, ... }:

let
  cfg = config.services.jitsi-openid;
in
{
  options = {
    services.jitsi-openid = {
      package = lib.mkPackageOption pkgs "jitsi-openid" { };
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

      environment = {
        LISTEN_ADDR = "${if (lib.hasInfix ":" cfg.listen.addr) then "[${cfg.listen.addr}]" else cfg.listen.addr}:${toString cfg.listen.port}";
        JITSI_SECRET_FILE = "$d/jitsi_secret_file";
        JITSI_URL = cfg.jitsiUrl;
        JITSI_SUB = cfg.jitsiSub;
        ISSUER_URL = cfg.issuerUrl;
        BASE_URL = cfg.baseUrl;
        CLIENT_ID = cfg.clientId;
        CLIENT_SECRET_FILE = "%d/client_secret_file";
      };

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/jitsi-openid";
        DynamicUser = true;
        User = "jitsi-openid";

        LoadCredential = [
          "jitsi_secret_file:${cfg.jitsiSecretFile}"
          "client_secret_file:${cfg.clientSecretFile}"
        ];
      };
    };
  };
}
