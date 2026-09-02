{
  description = "gluck-herald — authenticated message gateway (telegram ⇄ figaro) behind kelliher-web";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    gluck-service-lib.url = "github:jack-work/gluck-service-lib";
    gluck-service-lib.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { self, nixpkgs, gluck-service-lib, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      herald = pkgs: pkgs.buildGoModule {
        pname = "herald";
        version = "0.1.0";
        src = ./.;
        vendorHash = null; # stdlib only — no dependencies to vendor
        # The module name is gluck-herald but the binary is `herald`, so name it
        # explicitly: buildGoModule would otherwise derive it from the module
        # path and lib.getExe would point at a file that does not exist.
        postInstall = "mv $out/bin/gluck-herald $out/bin/herald";
        meta.mainProgram = "herald";
      };

      nixosModule =
        { config, lib, pkgs, ... }:
        let
          cfg = config.services.gluck-herald;
        in
        {
          options.services.gluck-herald = {
            enable = lib.mkEnableOption "herald message gateway";

            port = lib.mkOption {
              type = lib.types.port;
              default = 9098;
              description = "Loopback port for the herald API";
            };

            tokenFile = lib.mkOption {
              type = lib.types.path;
              description = ''
                Path to the Telegram bot token, delivered to the unit through
                LoadCredential. Normally a sops secret path.
              '';
            };

            allowedChats = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              example = [ "487734915" ];
              description = ''
                Telegram chat ids herald will send to and accept from. Empty
                means any, which makes the gateway an open relay for anyone
                who finds the bot — set it.
              '';
            };

            clientIds = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ "herald" ];
              description = ''
                OIDC client_id allowlist. This is the gate that stops another
                service's token from opening herald: Authelia issues access
                tokens with an empty `aud`, so client_id is what carries the
                distinction.
              '';
            };

            requiredGroup = lib.mkOption {
              type = lib.types.str;
              default = "";
              description = "lldap group required on every authenticated route.";
            };

            issuer = lib.mkOption {
              type = lib.types.str;
              default = "https://auth.kelliher.info";
            };

            jwksUrl = lib.mkOption {
              type = lib.types.str;
              default = "http://127.0.0.1:9091/jwks.json";
              description = "Authelia's JWKS, fetched over loopback.";
            };

            subdomain = lib.mkOption {
              type = lib.types.str;
              default = "herald";
            };
          };

          config = lib.mkIf cfg.enable (
            gluck-service-lib.lib.mkService {
              inherit config lib pkgs;
              name = "gluck-herald";
              inherit (cfg) subdomain port;
              execStart = "${lib.getExe (herald pkgs)} serve";
              stateDirectory = "gluck-herald";

              # requireAuth gives both paths at once: browsers are
              # forward-authed to Authelia, while a request carrying
              # `Authorization: Bearer` is passed through untouched — which
              # is exactly why herald verifies the JWT itself.
              requireAuth = true;
              requiredGroups = lib.optional (cfg.requiredGroup != "") cfg.requiredGroup;

              environment = {
                HERALD_ISSUER = cfg.issuer;
                HERALD_JWKS = cfg.jwksUrl;
                HERALD_CLIENT_IDS = lib.concatStringsSep "," cfg.clientIds;
                HERALD_GROUP = cfg.requiredGroup;
                HERALD_CHATS = lib.concatStringsSep "," cfg.allowedChats;
              };

              # LoadCredential, not EnvironmentFile and not Environment=:
              # the value lands in a per-unit tmpfs at 0400 and vanishes with
              # the unit. Unit files live world-readable in /nix/store
              # forever, and argv is world-readable in /proc.
              #
              # DynamicUser stays on: herald writes only its own
              # StateDirectory and shares no file contract with another unit,
              # so it never needs a stable uid.
              extraServiceConfig = {
                LoadCredential = [ "token:${cfg.tokenFile}" ];
              };
            }
          );
        };
    in
    {
      nixosModules.default = nixosModule;
      nixosModules.gluck-herald = nixosModule;

      packages = forAllSystems (pkgs: {
        herald = herald pkgs;
        default = herald pkgs;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell { packages = [ pkgs.go pkgs.gopls ]; };
      });
    };
}
