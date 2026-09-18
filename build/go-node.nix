{ pkgs, target ? "gpu", debug ? "off" }:

let
  cevellBinaries = pkgs.buildGoModule {
    pname = "cevell-node";
    version = "1.0.0";
    src = pkgs.lib.cleanSource ./..;
    vendorHash = null;
    subPackages = [
      "cmd/cevell-node"
    ];
    env = {
      CGO_ENABLED = "0";
      GOFLAGS = "-mod=vendor";
    };
    ldflags = [
      "-s"
      "-w"
      "-X github.com/cevell/private-ai/pkg/config.BuildTarget=${target}"
      "-X github.com/cevell/private-ai/pkg/config.BuildDebug=${debug}"
      "-extldflags '-static'"
    ];
    doCheck = false;
  };
in
{
  packages = {
    "cevell-node" = cevellBinaries;
  };
}
