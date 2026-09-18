{
  pkgs,
  kernel,
  initrd,
  roothash,
  debug ? "off",
}:

let
  consoleArgs =
    if debug == "on" then
      "earlyprintk=serial,ttyS0,115200 console=ttyS0,115200 console=tty1 debug=on "
    else
      "console=ttyS0,115200 quiet loglevel=0 debug=off ";

  cmdline = pkgs.writeText "cevell-cmdline" (
    consoleArgs
    + "ro roothash=${roothash} "
    + "swiotlb=524288 nvme_core.io_timeout=4294967295 panic=30"
  );

  osRelease = pkgs.writeText "os-release" ''
    NAME="Cevell OS"
    ID=cevell
    VERSION="1.0.0"
    PRETTY_NAME="Cevell OS 1.0.0 (Private AI)"
  '';
in
pkgs.runCommand "cevell-uki.efi"
  {
    nativeBuildInputs = [
      pkgs.systemdUkify
      pkgs.systemd
    ];
  }
  ''
    set -euo pipefail

    stub="${pkgs.systemd}/lib/systemd/boot/efi/linuxx64.efi.stub"
    if [ ! -f "$stub" ]; then
      stub=$(find ${pkgs.systemd} -name "linuxx64.efi.stub" | head -n 1)
    fi

    extraSignArgs=""
    if [ -n "''${SECUREBOOT_KEY:-}" ] && [ -n "''${SECUREBOOT_CERT:-}" ]; then
      extraSignArgs="--secureboot-private-key=$SECUREBOOT_KEY --secureboot-certificate=$SECUREBOOT_CERT"
    fi

    ukify build \
      --linux="${kernel}" \
      --initrd="${initrd}" \
      --cmdline="@${cmdline}" \
      --os-release="@${osRelease}" \
      --stub="$stub" \
      $extraSignArgs \
      --output="$out"

    test -s "$out"
  ''
