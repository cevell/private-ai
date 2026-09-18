{
  pkgs,
  rootfs,
  kernel,
  initrd,
  repartDefinitions,
  repartSeed,
  basename,
  uki ? null,
}:

pkgs.runCommand "${basename}-image"
  {
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.dosfstools
      pkgs.e2fsprogs
      pkgs.fakeroot
      pkgs.gnutar
      pkgs.mtools
      pkgs.python3
      pkgs.systemd
    ];
  }
  ''
    set -euo pipefail
    mkdir -p "$out"

    fakeroot -- ${pkgs.python3}/bin/python3 ${./generate_disk.py} \
      "${rootfs}" \
      "$out/${basename}.raw" \
      "${repartDefinitions}" \
      "${repartSeed}" \
      "${kernel}" \
      "${initrd}" \
      "$out" \
      "${if uki == null then "" else toString uki}"

    test -s "$out/${basename}.raw"
    test -s "$out/${basename}.vmlinuz"
    test -s "$out/${basename}.initrd"
    test -s "$out/${basename}.roothash"
  ''
