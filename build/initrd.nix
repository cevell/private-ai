{
  pkgs,
}:

let
  rustInitrd = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
    pname = "cevell-initrd";
    version = "1.0.0";
    src = ../crates/cevell-initrd;
    cargoLock = {
      lockFile = ../crates/cevell-initrd/Cargo.lock;
    };
    doCheck = false;
  };
in
pkgs.runCommand "initrd.cpio.zst"
  {
    nativeBuildInputs = [
      pkgs.cpio
      pkgs.zstd
      pkgs.findutils
    ];
  }
  ''
    set -euo pipefail

    stage="$TMPDIR/initrd_stage"
    mkdir -p "$stage"/{dev,proc,run,sys,usr/bin,lib/modules}

    cp "${rustInitrd}/bin/cevell-initrd" "$stage/init"
    cp "${rustInitrd}/bin/cevell-initrd" "$stage/usr/bin/cevell-initrd"
    chmod 755 "$stage/init" "$stage/usr/bin/cevell-initrd"
    cp ${./../boot-efi/initrd-modules/01-dm-bufio.ko} "$stage/lib/modules/01-dm-bufio.ko"
    cp ${./../boot-efi/initrd-modules/02-dm-verity.ko} "$stage/lib/modules/02-dm-verity.ko"

    (cd "$stage" && find . -mindepth 1 | sort | cpio -o -H newc -R 0:0 --reproducible) | zstd -19 -T0 > "$out"
    test -s "$out"
  ''
