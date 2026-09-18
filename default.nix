{ pkgs ? import <nixpkgs> { config.allowUnfree = true; }, target ? "gpu", debug ? null }:

let
  assertDebug =
    if debug == null then
      throw "FATAL CONFIGURATION ERROR: Mandatory 'debug' argument is missing. You MUST build with --argstr debug on or --argstr debug off"
    else if debug != "on" && debug != "off" then
      throw "FATAL CONFIGURATION ERROR: 'debug' argument must be 'on' or 'off'. Received: '${debug}'"
    else debug;

  repartSeed = "cb196bf6-3372-471f-b15d-acbadb745b0f";
  kernelPath = ./boot-efi/vmlinuz-aws;
  nvidiaModules = ./boot-efi/nvidia-modules;

  initrd = import ./build/initrd.nix { inherit pkgs; };
  go = import ./build/go-node.nix { inherit pkgs target; debug = assertDebug; };
  rootfs = import ./build/rootfs.nix {
    inherit pkgs target nvidiaModules;
    runtimeGo = go.packages."cevell-node";
  };
  image = import ./build/uefi-image.nix;

  # Pass 1: Calculate deterministic root hash
  pass1Image = image {
    inherit pkgs repartSeed;
    rootfs = "${rootfs}/cevell-rootfs.tar";
    kernel = kernelPath;
    inherit initrd;
    repartDefinitions = ./repart.d/pass1;
    basename = "pass1";
  };
  roothash = builtins.readFile "${pass1Image}/pass1.roothash";

  # Pass 2: Assemble Unified Kernel Image with roothash
  buildUki = import ./build/uki.nix;
  uki = buildUki {
    inherit pkgs initrd;
    kernel = kernelPath;
    inherit roothash;
    debug = assertDebug;
  };

  # Final Bootable UEFI Disk Image
  bootableImage = image {
    inherit pkgs repartSeed;
    rootfs = "${rootfs}/cevell-rootfs.tar";
    kernel = kernelPath;
    inherit initrd uki;
    repartDefinitions = ./repart.d;
    basename = "cevell-os";
  };
in
go.packages // {
  inherit initrd uki rootfs;
  "roothash-value" = roothash;
  "rootfs-archive" = "${rootfs}/cevell-rootfs.tar";
  "bootable-image" = bootableImage;
}
