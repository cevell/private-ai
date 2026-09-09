{ pkgs, runtimeGo, target ? "gpu", nvidiaModules ? ./../boot-efi/nvidia-modules, nvidiaFirmware ? null }:

let
  caCerts = pkgs.cacert;
  staticKmod = pkgs.pkgsStatic.kmod;
  staticBusybox = pkgs.pkgsStatic.busybox;
  pythonPkg = pkgs.python312;
  uvPkg = pkgs.uv;
  gccLibs = pkgs.stdenv.cc.cc.lib;
  nvidiaComputeDeb = pkgs.fetchurl {
    name = "libnvidia-compute_595.71.05-1ubuntu1_amd64.deb";
    url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/libnvidia-compute_595.71.05-1ubuntu1_amd64.deb";
    sha256 = "6e934848e693668ee678bd5346d7688774925700a0a35d943a2adfff2c8b4076";
  };
  nvidiaFirmwareDeb = pkgs.fetchurl {
    name = "nvidia-firmware_595.71.05-1ubuntu1_amd64.deb";
    url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/nvidia-firmware_595.71.05-1ubuntu1_amd64.deb";
    sha256 = "105ceeae7c20cce66109a636f5a9bcd4bb4a820e0937f7407b91945dceaa5086";
  };
  nvidiaKernelDeb = pkgs.fetchurl {
    name = "linux-objects-nvidia-595-open-7.0.0-1006-aws_7.0.0-1006.6_amd64.deb";
    url = "http://archive.ubuntu.com/ubuntu/pool/restricted/l/linux-restricted-modules-aws/linux-objects-nvidia-595-open-7.0.0-1006-aws_7.0.0-1006.6_amd64.deb";
    sha256 = "d6757cc556979c76b6f1118d906bc62eef412b2b51e4cccebb5844782962dbf6";
  };
  nftablesPkg = pkgs.nftables;
  runtimeClosure = pkgs.closureInfo { rootPaths = [ pythonPkg uvPkg caCerts gccLibs pkgs.bash pkgs.coreutils pkgs.gnutar pkgs.gzip pkgs.glibc nftablesPkg ]; };
in
pkgs.runCommand "cevell-rootfs"
  {
    nativeBuildInputs = [
      pkgs.gnutar
      pkgs.coreutils
      pkgs.busybox
      pkgs.e2fsprogs
      pkgs.dpkg
    ];
  }
  ''
    set -euo pipefail

    root="$TMPDIR/rootfs"
    mkdir -p "$root"/{bin,sbin,usr/bin,usr/sbin,usr/lib,usr/lib64,usr/lib/x86_64-linux-gnu,lib,lib64,usr/local/cuda/lib,usr/local/cuda/lib64,usr/local/cuda/bin,usr/share/udhcpc,etc,run,var,var/tmp,tmp,proc,sys,dev,dev/shm,dev/pts,dev/dri,dev/vfio,dev/accel,mnt/ramdisk,opt/models,root}
    mkdir -p "$root"/etc/{cevell,cevell/auth,ssl/certs,modprobe.d}
    mkdir -p "$root"/usr/lib/systemd
    mkdir -p "$root"/mnt/ramdisk/models
    mkdir -p "$root"/mnt/ramdisk/cache
    mkdir -p "$root"/mnt/ramdisk/home
    mkdir -p "$root"/var/cache/huggingface
    mkdir -p "$root"/nix/store
    chmod 1777 "$root"/tmp
    chmod 1777 "$root"/var/tmp
    chmod 1777 "$root"/dev/shm

    # 1. Base User and Group Identity
    cat << 'PASSWD' > "$root"/etc/passwd
root:x:0:0:root:/root:/sbin/nologin
cevell:x:1000:1000:Cevell Service User:/var/empty:/bin/false
nobody:x:65534:65534:Nobody:/:/bin/false
PASSWD

    cat << 'GROUP' > "$root"/etc/group
root:x:0:
cevell:x:1000:
nogroup:x:65534:
kvm:x:998:cevell
GROUP

    cat << 'SHADOW' > "$root"/etc/shadow
root:!*:19700:0:99999:7:::
cevell:!*:19700:0:99999:7:::
nobody:!*:19700:0:99999:7:::
SHADOW
    chmod 0600 "$root"/etc/shadow

    cat << 'NSSWITCH' > "$root"/etc/nsswitch.conf
passwd:    files
group:     files
shadow:    files
hosts:     files dns
networks:  files
protocols: files
services:  files
ethers:    files
rpc:       files
NSSWITCH

    # 2. System Configuration & OS Metadata
    cat << 'OSREL' > "$root"/usr/lib/os-release
NAME="Cevell OS"
ID=cevell
ID_LIKE=linux
VERSION="1.0.0 (Confidential AI)"
VERSION_ID="1.0.0"
PRETTY_NAME="Cevell OS 1.0.0 (Private AI)"
ANSI_COLOR="0;36"
HOME_URL="https://cevell.com"
OSREL

    echo "cevell-cvm" > "$root"/etc/hostname
    cat << 'HOSTS' > "$root"/etc/hosts
127.0.0.1   localhost cevell-cvm
::1         localhost ip6-loopback
HOSTS

    # Symlink /etc/resolv.conf -> /run/resolv.conf for writable dynamic DNS
    ln -sf /run/resolv.conf "$root"/etc/resolv.conf

    # 3. Zone-Based Stateful Firewall
    cat << 'NFT' > "$root"/etc/nftables.conf
#!/usr/sbin/nft -f
flush ruleset

table inet firewall {
    chain inbound_filter {
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ct state established,related accept
        ct state invalid drop
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
        udp sport 67 udp dport 68 accept
        tcp dport { 443 } accept
    }
    chain forward_filter {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
    }
    chain outbound_filter {
        type filter hook output priority 0; policy accept;
    }
}
NFT
    chmod 0755 "$root"/etc/nftables.conf

    # 4. udhcpc Default DHCP Event Script
    cat << 'UDHCPC' > "$root"/usr/share/udhcpc/default.script
#!/bin/sh
[ -z "$1" ] && echo "Error: should be called from udhcpc" && exit 1
case "$1" in
  deconfig)
    ip addr flush dev $interface 2>/dev/null || true
    ;;
  renew|bound)
    ip addr add $ip/''${mask:-24} dev $interface 2>/dev/null || true
    if [ -n "$router" ]; then
      ip route add $router dev $interface 2>/dev/null || true
      ip route add default via $router dev $interface onlink 2>/dev/null || true
    fi
    mkdir -p /run
    echo "nameserver 169.254.169.253" > /run/resolv.conf
    for i in $dns ; do
      echo "nameserver $i" >> /run/resolv.conf
    done
    echo "nameserver 8.8.8.8" >> /run/resolv.conf
    ;;
esac
exit 0
UDHCPC
    chmod 0755 "$root"/usr/share/udhcpc/default.script

    # Blacklist open-source nouveau driver to prevent conflicts with proprietary nvidia.ko
    cat << 'BLACKLIST' > "$root"/etc/modprobe.d/blacklist-nouveau.conf
blacklist nouveau
options nouveau modeset=0
install nouveau /bin/true
BLACKLIST

    cat << 'NVCONF' > "$root"/etc/modprobe.d/nvidia.conf
options nvidia NVreg_EnableGpuFirmware=1 NVreg_OpenRmEnableUnsupportedGpus=1 NVreg_RegistryDwords="RMEnableGspOnAllGpus=1" NVreg_PreserveVideoMemoryAllocations=1
NVCONF

    # Prevent kernel PCI auto-probe from loading nvidia.ko before LKCA crypto modules are ready.
    # cevell-node loads NVIDIA modules explicitly via finit_module(2) syscall in LoadDirectNVIDIAModules()
    # after LKCA algorithms (ecdsa_generic, aesni-intel, ghash-clmulni-intel, etc.) are loaded.
    # finit_module(2) bypasses modprobe entirely, so this blacklist only blocks the unwanted auto-probe.
    cat << 'NVBLACKLIST' > "$root"/etc/modprobe.d/blacklist-nvidia-autoload.conf
# Prevent kernel PCI modalias auto-loading of nvidia.ko before LKCA crypto is ready.
# On NVIDIA H100 with Intel TDX, GSP firmware requires kernel crypto algorithms
# (ecdsa_generic, aesni-intel, ghash-clmulni-intel) for SPDM/DICE authentication.
# Without them, GSP DMA fails with NV_ERR_INVALID_DATA (0x25) and RmInitAdapter bails.
# cevell-node loads these modules explicitly in the correct order via finit_module(2).
install nvidia /bin/true
install nvidia_modeset /bin/true
install nvidia_uvm /bin/true
NVBLACKLIST

    # 5. Copy Kernel Modules Tree & NVIDIA Drivers
    mkdir -p "$root/lib/modules"
    mkdir -p "$root/usr/lib/cevell/kernel-modules"
    mkdir -p "$root/lib/modules/7.0.0-1006-aws/updates/dkms"
    mkdir -p "$root/lib/modules/7.0.0-1006-aws/kernel/drivers/video"

    if [ -d "${./../boot-efi/modules-tree/lib/modules/7.0.0-1006-aws}" ]; then
      cp -a --remove-destination "${./../boot-efi/modules-tree/lib/modules/7.0.0-1006-aws}" "$root/lib/modules/7.0.0-1006-aws"
      chmod -R u+w "$root/lib/modules/7.0.0-1006-aws"
    fi

    # Extract NVIDIA Kernel Modules Package (linux-objects-nvidia-595-open-7.0.0-1006-aws)
    mkdir -p "$TMPDIR/nvidia-kernel-unpack"
    dpkg-deb -x ${nvidiaKernelDeb} "$TMPDIR/nvidia-kernel-unpack"
    if [ -d "$TMPDIR/nvidia-kernel-unpack/lib/modules/7.0.0-1006-aws" ]; then
      cp -a "$TMPDIR"/nvidia-kernel-unpack/lib/modules/7.0.0-1006-aws/kernel/nvidia-595-open/*.ko "$root/lib/modules/7.0.0-1006-aws/kernel/drivers/video/" || true
      cp -a "$TMPDIR"/nvidia-kernel-unpack/lib/modules/7.0.0-1006-aws/kernel/nvidia-595-open/*.ko "$root/lib/modules/7.0.0-1006-aws/updates/dkms/" || true
      cp -a "$TMPDIR"/nvidia-kernel-unpack/lib/modules/7.0.0-1006-aws/kernel/nvidia-595-open/*.ko "$root/usr/lib/cevell/kernel-modules/" || true
      cp -a "$TMPDIR"/nvidia-kernel-unpack/lib/modules/7.0.0-1006-aws/kernel/nvidia-595-open/*.ko "$root/lib/modules/" || true
    fi

    if [ -d "${nvidiaModules}" ]; then
      cp -a "${nvidiaModules}"/*.ko "$root/usr/lib/cevell/kernel-modules/" || true
      cp -a "${nvidiaModules}"/*.ko "$root/lib/modules/" || true
      cp -a "${nvidiaModules}"/*.ko "$root/lib/modules/7.0.0-1006-aws/updates/dkms/" || true
      cp -a "${nvidiaModules}"/*.ko "$root/lib/modules/7.0.0-1006-aws/kernel/drivers/video/" || true
    fi

    if [ -d "$root/lib/modules/7.0.0-1006-aws" ]; then
      ${staticKmod}/bin/depmod -a -b "$root" 7.0.0-1006-aws || true
    fi

    # 6. Copy Essential Binaries & CA Store
    install -m 0755 "${runtimeGo}/bin/cevell-node" "$root"/usr/bin/cevell-node
    ln -sf /usr/bin/cevell-node "$root"/sbin/init

    mkdir -p "$root"/etc/cevell/vllm
    if [ -f "${./../configs/vllm/requirements.txt}" ]; then
      cp "${./../configs/vllm/requirements.txt}" "$root"/etc/cevell/vllm/requirements.txt
    fi
    if [ -f "${./../configs/vllm/requirements.lock.txt}" ]; then
      cp "${./../configs/vllm/requirements.lock.txt}" "$root"/etc/cevell/vllm/requirements.lock.txt
    fi

    # Copy full closure of python, uv, glibc, and gcc runtime into /nix/store
    while read -r storePath; do
      cp -a "$storePath" "$root/nix/store/"
    done < "${runtimeClosure}/store-paths"

    ln -sf "${pythonPkg}/bin/python3" "$root"/usr/bin/python3
    ln -sf "${pythonPkg}/bin/python3" "$root"/usr/bin/python
    ln -sf "${pythonPkg}/bin/python3" "$root"/bin/python3
    ln -sf "${uvPkg}/bin/uv" "$root"/usr/bin/uv
    ln -sf "${uvPkg}/bin/uv" "$root"/bin/uv

    # Install nftables firewall CLI (required by ApplyFirewallConfig)
    ln -sf "${nftablesPkg}/bin/nft" "$root"/usr/sbin/nft
    ln -sf "${nftablesPkg}/bin/nft" "$root"/sbin/nft
    ln -sf "${nftablesPkg}/bin/nft" "$root"/usr/bin/nft

    # Install static busybox binary & general utilities & udhcpc
    install -m 0755 "${staticBusybox}/bin/busybox" "$root"/bin/busybox
    for tool in sh ash ls cp mv rm cat mkdir ps kill sleep grep sed awk ip udhcpc; do
      ln -sf /bin/busybox "$root"/bin/"$tool"
      ln -sf /bin/busybox "$root"/usr/bin/"$tool"
      ln -sf /bin/busybox "$root"/sbin/"$tool"
      ln -sf /bin/busybox "$root"/usr/sbin/"$tool"
    done

    # Install static kmod toolchain for robust kernel module loading & dependency resolution
    install -m 0755 "${staticKmod}/bin/kmod" "$root"/bin/kmod
    for tool in modprobe depmod insmod rmmod lsmod modinfo; do
      ln -sf /bin/kmod "$root"/bin/"$tool"
      ln -sf /bin/kmod "$root"/sbin/"$tool"
      ln -sf /bin/kmod "$root"/usr/bin/"$tool"
      ln -sf /bin/kmod "$root"/usr/sbin/"$tool"
    done

    # Link dynamic loader and glibc runtime into standard locations for manylinux wheels
    for lib in "${pkgs.glibc}"/lib/*.so*; do
      if [ -e "$lib" ]; then
        cp -a "$lib" "$root"/lib64/ || true
        cp -a "$lib" "$root"/lib/ || true
        cp -a "$lib" "$root"/usr/lib64/ || true
        cp -a "$lib" "$root"/usr/lib/x86_64-linux-gnu/ || true
      fi
    done
    if [ -f "${pkgs.glibc}/lib/ld-linux-x86-64.so.2" ]; then
      ln -sf "${pkgs.glibc}/lib/ld-linux-x86-64.so.2" "$root"/lib64/ld-linux-x86-64.so.2
      ln -sf "${pkgs.glibc}/lib/ld-linux-x86-64.so.2" "$root"/lib/ld-linux-x86-64.so.2
      ln -sf "${pkgs.glibc}/lib/ld-linux-x86-64.so.2" "$root"/usr/lib64/ld-linux-x86-64.so.2
      ln -sf "${pkgs.glibc}/lib/ld-linux-x86-64.so.2" "$root"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    fi

    # Link GCC C++ and OpenMP runtime into standard library paths
    for lib in "${gccLibs}"/lib/libstdc++.so* "${gccLibs}"/lib/libgomp.so* "${gccLibs}"/lib/libgcc_s.so*; do
      if [ -e "$lib" ]; then
        cp -a "$lib" "$root"/usr/lib64/ || true
        cp -a "$lib" "$root"/lib64/ || true
        cp -a "$lib" "$root"/lib/ || true
        cp -a "$lib" "$root"/usr/lib/x86_64-linux-gnu/ || true
      fi
    done

    # Prepare firmware directories
    mkdir -p "$root"/lib/firmware/nvidia/595.71.05
    mkdir -p "$root"/lib/firmware/nvidia
    mkdir -p "$root"/usr/lib/firmware/nvidia/595.71.05
    mkdir -p "$root"/usr/lib/firmware/nvidia

    # Extract NVIDIA GSP firmware package
    mkdir -p "$TMPDIR/nvidia-firmware-unpack"
    dpkg-deb -x ${nvidiaFirmwareDeb} "$TMPDIR/nvidia-firmware-unpack"
    if [ -d "$TMPDIR/nvidia-firmware-unpack/lib/firmware" ]; then
      cp -a "$TMPDIR"/nvidia-firmware-unpack/lib/firmware/* "$root"/lib/firmware/ || true
    fi
    if [ -d "$TMPDIR/nvidia-firmware-unpack/usr/lib/firmware" ]; then
      cp -a "$TMPDIR"/nvidia-firmware-unpack/usr/lib/firmware/* "$root"/lib/firmware/ || true
    fi

    # Support optional out-of-tree firmware overrides
    if [ -n "${if nvidiaFirmware != null then toString nvidiaFirmware else ""}" ] && [ -d "${if nvidiaFirmware != null then toString nvidiaFirmware else ""}" ]; then
      cp -a "${if nvidiaFirmware != null then toString nvidiaFirmware else ""}"/* "$root"/lib/firmware/nvidia/595.71.05/ || true
      cp -a "${if nvidiaFirmware != null then toString nvidiaFirmware else ""}"/* "$root"/lib/firmware/nvidia/ || true
    fi

    # Populate all standard firmware search paths with GSP firmware binaries
    if [ -d "$root"/lib/firmware/nvidia/595.71.05 ]; then
      for fw in "$root"/lib/firmware/nvidia/595.71.05/*; do
        if [ -f "$fw" ]; then
          base=$(basename "$fw")
          cp -a "$fw" "$root"/lib/firmware/nvidia/"$base" || true
          cp -a "$fw" "$root"/usr/lib/firmware/nvidia/595.71.05/"$base" || true
          cp -a "$fw" "$root"/usr/lib/firmware/nvidia/"$base" || true
        fi
      done
    fi

    # Extract NVIDIA user-space compute and NVML runtime libraries
    mkdir -p "$TMPDIR/nvidia-unpack"
    dpkg-deb -x ${nvidiaComputeDeb} "$TMPDIR/nvidia-unpack"
    if [ -d "$TMPDIR/nvidia-unpack/usr/lib/x86_64-linux-gnu" ]; then
      cp -a "$TMPDIR"/nvidia-unpack/usr/lib/x86_64-linux-gnu/* "$root"/usr/lib/x86_64-linux-gnu/ || true
      cp -a "$TMPDIR"/nvidia-unpack/usr/lib/x86_64-linux-gnu/* "$root"/usr/lib64/ || true
      cp -a "$TMPDIR"/nvidia-unpack/usr/lib/x86_64-linux-gnu/* "$root"/lib64/ || true
      cp -a "$TMPDIR"/nvidia-unpack/usr/lib/x86_64-linux-gnu/* "$root"/usr/local/cuda/lib64/ || true
      cp -a "$TMPDIR"/nvidia-unpack/usr/lib/x86_64-linux-gnu/* "$root"/usr/local/cuda/lib/ || true
    fi
    if [ -d "$TMPDIR/nvidia-unpack/usr/bin" ]; then
      cp -a "$TMPDIR"/nvidia-unpack/usr/bin/* "$root"/usr/bin/ || true
      cp -a "$TMPDIR"/nvidia-unpack/usr/bin/* "$root"/bin/ || true
    fi
    if [ -d "$TMPDIR/nvidia-unpack/lib/firmware" ]; then
      cp -a "$TMPDIR"/nvidia-unpack/lib/firmware/* "$root"/lib/firmware/ || true
    fi
    if [ -d "$TMPDIR/nvidia-unpack/usr/lib/firmware" ]; then
      cp -a "$TMPDIR"/nvidia-unpack/usr/lib/firmware/* "$root"/lib/firmware/ || true
    fi

    # Ensure libcuda.so, libnvidia-ml.so, and libnvidia-ptxjitcompiler.so soname symlinks exist in all library paths
    for dir in "$root"/usr/lib/x86_64-linux-gnu "$root"/usr/lib64 "$root"/lib64 "$root"/lib "$root"/usr/local/cuda/lib64 "$root"/usr/local/cuda/lib; do
      if [ -d "$dir" ]; then
        if [ -e "$dir"/libcuda.so.1 ] && [ ! -e "$dir"/libcuda.so ]; then
          ln -sf libcuda.so.1 "$dir"/libcuda.so
        fi
        if [ -e "$dir"/libnvidia-ml.so.1 ] && [ ! -e "$dir"/libnvidia-ml.so ]; then
          ln -sf libnvidia-ml.so.1 "$dir"/libnvidia-ml.so
        fi
        if [ -e "$dir"/libnvidia-ptxjitcompiler.so.1 ] && [ ! -e "$dir"/libnvidia-ptxjitcompiler.so ]; then
          ln -sf libnvidia-ptxjitcompiler.so.1 "$dir"/libnvidia-ptxjitcompiler.so
        fi
      fi
    done

    # Dynamic linker configuration for CUDA and vLLM
    cat << 'LDSOCONF' > "$root"/etc/ld.so.conf
/usr/local/cuda/lib64
/usr/local/cuda/lib
/usr/lib/x86_64-linux-gnu
/usr/lib64
/usr/lib
/lib64
/lib
/mnt/ramdisk/vllm/lib
/mnt/ramdisk/vllm/lib64
LDSOCONF

    # Install CA bundle
    cp ${caCerts}/etc/ssl/certs/ca-bundle.crt "$root"/etc/ssl/certs/ca-certificates.crt
    ln -sf /etc/ssl/certs/ca-certificates.crt "$root"/etc/ssl/certs/ca-bundle.crt

    # 7. Build Deterministic Rootfs Archive
    mkdir -p "$out"
    tar --create \
      --file="$out/cevell-rootfs.tar" \
      --directory="$root" \
      --numeric-owner --owner=0 --group=0 \
      --sort=name \
      --mtime='@0' \
      .

    test -s "$out/cevell-rootfs.tar"
  ''
