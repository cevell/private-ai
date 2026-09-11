# Cevell OS

If you need private AI, you are in the right place.

> **Managed Infrastructure & Free Deployment**  
> Visit [cevell.com](https://cevell.com) for free forever deployment and managed infra service.

---

## Overview

When you send prompts, proprietary code, or confidential documents to standard cloud AI services or run models on conventional cloud virtual machines, your data is exposed. Cloud administrators, underlying hypervisors, and intermediate network infrastructure can inspect system memory, capture prompts and generated tokens, log traffic, or modify server binaries.

Cevell OS addresses this at the hardware level. It is a specialized, hardware-attested operating system and Confidential Virtual Machine (CVM) runtime designed for verifiable, leak-proof AI inference.

### How It Works

1. **Hardware Enclave Shielding**: The operating system runs inside a hardware-isolated Confidential VM (AMD SEV-SNP or Intel TDX) with confidential GPU acceleration (NVIDIA Hopper H100/H200 and Blackwell B200). CPU memory and GPU VRAM are encrypted at the physical silicon layer using keys generated on-die by the processors. Neither the cloud provider hosting the virtual machine nor an attacker with host root privileges can read or dump physical memory.
2. **Cryptographic Attestation Before Transmission**: Before your client transmits any sensitive data, the physical processor issues a cryptographically signed hardware attestation quote. Your client independently verifies this quote against vendor root certificates (AMD, Intel, NVIDIA) to prove that genuine, untampered Cevell OS code is running.
3. **Application-Layer End-to-End Encryption (HPKE)**: Requests are encrypted on your client using RFC 9180 Hybrid Public Key Encryption bound to the enclave's attested public key. Intermediate reverse proxies, cloud load balancers, and network gateways only forward opaque ciphertext. Decryption occurs strictly within encrypted enclave memory immediately prior to inference, and responses are re-encrypted before leaving the enclave.
4. **Hermetic Lockdown and Sealing**: The root filesystem is cryptographically verified on every block read using `dm-verity`. All interactive consoles, SSH servers, and debugging ports are permanently compiled out. Once model weights are provisioned, an optional seal command severs all outbound network egress, creating an air-gapped inference engine that cannot leak data to the internet.

---

## Building from Source

Cevell OS uses Nix to produce bit-for-bit reproducible, hermetic disk images.

### Prerequisites

- Linux workstation with the [Nix Package Manager](https://nixos.org/download.html) installed.
- Unfree packages enabled (`config.allowUnfree = true`).

### Build Command

```bash
# Build the production bootable UEFI image (zero console, hermetic lockdown):
nix-build default.nix --argstr debug off --arg target '"gpu"' -A bootable-image --out-link result-image
```

### Build Artifacts

- `result-image/cevell-os.raw`: Bootable UEFI GPT raw disk image.
- `result-image/cevell-os.roothash`: Cryptographic `dm-verity` root hash for independent attestation measurement matching.

---

## Runtime Endpoints

All external communication occurs over TLS 1.3 (port 443). Internal inference engine ports (port 8000) are blocked from external access by kernel-level `nftables` firewall rules.

| Method | Endpoint | Authentication | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/v1/health` | Public | Node readiness and hardware platform. Model identifier is withheld by default. |
| `GET` | `/.well-known/cevell-attestation` | Public | Hardware silicon attestation report bound to the CVM's ephemeral TLS and HPKE public keys. |
| `GET` | `/v1/attestation?nonce=<HEX>` | Public | Dynamic silicon attestation report embedding a caller-specified challenge nonce to prevent replay attacks. |
| `GET` | `/.well-known/cevell-certificate` | Public | Active ephemeral self-signed X.509 TLS certificate in PEM format. |
| `POST` | `/v1/auth/register` | Proof-of-Possession | First-boot single-key latch. Enrolls the authorized operator Ed25519 public key. |
| `POST` | `/v1/models/load` | Ed25519 | Provisions model weights, computes the maximum viable context ceiling for physical VRAM, and initializes inference. |
| `GET` | `/v1/models` | Ed25519 | Returns the active model status, maximum context ceiling, and current allocated context length. |
| `POST` | `/v1/chat/completions` | Ed25519 | Standard JSON chat completions or streaming Server-Sent Events (SSE) token chunks. |
| `POST` | `/v1/system/seal` | Ed25519 | Hermetically seals the CVM: drops all outbound egress networking and disables further model modifications. |

---

## Technical Architecture and Mechanics

### 1. Hardware Silicon Attestation and Cryptographic Binding

Cevell OS eliminates trust in cloud providers by anchoring security in physical hardware attestation:

- **CPU Enclaves**: Supported on AMD SEV-SNP and Intel TDX platforms. During boot, hardware registers cryptographic measurements of the initial firmware, kernel, and unified kernel image (UKI) in hardware measurement registers (MRTD / PCRs).
- **GPU Confidential Computing**: On NVIDIA Hopper H100/H200 platforms, the GPU operates in On-Die Confidential Computing mode. Firmware and state are verified using SPDM 1.2 and a 5-tier DICE certificate chain rooted in NVIDIA's factory silicon fuses.
- **Dual-Partition REPORT_DATA Binding**: The hardware quote binds to an exact 64-byte `REPORT_DATA` structure:
  - Bytes 0–31: SHA-256 fingerprint of the ephemeral TLS certificate generated inside the enclave.
  - Bytes 32–63: `SHA-256(HPKE_Pub || Nonce || GPU_Evidence_Digest)`.
  This mathematical proof prevents splicing attacks where a host attempts to front an authentic enclave with an unauthorized TLS termination proxy.

### 2. Application-Layer End-to-End Encryption (RFC 9180 HPKE)

To prevent data inspection by intermediate reverse proxies or edge gateways, client applications can communicate using RFC 9180 Hybrid Public Key Encryption (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305):

- The client queries the attested HPKE public key from `/.well-known/cevell-attestation`.
- Prompts are encapsulated into an encrypted binary envelope (`application/x-cevell-hpke`) before being sent across the network.
- The `cevell-node` reverse proxy decrypts the envelope in-memory, streams prompt tokens to the inference engine, and re-encrypts output token chunks with the client's ephemeral sender key prior to transmission.

### 3. Immutable dm-verity Filesystem

The operating system root filesystem is packaged as a squashfs filesystem protected by kernel-level `dm-verity`:
- Every 4096-byte block read by the kernel is validated against a SHA-256 Merkle tree in real time.
- If any byte of the rootfs is modified by the underlying hypervisor or host storage layer, the kernel immediately halts I/O and panics.
- The root hash (`roothash`) is baked directly into the signed kernel command line within the Unified Kernel Image (UKI), ensuring it is immutable and measured by hardware attestation.

### 4. Zero-Console Hardening and Hermetic Sealing

To prevent lateral intrusion and side-channel leakage:
- **Zero-Console Mode**: Production builds compile out virtual serial ports (`ttyS0`), virtual consoles (`tty1-tty6`), early printk, and hypervisor communication channels (`loglevel=0 console=null panic=30`).
- **No SSH / Interactive Shells**: The image contains no SSH daemon, no login binaries, and no user accounts.
- **Dynamic Sealing (`POST /v1/system/seal`)**: After pulling authorized weights from a repository or storage bucket, the operator calls the seal endpoint. The kernel flushes all routing tables, drops all outbound TCP/UDP traffic via `nftables`, and permanently disables the `/v1/models/load` endpoint until the virtual machine is power-cycled.

### 5. Zero-Trust Single-Key Operator Authentication

Cevell OS does not use static pre-shared API keys baked into disk images:
- On initial launch, the node enters an unlatched state.
- The authorized client registers its 32-byte Ed25519 public key via `POST /v1/auth/register` with a signed challenge nonce.
- Once registered, the identity is irreversibly latched in memory. All administrative and inference requests require an HTTP `Authorization: Cevell-Ed25519` header containing a cryptographic signature across the HTTP method, request URI, timestamp, nonce, and request body hash.

---

## Documentation

- [SECURITY_MODEL.md](SECURITY_MODEL.md): Threat model, trust boundaries, sequence flows, and formal anti-splicing invariants.
- [CRYPTO_MODEL.md](CRYPTO_MODEL.md): Mathematical formulations, 64-byte `REPORT_DATA` binary offsets, and relying-party attestation verification code.
- [AGENTS.md](AGENTS.md): Architectural guide and invariants for automated coding agents and security auditors.
- [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md): Third-party software inventory, licenses (GPLv2, MIT, Apache 2.0, NVIDIA Driver), and written offer for source code.

---

## License

Cevell OS is licensed under the **PolyForm Shield License 1.0.0** ([LICENSE](LICENSE)).

- **Permitted Use (Free for Internal & Self-Hosted Operations)**: Free for internal commercial business operations, private enterprise deployments on on-premises or cloud infrastructure, personal research, benchmarking, security audits, and cryptographic silicon attestation verification (dm-verity, UKI PCRs, MRTD).
- **Prohibited Use (Anti-Competition & Arbitrage Protection)**: Providing the software, runtime, or derived images as a hosted service, managed platform, compute-as-a-service, or commercial substitute competing with [cevell.com](https://cevell.com) is strictly prohibited without a commercial license. For commercial licensing and partnership inquiries, visit [cevell.com](https://cevell.com) or contact [contact@mail.cevell.com](mailto:contact@mail.cevell.com).
- **Third-Party Components**: Upstream packages (Linux kernel, NVIDIA open drivers, BusyBox, etc.) are governed by their respective upstream licenses ([THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)).
