# Client Authentication Public Key Configuration

Cevell OS verifies requests against an authorized operator Ed25519 public key discovered at launch time (PID 1).

### Key Provisioning Options

1. **Cloud Instance Metadata (Recommended for Zero-Touch Deployment)**:
   Set the GCP instance guest attribute or metadata key `cevell-auth-pub` (or `auth-pub`, `ssh-keys`) when launching the virtual machine. The CVM will discover and latch this key automatically without modifying the underlying raw disk image.

2. **Compile-Time Image Configuration**:
   Place your 32-byte Ed25519 public key in `auth.pub` in this directory before building the production image (`DEBUG=off ./scripts/build-production.sh`). The build system bundles it into `/etc/cevell/auth/auth.pub` inside the cryptographically verified `dm-verity` rootfs.

3. **Local Testing Environment Variable**:
   Set `CEVELL_AUTH_PUB` in local development or unit test environments.

### Supported Formats
- **Hex encoded** (64 characters): `<64-character-hex-encoded-public-key>`
- **Base64 encoded** (44 characters): `<44-character-base64-encoded-public-key>`
- **Raw 32 bytes binary**
