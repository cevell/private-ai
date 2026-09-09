# Client Authentication Public Key Configuration

Place your 32-byte Ed25519 public key in `auth.pub` in this directory before building the production image (`nix-build default.nix --argstr debug off`).

### Supported Formats:
1. **Hex encoded** (64 characters): `<64-character-hex-encoded-public-key>`
2. **Base64 encoded** (44 characters): `<44-character-base64-encoded-public-key>`
3. **Raw 32 bytes binary**

The Nix build system will bundle `auth.pub` into `/etc/cevell/auth/auth.pub` in the rootfs, ensuring the CVM verifies only requests signed with the corresponding private key (e.g. `operator.pem`).
