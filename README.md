# File Transfer Extension

`flowsteward.file-transfer` streams opaque files over FTP, explicit FTPS, and
SFTP. HTTP and HTTPS downloads stay in the built-in `http_request` step.

Production FTP/FTPS accounts must be server-side jailed or chrooted to their
configured `root_path`. FTP has no portable realpath or symlink contract, so the
extension's lexical checks are not a hard filesystem sandbox by themselves. At
connect time the extension verifies that `CWD root_path` succeeds and `PWD`
returns a non-empty current directory; hard root isolation is delegated to the
server-side jail.

Production deployments must leave `FS_ALLOW_PRIVATE_REMOTE_URLS` disabled. That
global escape hatch is only for local development and protocol fixtures.

Transfers default to a 200 MiB artifact ceiling. Operators can change the shared
producer/consumer limit with `FS_EXTENSION_ARTIFACT_MAX_BYTES`; explicit workflow
`max_bytes` values and signed grants may only reduce the effective limit. Long-running
fetch and upload subprocesses use `FS_EXTENSION_OPERATION_TIMEOUT_SECONDS` (300 seconds
by default) plus bounded host cleanup headroom.

## SFTP Host Key Fingerprint

SFTP connections pin the server host key fingerprint so credentials and file
contents are not sent to an impersonating server. The connection UI fetches this
fingerprint automatically before saving a new SFTP connection and asks the user
to trust that server identity. The stored value uses canonical OpenSSH SHA-256
form, such as `SHA256:abc123...`.

One way to independently inspect a server key is:

```bash
ssh-keyscan -p 22 sftp.example.com 2>/dev/null | ssh-keygen -lf - -E sha256
```

Verify the printed fingerprint with the server owner or another trusted source
before saving it. Do not treat a first-seen fingerprint as trusted just because
the network request succeeded.

## Dependency Security

Paramiko is bundled extension-locally because SFTP is part of this extension's
explicit protocol surface. The extension is pinned to Paramiko 5.x so RSA keys
cannot fall back to SHA-1 `ssh-rsa` signatures. Runtime hardening still disables
legacy `ssh-rsa` and DSA host-key negotiation, and disables `ssh-rsa` for RSA
public-key user authentication. RSA remains allowed only through negotiated
`rsa-sha2-*` algorithms. Ed25519, ECDSA NIST, and RSA-SHA2 host keys must still
be pinned by canonical OpenSSH `SHA256:<base64>` fingerprint.

## Independent Release Gate

This directory is intended to be portable as its own extension repository. The
extension-local CI gate does not import private `core.*` modules:

```bash
bash scripts/ci.sh
```

When running inside the Flow Steward monorepo, `scripts/ci.sh` automatically
uses the same dependency path as a standalone repository: `requirements-dev.txt`
installs the pinned public SDK wheel from `dev-wheels/`. Do not rely on
monorepo-relative SDK paths; update the versioned SDK wheel when the public SDK
contract changes.
