# File Transfer Extension

`flowsteward.file-transfer` streams opaque files between Flow Steward artifacts
and four kinds of storage: FTP and explicit FTPS, SFTP, S3-compatible object
storage, and Dropbox. HTTP and HTTPS downloads stay in the built-in
`http_request` step.

Every connection offers the same three workflow operations:

| Operation | Inputs | Result |
|---|---|---|
| List Files (`list_files`) | `connection_ref`, `path`, `name_glob?`, `limit?` | `files` (`name`, `size_bytes`, `modified_at`), `truncated` |
| Download File (`fetch_file`) | `connection_ref`, `path`, `name_glob?`, `select?`, `max_bytes?` | `artifact_handle`, `artifact_filename`, `source_filename`, `remote_path`, `sha256`, `size_bytes` |
| Upload File (`upload_file`) | `connection_ref`, `artifact_handle`, `remote_path`, `overwrite?`, `max_bytes?` | `uploaded`, `remote_path`, `sha256`, `size_bytes`, `overwrite_protection` |

Paths are relative to the connection's root and use `/`; `.` is the root
itself. Absolute paths, backslashes, control characters and `.`/`..` segments
are refused. Names are taken literally: `%2F` stays three characters.

## How It Is Built

All connection types implement one interface, `FileConnection` in
`file_connections.py`, with exactly `list_files`, `fetch_file` and
`upload_file`. The common layer in `file_operations.py` owns everything the
types share: payload validation, glob selection, byte limits, hashing, artifact
grants and result shapes. `connection_factory.py` maps the four
`connection_type_id` values to their classes in `connections/`; there is no
other way to pick a protocol. `main.py` only reads JSON and writes JSON.

## Limits That Apply To Every Connection

- **Listing** reads at most 500 raw entries of one directory. Folders, links,
  directory markers and names that cannot be expressed as a path still count.
  When there are more, the result says `truncated: true`. There is no cursor,
  recursion or account-wide search.
- **Glob download** refuses with `directory_too_large` when the listing was
  truncated, even if only one name matches what was seen. `select` is `only`
  (default; more than one match is `ambiguous_match`), `latest_name`, or
  `latest_modified` (refused when a matching file has no reliable timestamp).
- **Size.** Transfers default to a 200 MiB ceiling. Operators can change it with
  `FS_EXTENSION_ARTIFACT_MAX_BYTES` (1 MiB to 10 GiB); a workflow's `max_bytes`
  and the signed artifact grant can only lower it.
- **Time.** One deadline, `FS_EXTENSION_OPERATION_TIMEOUT_SECONDS` (300 seconds
  by default, 30 to 3600), covers the whole operation; Core adds 30 seconds of
  cleanup headroom.
- **Streaming.** Files move in pieces of at most 1 MiB; uploads are buffered at
  most 8 MiB at a time. File bodies never enter workflow state.
- **Upload outcome.** An upload that broke off after the remote write may have
  happened reports `timeout_unknown` and is never repeated automatically.
  `overwrite` is off by default. In test mode no upload reaches any server.

## FTP and FTPS

Production FTP/FTPS accounts must be server-side jailed or chrooted to their
configured `root_path`. FTP has no portable realpath or symlink contract, so the
extension's lexical checks are not a hard filesystem sandbox by themselves. At
connect time the extension verifies that `CWD root_path` succeeds and `PWD`
returns a non-empty current directory; hard root isolation is delegated to the
server-side jail. Plaintext FTP requires an explicit acknowledgement.

Uploads go to a temporary file in the same directory and are renamed into
place; `overwrite_protection` is `best_effort`.

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

Paramiko is pinned to 5.x so RSA keys cannot fall back to SHA-1 `ssh-rsa`
signatures; legacy `ssh-rsa` and DSA host keys are refused.

## S3-Compatible Storage

A connection names one HTTPS endpoint origin, a region, one bucket, an optional
key prefix that every path is relative to, and path or virtual-host addressing.
Keys go in encrypted connection secrets: access key ID, secret access key and,
for temporary credentials, a session token.

- **Credentials** come only from the connection. Environment variables, AWS
  profiles and config files, instance metadata and botocore plugins are never
  consulted; a connection without keys is refused before any network use.
- **Network.** The endpoint host is resolved and checked once per operation;
  every connection goes to that address, TLS is verified against the configured
  host name, proxies are not used, and a redirect away from the endpoint never
  connects. TLS trusts the host's certificate store (`SSL_CERT_FILE`), not
  `AWS_CA_BUNDLE`.
- **Listing** shows only the objects directly under the directory's prefix:
  `feeds` never includes `feeds-old`, and objects whose key ends in `/` are
  folder markers, not files.
- **Uploads** are multipart and committed with `CompleteMultipartUpload`. Without
  `overwrite` the commit is conditional (`If-None-Match: *`), so an existing
  object is never replaced; `overwrite_protection` is `atomic`. A service that
  rejects conditional writes answers `not_supported_by_server`; a service that
  silently ignores them cannot be detected, so use one from the tested list. On
  a known failure the extension aborts its own unfinished upload; it never
  deletes objects.
- **Permissions needed:** list the bucket under the prefix, read objects, and
  for uploads write objects and abort the extension's own multipart uploads.

Verified for this release, with path and virtual-host addressing and the
conditional create: MinIO (built from commit 9e49d5e7) and Tigris through
Railway Buckets. AWS S3 general-purpose buckets are the intended target but were
not run against for this release; every other S3-compatible service is
unverified, so run tests/test_s3_protocol_integration.py against it first.

## Dropbox

Dropbox uses a Dropbox app that belongs to the project. Create it in the Dropbox
App Console with **Scoped access** and enable exactly `files.metadata.read`,
`files.content.read` and `files.content.write`. Choose **Full Dropbox** to work
with files already in the account; **App folder** limits every path to the
app's own folder. On the extension's Dropbox tab, add the OAuth Redirect URI
shown there as a redirect URI and save the App key and App secret; the same tab
then connects accounts with Authorization Code + PKCE.

Core keeps the refresh token and the app secret; each operation receives only
the selected account's current access token, so connections and accounts never
share a client or token. Requests go only to `api.dropboxapi.com` and
`content.dropboxapi.com`, and redirects are refused.

Uploads up to 8 MiB are one request; larger files use an upload session that is
finished only after the whole artifact was read. Upload creates a file only in a
folder that already exists and never renames on conflict; without `overwrite` an
existing file is left alone (`already_exists`). Disconnecting an account in Flow
Steward deletes the stored tokens; it does not revoke the app's access in
Dropbox, which the account owner can do in their Dropbox security settings.

## Production Settings

Production deployments must leave `FS_ALLOW_PRIVATE_REMOTE_URLS` disabled. That
global switch is only for local development and protocol fixtures.

## Distribution

The extension ships as one portable Python ZIP with every dependency as a
pinned wheel for CPython 3.12 on Linux x86_64 and aarch64; `extension.yaml`
lists each wheel's SHA-256. Nothing is downloaded, resolved or built at install
or run time. `requirements.in` holds the direct requirements; the SFTP closure
stays at the 0.1.7 versions except `cryptography`, raised to 50.0.2 for a known
vulnerability. `THIRD_PARTY_NOTICES` and `licenses/` cover every bundled wheel.

## Independent Release Gate

This repository does not import private `core.*` modules. The extension-local
gate:

```bash
bash scripts/ci.sh
```

`requirements-dev.txt` installs the pinned public SDK wheel from `dev-wheels/`;
update that wheel when the public SDK contract changes.
