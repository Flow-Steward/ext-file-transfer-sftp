# Maintained AWS compatibility graph

File Transfer 0.3.6 ships `botocore 1.44.2+flowsteward.1`,
`aiobotocore 3.10.0+flowsteward.2`, official `python-dateutil 4.0.0` and
`tzdata 2026.6`. The two local versions identify Flow Steward's maintained
compatibility forks. They are not upstream releases or an upstream support claim.

Official PyPI metadata, checked on 2026-11-13, has no resolver-compatible graph
containing all three latest public releases: aiobotocore 3.10.0 requires botocore
`>=1.43.115,<1.43.118` and python-dateutil `<3`; botocore 1.44.2 also requires
python-dateutil `<3`. Both maintained forks therefore pin the exact tested
python-dateutil version, and aiobotocore pins the exact maintained botocore wheel.
Unmodified official wheels cannot install this graph.

The botocore fork changes its distribution/runtime version and its dateutil pin.
Its runtime implementation and service models are otherwise the official
1.44.2 files. The aiobotocore fork changes its distribution/runtime version,
its two peer pins, adds the upstream HTTP 429 retry checker to its copied
asynchronous retry-condition list, and copies a caller's presigned POST conditions before adding
bucket/key conditions. That last change ports the actual botocore 1.43.127
`generate_presigned_post` fix to the separately maintained asynchronous method.
Without it, two real presign calls contaminate the caller's original conditions
and the second policy with the first object's key. The regression demonstrates
that failure before the patch and verifies both resulting policies afterwards.

The official botocore 1.43.127-to-1.44.2 Python implementation changes make
standard retries the default, enable the previously gated retry policy, classify
unmodeled HTTP 429 responses as throttling, require HTTPS for bearer-token auth,
and honor the sign-in region for login-token refresh. The async retry condition
list duplicates upstream code and needs the added `ThrottlingStatusCodeChecker`;
without it the new real retry-context controls fail on empty and unmodeled 429
responses. Controls retain modeled nonretryable errors, nonthrottling 403 errors,
and the configured attempt cap. Other changed retry behavior is imported from
botocore or already present behind its now-enabled compatibility flag. The
extension explicitly sets standard mode with one SDK attempt, retaining its own
bounded read retries and single commit attempt. Bearer auth and login-token
providers remain outside its explicit-key-only S3 contract. The botocore service
models are retained unmodified, including the new 1.44.2 models.

Existing transport tests
exercise real S3 client creation, the S3 service model, XML parsing, request
signing, TLS transport, pinned endpoints, conditional writes, multipart uploads,
streaming reads, limits, cancellation, deadlines and explicit credentials.

The AWS files use dateutil's `parser.parse`, `tzutc` and `tzlocal` interfaces.
Dateutil 4 retains these interfaces. Its major changes since 2.9 are Python 3.11
minimum support, removal of six, a timezone-file implementation with tzdata
fallback and stricter `isoparse` numeric fields. This bundle uses Python 3.12.
An installed-graph control checks every runtime version and active peer requirement
against the manifest, plus distribution/runtime AWS version consistency.
Real timestamp controls cover S3 ISO/RFC822 GMT responses, explicit offsets,
numeric/string epochs and credential expiry parsing. Malformed ISO controls
also establish that the actual new dateutil implementation is installed.
SFTP, FTP/FTPS and Dropbox behavior remains covered by the full extension suite.

`dependency-sources.json` records each official PyPI wheel URL and SHA-256,
public base identity, local wheel identity/hash and exact source/metadata patch
hash. `patches/*.json` contains exact replacements bound to original file hashes.
The rebuilder changes only those recorded files, renames dist-info and recomputes
RECORD; upstream licenses and all other files are retained. All versions remain
under their original package names. Security tooling must query the public base
version as well as retaining the full local version in reports; a local suffix
must never hide an upstream advisory.

To reproduce, download the two official wheels from the URLs in the source
manifest into an empty directory, then run:

```sh
python scripts/rebuild_aws_wheels.py /path/to/official-wheels /path/to/output
```

The script rejects upstream or patch hash mismatches and verifies the rebuilt
wheel hashes. The release checks reproduce both wheel hashes from the official
source wheels on macOS and Linux. Bundle validation rejects local versions
without matching same-package/public-version provenance, a hashed official PyPI
source URL, existing bound patches and a manifest-locked local wheel.

This compatibility promise is restricted to this extension and this exact graph.
No arbitrary AWS service or alternate credential-provider support is claimed.
Tests use explicit test keys and a local TLS S3 protocol server; authenticated
AWS/MinIO integration is skipped without supplied service credentials. The
extension's explicit-key-only isolated session and its network boundaries remain
unchanged. Future public versions require a fresh source comparison and tests,
or removal of these forks once upstream supports the required graph.

Primary sources checked for this update:

- [Botocore 1.44.2 official PyPI metadata](https://pypi.org/pypi/botocore/1.44.2/json)
- [Aiobotocore 3.10.0 official PyPI metadata](https://pypi.org/pypi/aiobotocore/3.10.0/json)
- [Botocore retry implementation at 1.44.2](https://github.com/boto/botocore/blob/1.44.2/botocore/retries/standard.py)
- [Aiobotocore retry implementation at 3.10.0](https://github.com/aio-libs/aiobotocore/blob/3.10.0/aiobotocore/retries/standard.py)
