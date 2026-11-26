# File Transfer 0.3.12

- Rebuilt botocore from the official 1.44.11 wheel with the existing python-dateutil 4.0.0 compatibility pin.
- Rebuilt aiobotocore 3.10.0+flowsteward.7 with the new botocore pin and the existing HTTP 429 and presigned POST fixes.
- Updated the development-only packaging wheel to 26.4. CI now uses the same offline test dependencies as local verification.

[Changes from 0.3.11](https://github.com/Flow-Steward/ext-file-transfer-sftp/compare/v0.3.11...v0.3.12)
