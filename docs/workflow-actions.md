# Workflow actions

Create and select a File Transfer project connection for FTP, FTPS, SFTP, S3-compatible storage or Dropbox; configure its root and credentials. For SFTP, verify and save the host-key fingerprint.

Select the connection in the workflow step. Map returned message IDs, file handles or dataset handles into later steps rather than pasting credentials or local paths.

## Discover SFTP host key (`discover_host_key`)

Fetch the SFTP server host-key fingerprint before saving a connection. Select an SFTP connection with the server host and port configured; compare the discovered fingerprint with a trusted server administrator before saving it. Example: Inspect the SFTP fingerprint during setup and compare it with the server administrator's value.

Result fields: `host_key_fingerprint`, `host_key_type`.

## Test file storage connection (`test_connection`)

Validate that the selected connection is reachable and its configured root can be read. Create and select a File Transfer project connection for FTP, FTPS, SFTP, S3-compatible storage or Dropbox; configure its root and credentials. For SFTP, verify and save the host-key fingerprint. Example: Check the configured storage root before scheduling a supplier feed import.

Result fields: `protocol`, `use_tls`.

## List remote files (`list_files`)

List the regular files of one directory, bounded to 500 raw entries, without reading file bodies. Create and select a File Transfer project connection for FTP, FTPS, SFTP, S3-compatible storage or Dropbox; configure its root and credentials. For SFTP, verify and save the host-key fingerprint. Example: List .csv filenames under incoming using name_glob=*.csv before importing a feed.

Inputs:

- `path`: Directory relative to the connection root. Use "." for the root itself.
- `name_glob`: Optional filename pattern such as *.csv. With a download, path becomes the directory in which to match files.
- `limit`: Maximum number of results to return in this page.

Result fields: `files`, `truncated`.

## Download remote file (`fetch_file`)

Download one remote file selected by path or filename pattern into a workflow artifact. Returns the downloaded file metadata and checksum. Create and select a File Transfer project connection for FTP, FTPS, SFTP, S3-compatible storage or Dropbox; configure its root and credentials. For SFTP, verify and save the host-key fingerprint. Example: Download the newest matching *.csv file from incoming with select=latest_modified, then pass the artifact to tabular processing.

Inputs:

- `path`: Without a filename glob this is the file to fetch. With a glob it is the directory to search; use "." for the connection root.
- `name_glob`: Optional. When set, Path is treated as a directory and the glob selects the file inside it.
- `select`: Choose only to require one match, latest_modified for the newest modification time, or latest_name for the last filename in sort order.
- `max_bytes`: Maximum allowed file size in bytes. Leave empty to use the host's configured artifact limit; oversized files fail.

Result fields: `artifact_handle`, `artifact_filename`, `source_filename`, `remote_path`, `sha256`, `size_bytes`.

## Upload file to remote storage (`upload_file`)

Upload one workflow file artifact to a remote path; replace an existing file only when overwrite is enabled. Create and select a File Transfer project connection for FTP, FTPS, SFTP, S3-compatible storage or Dropbox; configure its root and credentials. For SFTP, verify and save the host-key fingerprint. Example: Upload a generated report artifact to reports/daily.pdf, enabling overwrite only when replacement is intended.

Inputs:

- `artifact_handle`: Map the file artifact handle returned by an earlier download or file-generation step. The file must be available to this workflow run.
- `remote_path`: Destination filename and any directory relative to the configured connection root.
- `overwrite`: Enable to replace a file already at the destination. Leave disabled to reject an existing file.
- `max_bytes`: Maximum allowed file size in bytes. Leave empty to use the host's configured artifact limit; oversized files fail.

Result fields: `uploaded`, `remote_path`, `sha256`, `size_bytes`, `overwrite_protection`.
