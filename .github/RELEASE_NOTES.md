**0.3.1: logo fix.** The logo (`icon.png`) now has a transparent background; in 0.3.0 the Flow Steward wave sat on a black box on dark themes.

**Needs a Flow Steward Core that speaks the final extension host contract.** 0.3.0 speaks `extension_host_v2` with its final execution scope (`group_id`, `for_each_id`, `step_id`, `step_execution_id`) and is built on `flowsteward-extension-sdk` 0.4.0. A request with another contract, a missing scope key, both a Group and a For each as its owner, or a step without its execution is refused (`invalid_host_envelope`) before any artifact is read or written and before any server is contacted. An older Core does not run this release.

New in 0.3.0: List Files, Download File and Upload File work the same for a step at the root, in a Group or in a For each, for FTP/FTPS, SFTP, S3-compatible storage and Dropbox. The extension now has a logo (`icon.png`).

**Needs a newer Flow Steward Core for Dropbox.** Dropbox accounts are connected on the same tab where the Dropbox app is set up. A Core that does not yet show an OAuth provider's setup and Connect form together shows only the App key / App secret form there, so Dropbox cannot be connected until Core is updated. FTP, FTPS, SFTP and S3-compatible storage work on the current Core.

New in 0.2.x: S3-compatible storage and Dropbox connections next to FTP/FTPS/SFTP, with the same three operations (List Files, Download File, Upload File) for every connection type.
