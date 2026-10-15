"""SFTP connections over the existing host-key-pinned ``SFTPClient``."""

from __future__ import annotations

from connections import ProtocolClientConnection


class SFTPConnection(ProtocolClientConnection):
    pass
