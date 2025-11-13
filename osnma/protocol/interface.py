# Protocol adapter interface for broadcast authentication schemes.
# Add as osnma/protocol/interface.py

class Protocol:
    """Protocol adapter interface for broadcast authentication schemes.

    Implementations must provide keygen(), sign(), verify(), and helpers.
    """

    def keygen(self):
        """Return (private_key, public_key, key_id)"""
        raise NotImplementedError

    def sign(self, message: bytes, private_key) -> bytes:
        """Return signature bytes for message"""
        raise NotImplementedError

    def verify(self, message: bytes, signature: bytes, public_key) -> bool:
        """Return True if signature valid"""
        raise NotImplementedError

    def serialize_public_key(self, public_key) -> bytes:
        raise NotImplementedError

    def deserialize_public_key(self, blob: bytes):
        raise NotImplementedError

    def signature_size(self) -> int:
        """Return expected signature size in bytes (or None if variable)"""
        return None
