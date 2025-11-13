# ECDSA adapter using cryptography
# Add as osnma/protocol/adapters/ecdsa_adapter.py

from osnma.protocol.interface import Protocol
from osnma.protocol.registry import register

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

class ECDSAAdapter(Protocol):
    def __init__(self, curve=ec.SECP256R1()):
        self.curve = curve

    def keygen(self):
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        # serialize public key (PEM)
        pk_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, pk_pem, 'ecdsa-p256'

    def sign(self, message: bytes, private_key) -> bytes:
        # Use SHA256
        return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, message: bytes, signature: bytes, public_key_blob) -> bool:
        try:
            public_key = serialization.load_pem_public_key(public_key_blob)
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def serialize_public_key(self, public_key) -> bytes:
        return public_key

    def deserialize_public_key(self, blob: bytes):
        return blob

    def signature_size(self) -> int:
        # DER encoded signature size varies, so return None
        return None

# register adapter under name 'ecdsa'
register('ecdsa', ECDSAAdapter)
