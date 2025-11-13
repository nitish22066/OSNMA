# PQC adapter placeholder using python-oqs if present
# Add as osnma/protocol/adapters/pqc_adapter.py

from osnma.protocol.interface import Protocol
from osnma.protocol.registry import register

try:
    import oqs
except Exception:
    oqs = None

class PQCAdapter(Protocol):
    def __init__(self, algorithm='Dilithium2'):
        if oqs is None:
            raise RuntimeError('python-oqs not available; install python-oqs to use PQCAdapter')
        self.algorithm = algorithm

    def keygen(self):
        with oqs.Signature(self.algorithm) as s:
            pk = s.generate_keypair()
            sk = s.export_secret_key()
        # key_id placeholder
        return sk, pk, f'pqc-{self.algorithm}'

    def sign(self, message: bytes, private_key) -> bytes:
        with oqs.Signature(self.algorithm) as s:
            return s.sign(message, private_key)

    def verify(self, message: bytes, signature: bytes, public_key) -> bool:
        with oqs.Signature(self.algorithm) as s:
            try:
                return s.verify(message, signature, public_key)
            except Exception:
                return False

    def serialize_public_key(self, public_key) -> bytes:
        return public_key

    def deserialize_public_key(self, blob: bytes):
        return blob

    def signature_size(self) -> int:
        return None

# register adapter under name 'pqc' only if oqs available
if oqs is not None:
    register('pqc', PQCAdapter)
