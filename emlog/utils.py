from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_ecdsa_key_pair(backend):
    """
    Generates ECDSA key-pair for signing message blocks (SECP256R1 curve).
    
    Output:
    sig_k : Signing key
    ver_k : Verification key
    """
    sig_k = ec.generate_private_key(ec.SECP256R1(), backend)
    ver_k = sk.public_key()
    return (sk, pk)

def derive_key(backend, k, item_id):
    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"emlog",
                backend=backend)
    return hkdf.derive(k+bytes(item_id))