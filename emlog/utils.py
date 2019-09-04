import logging
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

backend = default_backend()
SHA256_BYTES = 32
logger = logging.getLogger()

def generate_block_digest(block_msgs):
    digest = hashes.Hash(hashes.SHA256(), backend=backend)
    for m in block_msgs:
        digest.update(m.hmac)
    return digest.finalize()

def verify_message(m, last_msg_key, encoding="utf8"):
    h = hmac.HMAC(last_msg_key, hashes.SHA256(), backend)
    h.update(bytes(m.msg, encoding=encoding))
    return h.verify(m.hmac)

def derive_key(k, item_id=0):
    """
    Derives a new key using HKDF w/SHA256.

    Input:
    k : Key material from which to derive a new key.
    item_id : Integer, e.g. message ID, to use as a quasi-salt.
    
    Output: Fresh key derived from k and item_id using HKDF.
    """
    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=SHA256_BYTES,
                salt=None,
                info=b"emlog",
                backend=backend)
    return hkdf.derive(k+bytes(item_id))


def read_key_bytes(key_path):
    with open(key_path, 'rb') as f:
        key_bytes = f.read()
    return key_bytes

def load_sig_key(sig_key_path):
    sig_key_bytes = read_key_bytes(sig_key_path)
    logging.debug(f"Loading {sig_key_path}...")
    return serialization.load_pem_private_key(sig_key_bytes, None, backend)

def load_ver_key(ver_key_path):
    ver_key_bytes = read_key_bytes(ver_key_path)
    logging.debug(f"Loading {ver_key_path}...")
    return serialization.load_pem_public_key(ver_key_bytes, backend)

class UnexpectedBlocksException(Exception):
    """ Raised when the number of blocks is not that which is expected """

class UnexpectedNumberOfBlockKeys(Exception):
    """ Raised when the number of blocks is not that which is expected """

class InvalidBlockSignature(Exception):
    """ Raised when a block signature fails to verify """

class InvalidMessageHMAC(Exception):
    """ Raised when a message HMAC fails to verify """