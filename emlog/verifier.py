import os
import logging
import pickle

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger()

class Verifier:
    def __init__(self, rlk_secret, storage_key):
        self.aesgcm = AESGCM(storage_key)

    def verify(data):
        encrypted_blocks = pickle.loads(data)
        logger.debug(f"Pickled data: {self.encrypted_blocks}")
        # Each block in encrypted_blocks contains an iv and enc_bytes.
        # enc_bytes is an encrypted pickled representation of the block,
        # keyed under storage_key with iv.
        for enc_block in encrypted_blocks:
            logger.debug(f"enc_block: {enc_block}")
            pkl_block = self.aesgcm.decrypt(enc_block['iv'], enc_block['enc_bytes'], None)
            block = pickle.loads(pkl_block)
            logger.debug(f"Unpickled block: {block}")
            logger.debug(f"block sig: {block.sig}")
            logger.debug(f"block id: {block.block_id}")
