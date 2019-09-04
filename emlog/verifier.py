import os
import logging
import pickle

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from .utils import *

logger = logging.getLogger()

class Verifier:
    def __init__(self, rlk_secret, storage_key, ver_key,
                 m=5, c=8, encoding="utf8"):
        self.rlk = derive_key(rlk_secret)
        self.aesgcm = AESGCM(storage_key)
        self.ver_k = load_ver_key(ver_key)
        self.m = m
        self.c = c
        self.encoding = encoding

    def recover_blocks(self, pickled_enc_blocks):
        # Each block in encrypted_blocks contains an iv and enc_bytes.
        # enc_bytes is an encrypted pickled representation of the block,
        # keyed under storage_key and using iv.
        encrypted_blocks = pickle.loads(pickled_enc_blocks)
        decrypted_blocks = []
        for enc_block in encrypted_blocks:
            pkl_block = self.aesgcm.decrypt(nonce=enc_block['iv'], data=enc_block['enc_bytes'], associated_data=None)
            # Store decrypted blocks
            block = pickle.loads(pkl_block)
            decrypted_blocks.append(block)
        return decrypted_blocks


    def verify(self, data):
        """
        Verifies a given block group and the blocks and messages therein.

        Input:
        data : Pickled array containing an encrypted block group.

        Excepts:
        UnexpectedBlocksException : 
        UnexpectedNumberofBlockKeys : 
        InvalidBlockSignature : 
        InvalidMessageHMAC : 
        """
        recovered_blocks = self.recover_blocks(data)
        if len(recovered_blocks) != self.c:
            raise UnexpectedBlocksException(
                f"Expected {self.c} blocks, got {len(recovered_blocks)}!")

        # 1. Derive block keys from IK and stored block_id.
        # The requisite IK is calculated using block_id // c, from
        # the first observed block_id, which gives the number of
        # deriviations necessary from rlk.
        # Recall that only one IK is needed to verify a block group
        first_block_id = recovered_blocks[0].block_id
        no_extra_ik_derivations = first_block_id // self.c
        block_id_count = 1

        # Rlk derives the 1st IK; the rest use IK and block_id.
        last_derived_ik = derive_key(self.rlk, block_id_count)
        if no_extra_ik_derivations > 0:
            for _ in range(no_extra_ik_derivations):
                block_id_count += self.m
                last_derived_ik = derive_key(self.last_derived_ik,
                                             block_id_count)

        # 2. Derive block keys from last_derived_ik.
        last_block_key = derive_key(last_derived_ik, first_block_id)
        block_keys = [last_block_key]
        for i in range(self.c-1):
            last_block_key = derive_key(last_block_key, 1+first_block_id+i)
            block_keys.append(last_block_key)

        if len(block_keys) != self.c:
            raise UnexpectedNumberofBlockKeys(
                f"No. block keys ({len(block_keys)}) exceeds block group size ({self.c})!")

        # 3. Verify block signatures.
        for block in recovered_blocks:
            block_digest_bytes = generate_block_digest(block.msgs)
            try:
                self.ver_k.verify(block.sig, block_digest_bytes, ec.ECDSA(hashes.SHA256()))
            except ec.InvalidSignature:
                raise InvalidBlockSignature(f"Block {block.block_id} sig. failed to verify!")
            
        # 4. Verify message HMACs 
        for i, block in enumerate(recovered_blocks):
            # Get block key
            block_key = block_keys[i]
            for j, m in enumerate(block.msgs):
                # First message key is derived from the block key.
                if j == 0:
                    # Careful: messages are *not* zero-indexed.
                    last_msg_key = derive_key(block_key, j+1)
                else:
                    last_msg_key = derive_key(last_msg_key, j+1)
                try:
                    verify_message(m, last_msg_key, self.encoding)
                except InvalidSignature:
                    raise InvalidMessageHMAC(f"Message {m.msg_id} HMAC failed to verify!")