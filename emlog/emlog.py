import os
import logging
import pickle

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from .utils import *

from datetime import datetime

__author__ = "Carlton Shepherd"

logger = logging.getLogger()

AES_GCM_KEY_BITS = 192
AES_GCM_IV_BYTES = 16
backend = default_backend()


class Block:
    def __init__(self, msgs, block_id, sig):
        self.msgs = msgs
        self.block_id = block_id
        self.sig = sig

class Message:
    def __init__(self, msg, msg_id, hmac):
        self.msg = msg
        self.msg_id = msg_id
        self.hmac = hmac

    def __str__(self):
        return f"[msg:{self.msg}, msg_id:{self.msg_id}, hmac:{self.hmac}]"

class Emlog:
    def __init__(self, rlk_secret, storage_key=None, sig_key=None, ver_key=None, m=5, c=8, encoding="utf8", write_to_file=True):
        """
        Initialises the system.

        Inputs:
        rlk_secret : Root secret to seed root logging key (RLK) generation
        m : Maximum number of messages per block
        c : Maximum number of blocks per IK
        encoding : Encoding of messages (default: UTF-8)
        """
        self.m = m
        self.c = c
        self.encoding = encoding
        self.rlk = derive_key(rlk_secret)

        if sig_key:
            self.sig_k = load_sig_key(sig_key)
        else:
            self.sig_k = ec.generate_private_key(ec.SECP256R1(), backend)

        if ver_key:
            self.ver_k = load_ver_key(ver_key)
        else:
            self.ver_k = self.sig_k.public_key()

        if storage_key == None:
            logging.debug("Generating AES key...")
            storage_key = AESGCM.generate_key(bit_length=AES_GCM_KEY_BITS)

        self.aesgcm = AESGCM(storage_key)
        self.block_id = 1
        self.current_ik = derive_key(self.rlk, self.block_id)
        self.current_bk = derive_key(self.current_ik, self.block_id)
        self.blocks = []
        self.msg_id = 1

    def _generate_block_sig(self):
        """
        Generates block signature from the current list of message HMACS
        under sig_k over h(m_1.hmac, m_2.hmac, ..., m_n.hmac).

        Output:
        sig : Block ECDSA signature.
        """
        block_digest_bytes = generate_block_digest(self.current_block_msgs)
        return self.sig_k.sign(block_digest_bytes, ec.ECDSA(hashes.SHA256()))


    def export_public_key(self, fpath):
        ver_k_bytes = self.ver_k.public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(fpath, 'wb') as f:
            f.write(ver_k_bytes)


    def export_private_key(self, fpath):
        sig_k_bytes = self.sig_k.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption())
        with open(fpath, 'wb') as f:
            f.write(sig_k_bytes)

    def _write_encrypted_blocks(self, enc_blocks):
        """
        Writes a list of encrypted blocks to file.

        Input:
        enc_blocks : list of encrypted blocks in the form of dicts
        with structure {"iv" : iv, "enc_bytes" : enc_bytes}.
        """
        fpath = "emlog_" + str(datetime.now()).replace(" ", "_") + ".log"
        with open(fpath, "wb") as f:
            logger.debug(f"Writing to {fpath}...")
            f.write(pickle.dumps(enc_blocks))


    def _store_blocks(self, blocks):
        """
        Stores the current set of in-memory blocks to persistent storage.
        192-bit AES-GCM is used by default for encrypting data to file.
        """
        encrypted_blocks = []
        for block in blocks:
            pkl = pickle.dumps(block)
            iv = os.urandom(AES_GCM_IV_BYTES)
            encrypted_blocks.append({
                "iv" : iv,
                "enc_bytes" : self.aesgcm.encrypt(iv, pkl, None)
            })
        self._write_encrypted_blocks(encrypted_blocks)
            

    def insert(self, msg):
        """
        Inserts a new message; integrity protection is applied transparently
        using HMACs keyed under message keys derived in a chained manner.

        Input:
        msg : Message string (UTF-8 encoded)
        """
        # Derive new message key from current block key if msg_id == 0
        # and initialise new block message list, otherwise derive
        # new message key from previous message key and new msg_id
        if self.msg_id == 1:
            self.current_mk = derive_key(self.current_bk, self.msg_id)
            self.current_block_msgs = []
        else:
            self.current_mk = derive_key(self.current_mk, self.msg_id)

        # Compute HMAC on msg text keyed under current_mk
        hmac_obj = hmac.HMAC(self.current_mk, hashes.SHA256(), backend)
        hmac_obj.update(bytes(msg, encoding=self.encoding))
        msg_hmac = hmac_obj.finalize()

        self.current_block_msgs.append(Message(msg, self.msg_id, msg_hmac))

        # Check whether the block limit is reached; if so, create new Block
        # object and insert this block's msg list
        if self.msg_id != self.m:
           self.msg_id += 1
        else:
            sig = self._generate_block_sig()
            self.msg_id = 1

            self.blocks.append(Block(self.current_block_msgs, self.block_id, sig))

            # Check if in-memory block limit, c, is reached; if so,
            # securely store current blocks to file and reset the block list.
            # After this, derive a new IK and, from it, a new BK.
            if self.block_id == self.c:
                if write_to_file:
                    self._store_blocks(self.blocks)
                self.blocks = []

                # Derive new IK and BK
                self.current_ik = derive_key(self.current_ik, self.block_id)
                self.current_bk = derive_key(self.current_ik, self.block_id)
            self.block_id += 1

# TODO allow output redirection of log files to emlog via terminal.
# Add to main method below.
if __name__ == '__main__':
    pass