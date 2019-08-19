import os
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__author__ = "Carlton Shepherd"

backend = default_backend()
logger = logging.getLogger()


class Block:
    def __init__(self, msgs, block_id, sig):
        self.msgs = msgs
        self.block_id = block_id
        self.sig = sig

    def __str__(self):
        msg_strs = "\n".join([str(m) for m in self.msgs])
        return f"msgs: [{msg_strs}], block_id:{block_id}, sig:{sig}"


class Message:
    def __init__(self, msg, msg_id, hmac):
        self.msg = msg
        self.msg_id = msg_id
        self.hmac = hmac

    def __str__(self):
        return f"[msg:{self.msg}, msg_id:{self.msg_id}, hmac:{self.hmac}]"


class Emlog:
    def __init__(self, rlk_secret, m=32, c=8, encoding="utf8"):
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

        # Derive root logging key (RLK) from the root secret
        self.rlk = self._derive_key(rlk_secret)

        # Generate ECDSA key-pair for signing message blocks w/SECP256R1 curve
        self.sig_k = ec.generate_private_key(ec.SECP256R1(), backend)
        self.ver_k = self.sig_k.public_key()

        # Derive initial IK and block key
        self.block_id = 1
        self.current_ik = self._derive_key(self.rlk, self.block_id)
        self.current_bk = self._derive_key(self.current_ik, self.block_id)
        self.blocks = []
        self.msg_id = 1
        logger.debug(f"rlk: {self.rlk}")
        logger.debug(f"(sig_k, ver_k): {self.sig_k, self.ver_k}")
        logger.debug(f"current_ik: {self.current_ik}")
        logger.debug(f"current_bk: {self.current_bk}")
        logger.debug(f"block_id: {self.block_id}")


    def _derive_key(self, k, item_id=0):
        """
        Derives a new key using Krawczyk's HKDF method using SHA256.

        Input:
        k : Key material from which to derive a new key.
        item_id : Integer, e.g. message ID, to use as a quasi-salt.

        Output: Fresh key derived from k and item_id using HKDF.
        """
        hkdf = HKDF(algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"emlog",
                    backend=backend)
        return hkdf.derive(k+bytes(item_id))


    def _generate_block_sig(self):
        """
        Generates block signature from the current list of message HMACS
        under sig_k over h(m_1.hmac, m_2.hmac, ..., m_n.hmac).

        Output:
        sig : Block signature (using SECP256R1).
        """
        logger.verbose("***** Generating block signature *****")
        digest = hashes.Hash(hashes.SHA256(), backend=backend)
        for m in self.current_block_msgs:
            logger.verbose(f"Hashing {m}")
            digest.update(m.hmac)
        digest_bytes = digest.finalize()
        return self.sig_k.sign(digest_bytes,
                               ec.ECDSA(hashes.SHA256()))

    def _store_blocks(self):
        logger.verbose("Storing in-memory blocks to file...")
        

        raise NotImplementedError()


    def insert(self, msg):
        """
        Inserts a new message; integrity protection is applied transparently
        using HMACs keyed under message keys derived in a chained manner.

        Input:
        msg : Message string (UTF-8 encoded)
        """
        logger.verbose(f"Inserting msg: {msg}")

        # Derive new message key from current block key if msg_id == 0
        # and initialise new block message list, otherwise derive
        # new message key from previous message key and new msg_id
        if self.msg_id == 1:
            self.current_mk = self._derive_key(self.current_bk, self.msg_id)
            self.current_block_msgs = []
        else:
            self.current_mk = self._derive_key(self.current_mk, self.msg_id)

        # Compute HMAC on msg text keyed under current_mk
        hmac_obj = hmac.HMAC(self.current_mk, hashes.SHA256(), backend)
        hmac_obj.update(bytes(msg, encoding=self.encoding))
        msg_hmac = hmac_obj.finalize()
        logger.debug(f"msg_hmac: {msg_hmac}")

        # Update with new Message object
        self.current_block_msgs.append(Message(msg, self.msg_id, msg_hmac))
        self.msg_id += 1
        logger.debug(f"msg_id: {self.msg_id}")

        # Check whether the block limit is reached; if so, create new Block
        # object and insert this block's msg list
        if self.msg_id == self.m:
            logger.debug("***** Block limit reached *****")
            logger.debug(f"m: {self.m}, msg_id: {self.msg_id}")
            sig = self._generate_block_sig()
            self.block_id += 1
            self.msg_id = 1

            # Append in-memory block list with new Block object
            self.blocks.append(Block(self.current_block_msgs, self.block_id, sig))

            # Check if in-memory block limit, c, is reached; if so,
            # securely store to file and reset the block list.
            # After this, derive a new IK and, from it, derive a new BK.
            if self.block_id == self.c:
                logger.debug("***** In-memory block limit reached *****")
                self._store_blocks()
                del self.blocks
                self.blocks = []

                # Derive new IK and BK
                self.current_ik = self._derive_key(self.current_ik, self.block_id)
                self.current_bk = self._derive_key(self.current_ik, self.block_id)