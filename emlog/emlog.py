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
    """
    Block placeholder obj (for structure).
    """
    def __init__(self, msgs, block_id, sig):
        self.msgs = msgs
        self.block_id = block_id
        self.sig = sig

    def __str__(self):
        pass


class Message:
    """
    Message placeholder obj (for structure).
    """
    def __init__(self, msg, msg_id, hmac):
        self.msg = msg
        self.msg_id = msg_id
        self.hmac = hmac

    def __str__(self):
        pass


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

        # Generate signing key pair
        self.sig_k, self.ver_k = self._generate_ecdsa_key_pair()

        # Derive initial IK and block key
        self.block_id = 1
        self.current_ik = self._derive_key(self.rlk, self.block_id)
        self.current_bk = self._derive_key(self.current_ik, self.block_id)
        self.block_list = []
        self.msg_id = 1
        logger.debug(f"rlk: {self.rlk}")
        logger.debug(f"(sk, pk): {self.sig_k, self.ver_k}")
        logger.debug(f"current_ik: {self.current_ik}")
        logger.debug(f"current_bk: {self.current_bk}")
        logger.debug(f"block_id: {self.block_id}")
        

    def _generate_ecdsa_key_pair(self):
        """
        Generates ECDSA key-pair for signing message blocks (SECP256R1 curve).
    
        Output:
        sig_k : Signing key
        ver_k : Verification key
        """
        sig_k = ec.generate_private_key(ec.SECP256R1(), backend)
        ver_k = sig_k.public_key()
        return (sig_k, ver_k)


    def _derive_key(self, k, item_id=0):
        hkdf = HKDF(algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"emlog",
                    backend=backend)
        return hkdf.derive(k+bytes(item_id))


    def _generate_block_sig(self):
        """
        Generate block signature from the current list of messages under
        the signing key generated in _generate_ecdsa_key_pair(self).

        Output:
        sig : Block signature
        """
        logger.debug("***** Generating block signature *****")
        # Generate signature
        # Compute sig(h(m1.hmac, m2.hmac, ..., mn.hmac))
        raise NotImplementedError()


    def _store(self):
        raise NotImplementedError()


    def insert(self, msg):
        """
        Inserts a new message; integrity protection is applied transparently
        using HMACs keyed under message keys derived in a chained fashion.

        Input:
        msg : Message string (UTF-8 encoded)
        """
        logger.debug(f"msg: {msg}")

        # Derive new message key from current block key if msg_id == 0,
        # otherwise derive from previous message key
        if self.msg_id == 1:
            self.current_mk = self._derive_key(self.current_bk, self.msg_id)
            # Initialise list for maintaining current block message objs
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

        # Check whether the block limit is reached; if so, create new Block
        # object and insert this block's msg list
        if self.msg_id == self.m:
            logger.debug(f"***** Block limit reached *****")
            logger.debug(f"m: {self.m}, msg_id: {self.msg_id}")
            sig = self._generate_block_sig()
            self.block_id += 1
            self.msg_id = 1

            # Append in-memory block list with new Block object
            self.block_list.append(Block(self.current_block_msgs, self.block_id, sig))

            # Check if in-memory block limit, c, is reached; if so,
            # securely store to file and reset the block list.
            # After this, derive a new IK and, from it, derive a new BK.
            if self.block_id == self.c:
                # TODO store current block list to file
                self._store()


                # Reset block list
                del self.block_list
                self.block_list = []

                # Derive new IK and BK
                self.current_ik = self._derive_key(self.current_ik, self.block_id)
                self.current_bk = self._derive_key(self.current_ik, self.block_id)