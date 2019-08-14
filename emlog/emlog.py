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


class Message:
    """
    Message placeholder obj (for structure).
    """
    def __init__(self, msg, msg_id, hmac):
        self.msg = msg
        self.msg_id = msg_id
        self.hmac = hmac


class Emlog:
    def __init__(self, rlk_secret, m=32, c=8):
        """
        Initialises the system.

        Inputs:
        rlk_secret : Root secret to seed root logging key (RLK) generation
        m : Maximum number of messages per block
        c : Maximum number of blocks per IK
        """
        self.m = m
        self.c = c

        # Derive root logging key (RLK) from the root secret
        self.rlk = derive_key(rlk_secret)

        # Generate signing key pair
        self.sig_k, self.ver_k = generate_ecdsa_key_pair()

        # Derive initial IK and block key
        self.block_id = 1
        self.current_ik = derive_key(self.rlk, self.block_id)
        self.current_bk = derive_key(self.current_ik, self.block_id)
        self.current_blocks = []
        self.msg_id = 1
        logger.debug(f"rlk: {self.rlk}")
        logger.debug(f"(sk, pk): {self.sk, self.pk}")
        logger.debug(f"current_ik: {self.current_ik}")
        logger.debug(f"current_bk: {self.current_bk}")
        logger.debug(f"block_id: {self.block_id}")
        
    def __generate_ecdsa_key_pair(self):
        """
        Generates ECDSA key-pair for signing message blocks (SECP256R1 curve).
    
        Output:
        sig_k : Signing key
        ver_k : Verification key
        """
        sig_k = ec.generate_private_key(ec.SECP256R1(), backend)
        ver_k = sk.public_key()
        return (sig_k, ver_k)

    def __derive_key(self, k, item_id=0):
        hkdf = HKDF(algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"emlog",
                    backend=backend)
        return hkdf.derive(k+bytes(item_id))


    def __generate_block_sig(self):
        raise NotImplementedError()


    def insert(self, msg):
        """
        Inserts a new message; integrity protection is applied transparently
        using HMACs keyed under message keys derived in a chained fashion.

        Input:
        msg : Message string
        """
        logger.debug(f"msg: {msg}")

        # Derive new message key from current block key if msg_id == 0,
        # otherwise derive from previous message key
        if self.msg_id == 1:
            self.current_mk = derive_key(self.current_bk, self.msg_id)
            # Initialise list for maintaining current block message objs
            self.current_msgs = []
        else:
            self.current_mk = derive_key(self.current_mk, self.msg_id)

        # Compute HMAC on msg text keyed under current_mk
        hmac_obj = hmac.HMAC(self.current_mk, hashes.SHA256(), backend)
        hmac_obj.update(bytes(msg))
        msg_hmac = hmac_obj.finalize()

        # Create Message obj
        self.current_msgs.append(Message(msg, self.msg_id, msg_hmac))

        # Check whether the block limit is reached; if so, create new Block
        # obj and insert this block's msg list
        if self.msg_id == self.m:
            # Compute sig(h(m1.hmac, m2.hmac, ..., mn.hmac))
            # TODO IMPLEMENT SIG
            sig = self.__generate_block_sig(self.current_msgs)
            self.current_block = Block(self.current_msgs, self.block_id, sig)
            self.block_id += 1
            self.msg_id = 1

            # Check if in-memory block limit, c, is reached; if so,
            # store 
            if self.block_id == self.c:
                pass