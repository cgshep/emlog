import os
import logging
import pickle

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class Verifier:
    def __init__(self, fpath):
        pass

    def __str__(self):
        pass

    def _load_data(self, fpath):
        pass