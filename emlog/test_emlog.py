from emlog import Emlog

import logging

rlk_secret = b"test-secret"
emlog = Emlog(rlk_secret)
logger = logging.getLogger()

# These tests use sample Apache access logs from:
# http://www.monitorware.com/en/logsamples/apache.php
fpath = "test_data.log"
with open(fpath) as f:
    data = f.readlines()

logger.debug(f"# log lines in {fpath}: {len(data)}")
    

        
def test_block_id():
    pass


def test_message_hash():
    pass


def test_block_key_derive():
    pass


def test_ik_derive():
    pass