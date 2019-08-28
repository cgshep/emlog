from emlog.emlog import Emlog
import logging

rlk_secret = b"test-secret"
emlog = Emlog(rlk_secret)
logger = logging.getLogger()

# Use sample Apache access logs available freely from:
# http://www.monitorware.com/en/logsamples/apache.php
fpath = "data/test_data.log"
verifier_fpath = "emlog_2019-08-21_22:33:52.640899.log"
with open(fpath) as f:
    data = f.readlines()

logger.debug(f"# log lines in {fpath}: {len(data)}")
        
def test_block_id():
    logger.debug(f"========== emlog.insert() ==========")
    # Test 50 messages
    for d in data[:50]:
        emlog.insert(d)

def test_verifier():
    verifier = Verifier(verifier_fpath)
    

def test_message_hash():
    pass


def test_block_key_derive():
    pass


def test_ik_derive():
    pass