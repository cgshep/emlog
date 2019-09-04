from emlog import emlog, verifier

import logging

logger = logging.getLogger()

data_dir = "data"

# Define key data
rlk_secret = b"test-secret"
storage_key = b"3\xfe\x0f/\xe6e\xf07b/?\x0f\xb6\xec\xdb\x1b\x12&\xb2.e\x94\xad\x02"

#
# Emlog setup
#
emlog = emlog.Emlog(rlk_secret=rlk_secret,
                    storage_key=storage_key,
                    sig_key="private_key.pem",
                    ver_key="public_key.pem",
                    write_to_file=False)

# Use sample Apache access logs, available freely from:
# http://www.monitorware.com/en/logsamples/apache.php
fpath = f"{data_dir}/test_logs.log"
with open(fpath) as f:
    data = f.readlines()
logger.debug(f"# log lines in {fpath}: {len(data)}")

#
# Verifier setup
#
verifier_fpath = f"{data_dir}/test_data.log"
with open(verifier_fpath, 'rb') as f1:
    v_data = f1.read()
v = verifier.Verifier(rlk_secret=rlk_secret,
                      storage_key=storage_key,
                      ver_key="public_key.pem")

def test_block_id():
    logger.debug(f"========== emlog.insert() ==========")
    # test 50 messages
    for d in data[:50]:
        emlog.insert(d)

def test_verifier():
    v.verify(v_data)

def test_message_hash():
    pass


def test_block_key_derive():
    pass


def test_ik_derive():
    pass