"""
Test the encryption keys database at the model level
"""

import time
from passzero.models import EncryptionKeys, EncryptionKeysDB_V1
from passzero.models.encryption_keys import EncryptionKeyEntry_V1


MASTER_PASSWORD = "master password 123"


def test_encryption_key_db_empty():
    """Encrypt and decrypt an empty (new) database"""
    keys_db_in = EncryptionKeysDB_V1(
        entry_keys={},
        link_keys={},
        version=1,
        # just made up
        user_id=1,
        id=None
    )

    enc_keys_db = EncryptionKeys()
    enc_keys_db.encrypt(MASTER_PASSWORD, keys_db_in)

    # try to decrypt it using the user's password
    keys_db_out = enc_keys_db.decrypt(MASTER_PASSWORD)
    assert keys_db_out["entry_keys"] == {}
    assert keys_db_out["link_keys"] == {}


def test_encryption_key_db_nonempty():
    """Encrypt and decrypt an empty (new) database"""
    entry_keys_in = {
        "10": EncryptionKeyEntry_V1({
            "key": b"hello world",
            "last_modified": 3,
        }),
        "205": EncryptionKeyEntry_V1({
            "key": b"foo",
            "last_modified": int(time.time()),
        }),
    }
    keys_db_in = EncryptionKeysDB_V1(
        entry_keys=entry_keys_in,
        link_keys={},
        version=1,
        # just made up
        user_id=1,
        id=None
    )

    enc_keys_db = EncryptionKeys()
    enc_keys_db.encrypt(MASTER_PASSWORD, keys_db_in)

    # try to decrypt it using the user's password
    keys_db_out = enc_keys_db.decrypt(MASTER_PASSWORD)
    assert keys_db_out["entry_keys"] == entry_keys_in
    assert keys_db_out["link_keys"] == {}
