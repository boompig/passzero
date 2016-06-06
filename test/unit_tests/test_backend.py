from backend import encrypt_entry
from models import Entry
from nose.tools import assert_equal


def test_encrypt_and_decrypt_entry():
    dec_entry = {
        "account": "test account",
        "username": "test username",
        "password": "test password",
        "extra": "test extra"
    }
    user_key = "test master key"
    entry = encrypt_entry(dec_entry, user_key)
    assert isinstance(entry, Entry)
    dec_entry_again = entry.decrypt(user_key)
    fields = ["account", "username", "password", "extra"]
    for field in fields:
        assert_equal(dec_entry_again[field], dec_entry[field])


if __name__ == "__main__":
    nose.main()
