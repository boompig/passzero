import nose
import sys

# authentication
from crypto_utils import get_salt, get_hashed_password
# entry
from crypto_utils import pad_key, encrypt_field, decrypt_field
SALT_SIZE = 64


class DecryptedEntry(object):
    def __init__(self, account, username, password, extra=None):
        self.account = account
        self.username = username
        self.password = password
        self.extra = extra

    def encrypt(self, raw_key):
        salt = pad_key(raw_key)
        return EncryptedEntry(
            account=self.account,
            username=encrypt_field(raw_key, salt, self.username),
            password=encrypt_field(raw_key, salt, self.password),
            extra=encrypt_field(raw_key, salt, self.extra),
            padding=salt
        )


class EncryptedEntry(object):
    def __init__(self, account, username, password, extra, padding):
        self.account = account
        self.username = username
        self.password = password
        self.extra = extra
        self.padding = padding

    def decrypt(self, raw_key):
        return DecryptedEntry(
            account=self.account,
            username=decrypt_field(raw_key, self.padding, self.username),
            password=decrypt_field(raw_key, self.padding, self.password),
            extra=decrypt_field(raw_key, self.padding, self.extra)
        )


def assert_dec_entries_same(entry_1, entry_2):
    assert entry_1.account == entry_2.account
    assert entry_1.username == entry_2.username
    assert entry_1.password == entry_2.password
    assert entry_1.extra == entry_2.extra


def assert_not_dec_entries_same(entry_1, entry_2):
    assert (entry_1.account != entry_2.account or
    entry_1.username != entry_2.username or
    entry_1.password != entry_2.password or
    entry_1.extra != entry_2.extra)


def test_hash_password():
    password = "Hello world!"
    salt = get_salt(SALT_SIZE)
    hashed_password = get_hashed_password(password, salt)
    assert get_hashed_password(password, salt) == hashed_password


def test_encrypt_decrypt_entry():
    password = "Hello world!"
    entry = DecryptedEntry(
        account="Some Account",
        username="Some Username",
        password="Some Password",
        extra="there is extra data here"
    )
    enc_entry = entry.encrypt(password)
    dec_entry = enc_entry.decrypt(password)
    assert_dec_entries_same(entry, dec_entry)


def test_change_entry_password():
    """One problem might be that the password changes, so padding become different length"""
    password = "Hello world!"
    password_1 = "1234567"
    password_2 = "123456789012345678901234567890"
    entry = DecryptedEntry(
        account="Some Account",
        username="Some Username",
        password=password_1,
        extra="there is extra data here"
    )
    enc_entry = entry.encrypt(password)
    dec_entry = enc_entry.decrypt(password)
    dec_entry.password = password_2
    enc_entry_2 = dec_entry.encrypt(password)
    dec_entry_2 = enc_entry_2.decrypt(password)
    assert_not_dec_entries_same(entry, dec_entry_2)
    assert_dec_entries_same(dec_entry, dec_entry_2)

if __name__ == "__main__":
    print >>sys.stderr, "Error: run this script with nosetests!"
    sys.exit(1)
