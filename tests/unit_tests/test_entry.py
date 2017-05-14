from passzero.models import Entry

def test_encrypt_and_decrypt_entry_v4():
    dec_entry_in = {
        "account": "test account",
        "username": "test username",
        "password": "test password",
        "extra": "test extra"
    }
    user_key = "test master key"
    entry = Entry()
    entry.encrypt_v4(user_key, dec_entry_in)
    assert entry.version == 4
    dec_entry_out = entry.decrypt(user_key)
    for field in dec_entry_in:
        assert dec_entry_out[field] == dec_entry_in[field]


def test_encrypt_and_decrypt_entry_v3():
    dec_entry_in = {
        "account": "test account",
        "username": "test username",
        "password": "test password",
        "extra": "test extra"
    }
    user_key = "test master key"
    entry = Entry()
    entry.encrypt_v3(user_key, dec_entry_in)
    assert entry.version == 3
    dec_entry_out = entry.decrypt(user_key)
    for field in dec_entry_in:
        assert dec_entry_out[field] == dec_entry_in[field]


def test_encrypt_and_decrypt_entry_v1():
    dec_entry_in = {
        "account": "test account",
        "username": "test username",
        "password": "test password",
        "extra": "test extra"
    }
    user_key = "test master key"
    entry = Entry()
    entry.encrypt_v1(user_key, dec_entry_in)
    assert entry.version == 1
    dec_entry_out = entry.decrypt(user_key)
    for field in dec_entry_in:
        print(field)
        assert dec_entry_out[field] == dec_entry_in[field]

