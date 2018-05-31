import six

from passzero.models import Entry_v5


def test_encrypt_and_decrypt_entry_v5():
    dec_entry_in = {
        u"account": u"test account",
        u"username": u"test username",
        u"password": u"test password",
        u"extra": u"test extra",
        u"has_2fa": True
    }
    user_key = u"test master key"
    entry = Entry_v5()
    entry.encrypt(user_key, dec_entry_in)
    assert entry.version == 5
    dec_entry_out = entry.decrypt(user_key)
    for field in dec_entry_in:
        assert dec_entry_out[field] == dec_entry_in[field]


