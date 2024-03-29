"""
Test entries at the model level
"""

import six

from passzero.models import Entry, Entry_v4, Entry_v3, Entry_v2


def test_encrypt_and_decrypt_entry_v4():
    dec_entry_in = {
        u"account": u"test account",
        u"username": u"test username",
        u"password": u"test password",
        u"extra": u"test extra",
        u"has_2fa": True
    }
    user_key = u"test master key"
    entry = Entry_v4()
    entry_key = entry.encrypt(user_key, dec_entry_in)
    assert entry.version == 4
    # test .decrypt
    dec_entry_out_1 = entry.decrypt(user_key)
    for field in dec_entry_in:
        assert dec_entry_out_1[field] == dec_entry_in[field]
    assert dec_entry_out_1["version"] == 4
    # test .decrypt_with_entry_key
    dec_entry_out_2 = entry.decrypt_with_entry_key(entry_key)
    for field in dec_entry_in:
        assert dec_entry_out_2[field] == dec_entry_in[field]


def test_encrypt_and_decrypt_entry_v3():
    dec_entry_in = {
        u"account": u"test account",
        u"username": u"test username",
        u"password": u"test password",
        u"extra": u"test extra",
        u"has_2fa": True
    }
    user_key = u"test master key"
    entry = Entry_v3()
    entry_key = entry.encrypt(user_key, dec_entry_in)
    assert entry.version == 3
    # test .decrypt
    dec_entry_out_1 = entry.decrypt(user_key)
    for field in dec_entry_in:
        assert dec_entry_out_1[field] == dec_entry_in[field]
    assert dec_entry_out_1["version"] == 3
    # test .decrypt_with_entry_key
    dec_entry_out_2 = entry.decrypt_with_entry_key(entry_key)
    for field in dec_entry_in:
        assert dec_entry_out_2[field] == dec_entry_in[field]


def test_encrypt_and_decrypt_entry_v2():
    dec_entry_in = {
        u"account": u"test account",
        u"username": u"test username",
        u"password": u"test password",
        u"extra": u"test extra",
        u"has_2fa": True
    }
    user_key = u"test master key"
    entry = Entry_v2()
    entry_key = entry.encrypt(user_key, dec_entry_in)
    # make sure the iv is also preserved
    assert entry.version == 2
    # test .decrypt
    dec_entry_out_1 = entry.decrypt(user_key)
    for field in [u"account", u"username", u"password", u"extra", u"has_2fa"]:
        assert dec_entry_out_1[field] == dec_entry_in[field]
    assert dec_entry_out_1["version"] == 2
    # test .decrypt_with_entry_key
    dec_entry_out_2 = entry.decrypt_with_entry_key(entry_key)
    for field in dec_entry_in:
        assert dec_entry_out_2[field] == dec_entry_in[field]


def test_encrypt_and_decrypt_entry_v1():
    dec_entry_in = {
        u"account": u"test account",
        u"username": u"test username",
        u"password": u"test password",
        u"extra": u"test extra",
        u"has_2fa": True
    }
    user_key = u"test master key"
    assert isinstance(user_key, six.text_type)
    entry = Entry()
    entry.encrypt(user_key, dec_entry_in)
    assert entry.version == 1
    dec_entry_out = entry.decrypt(user_key)
    for field in [u"account", u"username", u"password", u"extra", u"has_2fa"]:
        assert dec_entry_out[field] == dec_entry_in[field]
    assert dec_entry_out["version"] == 1
