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
    entry_key = entry.encrypt(user_key, dec_entry_in)
    assert entry.version == 5
    # test .decrypt
    dec_entry_out_1 = entry.decrypt(user_key)
    for field in dec_entry_in:
        assert dec_entry_out_1[field] == dec_entry_in[field]
    # make sure that the resultant entry has a last_modified field
    assert "last_modified" in dec_entry_out_1
    # test .decrypt_with_entry_key
    dec_entry_out_2 = entry.decrypt_with_entry_key(entry_key)
    for field in dec_entry_in:
        assert dec_entry_out_2[field] == dec_entry_in[field]


def test_encrypt_and_decrypt_entry_v5_utf_password():
    """Make sure we can use some non-ASCII characters in the password"""
    dec_entry_in = {
        u"account": u"test account",
        u"username": u"test username",
        u"password": u"test password",
        u"extra": u"test extra",
        u"has_2fa": True
    }
    user_key = u"你好Sträfchen"
    entry = Entry_v5()
    entry_key = entry.encrypt(user_key, dec_entry_in)
    assert entry.version == 5
    # test .decrypt
    dec_entry_out_1 = entry.decrypt(user_key)
    for field in dec_entry_in:
        assert dec_entry_out_1[field] == dec_entry_in[field]
    # make sure that the resultant entry has a last_modified field
    assert "last_modified" in dec_entry_out_1
    # test .decrypt_with_entry_key
    dec_entry_out_2 = entry.decrypt_with_entry_key(entry_key)
    for field in dec_entry_in:
        assert dec_entry_out_2[field] == dec_entry_in[field]
