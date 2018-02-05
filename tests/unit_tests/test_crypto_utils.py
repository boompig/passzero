from passzero.crypto_utils import (decrypt_field_v2, encrypt_field_v2, extend_key,
                          get_iv, get_kdf_salt)

def test_encrypt_decrypt_v2():
    user_key = u"hello"
    username = u"my username"
    kdf_salt = get_kdf_salt()
    extended_key = extend_key(user_key, kdf_salt)
    iv = get_iv()
    # 
    username_enc = encrypt_field_v2(extended_key,
         username, iv)
    username_dec_out = decrypt_field_v2(extended_key, username_enc, iv)
    assert username_dec_out == username
