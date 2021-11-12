from passzero.models import Link


def test_encrypt_and_decrypt_link_v1():
    dec_link_in = {
        u"service_name": u"test service",
        u"link": u"https://example.com/test#foo",
    }
    user_key = u"test master key"
    link = Link()
    symmetric_key = link.encrypt(user_key, dec_link_in)
    assert link.version == 1
    # test .decrypt
    dec_link_out_1 = link.decrypt(user_key).to_json()
    for field in dec_link_in:
        assert dec_link_out_1[field] == dec_link_in[field]
    # test .decrypt_with_link_key
    dec_link_out_2 = link.decrypt_symmetric(symmetric_key).to_json()
    for field in dec_link_in:
        assert dec_link_out_2[field] == dec_link_in[field]
