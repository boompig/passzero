from passzero.backend import encrypt_entry, create_inactive_user, get_account_with_email
from passzero.models import User, Entry
from nose.tools import assert_equal
from mock import MagicMock


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


def test_get_account_with_email():
    session = MagicMock()
    email = "fake_email"
    password = "fake password"
    created_user = create_inactive_user(session, email, password)
    assert isinstance(created_user, User)
    assert_equal(created_user.email, email)
    # TODO this is not a test, just makes sure that nothing crashes
    user = get_account_with_email(session, email)
    assert True


if __name__ == "__main__":
    nose.main()
