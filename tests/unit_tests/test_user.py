import nose
from mock import MagicMock

from passzero.backend import create_inactive_user
from passzero.crypto_utils import PasswordHashAlgo
from passzero.models import User


def test_authenticate_user():
    session = MagicMock()
    user_key = u"fake password"
    user = create_inactive_user(
        session, u"fake email", user_key)
    assert isinstance(user, User)
    assert user.authenticate(user_key)
    assert not user.authenticate(u"")
    assert not user.authenticate(u"fake password!")


def test_authenticate_user_argon2():
    session = MagicMock()
    user_key = u"fake password"
    user = create_inactive_user(
        session, u"fake email", user_key,
        password_hash_algo=PasswordHashAlgo.Argon2
    )
    assert isinstance(user, User)
    assert user.authenticate(user_key)
    assert not user.authenticate(u"")
    assert not user.authenticate(u"fake password!")


if __name__ == "__main__":
    nose.run()

