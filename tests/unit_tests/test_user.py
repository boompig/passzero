from mock import MagicMock
from passzero.backend import create_inactive_user
from passzero.models import User 
import nose


def test_authenticate_user():
    session = MagicMock()
    user_key = u"fake password"
    user = create_inactive_user(
        session, u"fake email", user_key)
    assert isinstance(user, User)
    assert user.authenticate(user_key)


if __name__ == "__main__":
    nose.run()

