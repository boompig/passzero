from mock import MagicMock
import nose

from passzero.models import User 
from passzero.backend import create_inactive_user
from config import SALT_SIZE

def test_authenticate_user():
    session = MagicMock()
    user_key = "fake password"
    user = create_inactive_user(
        session, "fake email", user_key, 
        salt_size=SALT_SIZE)
    assert isinstance(user, User)
    assert user.authenticate(user_key)


if __name__ == "__main__":
    nose.run()

