from datetime import datetime

import six

from passzero.crypto_utils import (PasswordHashAlgo,
                                   constant_time_compare_passwords,
                                   get_hashed_password)

from .shared import db


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, db.Sequence("users_id_seq"), primary_key=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String, nullable=False)
    password_hash_algo = db.Column(db.Enum(PasswordHashAlgo), nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=False)
    last_login = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    DEFAULT_PASSWORD_HASH_ALGO = PasswordHashAlgo.Argon2

    # password generation preferences
    # number of characters in password
    default_random_password_length = db.Column(db.Integer, nullable=False, default=12)
    # number of words in passphrase
    default_random_passphrase_length = db.Column(db.Integer, nullable=False, default=4)

    def authenticate(self, form_password: str) -> bool:
        """
        :param form_password:   user-submitted password
        :type form_password:    unicode
        :return:                True on success, False on failure.
        :rtype:                 bool"""
        assert isinstance(form_password, six.text_type)
        # salt stored as unicode but should really be bytes
        assert isinstance(self.salt, six.text_type)
        assert isinstance(self.password, six.text_type)
        return constant_time_compare_passwords(
            password_hash=self.password,
            password=form_password,
            salt=self.salt.encode("utf-8"),
            hash_algo=self.password_hash_algo
        )

    def change_password(self, new_password: str) -> None:
        """Note: this method ONLY changes the password, and does not decrypt/encrypt the entries
        This method should *only* be used when recovering a password"""
        assert isinstance(new_password, six.text_type)
        # salt stored as unicode but should really be bytes
        assert isinstance(self.salt, six.text_type)
        # also update the password hashing algo
        hashed_password = get_hashed_password(
            password=new_password,
            salt=self.salt.encode("utf-8"),
            hash_algo=User.DEFAULT_PASSWORD_HASH_ALGO
        )
        # this field is unicode
        self.password = hashed_password.decode("utf-8")
        self.password_hash_algo = User.DEFAULT_PASSWORD_HASH_ALGO
        assert isinstance(self.password, six.text_type)

    def __repr__(self) -> str:
        return "<User(email={}, password={}, salt={}, active={}, password_hash_algo={})>".format(
            self.email, self.password, self.salt, str(self.active), str(self.password_hash_algo))
