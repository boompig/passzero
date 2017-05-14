import binascii
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

from passzero.config import TOKEN_SIZE
from passzero.crypto_utils import (byte_to_hex_legacy, decrypt_field_v1,
                                   decrypt_field_v2, decrypt_messages,
                                   decrypt_password_legacy, encrypt_field_v1,
                                   encrypt_field_v2, encrypt_messages,
                                   encrypt_password_legacy, extend_key,
                                   get_hashed_password, get_iv, get_kdf_salt,
                                   hex_to_byte_legacy, pad_key_legacy,
                                   random_hex)

from .utils import base64_encode

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, db.Sequence("users_id_seq"), primary_key=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String, nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=False)
    last_login = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def authenticate(self, form_password):
        """Return True on success, False on failure."""
        hashed_password = get_hashed_password(form_password, self.salt)
        return self.password == hashed_password

    def change_password(self, new_password):
        hashed_password = get_hashed_password(new_password, self.salt)
        self.password = hashed_password

    def __repr__(self):
        return "<User(email=%s, password=%s, salt=%s, active=%s)>" % (self.email, self.password, self.salt, str(self.active))


class AuthToken(db.Model):
    __tablename__ = "auth_tokens"
    id = db.Column(db.Integer, db.Sequence("entries_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.String, nullable=False)
    issue_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # in seconds
    MAX_AGE = 15 * 60

    def random_token(self):
        self.token = random_hex(TOKEN_SIZE)

    def is_expired(self):
        delta = datetime.utcnow() - self.issue_time
        return delta.seconds > self.MAX_AGE

    def __repr__(self):
        return "<AuthToken(user_id=%d, token=%s)>" % (self.user_id, self.token)


class EncryptedEntry(db.Model):
    __tablename__ = "enc_entries"
    id = db.Column(db.Integer, db.Sequence("entries_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    account = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    extra = db.Column(db.String, nullable=False)
    key_salt = db.Column(db.String)
    iv = db.Column(db.String)

    def to_json(self):
        return {
            "id": self.id,
            "account": self.account,
            "username": self.username,
            "password": self.password,
            "extra": self.extra,
            "key_salt": self.key_salt,
            "iv": self.iv
        }


class Entry(db.Model):
    __tablename__ = "entries"
    id = db.Column(db.Integer, db.Sequence("entries_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    account = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    padding = db.Column(db.String)
    extra = db.Column(db.String)
    key_salt = db.Column(db.String)
    iv = db.Column(db.String)
    version = db.Column(db.Integer, nullable=False)
    pinned = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return "<Entry(account=%s, username=%s, password=%s, padding=%s, user_id=%d)>" % (self.account, self.username, self.password, self.padding, self.user_id)

    def decrypt(self, key):
        """Return a dictionary mapping fields to their decrypted values."""
        assert key is not None
        if self.version == 1:
            return self._decrypt_version_1(key)
        elif self.version == 2:
            return self._decrypt_version_2(key)
        elif self.version == 3:
            return self._decrypt_version_3(key)
        elif self.version == 4:
            return self._decrypt_version_4(key)
        else:
            raise AssertionError("Unsupported version: {}".format(self.version))

    def _decrypt_version_4(self, key):
        """
        Version 4 encrypts, sequentially, the following data:
        - username
        - password
        - extra field
        Notably, 'account' field is *not* encrypted
        """
        kdf_salt = binascii.a2b_base64(self.key_salt)
        extended_key = extend_key(key, kdf_salt)
        iv = binascii.a2b_base64(self.iv)
        messages = [
            binascii.a2b_base64(self.username),
            binascii.a2b_base64(self.password),
            binascii.a2b_base64(self.extra)
        ]
        dec_messages = decrypt_messages(extended_key, iv, messages)
        return {
            "account": self.account,
            "username": dec_messages[0],
            "password": dec_messages[1],
            "extra": dec_messages[2]
        }

    def _decrypt_version_3(self, key):
        kdf_salt = binascii.a2b_base64(self.key_salt)
        extended_key = extend_key(key, kdf_salt)
        iv = binascii.a2b_base64(self.iv)
        messages = [
            binascii.a2b_base64(self.account),
            binascii.a2b_base64(self.username),
            binascii.a2b_base64(self.password),
            binascii.a2b_base64(self.extra)
        ]
        dec_messages = decrypt_messages(extended_key, iv, messages)
        return {
            "account": dec_messages[0],
            "username": dec_messages[1],
            "password": dec_messages[2],
            "extra": dec_messages[3]
        }

    def _decrypt_version_1(self, key):
        return self._decrypt_with_padding(key)

    def _decrypt_version_2(self, key):
        key_salt = hex_to_byte_legacy(self.key_salt)
        iv = hex_to_byte_legacy(self.iv)
        extended_key = extend_key(key, key_salt)
        dec_password = decrypt_field_v2(extended_key, self.password, iv)
        if self.extra:
            try:
                dec_extra = decrypt_field_v2(extended_key, self.extra, iv)
            except TypeError:
                dec_extra = self.extra
        else:
            dec_extra = ""
        try:
            dec_username = decrypt_field_v2(extended_key, self.username, iv)
        except TypeError:
            dec_username = self.username
        return {
            "account": self.account,
            "username": dec_username,
            "password": dec_password,
            "extra": dec_extra
        }

    def _decrypt_with_padding(self, key):
        dec_password = decrypt_password_legacy(key + self.padding, self.password)
        if self.extra:
            try:
                dec_extra = decrypt_field_v1(key, self.padding, self.extra)
            except TypeError:
                dec_extra = self.extra
        else:
            dec_extra = ""
        try:
            dec_username = decrypt_field_v1(key, self.padding, self.username)
        except TypeError:
            dec_username = self.username
        return {
            "account": self.account,
            "username": dec_username,
            "password": dec_password,
            "extra": dec_extra
        }

    def encrypt_v4(self, master_key, dec_entry):
        """
        :param master_key:  The user's key, used to derive entry-specific enc key
        :param dec_entry:   Entry to encrypt (dictionary of fields)
        """
        assert isinstance(master_key, str)
        assert isinstance(dec_entry, dict)
        # generate random new IV
        iv = get_iv()
        kdf_salt = get_kdf_salt()
        extended_key = extend_key(master_key, kdf_salt)
        fields = ["username", "password", "extra"]
        messages = [dec_entry[field] for field in fields]
        enc_messages = encrypt_messages(extended_key, iv, messages)
        enc_entry = {}
        for field, enc_message in zip(fields, enc_messages):
            enc_entry[field] = base64_encode(enc_message)
        # entry contents
        self.account = dec_entry["account"]
        self.username = enc_entry["username"]
        self.password = enc_entry["password"]
        self.extra = enc_entry["extra"]
        # metadata - which encryption scheme to use to decrypt
        self.version = 4
        self.pinned = False
        self.key_salt = base64_encode(kdf_salt)
        self.iv = base64_encode(iv)
        # old information
        self.padding = None


    def encrypt_v3(self, master_key, dec_entry):
        """
        :param master_key:  The user's key, used to derive entry-specific enc key
        :param dec_entry:   Entry to encrypt (dictionary of fields)
        """
        # generate random new IV
        iv = get_iv()
        kdf_salt = get_kdf_salt()
        extended_key = extend_key(master_key, kdf_salt)
        fields = ["account", "username", "password", "extra"]
        messages = [dec_entry[field] for field in fields]
        enc_messages = encrypt_messages(extended_key, iv, messages)
        enc_entry = {}
        for field, enc_message in zip(fields, enc_messages):
            enc_entry[field] = base64_encode(enc_message)
        # entry contents
        self.account = enc_entry["account"]
        self.username = enc_entry["username"]
        self.password = enc_entry["password"]
        self.extra = enc_entry["extra"]
        # metadata - which encryption scheme to use to decrypt
        self.version = 3
        self.pinned = False
        self.iv = base64_encode(iv)
        self.key_salt = base64_encode(kdf_salt)
        # old information
        self.padding = None

    def encrypt_v2(self, master_key, dec_entry):
        """
        WARNING: This is not secure! Do not use this!
        This is only here to satisfy the unit test for decryption of these old entries
        If they are still alive in the database
        """
        if "extra" not in dec_entry:
            dec_entry["extra"] = ""
        key_salt = get_kdf_salt()
        iv = get_iv()
        extended_key = extend_key(master_key, key_salt)
        self.account = dec_entry["account"]
        self.username = encrypt_field_v2(extended_key, dec_entry["username"], iv)
        self.password = encrypt_field_v2(extended_key, dec_entry["password"], iv)
        self.extra = encrypt_field_v2(extended_key, dec_entry["extra"], iv)
        self.key_salt = byte_to_hex_legacy(key_salt)
        self.iv = byte_to_hex_legacy(iv)
        self.version = 2

    def encrypt_v1(self, master_key, dec_entry):
        """
        WARNING: This is not secure! Do not use this!
        This is only here to satisfy the unit test for decryption of these old entries
        If they are still alive in the database
        """
        self.padding = pad_key_legacy(master_key)
        self.account = dec_entry["account"]
        self.username = encrypt_field_v1(master_key,
                self.padding, dec_entry["username"])
        self.password = encrypt_password_legacy(master_key + self.padding,
                dec_entry["password"])
        self.extra = encrypt_field_v1(master_key, self.padding, dec_entry["extra"])
        self.version = 1
