import binascii
import hmac
from datetime import datetime

from werkzeug.datastructures import FileStorage

from aead import AEAD
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

    # password generation preferences
    # number of characters in password
    default_random_password_length = db.Column(db.Integer, nullable=False, default=12)
    # number of words in passphrase
    default_random_passphrase_length = db.Column(db.Integer, nullable=False, default=4)

    def authenticate(self, form_password):
        """
        :param form_password:   user-submitted password
        :type form_password:    unicode
        :return:                True on success, False on failure.
        :rtype:                 bool"""
        hashed_password = get_hashed_password(form_password, self.salt)
        # prevent timing attacks by using constant-time comparison
        # can't use compare_digest directly because args can't be unicode strings
        d1 = hmac.new(self.password).digest()
        d2 = hmac.new(hashed_password).digest()
        return hmac.compare_digest(d1, d2)

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
        """
        :return:                True iff expired
        :rtype:                 bool
        """
        delta = datetime.utcnow() - self.issue_time
        return delta.seconds > self.MAX_AGE

    def __repr__(self):
        return "<AuthToken(user_id=%d, token=%s)>" % (self.user_id, self.token)


class Entry(db.Model):
    __tablename__ = "entries"
    id = db.Column(db.Integer, db.Sequence("entries_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    account = db.Column(db.String, nullable=False)

    # these fields are *always* encrypted
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    padding = db.Column(db.String)
    extra = db.Column(db.String)
    
    # this field is *never* encrypted
    has_2fa = db.Column(db.Boolean, default=False, nullable=False)

    key_salt = db.Column(db.String)
    iv = db.Column(db.String)
    version = db.Column(db.Integer, nullable=False)
    pinned = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return "<Entry(account=%s, username=%s, password=%s, padding=%s, user_id=%d)>" % (self.account, self.username, self.password, self.padding, self.user_id)

    def to_json(self):
        """
        :return:            All fields of the entry, some possibly still encrypted
        :rtype:             dict
        """
        assert self.version >= 4, "to_json is not well-defined for entries older than version 4"
        return {
            "id": self.id,
            "account": self.account,
            "username": self.username,
            "password": self.password,
            "extra": self.extra,
            "has_2fa": self.has_2fa,
            "version": self.version,
            "is_encrypted": True
        }

    def decrypt(self, key):
        """
        :return:            a dictionary mapping fields to their decrypted values.
        :rtype:             dict"""
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
            "extra": dec_messages[2],
            # add unencrypted metadata
            "has_2fa": self.has_2fa,
            "version": self.version
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
            "extra": dec_messages[3],
            "version": self.version
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
            Expected fields:
            - account
            - username
            - password
            - extra
            - has_2fa (bool)
        """
        assert isinstance(master_key, str) or isinstance(master_key, unicode)
        assert isinstance(dec_entry, dict)
        assert "has_2fa" in dec_entry, "Entry %s must have field 'has_2fa'" % str(dec_entry)
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
        # entry metadata
        self.has_2fa = dec_entry["has_2fa"]
        # encryption metadata - which encryption scheme to use to decrypt
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


class Service(db.Model):
    __tablename__ = "services"
    name = db.Column(db.String, primary_key=True, nullable=False)
    link = db.Column(db.String)
    has_two_factor = db.Column(db.Boolean)


class EncryptedDocument(db.Model):
    __tablename__ = "documents"
    id = db.Column(db.Integer, db.Sequence("documents_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String, nullable=False)
    # encrypted and base64-encoded
    document = db.Column(db.LargeBinary, nullable=False)
    # NOTE: this is not encrypted
    content_type = db.Column(db.String, nullable=False)
    # base64-encoded
    key_salt = db.Column(db.String, nullable=False)

    KEY_LENGTH = 32

    def extend_key(self, master_key):
        """Helper method.
        Call extend_key with the right parameters"""
        return extend_key(master_key, binascii.a2b_base64(self.key_salt),
            EncryptedDocument.KEY_LENGTH)

    def to_json(self):
        return {
            "id": self.id,
            "name": self.name,
            "contents": self.document
        }

    def decrypt(self, master_key):
        extended_key = self.extend_key(master_key)
        cryptor = AEAD(base64_encode(extended_key))
        assert type(self.name) == unicode
        assert type(self.document) == str
        pt = cryptor.decrypt(self.document, self.name.encode('utf-8'))
        return DecryptedDocument(
            name=self.name,
            contents=pt,
            id=self.id,
            content_type=self.content_type
        )

    def get_size(self):
        """
        A hacky method for estimating the size of user-supplied parameters in the file
        """
        return len(self.name) + len(self.document) + len(self.content_type)


class DecryptedDocument:
    def __init__(self, name, contents, id=None, content_type=None):
        """
        :param name: String, the user's name for the file. Not a filename.
        :param document: object for the file
        :param id: id if document already exists, None otherwise
        """
        assert id is None or isinstance(id, int)
        assert isinstance(name, unicode) or isinstance(name, str)
        assert isinstance(contents, FileStorage) or isinstance(contents, str)
        assert isinstance(content_type, unicode) or isinstance(content_type, str)
        self.id = id
        if isinstance(name, unicode):
            self.name = name.encode('utf-8')
        else:
            # str
            self.name = name
        if isinstance(contents, str):
            self.contents = contents
        else:
            # FileStorage
            self.contents = contents.read()
        if isinstance(content_type, unicode):
            self.content_type = content_type.encode('utf-8')
        else:
            # str
            self.content_type = content_type

    @staticmethod
    def extend_key(master_key):
        """
        Helper method.

        :return extended_key, params

        params:
            kdf_salt -> bytes
        """
        key_salt = get_kdf_salt()
        # need a 32-byte key (256 bits)
        extended_key = extend_key(master_key, key_salt, 32)
        return (extended_key, { "kdf_salt": key_salt } )

    def encrypt(self, key):
        """
        Create a *new* encrypted document from this document
        :param key: bytes
        :return: encrypted document with the content fields set
        """
        #AES_128_CBC_HMAC_SHA_256
        assert len(key) == 32, \
            "key must be 32 bytes long, actually %d bytes" % len(key)
        assert isinstance(self.name, str), "Name must be a byte string"
        assert isinstance(self.contents, str), "Contents must be bytes"
        cryptor = AEAD(base64_encode(key))
        ct = cryptor.encrypt(self.contents, self.name)
        assert isinstance(ct, str), "base-64 ciphertext"
        return EncryptedDocument(
            # contents
            name=self.name,
            document=ct,
            content_type=self.content_type
        )

    def to_json(self):
        return {
            "name": self.name,
            "contents": base64_encode(self.contents),
            "content_type": self.content_type
        }

    def get_size(self):
        """
        A hacky method for estimating the size of user-supplied parameters in the file
        """
        return len(self.name) + len(self.contents) + len(self.content_type)
