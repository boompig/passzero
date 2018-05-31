import binascii
from datetime import datetime
from typing import Tuple

import six
from aead import AEAD
from flask_sqlalchemy import SQLAlchemy
import msgpack
import nacl.pwhash
import nacl.secret
import nacl.utils

from passzero.config import TOKEN_SIZE
from passzero.crypto_utils import (PasswordHashAlgo, byte_to_hex_legacy,
                                   constant_time_compare_passwords,
                                   decrypt_field_v1, decrypt_field_v2,
                                   decrypt_messages, decrypt_password_legacy,
                                   encrypt_field_v1, encrypt_field_v2,
                                   encrypt_messages, encrypt_password_legacy,
                                   extend_key, get_hashed_password, get_iv,
                                   get_kdf_salt, hex_to_byte_legacy,
                                   pad_key_legacy, random_hex)

from .utils import base64_encode

db = SQLAlchemy()


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


class AuthToken(db.Model):
    __tablename__ = "auth_tokens"
    id = db.Column(db.Integer, db.Sequence("entries_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.String, nullable=False)
    issue_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # in seconds
    MAX_AGE = 15 * 60

    def random_token(self) -> None:
        self.token = random_hex(TOKEN_SIZE)

    def is_expired(self) -> bool:
        """
        :return:                True iff expired
        :rtype:                 bool
        """
        delta = datetime.utcnow() - self.issue_time
        return delta.seconds > self.MAX_AGE

    def __repr__(self):
        return "<AuthToken(user_id=%d, token=%s)>" % (self.user_id, self.token)


class Entry(db.Model):
    """This entry serves as both the v1 entry and the base class to other entries"""
    __tablename__ = "entries"
    id = db.Column(db.Integer, db.Sequence("entries_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    account = db.Column(db.String, nullable=False)

    # these fields are *always* encrypted
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    extra = db.Column(db.String)

    # this field is *never* encrypted
    has_2fa = db.Column(db.Boolean, default=False, nullable=False)

    # this field is used in Entry v1 encryption/decryption
    padding = db.Column(db.String)
    key_salt = db.Column(db.String)
    iv = db.Column(db.String)
    version = db.Column(db.Integer, nullable=False)
    pinned = db.Column(db.Boolean, default=False, nullable=False)

    __mapper_args__ = {
        "polymorphic_identity": 1,
        "polymorphic_on": version
    }

    def __repr__(self) -> str:
        return "<Entry(account={}, username={}, password={}, padding={}, user_id={})>".format(
            self.account, self.username, self.password, self.padding, self.user_id)

    def to_json(self) -> dict:
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

    def decrypt(self, key: str) -> dict:
        """Decrypt with padding
        :type key:              unicode string
        """
        assert isinstance(key, six.text_type)
        assert isinstance(self.username, six.text_type)
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

    def encrypt(self, master_key: str, dec_entry: dict):
        """
        WARNING: This is not secure! Do not use this!
        This is only here to satisfy the unit test for decryption of these old entries
        """
        assert isinstance(master_key, six.text_type)
        assert isinstance(dec_entry, dict)
        self.padding = pad_key_legacy(master_key)
        assert isinstance(self.padding, six.text_type)
        self.account = dec_entry[u"account"]
        assert isinstance(self.account, six.text_type)
        self.username = encrypt_field_v1(master_key, self.padding,
                                         dec_entry[u"username"])
        assert isinstance(self.username, six.text_type)
        self.password = encrypt_password_legacy(master_key + self.padding,
                                                dec_entry[u"password"])
        assert isinstance(self.password, six.text_type)
        self.extra = encrypt_field_v1(master_key, self.padding,
                                      dec_entry[u"extra"])
        assert isinstance(self.extra, six.text_type)
        self.version = 1


class Entry_v2(Entry):

    __mapper_args__ = {
        "polymorphic_identity": 2
    }

    def decrypt(self, key: str) -> dict:
        assert isinstance(key, six.text_type)
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

    def encrypt(self, master_key: str, dec_entry: dict):
        """
        WARNING: This is not secure! Do not use this!
        This is only here to satisfy the unit test for decryption of these old entries
        If they are still alive in the database
        """
        assert isinstance(master_key, six.text_type)
        assert isinstance(dec_entry, dict)
        if "extra" not in dec_entry:
            dec_entry["extra"] = u""
        key_salt = get_kdf_salt()
        iv = get_iv()
        extended_key = extend_key(master_key, key_salt)
        self.account = dec_entry["account"]
        # these should all be unicode
        self.username = encrypt_field_v2(extended_key, dec_entry["username"], iv)
        self.password = encrypt_field_v2(extended_key, dec_entry["password"], iv)
        self.extra = encrypt_field_v2(extended_key, dec_entry["extra"], iv)
        assert isinstance(self.account, six.text_type)
        assert isinstance(self.username, six.text_type)
        assert isinstance(self.password, six.text_type)
        assert isinstance(self.extra, six.text_type)
        self.key_salt = byte_to_hex_legacy(key_salt)
        self.iv = byte_to_hex_legacy(iv)
        self.version = 2


class Entry_v3(Entry):

    __mapper_args__ = {
        "polymorphic_identity": 3
    }

    def encrypt(self, master_key: str, dec_entry: dict):
        """
        :param master_key:  The user's key, used to derive entry-specific enc key
        :param dec_entry:   Entry to encrypt (dictionary of fields)
        """
        assert isinstance(master_key, six.text_type)
        assert isinstance(dec_entry, dict)
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

    def decrypt(self, key: str) -> dict:
        assert isinstance(key, six.text_type)
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


class Entry_v4(Entry):
    """This entry type encrypts the following fields:
    - username
    - password
    - extra

    And leaves the following fields unencrypted:
    - account
    - has_2fa

    This design choice is driven by the need to search and audit entries
    without decrypting everything

    The fields are encrypted using the `encrypt_messages` method in crypto_utils
    It is roughly equivalent to applying AES - MODE CFB.
    The issue with this approach is that there is no authentication associated with the message contents:
    i.e. there is no guarantee that the data has not been tampered with while in storage

    When using this version, you have to be careful with the `iv`: do not reuse this

    Entry-specific keys are generated using PBKDF2. Be careful with `kdf_salt`: do not reuse this
    """

    __mapper_args__ = {
        "polymorphic_identity": 4
    }

    def decrypt(self, key: str) -> dict:
        """
        Version 4 encrypts, sequentially, the following data:
        - username
        - password
        - extra field
        Notably, 'account' field is *not* encrypted
        """
        assert isinstance(key, six.text_type)
        kdf_salt = binascii.a2b_base64(self.key_salt)
        assert isinstance(kdf_salt, bytes)
        extended_key = extend_key(key, kdf_salt)
        assert isinstance(extended_key, bytes)
        iv = binascii.a2b_base64(self.iv)
        assert isinstance(iv, bytes)
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

    def encrypt(self, master_key: str, dec_entry: dict):
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
        assert isinstance(master_key, six.text_type)
        assert isinstance(dec_entry, dict)
        assert "has_2fa" in dec_entry, "Entry %s must have field 'has_2fa'" % str(dec_entry)
        # generate random new IV
        iv = get_iv()
        assert isinstance(iv, bytes)
        kdf_salt = get_kdf_salt()
        assert isinstance(kdf_salt, bytes)
        extended_key = extend_key(master_key, kdf_salt)
        assert isinstance(extended_key, bytes)
        fields = ["username", "password", "extra"]
        messages = [dec_entry[field] for field in fields]
        enc_messages = encrypt_messages(extended_key, iv, messages)
        enc_entry = {}
        for field, enc_message in zip(fields, enc_messages):
            enc_entry[field] = base64_encode(enc_message).decode("utf-8")
            assert isinstance(enc_entry[field], six.text_type)
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
        self.key_salt = base64_encode(kdf_salt).decode("utf-8")
        assert isinstance(self.key_salt, six.text_type)
        self.iv = base64_encode(iv).decode("utf-8")
        assert isinstance(self.iv, six.text_type)
        # old information
        self.padding = None


class Entry_v5(Entry):
    """This entry type encrypts the following fields:
    - username
    - password
    - extra

    And leaves the following fields unencrypted:
    - account
    - has_2fa

    For the same reason as in v4.

    HOWEVER: the encrypted fields are stored in one monolithic binary blob in the `contents` field
    The fields relevant fields are left as empty strings

    The fields are encrypted using the `encrypt_messages` method in crypto_utils
    It is roughly equivalent to applying AES - MODE CFB.
    The issue with this approach is that there is no authentication associated with the message contents:
    i.e. there is no guarantee that the data has not been tampered with while in storage

    When using this version, you have to be careful with the (iv, nonce, salt): do not reuse these

    Entry-specific keys are generated using PBKDF2.
    """

    # self.key_salt should be of type unicode

    __mapper_args__ = {
        "polymorphic_identity": 5
    }

    # a new contents object
    contents = db.Column(db.LargeBinary)

    def __get_entry_key(self, master_key: str, kdf_salt: bytes) -> bytes:
        return nacl.pwhash.argon2id.kdf(
            size=nacl.secret.SecretBox.KEY_SIZE,
            # TODO: this may not always be possible if a unicode password is used
            password=master_key.encode("utf-8"),
            salt=kdf_salt,
        )

    def decrypt(self, key: str) -> dict:
        """
        Raises `nacl.exceptions.CryptoError` on failure to authenticate cyphertext
        """
        assert isinstance(key, six.text_type)
        assert isinstance(self.key_salt, six.text_type)
        kdf_salt = binascii.a2b_base64(self.key_salt.encode("utf-8"))
        entry_key = self.__get_entry_key(key, kdf_salt)
        box = nacl.secret.SecretBox(entry_key)
        assert isinstance(self.contents, bytes)
        dec_contents = box.decrypt(self.contents)
        dec_contents_d = msgpack.unpackb(dec_contents, raw=False)
        # fill in the unencrypted data
        dec_contents_d["account"] = self.account
        dec_contents_d["has_2fa"] = self.has_2fa
        dec_contents_d["version"] = self.version
        return dec_contents_d

    def encrypt(self, master_key: str, dec_entry: dict) -> None:
        assert isinstance(master_key, six.text_type)
        assert isinstance(dec_entry, dict)
        dec_contents_d = {
            "username": dec_entry["username"],
            "password": dec_entry["password"],
            "extra": dec_entry["extra"]
        }
        dec_contents = msgpack.packb(dec_contents_d, use_bin_type=True)
        kdf_salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
        # generate a new entry key
        entry_key = self.__get_entry_key(master_key, kdf_salt)
        # what's nice is that pynacl generates a random nonce
        box = nacl.secret.SecretBox(entry_key)
        self.contents = box.encrypt(dec_contents)
        # metadata
        self.version = 5
        self.pinned = False
        self.key_salt = base64_encode(kdf_salt).decode("utf-8")
        assert isinstance(self.key_salt, six.text_type)
        # unencrypted data
        self.account = dec_entry["account"]
        self.has_2fa = dec_entry["has_2fa"]
        # old information (other entry versions)
        self.padding = None
        self.username = b""
        self.password = b""
        self.extra = b""
        self.iv = None


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
    # base64-encoded
    key_salt = db.Column(db.String, nullable=False)

    KEY_LENGTH = 32

    def extend_key(self, master_key: str) -> bytes:
        """Helper method.
        Call extend_key with the right parameters"""
        assert isinstance(master_key, six.text_type)
        # sadly, base64-encoded
        assert isinstance(self.key_salt, six.text_type)
        return extend_key(
            master_key,
            binascii.a2b_base64(self.key_salt),
            EncryptedDocument.KEY_LENGTH
        )

    def to_json(self) -> dict:
        """
        NOTE: this is a really bad idea.
        Since the contents are bytes and will not make any sense on the client side
        """
        assert isinstance(self.document, bytes)
        return {
            "id": self.id,
            "name": self.name,
            "contents": self.document.decode("utf-8")
        }

    def decrypt(self, master_key: str) -> "DecryptedDocument":
        assert isinstance(master_key, six.text_type)
        extended_key = self.extend_key(master_key)
        cryptor = AEAD(base64_encode(extended_key))
        assert isinstance(self.name, six.text_type)
        assert isinstance(self.document, bytes)
        pt = cryptor.decrypt(self.document, self.name.encode("utf-8"))
        return DecryptedDocument(
            name=self.name,
            contents=pt
        )


class DecryptedDocument:

    def __init__(self, name: str, contents) -> None:
        """
        :param name: String, the user's name for the file. Not a filename.
        :param document: object for the file
        """
        assert isinstance(name, six.text_type)
        self.name = name
        if isinstance(contents, bytes):
            # data is already binary data
            self.contents = contents
        elif isinstance(contents, six.text_type):
            # convert data from unicode to binary
            self.contents = contents.encode("utf-8")
        else:
            # some kind of streaming object
            # get the binary value
            # there are different interfaces for some reason
            try:
                self.contents = contents.stream.getvalue()
            except AttributeError:
                self.contents = contents.stream.read()

    @staticmethod
    def extend_key(master_key: str) -> Tuple[bytes, dict]:
        """
        Helper method.

        :return: extended_key, params

        params:
            kdf_salt -> bytes
        """
        assert isinstance(master_key, six.text_type)
        key_salt = get_kdf_salt()
        assert isinstance(key_salt, bytes)
        # need a 32-byte key (256 bits)
        extended_key = extend_key(master_key, key_salt, 32)
        assert isinstance(extended_key, bytes)
        return (extended_key, {"kdf_salt": key_salt})

    def encrypt(self, key: bytes) -> "EncryptedDocument":
        """
        :param key:         bytes
        :return:            encrypted document with the content fields set
        """
        assert isinstance(key, bytes)
        # AES_128_CBC_HMAC_SHA_256
        assert len(key) == 32, \
               "key must be 32 bytes long, actually %d bytes" % len(key)
        assert isinstance(self.name, six.text_type), \
               "Name must be a unicode string"
        assert isinstance(self.contents, bytes), \
               "Contents must be bytes"
        cryptor = AEAD(base64_encode(key))
        ct = cryptor.encrypt(self.contents, self.name.encode("utf-8"))
        assert isinstance(ct, bytes), \
               "ciphertext is binary"
        return EncryptedDocument(
            # contents
            name=self.name,
            document=ct
        )

    def to_json(self) -> dict:
        """This is a really bad idea, to return a document this way.
        For now decode the doc into UTF-8
        """
        assert isinstance(self.name, six.text_type)
        assert isinstance(self.contents, bytes)
        return {
            "name": self.name,
            "contents": self.contents.decode("utf-8")
        }


class ApiToken(db.Model):
    __tablename__ = "api_tokens"
    id = db.Column(db.Integer, db.Sequence("api_token_id_seq"), primary_key=True)
    # for now there can be at most one API token per user
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True)

    # the actual token substance
    token = db.Column(db.String, nullable=False)
    # JTI (quick way to check uniqueness)
    token_identity = db.Column(db.String, nullable=False)

    issue_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expire_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def is_expired(self) -> bool:
        return self.expire_time < datetime.utcnow()
