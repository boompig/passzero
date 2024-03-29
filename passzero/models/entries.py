import binascii
import time
from base64 import b64encode

import msgpack
import nacl.pwhash
import nacl.secret
import nacl.utils
from nacl.bindings import crypto_secretbox_NONCEBYTES

from passzero.crypto_utils import (byte_to_hex_legacy, decrypt_field_v1,
                                   decrypt_field_v2, decrypt_messages,
                                   decrypt_password_legacy, encrypt_field_v1,
                                   encrypt_field_v2, encrypt_messages,
                                   encrypt_password_legacy, extend_key, get_iv,
                                   get_kdf_salt, hex_to_byte_legacy,
                                   pad_key_legacy)
from passzero.models.shared import db
from passzero.utils import base64_encode


class Entry(db.Model):
    """This entry serves as both the v1 entry and the base class to other entries"""
    __tablename__ = "entries"
    id = db.Column(db.Integer, db.Sequence("entries_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
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

    contents = db.Column(db.LargeBinary)

    __mapper_args__ = {
        "polymorphic_identity": 1,
        "polymorphic_on": version
    }

    def __repr__(self) -> str:
        return "<Entry(account={}, username={}, password={}, padding={}, user_id={})>".format(
            self.account, self.username, self.password, self.padding, self.user_id)

    def to_json(self) -> dict:
        """
        Convert the encrypted entry for export to the user over the network.
        Removes many non-public fields.

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

    def decrypt_with_entry_key(self, entry_key: bytes) -> dict:
        raise NotImplementedError("There is no entry-level key for v1 entries")

    def decrypt(self, master_key: str) -> dict:
        """Decrypt with padding
        :type key:              unicode string
        """
        assert isinstance(master_key, str)
        assert isinstance(self.username, str)
        dec_password = decrypt_password_legacy(master_key + self.padding, self.password)
        if self.extra:
            try:
                dec_extra = decrypt_field_v1(master_key, self.padding, self.extra)
            except TypeError:
                dec_extra = self.extra
        else:
            dec_extra = ""
        try:
            dec_username = decrypt_field_v1(master_key, self.padding, self.username)
        except TypeError:
            dec_username = self.username
        return {
            "id": self.id,
            "account": self.account,
            "username": dec_username,
            "password": dec_password,
            "extra": dec_extra,
            "has_2fa": self.has_2fa,
            "version": self.version,
        }

    def encrypt(self, master_key: str, dec_entry: dict) -> bytes:
        """
        WARNING: This is not secure! Do not use this!
        This is only here to satisfy the unit test for decryption of these old entries
        """
        assert isinstance(master_key, str)
        assert isinstance(dec_entry, dict)
        self.padding = pad_key_legacy(master_key)
        assert isinstance(self.padding, str)
        self.account = dec_entry[u"account"]
        assert isinstance(self.account, str)
        self.username = encrypt_field_v1(master_key, self.padding,
                                         dec_entry[u"username"])
        assert isinstance(self.username, str)
        self.password = encrypt_password_legacy(master_key + self.padding,
                                                dec_entry[u"password"])
        assert isinstance(self.password, str)
        self.extra = encrypt_field_v1(master_key, self.padding,
                                      dec_entry[u"extra"])
        assert isinstance(self.extra, str)
        self.has_2fa = dec_entry["has_2fa"]
        assert isinstance(self.has_2fa, bool)
        self.version = 1
        # NOTE: we are returning something here for forward-compatibility
        # however, this method works according to different principles than future versions
        # and uses a different key for each field
        return b""


class Entry_v2(Entry):
    """This is an old version of the entry
    DO NOT USE THIS VERSION. It exists for backwards compatibility only.

    The following fields are encrypted:
    - username
    - password
    - extra

    The following fields are *not* encrypted:
    - account
    """

    __mapper_args__ = {
        "polymorphic_identity": 2
    }

    def decrypt_with_entry_key(self, entry_key: bytes) -> dict:
        assert isinstance(entry_key, bytes)
        iv = hex_to_byte_legacy(self.iv)
        dec_password = decrypt_field_v2(entry_key, self.password, iv)
        if self.extra:
            try:
                dec_extra = decrypt_field_v2(entry_key, self.extra, iv)
            except TypeError:
                dec_extra = self.extra
        else:
            dec_extra = ""
        try:
            dec_username = decrypt_field_v2(entry_key, self.username, iv)
        except TypeError:
            dec_username = self.username
        return {
            "id": self.id,
            "account": self.account,
            "username": dec_username,
            "password": dec_password,
            "extra": dec_extra,
            "has_2fa": self.has_2fa,
            "version": self.version,
        }

    def decrypt(self, master_key: str) -> dict:
        assert isinstance(master_key, str)
        key_salt = hex_to_byte_legacy(self.key_salt)
        extended_key = extend_key(master_key, key_salt)
        return self.decrypt_with_entry_key(extended_key)

    def encrypt(self, master_key: str, dec_entry: dict) -> bytes:
        """
        WARNING: This is not secure! Do not use this!
        This is only here to satisfy the unit test for decryption of these old entries
        If they are still alive in the database
        """
        assert isinstance(master_key, str)
        assert isinstance(dec_entry, dict)
        if "extra" not in dec_entry:
            dec_entry["extra"] = u""
        key_salt = get_kdf_salt()
        iv = get_iv()
        extended_key = extend_key(master_key, key_salt)
        self.account = dec_entry["account"]
        self.has_2fa = dec_entry["has_2fa"]
        # these should all be unicode
        self.username = encrypt_field_v2(extended_key, dec_entry["username"], iv)
        self.password = encrypt_field_v2(extended_key, dec_entry["password"], iv)
        self.extra = encrypt_field_v2(extended_key, dec_entry["extra"], iv)
        assert isinstance(self.account, str)
        assert isinstance(self.username, str)
        assert isinstance(self.password, str)
        assert isinstance(self.extra, str)
        assert isinstance(self.has_2fa, bool)
        self.key_salt = byte_to_hex_legacy(key_salt)
        self.iv = byte_to_hex_legacy(iv)
        self.version = 2
        return extended_key


class Entry_v3(Entry):
    """This is an old version of the entry
    DO NOT USE THIS VERSION. It exists for backwards compatibility only.

    The following fields are encrypted:
    - account
    - username
    - password
    - extra

    The following fields are *not* encrypted:
    - has_2fa
    """

    __mapper_args__ = {
        "polymorphic_identity": 3
    }

    def encrypt(self, master_key: str, dec_entry: dict) -> bytes:
        """
        :param master_key:  The user's key, used to derive entry-specific enc key
        :param dec_entry:   Entry to encrypt (dictionary of fields)
        :return: key used for entry encryption
        """
        assert isinstance(master_key, str)
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
        self.account = enc_entry["account"].decode("utf-8")
        self.username = enc_entry["username"].decode("utf-8")
        self.password = enc_entry["password"].decode("utf-8")
        self.extra = enc_entry["extra"].decode("utf-8")
        # unencrypted contents (forward compatibility)
        self.has_2fa = dec_entry.get("has_2fa", False)
        # metadata - which encryption scheme to use to decrypt
        self.version = 3
        self.pinned = False
        self.iv = base64_encode(iv).decode("utf-8")
        self.key_salt = base64_encode(kdf_salt).decode("utf-8")
        # old information
        self.padding = None
        return extended_key

    def decrypt_with_entry_key(self, entry_key: bytes) -> dict:
        assert isinstance(entry_key, bytes)
        iv = binascii.a2b_base64(self.iv)
        messages = [
            binascii.a2b_base64(self.account),
            binascii.a2b_base64(self.username),
            binascii.a2b_base64(self.password),
            binascii.a2b_base64(self.extra)
        ]
        dec_messages = decrypt_messages(entry_key, iv, messages)
        return {
            "id": self.id,
            "account": dec_messages[0],
            "username": dec_messages[1],
            "password": dec_messages[2],
            "extra": dec_messages[3],
            "version": self.version,
            "has_2fa": self.has_2fa,
        }

    def decrypt(self, master_key: str) -> dict:
        assert isinstance(master_key, str)
        kdf_salt = binascii.a2b_base64(self.key_salt)
        extended_key = extend_key(master_key, kdf_salt)
        return self.decrypt_with_entry_key(extended_key)


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

    def to_json(self) -> dict:
        out = super().to_json()
        # remove irrelevant elements in order to conserve bandwidth
        del out["username"]
        del out["password"]
        del out["extra"]
        return out

    def decrypt_with_entry_key(self, entry_key: bytes) -> dict:
        assert isinstance(entry_key, bytes)
        iv = binascii.a2b_base64(self.iv)
        assert isinstance(iv, bytes)
        messages = [
            binascii.a2b_base64(self.username),
            binascii.a2b_base64(self.password),
            binascii.a2b_base64(self.extra)
        ]
        dec_messages = decrypt_messages(entry_key, iv, messages)
        return {
            "id": self.id,
            "account": self.account,
            "username": dec_messages[0],
            "password": dec_messages[1],
            "extra": dec_messages[2],
            # add unencrypted metadata
            "has_2fa": self.has_2fa,
            "version": self.version
        }

    def decrypt(self, master_key: str) -> dict:
        """
        Version 4 encrypts, sequentially, the following data:
        - username
        - password
        - extra field
        Notably, 'account' field is *not* encrypted
        """
        assert isinstance(master_key, str)
        kdf_salt = binascii.a2b_base64(self.key_salt)
        assert isinstance(kdf_salt, bytes)
        extended_key = extend_key(master_key, kdf_salt)
        return self.decrypt_with_entry_key(extended_key)

    def encrypt(self, master_key: str, dec_entry: dict) -> bytes:
        """
        :param master_key:  The user's key, used to derive entry-specific enc key
        :param dec_entry:   Entry to encrypt (dictionary of fields)
            Expected fields:
            - account
            - username
            - password
            - extra
            - has_2fa (bool)
        :return: key used for entry encryption
        """
        assert isinstance(master_key, str)
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
            assert isinstance(enc_entry[field], str)
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
        assert isinstance(self.key_salt, str)
        self.iv = base64_encode(iv).decode("utf-8")
        assert isinstance(self.iv, str)
        # old information
        self.padding = None
        return extended_key


class Entry_v5(Entry):
    """This entry type encrypts the following fields:
    - username
    - password
    - extra
    - last_modified - UNIX timestamp (possibly not in the data structure)

    And leaves the following fields unencrypted:
    - account
    - has_2fa

    For the same reason as in v4.

    HOWEVER: the encrypted fields are stored in one monolithic binary blob in the `contents` field

    The fields are encrypted using libsodium secret box (AEAD)
    The encryption key is derived from the master key using argon2id

    When using this version, you have to be careful with the key_salt: do not reuse this
    """

    # self.key_salt should be of type unicode

    __mapper_args__ = {
        "polymorphic_identity": 5
    }

    def to_json(self) -> dict:
        out = super().to_json()

        # remove irrelevant elements in order to conserve bandwidth
        del out["username"]
        del out["password"]
        del out["extra"]

        # return a variety of parameters for client-side encryption
        # key salt is already base64-encoded
        out["enc_key_salt_b64"] = self.key_salt
        # see https://pynacl.readthedocs.io/en/latest/_modules/nacl/secret/#SecretBox.decrypt
        nonce = self.contents[: crypto_secretbox_NONCEBYTES]
        # note that this includes the MAC
        ciphertext = self.contents[crypto_secretbox_NONCEBYTES:]
        out["enc_nonce_b64"] = b64encode(nonce).decode("utf-8")
        out["enc_ciphertext_b64"] = b64encode(ciphertext).decode("utf-8")
        return out

    def __get_entry_key(self, master_key: str, kdf_salt: bytes) -> bytes:
        assert isinstance(master_key, str)
        assert isinstance(kdf_salt, bytes)
        return nacl.pwhash.argon2id.kdf(
            size=nacl.secret.SecretBox.KEY_SIZE,
            # TODO: this may not always be possible if a unicode password is used
            password=master_key.encode("utf-8"),
            salt=kdf_salt,
            opslimit=nacl.pwhash.OPSLIMIT_INTERACTIVE,
            memlimit=nacl.pwhash.MEMLIMIT_INTERACTIVE,
        )

    def decrypt_with_entry_key(self, entry_key: bytes) -> dict:
        """
        Raises `nacl.exceptions.CryptoError` on failure to authenticate cyphertext
        """
        assert isinstance(entry_key, bytes)
        box = nacl.secret.SecretBox(entry_key)
        assert isinstance(self.contents, bytes)
        dec_contents = box.decrypt(self.contents)
        dec_contents_d = msgpack.unpackb(dec_contents, raw=False)
        # fill in the unencrypted data
        dec_contents_d["id"] = self.id
        dec_contents_d["account"] = self.account
        dec_contents_d["has_2fa"] = self.has_2fa
        dec_contents_d["version"] = self.version
        return dec_contents_d

    def decrypt(self, master_key: str, return_symmetric_key: bool = False) -> dict:
        """
        :param return_symmetric_key: If specified as True, return the symmetric key used to decrypt the entry
        Raises `nacl.exceptions.CryptoError` on failure to authenticate cyphertext
        """
        assert isinstance(master_key, str)
        assert isinstance(self.key_salt, str)
        kdf_salt = binascii.a2b_base64(self.key_salt.encode("utf-8"))
        entry_key = self.__get_entry_key(master_key, kdf_salt)
        dec_entry = self.decrypt_with_entry_key(entry_key)
        if return_symmetric_key:
            dec_entry["symmetric_key"] = entry_key
        return dec_entry

    def encrypt(self, master_key: str, dec_entry: dict) -> bytes:
        """
        This method is used to either create or re-encrypt an entry.
        We should zero out all fields that we don't use.
        Change all the fields that we do use.

        NOTE: user_id is not set in this method
        NOTE: id may not be set

        :return: The entry key used for the encryption
        """
        assert isinstance(master_key, str)
        assert isinstance(dec_entry, dict)
        dec_contents_d = {
            "username": dec_entry["username"],
            "password": dec_entry["password"],
            "extra": dec_entry["extra"],
            "last_modified": time.time(),
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
        assert isinstance(self.key_salt, str)
        # unencrypted data
        self.account = dec_entry["account"]
        self.has_2fa = dec_entry["has_2fa"]
        # old information (other entry versions)
        self.padding = None
        self.username = b""
        self.password = b""
        self.extra = b""
        self.iv = None
        return entry_key
