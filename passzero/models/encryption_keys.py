import binascii
from typing import Dict, Optional, TypedDict

import msgpack
import nacl.pwhash
import nacl.secret
import nacl.utils

from passzero.models.shared import db
from passzero.utils import base64_encode


class EncryptionKeyEntry_V1(TypedDict):
    # timestamp when the key was last modified, as seconds since UNIX epoch
    last_modified: int
    # the key itself is stored in binary format
    key: bytes


class EncryptionKeysDB_V1(TypedDict):
    """This is the decrypted form of `EncryptionKeys`"""
    # this is a map from str(entry_ids) to encryption keys
    # using string keys because msgpack/JSON doesn't support other key types
    entry_keys: Dict[str, EncryptionKeyEntry_V1]
    # this is a map from str(link_ids) to encryption keys
    # using string keys because msgpack/JSON doesn't support other key types
    link_keys: Dict[str, EncryptionKeyEntry_V1]
    # set if this is stored in the DB
    id: Optional[int]
    # set if this is stored in the DB
    user_id: Optional[int]
    version: int


class EncryptionKeys(db.Model):
    """Store the encryption keys for a particular user.
    Encryption keys themselves are encrypted using the user's master password.
    Ideally this means that when a user changes their master password, only this table has to be modified.
    If the keys are not stored, then all encrypted blobs must be re-encrypted.

    Each encrypted key database is a msgpack blob (for storage efficiency) encrypted with a symmetric key.
    These symmetric keys are derived using a key derivation function.
    """

    __tablename__ = "encryption_keys"
    id = db.Column(db.Integer, db.Sequence("encryption_keys_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # data - contains nonce (prefix)
    contents = db.Column(db.LargeBinary, nullable=False)

    # metadata
    version = db.Column(db.Integer, nullable=False)

    # fields used for encryption
    # base64-encoded binary
    kdf_salt = db.Column(db.String, nullable=False)
    # base64-encoded binary
    nonce = db.Column(db.String, nullable=False)

    def to_json(self) -> dict:
        """Convert the encrypted version of this object into a JSON representation.
        This will be sent back to the user for decryption."""
        # decode the nonce into binary
        nonce = binascii.a2b_base64(self.nonce.encode("utf-8"))
        # the message must start with the nonce
        contents = self.contents[len(nonce):]
        return {
            # send back the contents without the nonce in front
            "enc_contents_b64": base64_encode(contents).decode("utf-8"),
            # these are already base64-encoded
            "enc_nonce_b64": self.nonce,
            "enc_kdf_salt_b64": self.kdf_salt,
        }

    def derive_symmetric_key(self, master_key: str, kdf_salt: bytes) -> bytes:
        """Derive the symmetric key to be used in encryption/decryption"""
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

    def encrypt(self, master_key: str, dec_encryption_keys: EncryptionKeysDB_V1) -> None:
        """We use this method if we're updating to preserve the ID"""
        # NOTE: user_id is not set here
        assert isinstance(master_key, str)
        assert isinstance(dec_encryption_keys, dict)
        kdf_salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
        symmetric_key = self.derive_symmetric_key(master_key, kdf_salt)
        # make the contents small for storage
        pt = msgpack.packb(dec_encryption_keys, use_bin_type=True)
        assert isinstance(pt, bytes)
        box = nacl.secret.SecretBox(symmetric_key)
        nonce = nacl.utils.random(box.NONCE_SIZE)
        # save directly as large binary
        self.contents = box.encrypt(pt, nonce=nonce)
        # cryptographic parameters
        self.kdf_salt = base64_encode(kdf_salt).decode("utf-8")
        self.nonce = base64_encode(nonce).decode("utf-8")
        # metadata
        self.version = 1

    def decrypt(self, master_key: str) -> EncryptionKeysDB_V1:
        """
        Raises `nacl.exceptions.CryptoError` on failure to authenticate cyphertext
        """
        assert isinstance(master_key, str)
        assert isinstance(self.kdf_salt, str)
        assert isinstance(self.nonce, str)

        kdf_salt = binascii.a2b_base64(self.kdf_salt.encode("utf-8"))
        symmetric_key = self.derive_symmetric_key(master_key, kdf_salt)
        nonce = binascii.a2b_base64(self.nonce.encode("utf-8"))
        box = nacl.secret.SecretBox(symmetric_key)
        assert isinstance(self.contents, bytes)
        # first few bytes should be the nonce
        nonce_length = len(nonce)
        assert self.contents[:nonce_length] == nonce, "nonce does not match beginning of encrypted contents"
        # we then run the decryption *without* the nonce
        contents = self.contents[len(nonce):]
        pt = box.decrypt(contents, nonce=nonce)
        dec_encryption_keys = msgpack.unpackb(pt, raw=False)
        # fill in some fields in the decrypted data
        dec_encryption_keys["id"] = self.id
        dec_encryption_keys["user_id"] = self.user_id
        dec_encryption_keys["version"] = self.version
        return dec_encryption_keys
