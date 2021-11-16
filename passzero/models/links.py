"""
This class provides the model for all links
"""

from base64 import b64encode
from datetime import datetime
from typing import Optional

import msgpack
import nacl.pwhash
import nacl.secret
import nacl.utils
from nacl.bindings import crypto_secretbox_NONCEBYTES

from .shared import db


def _get_key(master_key: str, kdf_salt: bytes):
    """Deliberately similar to `Entry_v5.__get_entry_key`"""
    assert isinstance(master_key, str)
    assert isinstance(kdf_salt, bytes)
    return nacl.pwhash.argon2id.kdf(
        size=nacl.secret.SecretBox.KEY_SIZE,
        password=master_key.encode("utf-8"),
        salt=kdf_salt,
        opslimit=nacl.pwhash.OPSLIMIT_INTERACTIVE,
        memlimit=nacl.pwhash.MEMLIMIT_INTERACTIVE,
    )


class DecryptedLink:
    def __init__(self, service_name: str, link: str,
                 id: int = None, user_id: int = None,
                 version: int = None,
                 symmetric_key: Optional[bytes] = None) -> None:
        self.service_name = service_name
        self.link = link
        # if the link exists in the database
        self.id = id
        self.user_id = user_id
        self.version = version
        # if the link exists in the database
        # this is the symmetric key used to decrypt this link
        self.symmetric_key = symmetric_key

    def to_json(self) -> dict:
        return {
            "service_name": self.service_name,
            "link": self.link,
            "id": self.id,
            "user_id": self.user_id,
            "version": self.version,
        }


class Link(db.Model):
    """Storage idea is similar to Entry_v5
    Small difference: kdf_salt is stored directly as a binary type
    """

    __tablename__ = "links"

    id = db.Column(db.Integer, db.Sequence("links_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # this field contains all encrypted fields
    contents = db.Column(db.LargeBinary, nullable=False)

    # metadata fields are not encrypted
    version = db.Column(db.Integer, nullable=False)
    kdf_salt = db.Column(db.LargeBinary, nullable=False)
    # set when the link is created, then not modified on edits
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # changed each time the link is edited
    modified_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __mapper_args__ = {
        "polymorphic_identity": 1,
        "polymorphic_on": version
    }

    def to_json(self) -> dict:
        # see https://pynacl.readthedocs.io/en/latest/_modules/nacl/secret/#SecretBox.decrypt
        nonce = self.contents[: crypto_secretbox_NONCEBYTES]
        # note that this includes the MAC
        ciphertext = self.contents[crypto_secretbox_NONCEBYTES:]
        return {
            "id": self.id,
            "user_id": self.user_id,
            "version": self.version,
            "enc_kdf_salt_b64": b64encode(self.kdf_salt).decode("utf-8"),
            "enc_ciphertext_b64": b64encode(ciphertext).decode("utf-8"),
            "enc_nonce_b64": b64encode(nonce).decode("utf-8"),
        }

    def decrypt_symmetric(self, symmetric_key: bytes) -> DecryptedLink:
        """
        Deliberately similar to `Entry_v5.decrypt`
        Raises `nacl.exceptions.CryptoError` on failure to authenticate cyphertext
        """
        assert isinstance(symmetric_key, bytes)
        box = nacl.secret.SecretBox(symmetric_key)
        assert isinstance(self.contents, bytes)
        dec_contents = box.decrypt(self.contents)
        dec_contents_d = msgpack.unpackb(dec_contents, raw=False)
        return DecryptedLink(
            service_name=dec_contents_d["service_name"],
            link=dec_contents_d["link"],
            id=self.id,
            user_id=self.user_id,
            version=self.version,
            symmetric_key=symmetric_key,
        )

    def decrypt(self, master_key: str) -> DecryptedLink:
        """
        Deliberately similar to `Entry_v5.decrypt`
        Raises `nacl.exceptions.CryptoError` on failure to authenticate cyphertext
        """
        assert isinstance(master_key, str)
        symmetric_key = _get_key(master_key, self.kdf_salt)
        return self.decrypt_symmetric(symmetric_key)

    def encrypt(self, master_key: str, dec_link: dict) -> bytes:
        """
        Deliberately similar to `Entry_v5.encrypt`
        Assumed structure of `dec_link`:
            - service_name: str
            - link: str
            - user_id: int
            - id (optional): int
            - version (optional): int -> ignored
        """
        # NOTE: user_id not set here
        assert isinstance(master_key, str)
        assert isinstance(dec_link, dict), \
            f"expected decrypted link to be a dictionary, got type {type(dec_link)}"
        dec_contents_d = {
            "service_name": dec_link["service_name"],
            "link": dec_link["link"]
        }
        dec_contents = msgpack.packb(dec_contents_d, use_bin_type=True)
        kdf_salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
        assert isinstance(kdf_salt, bytes)
        symmetric_key = _get_key(master_key, kdf_salt)
        assert isinstance(symmetric_key, bytes)
        box = nacl.secret.SecretBox(symmetric_key)
        self.contents = box.encrypt(dec_contents)
        assert isinstance(self.contents, bytes)
        self.kdf_salt = kdf_salt
        self.version = 1
        # NOTE: do not use ID from dec_link
        # NOTE: do not use created_at from dec_link
        return symmetric_key
