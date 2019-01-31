"""
This class provides the model for all links
"""

import msgpack
import nacl.pwhash
import nacl.secret
import nacl.utils
import six

from .shared import db


def _get_key(master_key: str, kdf_salt: bytes):
    """Deliberately similar to `Entry_v5.__get_entry_key`"""
    assert isinstance(master_key, six.text_type)
    assert isinstance(kdf_salt, bytes)
    return nacl.pwhash.argon2id.kdf(
        size=nacl.secret.SecretBox.KEY_SIZE,
        password=master_key.encode("utf-8"),
        salt=kdf_salt,
        opslimit=nacl.pwhash.OPSLIMIT_INTERACTIVE,
        memlimit=nacl.pwhash.MEMLIMIT_INTERACTIVE,
    )


class Link(db.Model):
    """Storage idea is similar to Entry_v5
    Small difference: kdf_salt is stored directly as a binary type
    """

    __tablename__ = "links"

    id = db.Column(db.Integer, db.Sequence("links_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # this field contains all encrypted fields
    contents = db.Column(db.LargeBinary, nullable=False)

    # metadata fields are not encrypted
    version = db.Column(db.Integer, nullable=False)
    kdf_salt = db.Column(db.LargeBinary, nullable=False)

    __mapper_args__ = {
        "polymorphic_identity": 1,
        "polymorphic_on": version
    }

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "version": self.version,
        }

    def decrypt(self, master_key: str) -> dict:
        """
        Deliberately similar to `Entry_v5.decrypt`
        Raises `nacl.exceptions.CryptoError` on failure to authenticate cyphertext
        """
        assert isinstance(master_key, six.text_type)
        key = _get_key(master_key, self.kdf_salt)
        assert isinstance(key, bytes)
        box = nacl.secret.SecretBox(key)
        assert isinstance(self.contents, bytes)
        dec_contents = box.decrypt(self.contents)
        dec_contents_d = msgpack.unpackb(dec_contents, raw=False)
        # add unencrypted data and metadata
        dec_contents_d["version"] = self.version
        return dec_contents_d

    def encrypt(self, master_key, dec_link: dict) -> None:
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
        assert isinstance(master_key, six.text_type)
        assert isinstance(dec_link, dict)
        dec_contents_d = {
            "service_name": dec_link["service_name"],
            "link": dec_link["link"]
        }
        dec_contents = msgpack.packb(dec_contents_d, use_bin_type=True)
        kdf_salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
        assert isinstance(kdf_salt, bytes)
        key = _get_key(master_key, kdf_salt)
        assert isinstance(key, bytes)
        box = nacl.secret.SecretBox(key)
        self.contents = box.encrypt(dec_contents)
        assert isinstance(self.contents, bytes)
        self.kdf_salt = kdf_salt
        self.version = 1
        # NOTE: do not use ID from dec_link
