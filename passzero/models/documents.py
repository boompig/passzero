import binascii
from typing import Tuple

import nacl.pwhash
import nacl.secret
import nacl.utils
import six

from passzero.crypto_utils import extend_key, get_kdf_salt

from ..utils import base64_encode
from .shared import db


class EncryptedDocument(db.Model):
    __tablename__ = "documents"
    id = db.Column(db.Integer, db.Sequence("documents_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # not encrypted
    name = db.Column(db.String, nullable=False)
    mimetype = db.Column(db.String, nullable=False)
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
        Return an encrypted version of the document
        Provides a base64-encoded version of the ENCRYPTED document body
        """
        assert isinstance(self.document, bytes)
        return {
            "id": self.id,
            "name": self.name,
            "mimetype": self.mimetype,
            "contents": base64_encode(self.document).decode("utf-8")
        }

    def decrypt(self, master_key: str) -> "DecryptedDocument":
        assert isinstance(master_key, six.text_type)
        extended_key = self.extend_key(master_key)
        box = nacl.secret.SecretBox(extended_key)
        assert isinstance(self.name, six.text_type)
        assert isinstance(self.document, bytes)
        pt = box.decrypt(self.document)
        assert isinstance(pt, bytes)
        return DecryptedDocument(
            name=self.name,
            mimetype=self.mimetype,
            contents=pt
        )


class DecryptedDocument:

    def __init__(self, name: str, mimetype: str, contents) -> None:
        """
        :param name: String, the user's name for the file. Not a filename.
        :param document: object for the file
        """
        assert isinstance(name, six.text_type)
        self.name = name
        self.mimetype = mimetype
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

    def encrypt(self, extended_key: bytes) -> "EncryptedDocument":
        """
        :param key:         bytes
        :return:            encrypted document with the content fields set
        """
        assert isinstance(extended_key, bytes)
        # AES_128_CBC_HMAC_SHA_256
        assert len(extended_key) == 32, f"key must be 32 bytes long, actually {len(extended_key)} bytes"
        assert isinstance(self.name, six.text_type), "Name must be a unicode string"
        assert isinstance(self.contents, bytes), "Contents must be bytes"
        box = nacl.secret.SecretBox(extended_key)
        # nonce generated randomly here
        ct = box.encrypt(self.contents)
        assert isinstance(ct, bytes), "ciphertext is binary"
        return EncryptedDocument(
            # contents
            name=self.name,
            mimetype=self.mimetype,
            document=ct
        )

    def to_json(self) -> dict:
        """This is a really bad idea, to return a document this way.
        For now, return the contents as a base64-encoded string of the contents
        """
        assert isinstance(self.name, six.text_type)
        assert isinstance(self.contents, bytes)
        return {
            "name": self.name,
            "contents": base64_encode(self.contents).decode("utf-8"),
            "mimetype": self.mimetype
        }
