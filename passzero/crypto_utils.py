import enum
import hashlib
import hmac
import random
from typing import List

import nacl.pwhash
import six
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol import KDF


@enum.unique
class PasswordHashAlgo(enum.Enum):
    """Algorithms used for hashing the user's password
    Use explicit values to match up with the values in the database"""
    SHA512 = 1
    Argon2 = 2


def byte_to_hex_legacy(s: bytes) -> str:
    """
    :param s:       Byte-string
    :return:        s converted into a hex (unicode) string
    """
    assert isinstance(s, bytes)
    arr = bytearray(s)
    assert all([isinstance(c, int) for c in arr])
    # when it's python 3 we don't have to decode
    return "".join('{:02x}'.format(x) for x in arr)


def hex_to_byte_legacy(s: str) -> bytes:
    arr = bytearray.fromhex(s)
    return bytes(arr)


def pad_to_length(key: str, length: int) -> str:
    """Return the padding
    :type key:          unicode string
    :type length:       int
    :rtype:             unicode string
    """
    assert isinstance(key, str)
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    padding = []  # type: List[str]
    while len(key) + len(padding) < length:
        padding.append(random.choice(alphabet))
    # when it's python 3 we don't have to decode
    return "".join(padding)


def pad_key_legacy(key: str) -> str:
    """Return the padding
    :type key:      unicode string
    :rtype:         unicode string
    """
    assert isinstance(key, str)
    if len(key) < 16:
        return pad_to_length(key, 16)
    elif len(key) < 24:
        return pad_to_length(key, 24)
    elif len(key) < 32:
        return pad_to_length(key, 32)
    else:
        raise Exception("Key too long (%d chars)" % len(key))


def encrypt_password_legacy(padded_key: str, password: str) -> str:
    """Return encrypted password where encrypted password is a hex string"""
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(padded_key.encode("utf-8"), AES.MODE_CFB, iv)
    enc_password = iv + cipher.encrypt(password.encode("utf-8"))
    return byte_to_hex_legacy(enc_password)


def encrypt_field_v1(key: str, salt: str, field: str) -> str:
    """
    WARNING: do not use
    Return encrypted hex string of field
    :param key:             Encryption key
    :type key:              unicode string
    :param salt:            Salt for the encryption
    :type salt:             unicode string
    :param field:           Value of the field being encrypted
    :type field:            unicode string
    :rtype:                 unicode string
    """
    assert isinstance(key, str)
    assert isinstance(salt, str)
    assert isinstance(field, str)
    salted_key = (key + salt).encode("utf-8")
    actual_key = hashlib.sha256(salted_key).digest()
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(actual_key, AES.MODE_CFB, iv)
    enc_field = cipher.encrypt(field.encode("utf-8")) + iv
    hex_ciphertext = byte_to_hex_legacy(enc_field)
    return hex_ciphertext


def encrypt_field_v2(extended_key: bytes, message: str, iv: bytes) -> str:
    """Return encrypted hex string of extra field
    :param extended_key:        Bytes for the extended key
    :type extended_key:         bytes
    :param message:             The unicode message
    :type message:              unicode
    :param iv:                  Bytes for initialization vector
    :type iv:                   bytes
    :return:                    The encrypted field as unicode
    :rtype:                     unicode
    """
    assert isinstance(extended_key, bytes)
    assert isinstance(message, str)
    assert isinstance(iv, bytes)
    cipher = AES.new(extended_key, AES.MODE_CFB, iv)
    enc_msg = cipher.encrypt(message.encode("utf-8"))
    hex_ciphertext = byte_to_hex_legacy(enc_msg)
    assert isinstance(hex_ciphertext, str)
    return hex_ciphertext


def encrypt_messages(extended_key: bytes, iv: bytes, messages: List[str]) -> List[bytes]:
    """Encrypt a bunch of messages, in order, with the same IV.
    This approach uses a stream cipher"""
    assert isinstance(extended_key, bytes)
    assert isinstance(iv, bytes)
    cipher = AES.new(extended_key, AES.MODE_CFB, iv)
    enc_messages = [cipher.encrypt(message.encode("utf-8")) for message in messages]
    return enc_messages


def decrypt_messages(extended_key: bytes, iv: bytes, messages: List[bytes]):
    assert isinstance(extended_key, bytes)
    assert isinstance(iv, bytes)
    assert all([isinstance(msg, bytes) for msg in messages])
    cipher = AES.new(extended_key, AES.MODE_CFB, iv)
    # dec_messages = [cipher.decrypt(message).decode("utf-8") for message in messages]
    dec_messages_bytes = [cipher.decrypt(message) for message in messages]
    dec_messages = []
    for msg in dec_messages_bytes:
        try:
            dec_messages.append(msg.decode("utf-8"))
        except Exception as e:
            print(msg)
            raise e
    return dec_messages


def random_bytes(length):
    """
    :return bytes
    """
    return Random.new().read(length)


def random_string(length):
    """Return random byte string of given length"""
    return Random.new().read(length)


def get_kdf_salt(num_bytes=32):
    """
    :rtype: bytes
    """
    return random_bytes(num_bytes)


def extend_key(key: str, salt: bytes, key_length: int = 16) -> bytes:
    """Extend the given key into a key of length suitable for AES.
    :type key:          unicode
    :type salt:         bytes
    :rtype:             bytes
    """
    assert isinstance(key, str)
    assert isinstance(salt, bytes)
    assert isinstance(key_length, int)
    return KDF.PBKDF2(key, salt, count=1000, dkLen=key_length)


def get_iv() -> bytes:
    """:rtype       bytes"""
    return Random.new().read(AES.block_size)


def decrypt_field_v2(extended_key: bytes, hex_ciphertext: str, iv: bytes) -> str:
    """Return decrypted string of field
    :param extended_key:        Binary decryption key
    :type extended_key:         bytes
    :type hex_ciphertext:       unicode string
    :type iv:                   bytes
    :rtype:                     unicode string
    """
    assert isinstance(extended_key, bytes)
    assert isinstance(hex_ciphertext, str)
    assert isinstance(iv, bytes)
    ciphertext = hex_to_byte_legacy(hex_ciphertext)
    assert isinstance(ciphertext, bytes)
    if len(iv) < AES.block_size:
        raise TypeError("IV is too small")
    cipher = AES.new(extended_key, AES.MODE_CFB, iv)
    msg = cipher.decrypt(ciphertext).decode("utf-8")
    return msg


def decrypt_field_v1(key: str, salt: str, hex_ciphertext: str) -> str:
    """Return decrypted string of extra field
    :type key:              unicode string
    :type salt:             unicode string
    :type hex_ciphertext    unicode string
    :rtype:                 unicode string
    """
    assert isinstance(key, str)
    assert isinstance(salt, str)
    assert isinstance(hex_ciphertext, str)
    full_ciphertext = hex_to_byte_legacy(hex_ciphertext)
    iv = full_ciphertext[-1 * AES.block_size:]
    if len(iv) < AES.block_size:
        raise TypeError("IV is too small")
    ciphertext = full_ciphertext[:-1 * AES.block_size]
    bin_key = (key + salt).encode("utf-8")
    actual_key = hashlib.sha256(bin_key).digest()
    cipher = AES.new(actual_key, AES.MODE_CFB, iv)
    dec_extra = cipher.decrypt(ciphertext).decode("utf-8")
    return dec_extra


def decrypt_password_legacy(padded_key: str, hex_ciphertext: str) -> str:
    """Return the decrypted password
    :type padded_key:           unicode string
    :type hex_ciphertext:       unicode string
    :rtype:                     unicode string
    """
    assert isinstance(padded_key, str)
    assert isinstance(hex_ciphertext, str)
    ciphertext = hex_to_byte_legacy(hex_ciphertext)
    assert isinstance(ciphertext, bytes)
    iv = ciphertext[:AES.block_size]
    enc_password = ciphertext[AES.block_size:]
    cipher = AES.new(padded_key.encode("utf-8"), AES.MODE_CFB, iv)
    dec_password = cipher.decrypt(enc_password).decode("utf-8")
    return dec_password


def get_salt(size: int) -> bytes:
    """Create and return random salt of given size
    :rtype:                 8-bit string of size `size`
    """
    assert isinstance(size, int)
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    chars = []
    for i in range(size):
        chars.append(six.b(random.choice(alphabet)))
    return b"".join(chars)


def random_hex(size: int) -> str:
    alphabet = "abcdef1234567890"
    chars = [random.choice(alphabet) for i in range(size)]
    return "".join(chars)


def get_hashed_password(password: str, salt: bytes, hash_algo: PasswordHashAlgo) -> bytes:
    """
    :type password:            Unicode string
    :type salt:                bytes
    :type hash_algo:           PasswordHashAlgo (enum)
    :rtype:                    bytes
    """
    assert isinstance(password, str)
    assert isinstance(salt, bytes)
    assert isinstance(hash_algo, PasswordHashAlgo)
    if hash_algo == PasswordHashAlgo.SHA512:
        return __get_hashed_password_sha512(password, salt)
    elif hash_algo == PasswordHashAlgo.Argon2:
        return __get_hashed_password_argon2(password, salt)
    else:
        raise Exception("Unknown hash algorithm: {}".format(hash_algo))


def __get_hashed_password_argon2(password: str, salt: bytes) -> bytes:
    """
    Use the Argon2 algorithm to hash the user's password with the given salt
    NOTE: salt is not used in this method. The underlying library generates its own salt
    :type password:            Unicode string
    :type salt:                bytes
    :rtype:                    bytes
    """
    assert isinstance(password, str)
    assert isinstance(salt, bytes)
    b_password = (password).encode("utf-8")
    out_password = nacl.pwhash.argon2id.str(b_password)
    assert isinstance(out_password, bytes)
    return out_password


def __get_hashed_password_sha512(password: str, salt: bytes) -> bytes:
    """
    Use the SHA512 algorithm to hash the user's password with the given salt
    :type password:            Unicode string
    :type salt:                bytes
    :rtype:                    bytes
    """
    assert isinstance(password, str)
    assert isinstance(salt, bytes)
    # this is stupid because a password should be able to contain unicode fields
    b_password = (password).encode("utf-8")
    return six.b(hashlib.sha512(b_password + salt).hexdigest())


def constant_time_compare_passwords(password_hash: str, password: str, salt: bytes,
                                    hash_algo: PasswordHashAlgo) -> bool:
    """
    Compare the user's password to the given password and return whether they are equal in constant time
    :param password_hash:               The hash of the password stored in the database
    """
    assert isinstance(password_hash, str)
    assert isinstance(password, str)
    assert isinstance(salt, bytes)
    assert isinstance(hash_algo, PasswordHashAlgo)
    if hash_algo == PasswordHashAlgo.Argon2:
        # nacl.pwhash.verify expects (bytestring, bytestring which is an argon thingy)
        try:
            # API: (password_hash, password)
            nacl.pwhash.verify(password_hash.encode("utf-8"), password.encode("utf-8"))
            return True
        except nacl.exceptions.InvalidkeyError:
            return False
    elif hash_algo == PasswordHashAlgo.SHA512:
        hashed_password = __get_hashed_password_sha512(password, salt)
        # NOTE: I am aware that this is not very secure.
        # When users change passwords they will be converted to upgraded algo
        # MD5 only used for backwards compatibility reasons only
        d1 = hmac.new(hashed_password, digestmod=hashlib.md5).digest()
        d2 = hmac.new(password_hash.encode("utf-8"), digestmod=hashlib.md5).digest()
        return hmac.compare_digest(d1, d2)
    else:
        raise Exception("Unknown hash algorithm: {}".format(hash_algo))
