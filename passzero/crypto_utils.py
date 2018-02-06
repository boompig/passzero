import hashlib
import random

import six
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol import KDF


def byte_to_hex_legacy(s):
    """
    :param s:       Byte-string
    :return:        s converted into a hex (unicode) string
    """
    assert isinstance(s, bytes)
    arr = bytearray(s)
    assert all([isinstance(c, int) for c in arr])
    # when it's python 3 we don't have to decode
    return "".join('{:02x}'.format(x) for x in arr)


def hex_to_byte_legacy(s):
    arr = bytearray.fromhex(s)
    return bytes(arr)


def pad_to_length(key, length):
    """Return the padding
    :type key:          unicode string
    :type length:       int
    :rtype:             unicode string
    """
    assert isinstance(key, six.text_type)
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    padding = []
    while len(key) + len(padding) < length:
        padding.append(random.choice(alphabet))
    # when it's python 3 we don't have to decode
    return "".join(padding)


def pad_key_legacy(key):
    """Return the padding
    :type key:      unicode string
    :rtype:         unicode string
    """
    assert isinstance(key, six.text_type)
    if len(key) < 16:
        return pad_to_length(key, 16)
    elif len(key) < 24:
        return pad_to_length(key, 24)
    elif len(key) < 32:
        return pad_to_length(key, 32)
    else:
        raise Exception("Key too long (%d chars)" % len(key))


def encrypt_password_legacy(padded_key, password):
    """Return encrypted password where encrypted password is a hex string"""

    iv = Random.new().read(AES.block_size)
    cipher = AES.new(padded_key, AES.MODE_CFB, iv)
    enc_password = iv + cipher.encrypt(password)
    return byte_to_hex_legacy(enc_password)


def encrypt_field_v1(key, salt, field):
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
    assert isinstance(key, six.text_type)
    assert isinstance(salt, six.text_type)
    assert isinstance(field, six.text_type)
    salted_key = (key + salt).encode('utf-8')
    actual_key = hashlib.sha256(salted_key).digest()
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(actual_key, AES.MODE_CFB, iv)
    enc_field = cipher.encrypt(field) + iv
    hex_ciphertext = byte_to_hex_legacy(enc_field)
    return hex_ciphertext


def encrypt_field_v2(extended_key, message, iv):
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
    assert isinstance(message, six.text_type)
    assert isinstance(iv, bytes)
    cipher = AES.new(extended_key, AES.MODE_CFB, iv)
    enc_msg = cipher.encrypt(message)
    hex_ciphertext = byte_to_hex_legacy(enc_msg)
    assert isinstance(hex_ciphertext, six.text_type)
    return hex_ciphertext


def encrypt_messages(extended_key, iv, messages):
    """Encrypt a bunch of messages, in order, with the same IV.
    This approach uses a stream cipher"""
    assert isinstance(extended_key, bytes)
    assert isinstance(iv, bytes)
    cipher = AES.new(extended_key, AES.MODE_CFB, iv)
    enc_messages = [cipher.encrypt(message) for message in messages]
    return enc_messages


def decrypt_messages(extended_key, iv, messages):
    assert isinstance(extended_key, bytes)
    assert isinstance(extended_key, bytes)
    cipher = AES.new(extended_key, AES.MODE_CFB, iv)
    dec_messages = [cipher.decrypt(message).decode("utf-8") for message in messages]
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


def extend_key(key, salt, key_length=16):
    """Extend the given key into a key of length suitable for AES.
    :type key:          unicode
    :type salt:         bytes
    :rtype:             bytes
    """
    assert isinstance(key, six.text_type)
    assert isinstance(salt, bytes)
    assert isinstance(key_length, int)
    return KDF.PBKDF2(key, salt, count=1000, dkLen=key_length)


def get_iv():
    """:rtype       8-bit string"""
    return Random.new().read(AES.block_size)


def decrypt_field_v2(extended_key, hex_ciphertext, iv):
    """Return decrypted string of field
    :param extended_key:        Binary decryption key
    :type extended_key:         bytes
    :type hex_ciphertext:       unicode string
    :type iv:                   bytes
    :rtype:                     unicode string
    """
    assert isinstance(extended_key, bytes)
    assert isinstance(hex_ciphertext, six.text_type)
    assert isinstance(iv, bytes)
    ciphertext = hex_to_byte_legacy(hex_ciphertext)
    assert isinstance(ciphertext, bytes)
    if len(iv) < AES.block_size:
        raise TypeError("IV is too small")
    cipher = AES.new(extended_key, AES.MODE_CFB, iv)
    msg = cipher.decrypt(ciphertext).decode("utf-8")
    return msg


def decrypt_field_v1(key, salt, hex_ciphertext):
    """Return decrypted string of extra field
    :type key:              unicode string
    :type salt:             unicode string
    :type hex_ciphertext    unicode string
    :rtype:                 unicode string
    """
    assert isinstance(key, six.text_type)
    assert isinstance(salt, six.text_type)
    assert isinstance(hex_ciphertext, six.text_type)
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


def decrypt_password_legacy(padded_key, hex_ciphertext):
    """Return the decrypted password
    :type padded_key:           unicode string
    :type hex_ciphertext:       unicode string
    :rtype:                     unicode string
    """
    assert isinstance(padded_key, six.text_type)
    assert isinstance(hex_ciphertext, six.text_type)
    ciphertext = hex_to_byte_legacy(hex_ciphertext)
    assert isinstance(ciphertext, bytes)
    iv = ciphertext[:AES.block_size]
    enc_password = ciphertext[AES.block_size:]
    cipher = AES.new(padded_key, AES.MODE_CFB, iv)
    dec_password = cipher.decrypt(enc_password).decode("utf-8")
    return dec_password


def get_salt(size):
    """Create and return random salt of given size
    :rtype:                 byte-string of size `size`
    """
    assert isinstance(size, int)
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    chars = []
    for i in range(size):
        chars.append(six.b(random.choice(alphabet)))
    return b"".join(chars)


def random_hex(size):
    alphabet = "abcdef1234567890"
    chars = [random.choice(alphabet) for i in range(size)]
    return "".join(chars)


def get_hashed_password(password, salt):
    """
    :type password:            Unicode string
    :type salt:                byte-string
    :rtype:                    byte-string
    """
    assert isinstance(password, six.text_type)
    assert isinstance(salt, bytes)
    # this is stupid because a password should be able to contain unicode fields
    b_password = (password).encode("utf-8")
    return six.b(hashlib.sha512(b_password + salt).hexdigest())
