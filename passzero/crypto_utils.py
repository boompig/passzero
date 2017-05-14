from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
import hashlib
import random


def byte_to_hex(s):
    arr = [ord(c) for c in s]
    return ''.join('{:02x}'.format(x) for x in arr)


def hex_to_byte(s):
    return s.decode("hex")


def pad_to_length(key, length):
    """Return the padding"""
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    padding = []
    while len(key) + len(padding) < length:
        padding.append(random.choice(alphabet))

    return "".join(padding)


def pad_key(key):
    """Return the padding"""
    if len(key) < 16:
        return pad_to_length(key, 16)
    elif len(key) < 24:
        return pad_to_length(key, 24)
    elif len(key) < 32:
        return pad_to_length(key, 32)
    else:
        return None


def encrypt_messages(extended_key, iv, messages):
    """Encrypt a bunch of messages, in order, with the same IV.
    This approach uses a stream cipher"""
    cipher = AES.new(extended_key, AES.MODE_CFB, iv)
    enc_messages = [cipher.encrypt(message) for message in messages]
    return enc_messages


def decrypt_messages(extended_key, iv, messages):
    cipher = AES.new(extended_key, AES.MODE_CFB, iv)
    dec_messages = [cipher.decrypt(message) for message in messages]
    return dec_messages


def random_bytes(length):
    return Random.new().read(length)


def random_string(length):
    """Return random byte string of given length"""
    return Random.new().read(length)


def get_kdf_salt(num_bytes=32):
    return random_bytes(num_bytes)


def extend_key(key, salt):
    """Extend the given key into a key of length suitable for AES."""
    return KDF.PBKDF2(key, salt, count=1000)


def extend_key_fast(key, salt):
    """Extend the given key into a key of length suitable for AES.
    We use a low count because the derived key is never stored or transmitted.
    We only use this function in order to derive a different key for each entry.
    This is OK because our encryption is known-plaintext-attack resistant"""
    return KDF.PBKDF2(key, salt, count=1)


def get_iv():
    return Random.new().read(AES.block_size)


def decrypt_field_v2(extended_key, hex_ciphertext, iv):
    """Return decrypted string of extra field"""
    ciphertext = hex_to_byte(hex_ciphertext)
    if len(iv) < AES.block_size:
        raise TypeError("IV is too small")
    cipher = AES.new(extended_key, AES.MODE_CFB, iv)
    msg = cipher.decrypt(ciphertext)
    return msg


def decrypt_field_v1(key, salt, hex_ciphertext):
    """Return decrypted string of extra field"""
    full_ciphertext = hex_to_byte(hex_ciphertext)
    iv = full_ciphertext[-1 * AES.block_size:]
    if len(iv) < AES.block_size:
        raise TypeError("IV is too small")
    ciphertext = full_ciphertext[:-1 * AES.block_size]
    actual_key = hashlib.sha256(key + salt).digest()
    cipher = AES.new(actual_key, AES.MODE_CFB, iv)
    dec_extra = cipher.decrypt(ciphertext)
    return dec_extra


def decrypt_password(padded_key, hex_ciphertext):
    """Return the decrypted password"""
    ciphertext = hex_to_byte(hex_ciphertext)

    iv = ciphertext[:AES.block_size]
    enc_password = ciphertext[AES.block_size:]
    cipher = AES.new(padded_key, AES.MODE_CFB, iv)
    dec_password = cipher.decrypt(enc_password)
    return dec_password


def get_salt(size):
    """Create and return random salt of given size"""
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    chars = []
    for i in range(size):
        chars.append(random.choice(alphabet))
    return "".join(chars)


def random_hex(size):
    alphabet = "abcdef1234567890"
    chars = [random.choice(alphabet) for i in range(size)]
    return "".join(chars)


def get_hashed_password(password, salt):
    password = password.encode("utf-8")
    return hashlib.sha512(password + salt).hexdigest()
