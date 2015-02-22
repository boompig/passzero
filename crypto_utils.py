from Crypto.Cipher import AES
from Crypto import Random
import random
import hashlib


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


def encrypt_password(padded_key, password):
    """Return encrypted password where encrypted password is a hex string"""

    iv = Random.new().read(AES.block_size)
    cipher = AES.new(padded_key, AES.MODE_CFB, iv)
    enc_password = iv + cipher.encrypt(password)

    return byte_to_hex(enc_password)


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
    return hashlib.sha512(password + salt).hexdigest()
