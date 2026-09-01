"""Must-detect: insecure cipher."""
from Crypto.Cipher import DES


def make_cipher(key):
    return DES.new(key, DES.MODE_CBC)
