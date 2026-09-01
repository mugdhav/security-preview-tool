"""Must-NOT-detect: authenticated encryption via Fernet."""
from cryptography.fernet import Fernet


def encrypt(plaintext):
    key = Fernet.generate_key()
    return key, Fernet(key).encrypt(plaintext)
