from sbox import SBOX
from utils import hamming_weight


def encrypt(plaintext: int, key: int):
    """Encrypts a plaintext of bytes through the first round of AES and the SBOX."""
    return hamming_weight(SBOX[plaintext ^ key])
