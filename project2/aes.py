from typing import List
from sbox import SBOX


def encrypt(plaintext: List[int], key: int):
    """Encrypts a plaintext of bytes through the first round of AES and the SBOX."""
    return [SBOX[byte ^ key] for byte in plaintext]
