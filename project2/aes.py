from typing import List
from sbox import SBOX
from utils import hamming_weight, read_inputs


def encrypt(plaintext: int, key: int):
    """Encrypts a plaintext of bytes through the first round of AES and the SBOX."""
    return SBOX[plaintext ^ key]


if __name__ == "__name__":
    print(gen_h())
