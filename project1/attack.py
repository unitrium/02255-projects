from copy import deepcopy
from typing import List, Set

from .utils import KEY
from .aes import encrypt, add_round_key, sub_bytes, mix_columns, shift_rows


def create_encrypt_alpha_set(state: List[List[int]] = None, activeLine: int = 0, activeColumn: int = 0) -> Set[List[List[int]]]:
    """Create an alpha set filled with 0 and encrypt it."""
    if state is None:
        state = [[0] * 4] * 4
    alpha_set = gen_alpha_set(state, activeLine, activeColumn)
    return set([encrypt(value, KEY) for value in alpha_set])


def gen_alpha_set(state: List[List[int]], activeLine: int = 0, activeColumn: int = 0) -> Set[List[List[int]]]:
    """Create an alpha set."""
    alpha_set = set()
    for i in range(256):
        current = deepcopy(state)
        current[activeLine][activeColumn] = i
        alpha_set.add(current)
    return alpha_set


def reverse_last_round_on_byte(ciphertext: List[List[int]], round_key: List[List[int]], activeLine: int = 0, activeColumn: int = 0) -> List[List[int]]:
    """Reverse the last round on one byte for a given key."""
    state = add_round_key(ciphertext, round_key)
    state = shift_rows(ciphertext, inv=True)
    return state[activeLine][activeColumn]


def check_guess(state: List[List[int]], activeColumn: int = 0) -> bool:
    """Checks that a guess on a round key byte is correct."""
    sum = 0
    # number of matrix in an alpha set = 256
    for _, value in enumerate(state):
        sum ^= value[activeColumn]
    return (sum == 0)
