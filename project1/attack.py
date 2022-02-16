from copy import deepcopy
from collections import deque
from typing import List, Set

from project1.sbox import SBOX

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


def check_guess(state: List[List[List[int]]], activeLine: int = 0, activeColumn: int = 0) -> bool:
    """Checks that a guess on a round key byte is correct."""
    sum = 0
    # number of matrix in an alpha set = 256
    for _, value in enumerate(state):
        sum ^= value[activeLine][activeColumn]
    return (sum == 0)


def find_correct_key(possible_keys: List[List[List[int]]], ciphertext: List[List[int]]) -> List[List[int]]:
    """Removes the false positives to return the one true key."""
    pass


def get_previous_round_key(round_key: List[List[int]], round: int = 4):
    """Get the round key of the previous round."""
    previous = [[0] * 4] * 4
    for line in range(3, 1, -1):
        for col in range(4):
            previous[line][col] = round_key[line][col] ^ round_key[line-1][col]
    line = deque(previous[3]).rotate(1)
    previous[0] = list(line)
    for i in range(4):
        value = previous[0][i]
        previous[0][i] = SBOX[(value & 0b11110000) >> 4][value &
                                                         0b00001111]
    previous[0][0] ^= round**2
    for i in range(4):
        previous[0][i] = round_key[0][i] ^ previous[0][i]
    return previous


def guess_last_round_key(ciphertext: List[List[int]]) -> List[List[int]]:
    """Guess last round key from a ciphertext."""
    key = [[[]] * 4] * 4
    for i in range(4):
        for j in range(4):
            for byte in range(256):
                round_key = [[0] * 4] * 4
                round_key[i][j] = byte
                state = reverse_last_round_on_byte(ciphertext, round_key, i, j)
                alpha_set = gen_alpha_set(state, i, j)
                if check_guess(alpha_set, i, j):
                    key[i][j].append(byte)
    return find_correct_key(key, ciphertext)


def main():
