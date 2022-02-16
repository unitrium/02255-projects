from copy import deepcopy
from random import choice
from collections import deque
from typing import List, Set

from sbox import SBOX
from utils import KEY, create_0_matrix
from aes import encrypt, add_round_key, shift_rows


def create_encrypt_alpha_set(state: List[List[int]] = None, activeLine: int = 0, activeColumn: int = 0) -> List[List[List[int]]]:
    """Create an alpha set filled with 0 and encrypt it."""
    if state is None:
        state = create_0_matrix()
    alpha_set = gen_alpha_set(state, activeLine, activeColumn)
    return [encrypt(value, KEY) for value in alpha_set]


def gen_alpha_set(state: List[List[int]], activeLine: int = 0, activeColumn: int = 0) -> List[List[List[int]]]:
    """Create an alpha set."""
    alpha_set = []
    for i in range(256):
        current = deepcopy(state)
        current[activeLine][activeColumn] = i
        alpha_set.append(current)
    return alpha_set


def reverse_last_round_on_byte(ciphertext: List[List[int]], round_key: List[List[int]], activeLine: int = 0, activeColumn: int = 0) -> int:
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


def get_previous_round_key(round_key: List[List[int]], round: int = 4):
    """Get the round key of the previous round."""
    previous = create_0_matrix()
    for line in range(3, 1, -1):
        for col in range(4):
            previous[line][col] = round_key[line][col] ^ round_key[line-1][col]
    line = deque(previous[3]).rotate(1)
    previous[0] = list(line)
    for i in range(4):
        byte = previous[0][i]
        previous[0][i] = SBOX[(byte & 0b11110000) >> 4][byte & 0b00001111]
    previous[0][0] ^= round**2
    for i in range(4):
        previous[0][i] = round_key[0][i] ^ previous[0][i]
    return previous


def guess_last_round_key(ciphertext: List[List[int]]) -> List[List[int]]:
    """Guess last round key from a ciphertext."""
    key = [[[] for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            for byte in range(256):
                round_key = create_0_matrix()
                round_key[i][j] = byte
                state = create_0_matrix()
                state[i][j] = reverse_last_round_on_byte(
                    ciphertext, round_key, i, j)
                alpha_set = gen_alpha_set(state, i, j)
                if check_guess(alpha_set, i, j):
                    key[i][j].append(byte)
            if len(key[i][j]) > 1:
                line = choice([k for k in range(4) if k != i])
                col = choice([k for k in range(4) if k != j])
                test_alpha_set = create_encrypt_alpha_set(
                    activeLine=line, activeColumn=col)
                for byte in key[i][j]:
                    round_key = create_0_matrix()
                    round_key[i][j] = byte
                    reversed_test_alpha_set = [
                        create_0_matrix() for _ in range(256)]
                    for index, al_set in enumerate(test_alpha_set):
                        reversed_test_alpha_set[index][i][j] = reverse_last_round_on_byte(
                            al_set, round_key, i, j)
                    if not check_guess(reversed_test_alpha_set, i, j):
                        key[i][j].remove(byte)
                if len(key[i][j]) != 1:
                    raise Exception(
                        f"Number of bytes at position {i}, {j}: {len(key[i][j])}")
    return key


def main():
    """Example usage."""
    plaintext = [
        [0x2F, 0x7E, 0x15, 0x16],
        [0x28, 0xEE, 0xD2, 0xA6],
        [0xAB, 0xF7, 0x15, 0x98],
        [0x09, 0xCF, 0x4F, 0x3C]
    ]
    ciphertext = encrypt(plaintext, KEY)
    print(f"Cipher text is : {ciphertext}")

    last_round_key = guess_last_round_key(ciphertext)
    print(f"Last round key is : {last_round_key}")
    round_key = last_round_key
    for i in range(4, 0, -1):
        round_key = get_previous_round_key(round_key, i)

    print("Obtained round key is:")
    print(round_key)
    print("Actual round key is:")
    print(KEY)


if __name__ == "__main__":
    main()
