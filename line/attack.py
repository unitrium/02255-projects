from aes import encrypt, multiply_by_two
from typing import List
from utils import KEY, create_0_list
from collections import deque
from sbox import SBOX


def create_encrypt_alpha_set(column: int) -> List[List[int]]:
    "Return an encrypt alphaset"
    alpha_set = gen_alpha_set(column)
    return [encrypt(value, KEY) for value in alpha_set]


def gen_alpha_set(column: int) -> List[List[int]]:
    "Create an alpha set with byte number "
    alpha_set = []
    for i in range(256):
        temp = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        temp[column] = i
        alpha_set.append(temp)
    return alpha_set


def get_previous_round_key(round_key: List[int], rnd: int = 3):
    """Get the round key of the previous round."""
    previous = create_0_list()
    round_constant = 1
    for i in range(rnd):
        round_constant = multiply_by_two(round_constant)
    for col in range(4):
        for line in range(3, -1, -1):
            previous[4 * line + col] = round_key[4 *
                                                 line + col] ^ round_key[4 * line - 4 + col]
    line = deque(previous[12:])
    line.rotate(-1)
    line = list(line)
    for i in range(4):
        byte = SBOX[line[i]]
        if i == 0:
            byte ^= round_constant
        previous[i] = round_key[i] ^ byte
    return previous
