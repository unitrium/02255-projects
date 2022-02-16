from aes import encrypt
from typing import List
from utils import KEY


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
