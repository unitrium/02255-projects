from copy import deepcopy
from typing import List, Set

from .utils import KEY
from .aes import encrypt


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


def check_guess(state: List[List[int]], round_key: List[List[int]]) -> bool:
    """Checks that a guess on a round key byte is correct."""
    pass
