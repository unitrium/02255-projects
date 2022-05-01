"""Lightweight Cryptographic implementation of PRESENT. By Robin TROESCH"""
from typing import List

SBOX = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd,
        0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]
INVSBOX = [0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2,
           0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA]

PERMUTATION_BOX = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
                   4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
                   8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
                   12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]

INV_PERMUTATION_BOX = [0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
                       1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
                       2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
                       3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63]

INV_PERMUTATION_BOX = [PERMUTATION_BOX.index(x) for x in range(64)]


def s_box_layer(state: List[bool], reverse: bool = False):
    """Provides the SBOXLayer operation in place on a state."""
    box = INVSBOX if reverse else SBOX
    for i in range(16):
        word = state[4*i]*8 + state[4*i+1]*4 + state[4*i+2]*2 + state[4*i+3]
        word = box[word]
        state[4*i+3] = word & 0b0001
        state[4*i+2] = (word & 0b0010) >> 1
        state[4*i+1] = (word & 0b0100) >> 2
        state[4*i] = (word & 0b1000) >> 3


def p_layer(state: List[bool], reverse: bool = False) -> List[bool]:
    """Provides the permutation layer."""
    box = INV_PERMUTATION_BOX if reverse else PERMUTATION_BOX
    new_state = [0] * 64
    for index, bit in enumerate(state):
        new_state[box[index]] = bit
    return new_state


def add_round_key(state: List[bool], roundKey: List[bool]):
    """Provides the add round key operation."""
    for i in range(64):
        state[i] = state[i] ^ roundKey[i]


def update_registry(key_registry: List[bool], round: int) -> List[bool]:
    """Returns an updated key registry through PRESENT key schedule."""
    # The registry key is computed as an integer to allow for easier computation.
    new_key_registry = convert_to_int(key_registry)
    new_key_registry = ((new_key_registry & (2 ** 19 - 1))
                        << 61) + (new_key_registry >> 19)
    new_key_registry = (SBOX[new_key_registry >> 76] <<
                        76)+(new_key_registry & (2**76-1))
    new_key_registry ^= round << 15
    return convert_to_bitfield(new_key_registry, 80)


def convert_to_bitfield(n: int, size: int = 64):
    """Converts to an bitwise array representation and adds 0 if necessary."""
    value = [int(digit)
             for digit in bin(n)[2:]]  # [2:] to chop off the "0b" part
    padding = [0] * (size-len(value))
    return padding + value


def convert_to_int(bitfield: List[int]):
    """Converts a bitfield to an int."""
    value = 0
    nb_bits = len(bitfield) - 1
    for i in range(nb_bits, -1, -1):
        value += bitfield[nb_bits-i] * 2**i
    return value


def encrypt(plaintext: List[bool], key: List[bool]):
    """Encrypts a bitfield plaintext through PRESENT."""
    state = plaintext
    key_registry = key
    for i in range(1, 32):
        roundKey = key_registry[:64]
        add_round_key(state, roundKey)
        s_box_layer(state)
        state = p_layer(state)
        key_registry = update_registry(key_registry, i)
    add_round_key(state, key_registry[:64])
    return state


def compute_key_schedule(key: List[bool]) -> List[List[bool]]:
    """For the decryption compute the entire key_schedule."""
    key_registry = key
    schedule = []
    for round in range(1, 33):
        schedule.append(key_registry[:64])
        key_registry = update_registry(key_registry, round)
    return schedule


def decrypt(ciphertext: List[int], key: int):
    """Decrypt a bitfield ciphertext through PRESENT."""
    schedule = compute_key_schedule(key)
    state = ciphertext
    add_round_key(state, schedule[-1])
    for roundKey in reversed(schedule[:-1]):
        state = p_layer(state, reverse=True)
        s_box_layer(state, reverse=True)
        add_round_key(state, roundKey)
    return state


if __name__ == "__main__":
    plaintext = convert_to_bitfield(0)
    key = convert_to_bitfield(0, 80)
    ciphertext = encrypt(plaintext, key)
    decipheredText = decrypt(ciphertext, key)

    assert convert_to_int(decipheredText) == 0
