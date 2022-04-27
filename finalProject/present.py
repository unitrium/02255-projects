from typing import List

encryption = []
decryption = []


SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
        0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
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


def sBoxLayer(state: List[bool], reverse: bool = False):
    """Provides the SBOXLayer operation in place on a state."""
    box = INVSBOX if reverse else SBOX
    for i in range(16):
        word = state[4*i] + state[4*i+1]*2 + state[4*i+2]*4 + state[4*i+3]*8
        word = box[word]
        state[4*i] = word & 0b0001
        state[4*i+1] = (word & 0b0010) >> 1
        state[4*i+2] = (word & 0b0100) >> 2
        state[4*i+3] = (word & 0b1000) >> 3


def pLayer(state: List[bool], reverse: bool = False) -> List[bool]:
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
    new_key_registry = convert_to_int(key_registry)
    new_key_registry = new_key_registry >> 60
    new_key_registry = new_key_registry & 0x0FFFFFFFFFFFFFFF | SBOX[(
        new_key_registry & 0xF000000000000000) >> 60] << 60
    bit15 = (round & 1) ^ (new_key_registry & 0x8000)  # Extract bit 15
    bit16 = (round & 1) ^ (new_key_registry & 0x10000)  # Extract bit 16
    bit17 = (round & 1) ^ (new_key_registry & 0x20000)  # Extract bit 17
    bit18 = (round & 1) ^ (new_key_registry & 0x40000)  # Extract bit 18
    bit19 = (round & 1) ^ (new_key_registry & 0x80000)  # Extract bit 19
    newBits = (bit15 + bit16 * 2 + bit17 * 4 + bit18 * 8 + bit19 * 16) << 15
    new_key_registry = (new_key_registry & 0xFFFFFFFFFFF07FFF) | newBits
    return convert_to_bitfield(new_key_registry)


def convert_to_bitfield(n: int):
    """Converts to an bitwise array representation and adds 0 if necessary."""
    value = [int(digit)
             for digit in bin(n)[2:]]  # [2:] to chop off the "0b" part
    padding = [0] * (64-len(value))
    return padding + value


def convert_to_int(bitfield: List[int]):
    """Converts a bitfield to an int."""
    value = 0
    for i in range(63):
        value += bitfield[i] * 2**i
    return value


def encrypt(plaintext: List[bool], key: List[bool]):
    """Encrypts a bitfield plaintext through PRESENT."""
    state = plaintext
    key_registry = key
    for round in range(31):
        roundKey = key_registry[:64]
        add_round_key(state, roundKey)
        sBoxLayer(state)
        state = pLayer(state)
        encryption.append(state)
        key_registry = update_registry(key_registry, round)
    add_round_key(state, key_registry[:64])
    encryption.append(state)
    return state


def compute_key_schedule(key: List[bool]) -> List[List[bool]]:
    """For the decryption compute the entire key_schedule."""
    key_registry = key
    schedule = []
    for round in range(31):
        schedule.append(key_registry[:64])
        key_registry = update_registry(key_registry, round)
    return schedule


def decrypt(ciphertext: List[int], key: int):
    """Decrypt a bitfield ciphertext through PRESENT."""
    schedule = compute_key_schedule(key)
    state = ciphertext
    add_round_key(state, schedule[-1])
    decryption.append(state)
    for roundKey in reversed(schedule[:-1]):
        state = pLayer(state, reverse=True)
        sBoxLayer(state, reverse=True)
        add_round_key(state, roundKey)
        decryption.append(state)
    return state


if __name__ == "__main__":
    plaintext = convert_to_bitfield(63)
    key = convert_to_bitfield(20)
    ciphertext = encrypt(plaintext, key)
    decipheredText = decrypt(ciphertext, key)
    assert ciphertext != plaintext
    assert decipheredText == plaintext
