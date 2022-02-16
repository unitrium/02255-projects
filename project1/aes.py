"""An implementation of AES-128 in Python."""
from copy import deepcopy
from typing import List
from collections import deque
from sbox import SBOX, INVSBOX
from utils import create_0_matrix

ROUNDS = 4


def encrypt(plaintext: List[List[int]], key: List[List[int]]):
    """Encrypt a plaintext."""
    round_keys = key_schedule_128(key)
    state = add_round_key(plaintext, round_keys[0])
    for rnd in range(ROUNDS - 1):
        state = normal_round(state, round_keys[rnd + 1])
    ciphertext = last_round(state, round_keys[ROUNDS-1])
    return ciphertext


def decrypt(ciphertext:  List[List[int]], key: List[List[int]]):
    """Decrypt a ciphertext."""
    round_keys = key_schedule_128(key)
    state = add_round_key(ciphertext, round_keys[-1])
    state = sub_bytes(shift_rows(state, inv=True), inv=True)
    for rnd in range(ROUNDS-2, 0, -1):
        state = add_round_key(state, round_keys[rnd])
        state = sub_bytes(shift_rows(mix_columns(
            state, inv=True), inv=True), inv=True)
    state = add_round_key(state, round_keys[0])


def normal_round(state, round_key):
    """Apply one round of AES to the state."""
    return add_round_key(mix_columns(shift_rows(sub_bytes(state))), round_key)


def last_round(state, round_key):
    """Apply the last round of AES to the state."""
    return add_round_key(shift_rows(sub_bytes(state)), round_key)


def add_round_key(state: List[List[int]], round_key: List[List[int]]) -> List[List[int]]:
    """Apply the AddRoundKey step to the state."""
    new_state = create_0_matrix()
    for i in range(4):
        for j in range(4):
            new_state[i][j] = state[i][j] ^ round_key[i][j]
    return new_state


def sub_bytes(
        state: List[List[int]], inv=False) -> List[List[int]]:
    """Apply the SubBytes step to the state."""
    box = INVSBOX if inv else SBOX
    new_state = create_0_matrix()

    # bitwise AND mask of 1111 0000 to get the left 4 bits of the byte.
    for i in range(4):
        for j in range(4):
            byte = state[i][j]
            new_state[i][j] = box[(byte & 0b11110000) >> 4][byte & 0b00001111]
    return new_state


def shift_rows(state: List[List[int]], inv=False) -> List[List[int]]:
    """Apply the ShiftRows step to the state."""
    sign = -1 if inv else 1
    new_state = [[], [], [], []]
    for i in range(4):
        line = deque(state[i])
        line.rotate(sign * i)
        new_state[i] = list(line)
    return new_state


def mix_columns(state: List[List[int]], inv=False) -> List[List[int]]:
    """Apply the MixColumns step to the state."""
    mix = inverse_mix_one_column if inv else mix_one_column
    col0 = mix([state[0][0], state[1][0], state[2][0], state[3][0]])
    col1 = mix([state[0][1], state[1][1], state[2][1], state[3][1]])
    col2 = mix([state[0][2], state[1][2], state[2][2], state[3][2]])
    col3 = mix([state[0][3], state[1][3], state[2][3], state[3][3]])
    return [
        [col0[0], col1[0], col2[0], col3[0]],
        [col0[1], col1[1], col2[1], col3[1]],
        [col0[2], col1[2], col2[2], col3[2]],
        [col0[3], col1[3], col2[3], col3[3]]
    ]


def multiply_by_two(byte: int) -> int:
    """Multiply byte by two, reducing the result with the Rijndael polynomial."""
    result = (byte << 1) & 0xFF
    if (byte >> 7) & 1 == 1:
        result ^= 0x1B
    return result


def multiply_by_nine(byte: int) -> int:
    """Shortcut for multiply by nine."""
    return multiply_by_eight(byte) ^ byte


def multiply_by_eleven(byte: int) -> int:
    """Shortcut for multiply by 11."""
    return multiply_by_two(multiply_by_four(byte) ^ byte) ^ byte


def multiply_by_thirteen(byte: int) -> int:
    """Shortcut for 13."""
    return multiply_by_four(multiply_by_two(byte) ^ byte) ^ byte


def multiply_by_fourteen(byte: int) -> int:
    """Shortcut for 14."""
    return multiply_by_two(multiply_by_two(multiply_by_two(byte) ^ byte) ^ byte)


def multiply_by_four(byte: int) -> int:
    """Shortcut for multiply by four."""
    return multiply_by_two(multiply_by_two(byte))


def multiply_by_eight(byte: int) -> int:
    """Shortcut for multiply by eight."""
    return multiply_by_two(multiply_by_four(byte))


def mix_one_column(col: List[int]) -> List[int]:
    """Multiply a column with the MixColumns matrix."""
    b_0, b_1, b_2, b_3 = col
    return [
        multiply_by_two(b_0) ^       # 02 * b_0
        multiply_by_two(b_1) ^ b_1 ^  # 03 * b_1
        b_2 ^ b_3,                   # 01 * b_2 + 01 * b_3
        b_0 ^                        # 01 * b_0
        multiply_by_two(b_1) ^       # 02 * b_1
        multiply_by_two(b_2) ^ b_2 ^  # 03 * b_2
        b_3,                         # 01 * b_3
        b_0 ^ b_1 ^                  # 01 * b_0 + 01 * b_1
        multiply_by_two(b_2) ^       # 02 * b_2
        multiply_by_two(b_3) ^ b_3,  # 03 * b_3
        multiply_by_two(b_0) ^ b_0 ^  # 03 * b_0
        b_1 ^ b_2 ^                  # 01 * b_1 + 01 * b_2
        multiply_by_two(b_3),        # 02 * b_3
    ]


def inverse_mix_one_column(col: List[int]) -> List[int]:
    """Multiply a column with the inverse MixColumns matrix."""
    b_0, b_1, b_2, b_3 = col
    return [
        multiply_by_fourteen(b_0) ^
        multiply_by_eleven(b_1) ^
        multiply_by_thirteen(b_2) ^
        multiply_by_nine(b_3),
        multiply_by_nine(b_0) ^
        multiply_by_fourteen(b_1) ^
        multiply_by_eleven(b_2) ^
        multiply_by_thirteen(b_3),
        multiply_by_thirteen(b_0) ^
        multiply_by_nine(b_1) ^
        multiply_by_fourteen(b_2) ^
        multiply_by_eleven(b_3),
        multiply_by_eleven(b_0) ^
        multiply_by_thirteen(b_1) ^
        multiply_by_nine(b_2) ^
        multiply_by_fourteen(b_3),
    ]


def key_schedule_128(key: List[List[int]]):
    """Create the list of round keys from the key."""
    round_keys = [deepcopy(key)]
    round_constant = 1
    for i in range(1, ROUNDS):
        b_0, b_1, b_2, b_3 = (
            round_keys[i-1][3][1],
            round_keys[i-1][3][2],
            round_keys[i-1][3][3],
            round_keys[i-1][3][0],
        )
        b_0 = SBOX[(b_0 & 0b11110000) >> 4][b_0 &
                                            0b00001111]
        b_1 = SBOX[(b_1 & 0b11110000) >> 4][b_1 &
                                            0b00001111]
        b_2 = SBOX[(b_2 & 0b11110000) >> 4][b_2 &
                                            0b00001111]
        b_3 = SBOX[(b_3 & 0b11110000) >> 4][b_3 &
                                            0b00001111]
        b_0 ^= round_constant
        round_constant = multiply_by_two(round_constant)
        new_round_key = [[
            round_keys[i-1][0][0] ^ b_0,
            round_keys[i-1][0][1] ^ b_1,
            round_keys[i-1][0][2] ^ b_2,
            round_keys[i-1][0][3] ^ b_3,
        ]]
        for j in range(1, 4):
            new_round_key.append(
                [new_round_key[j-1][k] ^ round_keys[i-1][j][k]
                    for k in range(4)]
            )
        round_keys.append(new_round_key)
    return round_keys


def main():
    """Test the implementation with some test vectors."""
    # Test basic funtions
    assert multiply_by_two(0x80) == 0x1B
    assert mix_one_column([0xDB, 0x13, 0x53, 0x45]) == [0x8E, 0x4D, 0xA1, 0xBC]

    # Test round transformations
    before_sub_bytes = [[0x19, 0x3D, 0xE3, 0xBE],
                        [0xA0, 0xF4, 0xE2, 0x2B],
                        [0x9A, 0xC6, 0x8D, 0x2A],
                        [0xE9, 0xF8, 0x48, 0x08]]
    after_sub_bytes = [[0xD4, 0x27, 0x11, 0xAE], [0xE0, 0xBF, 0x98, 0xF1],
                       [0xB8, 0xB4, 0x5D, 0xE5], [0x1E, 0x41, 0x52, 0x30]]
    after_shift_rows = [[0xD4, 0xBF, 0x5D, 0x30], [0xE0, 0xB4, 0x52, 0xAE],
                        [0xB8, 0x41, 0x11, 0xF1], [0x1E, 0x27, 0x98, 0xE5]]
    after_mix_columns = [[0x04, 0x66, 0x81, 0xE5], [0xE0, 0xCB, 0x19, 0x9A], [
        0x48, 0xF8, 0xD3, 0x7A], [0x28, 0x06, 0x26, 0x4C]]
    assert sub_bytes(before_sub_bytes) == after_sub_bytes
    print(after_sub_bytes)
    print(shift_rows(after_sub_bytes))
    print(after_shift_rows)
    #assert shift_rows(after_sub_bytes) == after_shift_rows
    # assert mix_columns(after_shift_rows) == after_mix_columns

    # # Test full encryption
    # plaintext = [0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
    #              0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34]
    # key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    #        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C]
    # ciphertext = [0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
    #               0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32]
    # assert encrypt(plaintext, key) == ciphertext


if __name__ == "__main__":
    main()
