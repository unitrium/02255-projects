"""An implementation of AES-128 in Python."""
from typing import List
from sbox import SBOX, INVSBOX
ROUNDS = 4


def main():
    """Test the implementation with some test vectors."""
    # Test basic funtions
    assert multiply_by_two(0x80) == 0x1B
    assert mix_one_column([0xDB, 0x13, 0x53, 0x45]) == [0x8E, 0x4D, 0xA1, 0xBC]

    # Test round transformations
    before_sub_bytes = [0x19, 0x3D, 0xE3, 0xBE, 0xA0, 0xF4, 0xE2, 0x2B,
                        0x9A, 0xC6, 0x8D, 0x2A, 0xE9, 0xF8, 0x48, 0x08]
    after_sub_bytes = [0xD4, 0x27, 0x11, 0xAE, 0xE0, 0xBF, 0x98, 0xF1,
                       0xB8, 0xB4, 0x5D, 0xE5, 0x1E, 0x41, 0x52, 0x30]
    after_shift_rows = [0xD4, 0xBF, 0x5D, 0x30, 0xE0, 0xB4, 0x52, 0xAE,
                        0xB8, 0x41, 0x11, 0xF1, 0x1E, 0x27, 0x98, 0xE5]
    after_mix_columns = [0x04, 0x66, 0x81, 0xE5, 0xE0, 0xCB, 0x19, 0x9A,
                         0x48, 0xF8, 0xD3, 0x7A, 0x28, 0x06, 0x26, 0x4C]
    assert sub_bytes(before_sub_bytes) == after_sub_bytes
    assert shift_rows(after_sub_bytes) == after_shift_rows
    assert mix_columns(after_shift_rows) == after_mix_columns

    # Test full encryption
    plaintext = [0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
                 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34]
    key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
           0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C]
    ciphertext = [0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
                  0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32]
    assert encrypt(plaintext, key) == ciphertext


def encrypt(plaintext, key):
    """Encrypt a plaintext."""
    round_keys = key_schedule_128(key)
    state = add_round_key(plaintext, round_keys[0])
    for rnd in range(ROUNDS - 1):
        state = normal_round(state, round_keys[rnd + 1])
    ciphertext = last_round(state, round_keys[ROUNDS])
    return ciphertext


def decrypt(ciphertext: List[int], key: List[int]) -> List[int]:
    """Decrypt a ciphertext."""
    round_keys = key_schedule_128(key)
    state = add_round_key(ciphertext, round_keys[-1])
    state = sub_bytes(shift_rows(state, inv=True), inv=True)
    for rnd in range(ROUNDS-2, 0, -1):
        state = add_round_key(state, round_keys[rnd])
        state = sub_bytes(shift_rows(mix_columns(
            state, inv=True), inv=True), inv=True)
    state = add_round_key(state, round_keys[0])
    return state


def normal_round(state, round_key):
    """Apply one round of AES to the state."""
    return add_round_key(mix_columns(shift_rows(sub_bytes(state))), round_key)


def last_round(state, round_key):
    """Apply the last round of AES to the state."""
    return add_round_key(shift_rows(sub_bytes(state)), round_key)


def add_round_key(state, round_key):
    """Apply the AddRoundKey step to the state."""
    new_state = []
    for i in range(16):
        new_state.append(state[i] ^ round_key[i])
    return new_state


def sub_bytes(state: List[int], inv=False):
    """Apply the SubBytes step to the state."""
    box = INVSBOX if inv else SBOX
    new_state = []
    for i in range(16):
        new_state.append(box[state[i]])
    return new_state


def shift_rows(state: List[int], inv=False):
    """Apply the ShiftRows step to the state."""
    if not inv:
        new_state = [
            state[0],
            state[5],
            state[10],
            state[15],
            state[4],
            state[9],
            state[14],
            state[3],
            state[8],
            state[13],
            state[2],
            state[7],
            state[12],
            state[1],
            state[6],
            state[11],
        ]
    else:
        new_state = [
            state[0],
            state[13],
            state[10],
            state[7],
            state[4],
            state[1],
            state[14],
            state[11],
            state[8],
            state[5],
            state[2],
            state[15],
            state[12],
            state[9],
            state[6],
            state[3]
        ]
    return new_state


def mix_columns(state: List[int], inv=False):
    """Apply the MixColumns step to the state."""
    mix = inv_mix_one_column if inv else mix_one_column
    new_state = (
        mix([state[0], state[1], state[2], state[3]])
        + mix([state[4], state[5], state[6], state[7]])
        + mix([state[8], state[9], state[10], state[11]])
        + mix([state[12], state[13], state[14], state[15]])
    )
    return new_state


def multiply_by_two(byte):
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


def inv_mix_one_column(col: List[int]) -> List[int]:
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


def key_schedule_128(key: List[int]) -> List[List[int]]:
    """Create the list of round keys from the key."""
    round_keys = [[key[i] for i in range(16)]]
    round_constant = 1
    for i in range(ROUNDS):
        b_0, b_1, b_2, b_3 = (
            SBOX[round_keys[i][13]],
            SBOX[round_keys[i][14]],
            SBOX[round_keys[i][15]],
            SBOX[round_keys[i][12]],
        )
        b_0 ^= round_constant
        round_constant = multiply_by_two(round_constant)
        new_round_key = [
            round_keys[i][0] ^ b_0,
            round_keys[i][1] ^ b_1,
            round_keys[i][2] ^ b_2,
            round_keys[i][3] ^ b_3,
        ]
        for j in range(3):
            for k in range(4):
                new_round_key.append(
                    new_round_key[k + 4 * j] ^ round_keys[i][k + 4 * (j + 1)]
                )
        round_keys.append(new_round_key)
    return round_keys


if __name__ == "__main__":
    main()
