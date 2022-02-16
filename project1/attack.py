from aes import encrypt, multiply_by_two, add_round_key, shift_rows, sub_bytes
from typing import List
from random import choice
from project1old.aes import last_round
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


def reverse_last_round_on_byte(ciphertext: List[int], round_key: List[int]) -> List[int]:
    "Reverse the last round on one byte for a given key."
    # Step 01 : XOR with round key
    state = add_round_key(ciphertext, round_key)
    # Step 02 : Inverse ShiftRow
    state = shift_rows(state, True)
    # Step 03 : Inverse SubBytes
    state = sub_bytes(state, True)
    return(state)


def check_guess(last_round_alpha_set: List[List[int]], column: int) -> bool:
    "Check our guess on a round key byte on a column"
    total = 0
    for _, value in enumerate(last_round_alpha_set):
        total ^= value[column]
    return (total == 0)


def guess_last_round_key() -> List[int]:
    " Guess last round key from a ciphertext. "
    key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    n = 16
    # Step 01 : for each byte of the round key, we're going to try the reverse with the guessed key
    for i in range(n):
        temp_Round = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        temp_key = []
        cipher_alpha_set = create_encrypt_alpha_set(i)
        for byte in range(256):
            b = []
            temp_Round[i] = byte
            for ciphertext in cipher_alpha_set:
                b.append(shift_rows(
                    reverse_last_round_on_byte(ciphertext, temp_Round)))
            # Step 02 : Check the guess key
            if (check_guess(b, i)):
                temp_key.append(byte)
        # Step 03 : Check the number of good guess, if multiple good choice then supress the wrong one
        if (len(temp_key) > 1):
            test = choice([k for k in range(16) if k not in [i]])
            cipher_alpha_set_2 = create_encrypt_alpha_set(test)
            for item in temp_key:
                b = []
                temp_Round[i] = item
                for ciphertext in cipher_alpha_set_2:
                    b.append(shift_rows(
                        reverse_last_round_on_byte(ciphertext, temp_Round)))
                if (check_guess(b, i)):
                    key[i] = item
        else:
            key[i] = temp_key[0]
    return (key)


def main():
    """Example attack flow."""
    plaintext = [
        0x2F, 0x7E, 0x11, 0x16,
        0x28, 0xAE, 0xD4, 0xA6,
        0xA9, 0x77, 0x35, 0x88,
        0x09, 0xCF, 0x4F, 0x3C
    ]
    ciphertext = encrypt(plaintext, KEY)
    round_key = guess_last_round_key(ciphertext)
    for i in range(3, -1, -1):
        round_key = get_previous_round_key(round_key, i)
    assert round_key == KEY


if __name__ == "__main__":
    main()
