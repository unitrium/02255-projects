from random import choice
from typing import List
from utils import KEY

from aes import encrypt, add_round_key, shift_rows, sub_bytes, SBOX


def create_encrypt_alpha_set(column: int) -> List[List[int]]:
    "Return an encrypt delta set"
    alpha_set = gen_alpha_set(column)
    return [encrypt(value, KEY) for value in alpha_set]


def gen_alpha_set(column: int) -> List[List[int]]:
    "Create an delta set at the right byte (= column)"
    alpha_set = []
    for i in range(256):
        temp = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        temp[column] = i
        alpha_set.append(temp)
    return alpha_set


def reverse_last_round_on_byte(ciphertext: List[int], round_key: List[int]) -> List[int]:
    "Reverse the last round on one byte for a given key."
    "Step 01 : XOR with round key"
    state = add_round_key(ciphertext, round_key)
    "Step 02 : Inverse ShiftRow"
    state = shift_rows(state, True)
    "Step 03 : Inverse SubBytes"
    state = sub_bytes(state, True)
    return(state)


def check_guess(last_round_alpha_set: List[List[int]], column: int) -> bool:
    "Check our guess on a round key byte"
    total = 0
    "We XOR all the 256 values and verify if it's equal to 0"
    for _, value in enumerate(last_round_alpha_set):
        total ^= value[column]
    return (total == 0)


def guess_last_round_key() -> List[int]:
    " Guess the last roundkey with all the delta set. "
    key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    "Step 01 : for each byte of the round key, we're going to try the delta set with the guessed key"
    for i in range(16):
        temp_Round = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        temp_key = []
        cipher_alpha_set = create_encrypt_alpha_set(i)
        for byte in range(256):
            b = []
            temp_Round[i] = byte
            for ciphertext in cipher_alpha_set:
                b.append(shift_rows(
                    reverse_last_round_on_byte(ciphertext, temp_Round)))
            "Step 02 : Check the guess key"
            if (check_guess(b, i)):
                # print("Entrée n°", i)
                temp_key.append(byte)
        "Step 03 : Check the number of good guesses, if multiple good choices then supress the wrong one with other delta set"
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
    # print(key)
    return (key)


def get_previous_round_key(round_key: List[int], rnd: int):
    """Get the round key of the previous round."""
    previous = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    round_constant = [2**rnd, 0, 0, 0]
    # Forth Column
    previous[12] = round_key[8] ^ round_key[12]
    previous[13] = round_key[9] ^ round_key[13]
    previous[14] = round_key[10] ^ round_key[14]
    previous[15] = round_key[11] ^ round_key[15]
    # Third Column
    previous[8] = round_key[8] ^ round_key[4]
    previous[9] = round_key[9] ^ round_key[5]
    previous[10] = round_key[10] ^ round_key[6]
    previous[11] = round_key[11] ^ round_key[7]
    # Second Column
    previous[4] = round_key[4] ^ round_key[0]
    previous[5] = round_key[5] ^ round_key[1]
    previous[6] = round_key[6] ^ round_key[2]
    previous[7] = round_key[7] ^ round_key[3]
    # First Column
    # Step 1
    sub_rot_Word = [SBOX[previous[13]],
                    SBOX[previous[14]],
                    SBOX[previous[15]],
                    SBOX[previous[12]]]
    # Step 2
    previous[0] = round_constant[0] ^ round_key[0] ^ sub_rot_Word[0]
    previous[1] = round_constant[1] ^ round_key[1] ^ sub_rot_Word[1]
    previous[2] = round_constant[2] ^ round_key[2] ^ sub_rot_Word[2]
    previous[3] = round_constant[3] ^ round_key[3] ^ sub_rot_Word[3]
    return (previous)


def main():
    "Find last RoundKey thanks to deltaset"
    round_keys = []
    last_key = guess_last_round_key()
    round_keys.append(last_key)
    for i in range(4):
        round_keys.append(get_previous_round_key(round_keys[i], 3-i))
    print("The round keys are :")
    while (len(round_keys) != 0):
        print(round_keys.pop())


if __name__ == "__main__":
    main()
