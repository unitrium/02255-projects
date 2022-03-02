from math import sqrt
from typing import List

from numpy import average
from utils import read_inputs
from aes import encrypt


def gen_h() -> List[List[int]]:
    """Generates the H matrix."""
    h = []
    for plaintext in read_inputs():
        line = []
        for key in range(256):
            line.append(encrypt(plaintext, key))
        h.append(line)
    return h


def coefficient(h: List[int], traces: List[int]) -> int:
    """Pearson correlation coefficient."""
    avg_h = average(h)
    avg_t = average(traces)
    numerator = 0
    deno_left = 0
    deno_right = 0
    for i in range(len(h)):
        numerator += (h[i] - avg_h)*(traces[i]-avg_t)
        deno_left += (h[i] - avg_h)**2
        deno_right += (traces[i]-avg_t)**2
    denominator = sqrt(deno_left*deno_right)
    return numerator/denominator
