from math import sqrt
from typing import List
import numpy as np
import pandas as pd

from numpy import average
from utils import read_inputs, read_traces
from aes import encrypt


def gen_h(trace_file: str = "./traces/inputs7.dat") -> List[List[int]]:
    """Generates the H matrix."""
    h = []
    for plaintext in read_inputs(trace_file):
        line = []
        for key in range(256):
            line.append(encrypt(plaintext, key))
        h.append(line)
    return np.array(h)


def coefficient(h: List[int], traces: pd.DataFrame) -> int:
    """Pearson correlation coefficient."""
    avg_h = average(h)
    coefficient_over_time = []
    for column in traces:
        trace = traces[column]
        avg_t = trace.mean()
        numerator = 0
        deno_left = 0
        deno_right = 0
        for i, element in enumerate(trace):
            numerator += (h[i] - avg_h)*(element-avg_t)
            deno_left += (h[i] - avg_h)**2
            deno_right += (element-avg_t)**2
        denominator = sqrt(deno_left*deno_right)
        coefficient_over_time.append(abs(numerator/denominator))
    return max(coefficient_over_time)


if __name__ == "__main__":
    h = gen_h()  # trace_file='./traces/inputs_test.dat')
    traces = read_traces()  # filename='./traces/T_test.dat')
    max_coef = 0
    index = 0
    for i in range(256):
        print(i)
        coef = coefficient(h[:, i], traces)
        if coef > max_coef:
            index = i
            max_coef = coef
    print(f"Most likely key:{index}, {coef}")
