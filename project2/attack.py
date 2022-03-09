from math import sqrt
from typing import List, Tuple
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


def compute_correlation_coefficient(h: List[int], traces: pd.DataFrame) -> int:
    """Given an H matrix column and traces generates the Pearson correlation coefficient."""
    avg_h = average(h)
    coefficient_over_time = []
    # Iterate over all timestamps in the traces to find
    #  the one where the encryption happens.
    for column in traces:
        trace = traces[column]
        avg_t = trace.mean()
        numerator = 0
        denominator_left = 0
        denominator_right = 0
        for i, element in enumerate(trace):
            numerator += (h[i] - avg_h)*(element-avg_t)
            denominator_left += (h[i] - avg_h)**2
            denominator_right += (element-avg_t)**2
        denominator = sqrt(denominator_left*denominator_right)
        coefficient_over_time.append(abs(numerator/denominator))
    return max(coefficient_over_time)


def attack(inputs_filename: str = './traces/inputs_test.dat', traces_filename: str = './traces/T_test.dat') -> Tuple[int, int]:
    """Given input and corresponding traces, try a differencial power analysis."""
    h = gen_h(inputs_filename)
    traces = read_traces(traces_filename)
    max_coef = 0
    most_likely_key = 0
    # Iterrate over all possible keys.
    for i in range(256):
        coef = compute_correlation_coefficient(h[:, i], traces)
        if coef > max_coef:
            most_likely_key = i
            max_coef = coef
    return max_coef, most_likely_key


if __name__ == "__main__":
    # Test with the test data set.
    _, key = attack()
    assert key == 203
