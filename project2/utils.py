import pandas as pd


def read_inputs(filename: str = './traces/inputs7.dat'):
    """Reads the inputs."""
    with open(filename) as file:
        return list(map(lambda x: int(x), file.readline().split(",")))


def read_traces(filename: str = './traces/T7.dat') -> pd.DataFrame:
    """Read traces."""
    return pd.read_table(filename, sep=",").to_numpy()


def hamming_weight(byte: int) -> int:
    """Calculates the hamming weight of a byte, the number of 1 in the binary representation."""
    return bin(byte).count('1')


if __name__ == "__main__":
    print(read_traces())
    print(read_inputs())
