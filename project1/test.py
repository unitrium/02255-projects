from attack import get_previous_round_key
from aes import key_schedule_128
from utils import KEY


def main():
    """Test some functions."""
    schedule = key_schedule_128(KEY)
    previous = get_previous_round_key(schedule[-1], 3)
    assert schedule[-2] == previous
    previous = get_previous_round_key(schedule[-2], 2)
    assert schedule[-3] == previous
    previous = get_previous_round_key(schedule[-3], 1)
    assert schedule[-4] == previous
    previous = get_previous_round_key(schedule[-4], 0)
    assert KEY == previous


if __name__ == "__main__":
    main()
    print("Ok")
