from attack import attack

if __name__ == "__main__":
    coef, key = attack(inputs_filename='./traces/inputs7.dat',
                       traces_filename='./traces/T7.dat')
    print(f'Most likely key: {key} with a coefficient of {coef}')
