Sbox = [0xe, 0x4, 0xb, 0x2, 0x3, 0x8, 0x0, 0x9, 0x1, 0xa, 0x7, 0xf, 0x6, 0xc, 0x5, 0xd]

M = [
    [0x2, 0x3, 0x1, 0x1],
    [0x1, 0x2, 0x3, 0x1],
    [0x1, 0x1, 0x2, 0x3],
    [0x3, 0x1, 0x1, 0x2],
]


def decrypt(Y, wk, rk):
    wktemp = [0, 0, 0, 0]
    wktemp[0] = wk[2]
    wktemp[1] = wk[3]
    wktemp[2] = wk[0]
    wktemp[3] = wk[1]
    wk = wktemp
    rknew = []
    for i in range(len(rk) // 2):
        if i % 2 == 0:
            rktemp_1 = rk[len(rk) - 2 * i - 2]
            rktemp_2 = rk[len(rk) - 2 * i - 1]
        else:
            rktemp_1 = rk[len(rk) - 2 * i - 1]
            rktemp_2 = rk[len(rk) - 2 * i - 2]
        rknew.append(rktemp_1)
        rknew.append(rktemp_2)
    return G(Y, wk, rknew)


def G(X, wk, rk):

    Xarr = []
    andbit = 0xFFFF

    for i in range(4):
        tempx = ((X >> (16 * (3 - i))) & andbit)
        if i == 0:
            tempx = tempx ^ wk[0]
        elif i == 2:
            tempx = tempx ^ wk[1]
        Xarr.append(tempx)

    number_rounds = len(rk) // 2

    for i in range(number_rounds - 1):
        Xarr[1] = Xarr[1] ^ f(Xarr[0]) ^ rk[2 * i]
        Xarr[3] = Xarr[3] ^ f(Xarr[2]) ^ rk[2 * i + 1]
        Xarr = permutation(Xarr)

    Xarr[1] = Xarr[1] ^ f(Xarr[0]) ^ rk[len(rk) - 2]
    Xarr[3] = Xarr[3] ^ f(Xarr[2]) ^ rk[len(rk) - 1]
    Xarr[0] = Xarr[0] ^ wk[2]
    Xarr[2] = Xarr[2] ^ wk[3]

    enc = (Xarr[0] << (16 * 3)) ^ (Xarr[1] << (16 * 2)) ^ (Xarr[2] << 16) ^ Xarr[3]
    return enc


def f(b):
    andbyte = 0xF
    X = []
    Y = [0, 0, 0, 0]
    ret = []
    for i in range(4):
        ind = b >> (4 * (3 - i)) & andbyte
        X.append(Sbox[ind])

    for i in range(4):
        Y[i] = (gf(X[0], M[i][0]) ^ gf(X[1], M[i][1]) ^ gf(X[2], M[i][2]) ^ gf(X[3], M[i][3]))
        ret.append(Sbox[Y[i]])

    return (ret[0] << 12) ^ (ret[1] << 8) ^ (ret[2] << 4) ^ ret[3]


def gf(a, b):
    retval = 0
    while b:
        if b & 1:
            retval = retval ^ a
        a <<= 1
        if a & 16:
            a = a ^ 0x13
        b >>= 1
    return retval


def permutation(input):
    X = []
    Y = [0, 0, 0, 0, 0, 0, 0, 0]
    andbyte = 0xFF

    for i in range(len(input)):
        X.append((input[i] >> 8) & andbyte)
        X.append(input[i] & andbyte)

    Y[0] = X[2]
    Y[1] = X[7]
    Y[2] = X[4]
    Y[3] = X[1]
    Y[4] = X[6]
    Y[5] = X[3]
    Y[6] = X[0]
    Y[7] = X[5]

    retval = []
    for i in range(0, len(Y), 2):
        app = (Y[i] << 8) ^ Y[i + 1]
        retval.append(app)

    return retval


def keyschedule80bit(key):
    andbit16 = 0xFFFF
    andbit8 = 0xFF
    r = 25
    k = []
    rk = []
    for i in range(5):
        tempk = key >> 16 * (4 - i) & andbit16
        kl = tempk >> 8 & andbit8
        kr = tempk & andbit8
        k.append([kl, kr])

    wk = []
    wk.append(k[0][0] << 8 ^ k[1][1])
    wk.append(k[1][0] << 8 ^ k[0][1])
    wk.append(k[4][0] << 8 ^ k[3][1])
    wk.append(k[3][0] << 8 ^ k[4][1])
    for i in range(r):
        con80 = (((i + 1) << 27) ^ ((i + 1) << 17) ^ ((i + 1) << 10) ^ (i + 1)) ^ 0x0f1e2d3c
        con80_r1 = con80 >> 16
        con80_r2 = con80 & andbit16
        if i % 5 == 0 or i % 5 == 2:
            rk.append(con80_r1 ^ (k[2][0] << 8 ^ k[2][1]))
            rk.append(con80_r2 ^ (k[3][0] << 8 ^ k[3][1]))
        elif i % 5 == 1 or i % 5 == 4:
            rk.append(con80_r1 ^ (k[0][0] << 8 ^ k[0][1]))
            rk.append(con80_r2 ^ (k[1][0] << 8 ^ k[1][1]))
        elif i % 5 == 3:
            rk.append(con80_r1 ^ (k[4][0] << 8 ^ k[4][1]))
            rk.append(con80_r2 ^ (k[4][0] << 8 ^ k[4][1]))

    return rk, wk


def keyschedule128bit(key):
    andbit16 = 0xFFFF
    andbit8 = 0xFF
    r = 31
    k = []
    rk = []
    for i in range(8):
        tempk = (key >> (16 * (7 - i))) & andbit16
        kl = tempk >> 8 & andbit8
        kr = tempk & andbit8
        k.append([kl, kr])
    wk = []
    wk.append((k[0][0] << 8) ^ k[1][1])
    wk.append((k[1][0] << 8) ^ k[0][1])
    wk.append((k[4][0] << 8) ^ k[7][1])
    wk.append((k[7][0] << 8) ^ k[4][1])

    for i in range(r):
        if (2 * i + 2) % 8 == 0:
            tempk = [0, 0, 0, 0, 0, 0, 0, 0]
            tempk[0] = k[2]
            tempk[1] = k[1]
            tempk[2] = k[6]
            tempk[3] = k[7]
            tempk[4] = k[0]
            tempk[5] = k[3]
            tempk[6] = k[4]
            tempk[7] = k[5]
            k = tempk

        con128 = (((i + 1) << 27) ^ ((i + 1) << 17) ^ ((i + 1) << 10) ^ (i + 1)) ^ 0x6547a98b
        con128_l = con128 >> 16
        con128_r = con128 & andbit16
        index_r1 = (2 * i + 2) % 8
        index_r2 = (2 * i + 2 + 1) % 8
        tempk_r1 = k[index_r1][0] << 8 ^ k[index_r1][1]
        tempk_r2 = k[index_r2][0] << 8 ^ k[index_r2][1]
        val_r1 = tempk_r1 ^ con128_l
        val_r2 = tempk_r2 ^ con128_r
        rk.append(val_r1)
        rk.append(val_r2)
    return rk, wk


if __name__ == "__main__":
    key128 = 0x00112233445566778899aabbccddeeff
    key80 = 0x0123456789abcdef
    msg = 0x0123456789abcdef
    rk128, wk128 = keyschedule128bit(key128)
    rk80, wk80 = keyschedule80bit(key80)
    cipher128 = G(msg, wk128, rk128)
    cipher80 = G(msg, wk80, rk80)
    decipher128 = decrypt(cipher128, wk128, rk128)
    decipher80 = decrypt(cipher80, wk80, rk80)
    if decipher128 == msg and decipher80 == msg:
        print("correct")
