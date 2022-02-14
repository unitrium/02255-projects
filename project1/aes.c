#include "aes.h"

void SubBytes(block b, int activeIndexX, int activeIndexY)
{
    char left = b[activeIndexX][activeIndexY] & 240; //bitwise AND mask of 1111 0000 to get the left 4 bits of the byte.
    char right = b[activeIndexX][activeIndexY] & 15; //bitwise AND mask of 0000 1111 to get the remaining 4 bits of the byte.
    b[activeIndexX][activeIndexY] = S[left >> 4][right];
}

void InvSubBytes(block b, int activeIndexX, int activeIndexY)
{
    char left = b[activeIndexX][activeIndexY] & 240; //bitwise AND mask of 1111 0000 to get the left 4 bits of the byte.
    char right = b[activeIndexX][activeIndexY] & 15; //bitwise AND mask of 0000 1111 to get the remaining 4 bits of the byte.
    b[activeIndexX][activeIndexY] = SI[left >> 4][right];
}

void ShiftRows(block b)
{
    unsigned char temp;
    // Second row
    temp = b[1][3];
    b[1][3] = b[1][2];
    b[1][2] = b[1][1];
    b[1][0] = temp;

    // Third row
    temp = b[2][3];
    b[2][3] = b[2][1];
    b[2][1] = temp;
    temp = b[2][2];
    b[2][2] = b[2][0];
    b[2][0] = temp;

    // Fourth row
    temp = b[3][3];
    b[3][3] = b[3][0];
    b[3][0] = b[3][1];
    b[3][1] = b[3][2];
    b[3][2] = temp;
}

void InvShiftRows(block b)
{
    unsigned char temp;
    // Second row
    temp = b[1][3];
    b[1][3] = b[1][0];
    b[1][0] = b[1][1];
    b[1][1] = b[1][2];
    b[1][2] = temp;

    //Third row
    temp = b[2][3];
    b[2][3] = b[2][1];
    b[2][1] = temp;
    temp = b[2][2];
    b[2][2] = b[2][0];
    b[2][0] = temp;

    // Fourth row
    temp = b[3][3];
    b[3][3] = b[3][2];
    b[3][2] = b[3][1];
    b[3][1] = b[3][0];
    b[3][0] = temp;
}

void MixColumns(block b)
{
}

void InvMixColumns(block b)
{
}

void AddRoundKey(block b, block roundKey)
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            b[i][j] = b[i][j] ^ roundKey[i][j];
        }
    }
}

void KeySchedule(block *schedule, int rounds, block key)
{
    block roundKeys[rounds];
    roundKeys[0] = key;
    const roundConstant = 1;
    for (int round = 1; round <= rounds; round++)
    {
        char b0 = S[roundKeys[round - 1][3][1] & 15][roundKeys[round - 1][3][1] & 240];
        char b1 = S[roundKeys[round - 1][3][2] & 15][roundKeys[round - 1][3][2] & 240];
        char b2 = S[roundKeys[round - 1][3][3] & 15][roundKeys[round - 1][3][3] & 240];
        char b3 = S[roundKeys[round - 1][3][0] & 15][roundKeys[round - 1][3][0] & 240];
        b0 ^= roundConstant;
        roundKeys[round][3] = {b0, b1, b2, b3};
        for (int i = 0; i < 3; i++)
        {
            roundKeys[round][i] = {b0 ^ roundKeys[round - 1][i][0],
                                   roundKeys[round - 1][i][1],
                                   roundKeys[round - 1][i][2],
                                   roundKeys[round - 1][i][3]};
        }
    }
}