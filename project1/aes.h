#ifndef AES_H_
#define AES_H_

#include <stddef.h> // For size_t.
#include <stdint.h> // For uint8_t, uint32_t.

typedef unsigned char block[4][4]; // A block is a matrix of 4 by 4).

typedef struct AES
{
    size_t key_size;
    char *key[4];
    int rounds;
    block *round_keys;
    block *inv_round_keys;
} AES;

extern const char S[16][16];
extern const char SI[16][16];

#endif
