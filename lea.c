#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <tgmath.h>
#include "lea.h"

unsigned int rotL(unsigned int a, int b)
{
    return ((unsigned int)(a << b) | (a >> (32 - b)));
}

unsigned int rotR(unsigned int a, int b)
{
    return ((a >> b) | (unsigned int)(a << (32 - b)));
}

int KeySchedule(const unsigned char* userKey, const int bits, LEA_KEY* key)
{
    unsigned int Con[8] = { 0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957 };
    unsigned int T[8] = { 0, };

    for (int i = 0; i < 8; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            T[i] += userKey[4 * i + j] << (8 * j);
        }
    }

    switch (bits)
    {
    // 128bit key, 24 round
    case 128:
        for (int i = 0; i < 24; i++)
        {
            T[0] = rotL((T[0] + rotL(Con[i % 4], i)), 1);
            T[1] = rotL((T[1] + rotL(Con[i % 4], i + 1)), 3);
            T[2] = rotL((T[2] + rotL(Con[i % 4], i + 2)), 6);
            T[3] = rotL((T[3] + rotL(Con[i % 4], i + 3)), 11);
            key->rd_key[i * 6 + 0] = T[0], key->rd_key[i * 6 + 1] = T[1], key->rd_key[i * 6 + 2] = T[2];
            key->rd_key[i * 6 + 3] = T[1], key->rd_key[i * 6 + 4] = T[3], key->rd_key[i * 6 + 5] = T[1];
        }
        key->rounds = 24;
        break;
    // 192bit key, 28 round
    case 192:
        for (int i = 0; i < 28; i++)
        {
            T[0] = rotL((T[0] + rotL(Con[i % 6], i)), 1);
            T[1] = rotL((T[1] + rotL(Con[i % 6], i + 1)), 3);
            T[2] = rotL((T[2] + rotL(Con[i % 6], i + 2)), 6);
            T[3] = rotL((T[3] + rotL(Con[i % 6], i + 3)), 11);
            T[4] = rotL((T[4] + rotL(Con[i % 6], i + 4)), 13);
            T[5] = rotL((T[5] + rotL(Con[i % 6], i + 5)), 17);
            key->rd_key[i * 6 + 0] = T[0], key->rd_key[i * 6 + 1] = T[1], key->rd_key[i * 6 + 2] = T[2];
            key->rd_key[i * 6 + 3] = T[3], key->rd_key[i * 6 + 4] = T[4], key->rd_key[i * 6 + 5] = T[5];
        }
        key->rounds = 28;
        break;
    // 256bit key, 32 round
    case 256:
        for (int i = 0; i < 32; i++)
        {
            T[(6 * i) % 8] = rotL((T[(6 * i) % 8] + rotL(Con[i % 8], i)), 1);
            T[(6 * i + 1) % 8] = rotL((T[(6 * i + 1) % 8] + rotL(Con[i % 8], i + 1)), 3);
            T[(6 * i + 2) % 8] = rotL((T[(6 * i + 2) % 8] + rotL(Con[i % 8], i + 2)), 6);
            T[(6 * i + 3) % 8] = rotL((T[(6 * i + 3) % 8] + rotL(Con[i % 8], i + 3)), 11);
            T[(6 * i + 4) % 8] = rotL((T[(6 * i + 4) % 8] + rotL(Con[i % 8], i + 4)), 13);
            T[(6 * i + 5) % 8] = rotL((T[(6 * i + 5) % 8] + rotL(Con[i % 8], i + 5)), 17);
            key->rd_key[i * 6 + 0] = T[(6 * i) % 8], key->rd_key[i * 6 + 1] = T[(6 * i + 1) % 8], key->rd_key[i * 6 + 2] = T[(6 * i + 2) % 8];
            key->rd_key[i * 6 + 3] = T[(6 * i + 3) % 8], key->rd_key[i * 6 + 4] = T[(6 * i + 4) % 8], key->rd_key[i * 6 + 5] = T[(6 * i + 5) % 8];
        }
        key->rounds = 32;
        break;
    }
    return 0;
}

void printRK(LEA_KEY* key)
{
    printf("RK: \n");
    for (int i = 0; i < key->rounds; i++)
    {
        for (int j = 0; j < 6; j++)
        {
            printf("%06x ", key->rd_key[i * 6 + j]);
        }
        printf("\n");
    }
    printf("\n");
}

void encrypt_round(unsigned int* X, unsigned int* rdkey)
{
    unsigned int x0 = X[0];
    unsigned int x1 = X[1];
    unsigned int x2 = X[2];
    unsigned int x3 = X[3];

    X[0] = rotL(((x0 ^ rdkey[0]) + (x1 ^ rdkey[1])), 9);
    X[1] = rotR(((x1 ^ rdkey[2]) + (x2 ^ rdkey[3])), 5);
    X[2] = rotR(((x2 ^ rdkey[4]) + (x3 ^ rdkey[5])), 3);
    X[3] = x0;
}

void LEA_encrypt_uint8(const uint8_t* in, unsigned char* out, const LEA_KEY* key)
{
    unsigned int X[4] = { 0, };
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            X[i] += in[4 * i + j] << (8 * j);
        }
    }

    //printf("평문: ");
    //for (int i = 0; i < 16; i++)
    //{
    //    printf("%x ", in[i]);
    //}
    //printf("\n");

    for (int i = 0; i < key->rounds; i++)
    {
        //printf("X%d: %x %x %x %x\n", i, X[0], X[1], X[2], X[3]);
        encrypt_round(X, &(key->rd_key[6 * i]));
    }
    //printf("X%d: %x %x %x %x\n", key->rounds, X[0], X[1], X[2], X[3]);

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            out[4 * i + j] = (unsigned char)(X[i] >> (8 * j) & 0x000000ff);
        }
    }
    //printf("암호문: ");
    //for (int i = 0; i < 16; i++)
    //{
    //    printf("%x ", out[i]);
    //}
    //printf("\n\n");
}

void LEA_encrypt_uint32(const uint32_t* in, unsigned char* out, const LEA_KEY* key)
{
    unsigned int X[4] = { 0, };
    for (int i = 0; i < 4; i++)
    {
        X[i] = in[i];
    }

    printf("평문: ");
    for (int i = 0; i < 4; i++)
    {
        printf("%x ", in[i]);
    }
    printf("\n");

    for (int i = 0; i < key->rounds; i++)
    {
        printf("X%d: %x %x %x %x\n", i, X[0], X[1], X[2], X[3]);
        encrypt_round(X, &(key->rd_key[6 * i]));
    }
    printf("X%d: %x %x %x %x\n", key->rounds, X[0], X[1], X[2], X[3]);

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            out[4 * i + j] = (unsigned char)(X[i] >> (8 * j) & 0x000000ff);
        }
    }
    printf("암호문: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%x ", out[i]);
    }
    printf("\n\n");
}

void LEA_encrypt_uint64(const uint64_t* in, unsigned char* out, const LEA_KEY* key)
{
    unsigned int X[4] = { 0, };
    for (int i = 0; i < 2; i++)
    {
        X[2 * i] = (unsigned int)in[i];
        X[2 * i + 1] = (unsigned int)(in[i] >> 32);
    }

    printf("평문: ");
    for (int i = 0; i < 2; i++)
    {
        printf("%llx ", in[i]);
    }
    printf("\n");

    for (int i = 0; i < key->rounds; i++)
    {
        printf("X%d: %x %x %x %x\n", i, X[0], X[1], X[2], X[3]);
        encrypt_round(X, &(key->rd_key[6 * i]));
    }
    printf("X%d: %x %x %x %x\n", key->rounds, X[0], X[1], X[2], X[3]);

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            out[4 * i + j] = (unsigned char)(X[i] >> (8 * j) & 0x000000ff);
        }
    }
    printf("암호문: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%x ", out[i]);
    }
    printf("\n\n");
}

void decrypt_round(unsigned int* X, unsigned int* rdkey)
{
    unsigned int x0 = X[0];
    unsigned int x1 = X[1];
    unsigned int x2 = X[2];
    unsigned int x3 = X[3];

    X[0] = x3;
    X[1] = ((rotR(x0, 9) - (X[0] ^ rdkey[0]))) ^ rdkey[1];
    X[2] = ((rotL(x1, 5) - (X[1] ^ rdkey[2]))) ^ rdkey[3];
    X[3] = ((rotL(x2, 3) - (X[2] ^ rdkey[4]))) ^ rdkey[5];
}

void LEA_decrypt_uint8(const uint8_t* in, unsigned char* out, const LEA_KEY* key)
{
    unsigned int X[4] = { 0, };
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            X[i] += in[4 * i + j] << (8 * j);
        }
    }

    printf("암호문: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%x ", in[i]);
    }
    printf("\n");

    for (int i = 0; i < key->rounds; i++)
    {
        printf("X%d: %x %x %x %x\n", i, X[0], X[1], X[2], X[3]);
        decrypt_round(X, &(key->rd_key[6 * key->rounds - 6 * (i + 1)]));
    }
    printf("X%d: %x %x %x %x\n", key->rounds, X[0], X[1], X[2], X[3]);

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            out[4 * i + j] = (unsigned char)(X[i] >> (8 * j) & 0x000000ff);
        }
    }
    printf("복호문: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%x ", out[i]);
    }
}

void LEA_decrypt_uint32(const uint32_t* in, unsigned char* out, const LEA_KEY* key)
{
    unsigned int X[4] = { 0, };
    for (int i = 0; i < 4; i++)
    {
        X[i] = in[i];
    }

    printf("암호문: ");
    for (int i = 0; i < 4; i++)
    {
        printf("%x ", in[i]);
    }
    printf("\n");

    for (int i = 0; i < key->rounds; i++)
    {
        printf("X%d: %x %x %x %x\n", i, X[0], X[1], X[2], X[3]);
        decrypt_round(X, &(key->rd_key[6 * key->rounds - 6 * (i + 1)]));
    }
    printf("X%d: %x %x %x %x\n", key->rounds, X[0], X[1], X[2], X[3]);

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            out[4 * i + j] = (unsigned char)(X[i] >> (8 * j) & 0x000000ff);
        }
    }
    printf("복호문: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%x ", out[i]);
    }
}

void LEA_decrypt_uint64(const uint64_t* in, unsigned char* out, const LEA_KEY* key)
{
    unsigned int X[4] = { 0, };
    for (int i = 0; i < 2; i++)
    {
        X[2 * i] = (unsigned int)in[i];
        X[2 * i + 1] = (unsigned int)(in[i] >> 32);
    }

    printf("암호문: ");
    for (int i = 0; i < 2; i++)
    {
        printf("%llx ", in[i]);
    }
    printf("\n");

    for (int i = 0; i < key->rounds; i++)
    {
        printf("X%d: %x %x %x %x\n", i, X[0], X[1], X[2], X[3]);
        decrypt_round(X, &(key->rd_key[6 * key->rounds - 6 * (i + 1)]));
    }
    printf("X%d: %x %x %x %x\n", key->rounds, X[0], X[1], X[2], X[3]);

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            out[4 * i + j] = (unsigned char)(X[i] >> (8 * j) & 0x000000ff);
        }
    }
    printf("복호문: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%x ", out[i]);
    }
}