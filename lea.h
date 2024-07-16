#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <tgmath.h>

#define LEA_MAXNR	32
#define LEA_RK_WSIZE	6

// 매크로 정의
#define LEA_encrypt(in, out, key) _Generic((in), \
                                const uint8_t*: LEA_encrypt_uint8, \
                                const uint32_t*: LEA_encrypt_uint32, \
                                const uint64_t*: LEA_encrypt_uint64, \
                                uint8_t*: LEA_encrypt_uint8, \
                                uint32_t*: LEA_encrypt_uint32, \
                                uint64_t*: LEA_encrypt_uint64)(in, out, key)

#define LEA_decrypt(in, out, key) _Generic((in), \
                                const uint8_t*: LEA_decrypt_uint8, \
                                const uint32_t*: LEA_decrypt_uint32, \
                                const uint64_t*: LEA_decrypt_uint64, \
                                uint8_t*: LEA_decrypt_uint8, \
                                uint32_t*: LEA_decrypt_uint32, \
                                uint64_t*: LEA_decrypt_uint64)(in, out, key)

struct lea_key_st {
#ifdef LEA_LONG
    unsigned long rd_key[LEA_RK_WSIZE * (LEA_MAXNR + 1)];
#else
    unsigned int rd_key[LEA_RK_WSIZE * (LEA_MAXNR + 1)];
#endif
    int rounds;
};
typedef struct lea_key_st LEA_KEY;

int KeySchedule(const unsigned char* userKey, const int bits, LEA_KEY* key);
void printRK(LEA_KEY* key);

void encrypt_round(unsigned int* X, unsigned int* rdkey);
void LEA_encrypt_uint8(const uint8_t* in, unsigned char* out, const LEA_KEY* key);
void LEA_encrypt_uint32(const uint32_t* in, unsigned char* out, const LEA_KEY* key);
void LEA_encrypt_uint64(const uint64_t* in, unsigned char* out, const LEA_KEY* key);

void decrypt_round(unsigned int* X, unsigned int* rdkey);
void LEA_decrypt_uint8(const uint8_t* in, unsigned char* out, const LEA_KEY* key);
void LEA_decrypt_uint32(const uint32_t* in, unsigned char* out, const LEA_KEY* key);
void LEA_decrypt_uint64(const uint64_t* in, unsigned char* out, const LEA_KEY* key);