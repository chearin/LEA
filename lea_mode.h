#pragma once
#include <stdint.h>
#include "lea.h"

#define ENCRYPT 10
#define DECRYPT 20

void Lea_ecb(const uint8_t* in, uint8_t* out, const LEA_KEY* key, const int enc);
void LEA_cbc_encrypt(const uint8_t* in, uint8_t* out, size_t len, const LEA_KEY* key, uint8_t* ivec, const int enc);
void inc_counter(uint8_t* ivec);
void LEA_ctr_encrypt(const uint8_t* in, uint8_t* out, size_t len, const LEA_KEY* key, uint8_t* ivec);