#pragma once
#include <string.h>
#include "lea.h"
#include "lea_mode.h"

FILE* fileOpen(char* fname);
void str2hex(const unsigned char* str, uint8_t* hex, int len);
int is_same(uint8_t* CT, uint8_t* ANSWER, int len);

void LEA_ecb_KAT();
void LEA_ecb_MMT();
void LEA_ecb_MCT();

void LEA_cbc_KAT();
void LEA_cbc_MMT();
void LEA_cbc_MCT();

void LEA_ctr_KAT();
void LEA_ctr_MMT();
void LEA_ctr_MCT();
