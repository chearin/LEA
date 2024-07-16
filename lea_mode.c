#include "lea_mode.h"

void Lea_ecb(const uint8_t* in, uint8_t* out, const LEA_KEY* key, const int enc)
{
	if (enc == ENCRYPT)
	{
		LEA_encrypt(in, out, key);
	}
	else if (enc == DECRYPT)
	{
		LEA_decrypt(in, out, key);
	}
}

void LEA_cbc_encrypt(const uint8_t* in, uint8_t* out, size_t len, const LEA_KEY* key, uint8_t* ivec, const int enc)
{
	int Nb = len / 16;
	int remainBit = len - 16 * Nb;
	unsigned char iv[16] = { 0 };

	if (enc == ENCRYPT)
	{
		memcpy(iv, ivec, 16);

		for (int i = 0; i < Nb; i++)
		{
			for (int j = 0; j < 16; j++)
			{
				out[16 * i + j] = in[16 * i + j] ^ iv[j];
			}
			LEA_encrypt(out + 16 * i, out + 16 * i, key);
			memcpy(iv, out + 16 * i, 16);
		}
		//마지막 block
		if (remainBit)
		{
			//패딩하고 xor하기
			for (int i = 0; i < remainBit; i++)
			{
				out[16 * Nb + i] = in[16 * Nb + i] ^ iv[i];
			}
			memcpy(out + 16 * Nb + remainBit, iv + remainBit, 16 - remainBit);
			//암호화
			LEA_encrypt(out + 16 * Nb, out + 16 * Nb, key);
		}
	}
	else if (enc == DECRYPT)
	{
		memcpy(iv, ivec, 16);

		for (int i = 0; i < Nb; i++)
		{			
			LEA_decrypt(in + 16 * i, out + 16 * i, key);
			for (int j = 0; j < 16; j++)
			{
				out[16 * i + j] = out[16 * i + j] ^ iv[j];
			}
			memcpy(iv, in + 16 * i, 16);
		}
	}
}

void inc_counter(uint8_t* ivec)
{
	// 리틀엔디안 기준
	// 빅엔디안 따로 구현하면 int단위 증가로 최적화할 수 있음
	for (int k = 15; k >= 0; k--)
	{
		ivec[k]++;
		if (ivec[k])
		{
			return;
		}
	}
}

void LEA_ctr_encrypt(const uint8_t* in, uint8_t* out, size_t len, const LEA_KEY* key, uint8_t* ivec)
{
	int Nb = len / 16;
	int remainBit = len - 16 * Nb;

	for (int i = 0; i < Nb; i++)
	{
		LEA_encrypt(ivec, out + 16 * i, key);
		inc_counter(ivec);
		for (int j = 0; j < 16; j++)
		{
			out[16 * i + j] ^= in[16 * i + j];
		}
	}
	//마지막 block
	if (remainBit)
	{
		LEA_encrypt(ivec, out + 16 * Nb, key);
		inc_counter(ivec);
		for (int i = 0; i < remainBit; i++)
		{
			out[16 * Nb + i] ^= in[16 * Nb + i];
		}
	}
}