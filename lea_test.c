#define _CRT_SECURE_NO_WARNINGS
#include "lea_test.h"

FILE* fileOpen(const char* fname)
{
	FILE* fp;
	fp = fopen(fname, "r");

	return fp;
}

void str2hex(const unsigned char* str, uint8_t* hex, const int hexlen)
{
	unsigned char buffer[3] = { 0 };

	//hexlen은 변환할 바이트수(문자 2개가 1바이트)
	for (int i = 0; i < hexlen; i++)
	{
		buffer[0] = str[2 * i];
		buffer[1] = str[2 * i + 1];
		buffer[2] = '\0';
		hex[i] = strtol(buffer, NULL, 16);
	}
}

int is_same(const uint8_t* CT, const uint8_t* ANSWER, const int len)
{
	for (int i = 0; i < len; i++)
	{
		if (CT[i] != ANSWER[i])
		{
			return 0;
		}
	}
	return 1;
}

void LEA_ecb_KAT()
{
	FILE* fp;
	unsigned char input_str[1000] = { 0 };
	uint8_t KEY[16] = { 0 };
	uint8_t PT[16] = { 0 };
	uint8_t CT[16] = { 0 };
	uint8_t ANSWER[16] = { 0 };
	uint8_t buf[16] = { 0 };
	LEA_KEY key;

	// 128bit 키
	fp = fileOpen("LEA128(ECB)KAT.txt");

	while (fscanf(fp, "%s %s %s", buf, buf, input_str) != EOF)
	{
		//KEY값 저장
		str2hex(input_str, KEY, strlen(input_str) / 2);
		
		//PT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, PT, strlen(input_str) / 2);
		
		//정답인 CT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, ANSWER, strlen(input_str) / 2);		

		KeySchedule(KEY, 128, &key);
		Lea_ecb(PT, CT, &key, ENCRYPT);
		
		if (!is_same(CT, ANSWER, strlen(input_str) / 2))
		{
			printf("ecbKAT Fail...\n");
			return;
		}
	}
	printf("ecbKAT Success!!\n");

	fclose(fp);
}

void LEA_ecb_MMT()
{
	FILE* fp;
	unsigned char input_str[1000] = { 0 };
	uint8_t KEY[16] = { 0 };
	uint8_t PT[1000] = { 0 };
	uint8_t CT[1000] = { 0 };
	uint8_t ANSWER[1000] = { 0 };
	uint8_t buf[16] = { 0 };
	LEA_KEY key;
	int Nb;

	// 128bit 키
	fp = fileOpen("LEA128(ECB)MMT.txt");
	while (fscanf(fp, "%s %s %s", buf, buf, input_str) != EOF)
	{
		//KEY값 저장
		str2hex(input_str, KEY, strlen(input_str) / 2);

		//PT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, PT, strlen(input_str) / 2);

		//정답인 CT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, ANSWER, strlen(input_str) / 2);

		Nb = strlen(input_str) / 16;

		KeySchedule(KEY, 128, &key)	;
		for (int i = 0; i < Nb; i++)
		{
			Lea_ecb(PT + (i * 16), CT + (i * 16), &key, ENCRYPT);
		}

		if (!is_same(CT, ANSWER, strlen(input_str) / 2))
		{
			printf("ecbMMT Fail...\n");
			return;
		}
	}
	printf("ecbMMT Success!!\n");

	fclose(fp);
}

void LEA_ecb_MCT()
{
	FILE* fp;
	unsigned char input_str[1000] = { 0 };
	uint8_t KEY[16] = { 0 };
	uint8_t PT[16] = { 0 };
	uint8_t CT[16] = { 0 };
	uint8_t ANSWER[16] = { 0 };
	uint8_t buf[16] = { 0 };
	LEA_KEY key;

	// 128bit 키
	fp = fileOpen("LEA128(ECB)MCT.txt");

	while (fscanf(fp, "%s %s %s", buf, buf, input_str) != EOF)
	{
		//KEY값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, KEY, strlen(input_str) / 2);

		//PT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, PT, strlen(input_str) / 2);

		//정답인 CT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, ANSWER, strlen(input_str) / 2);
		
		KeySchedule(KEY, 128, &key);
		Lea_ecb(PT, CT, &key, ENCRYPT);
		for (int i = 0; i < 999; i++)
		{
			Lea_ecb(CT, CT, &key, ENCRYPT);
		}

		if (!is_same(CT, ANSWER, strlen(input_str) / 2))
		{
			printf("ecbMCT Fail...\n");
			return;
		}
	}
	printf("ecbMCT Success!!\n");

	fclose(fp);
}

void LEA_cbc_KAT()
{
	FILE* fp;
	unsigned char input_str[1000] = { 0 };
	uint8_t KEY[16] = { 0 };
	uint8_t IV[16] = { 0 };
	uint8_t PT[16] = { 0 };
	uint8_t CT[16] = { 0 };
	uint8_t ANSWER[16] = { 0 };
	uint8_t buf[16] = { 0 };
	LEA_KEY key;
	int len;

	// 128bit 키
	fp = fileOpen("LEA128(CBC)KAT.txt");

	while (fscanf(fp, "%s %s %s", buf, buf, input_str) != EOF)
	{
		//KEY값 저장
		str2hex(input_str, KEY, strlen(input_str) / 2);

		//IV값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, IV, strlen(input_str) / 2);

		//PT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, PT, strlen(input_str) / 2);
		len = strlen(input_str) / 2;

		//정답인 CT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, ANSWER, strlen(input_str) / 2);

		KeySchedule(KEY, 128, &key);
		LEA_cbc_encrypt(PT, CT, len, &key, IV, ENCRYPT);

		if (!is_same(CT, ANSWER, strlen(input_str) / 2))
		{
			printf("cbcKAT Fail...\n");
			return;
		}
	}
	printf("cbcKAT Success!!\n");

	fclose(fp);
}

void LEA_cbc_MMT()
{
	FILE* fp;
	unsigned char input_str[1000] = { 0 };
	uint8_t KEY[16] = { 0 };
	uint8_t IV[16] = { 0 };
	uint8_t PT[1000] = { 0 };
	uint8_t CT[1000] = { 0 };
	uint8_t ANSWER[1000] = { 0 };
	uint8_t buf[16] = { 0 };
	LEA_KEY key;
	int len;

	// 128bit 키
	fp = fileOpen("LEA128(CBC)MMT.txt");
	while (fscanf(fp, "%s %s %s", buf, buf, input_str) != EOF)
	{
		//KEY값 저장
		str2hex(input_str, KEY, strlen(input_str) / 2);

		//IV값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, IV, strlen(input_str) / 2);

		//PT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, PT, strlen(input_str) / 2);
		len = strlen(input_str) / 2;

		//정답인 CT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, ANSWER, strlen(input_str) / 2);

		KeySchedule(KEY, 128, &key);
		LEA_cbc_encrypt(PT, CT, len, &key, IV, ENCRYPT);

		if (!is_same(CT, ANSWER, len))
		{
			printf("cbcMMT Fail...\n");
			return;
		}
	}
	printf("cbcMMT Success!!\n");

	fclose(fp);
}

void LEA_cbc_MCT()
{
	FILE* fp;
	unsigned char input_str[1000] = { 0 };
	uint8_t KEY[16] = { 0 };
	uint8_t IV[16] = { 0 };
	uint8_t PT[16] = { 0 };
	uint8_t CT[16] = { 0 };
	uint8_t CT2[16] = { 0 };
	uint8_t ANSWER[16] = { 0 };
	uint8_t buf[16] = { 0 };
	LEA_KEY key;
	int len;

	// 128bit 키
	fp = fileOpen("LEA128(CBC)MCT.txt");

	while (fscanf(fp, "%s %s %s", buf, buf, input_str) != EOF)
	{
		//KEY값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, KEY, strlen(input_str) / 2);

		//IV값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, IV, strlen(input_str) / 2);

		//PT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, PT, strlen(input_str) / 2);
		len = strlen(input_str) / 2;

		//정답인 CT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, ANSWER, strlen(input_str) / 2);

		KeySchedule(KEY, 128, &key);
		LEA_cbc_encrypt(PT, CT, len, &key, IV, ENCRYPT);
		LEA_cbc_encrypt(IV, IV, len, &key, CT, ENCRYPT);
		for (int i = 0; i < 998; i++)
		{
			memcpy(CT2, IV, 16);
			LEA_cbc_encrypt(CT, IV, len, &key, IV, ENCRYPT);
			memcpy(CT, CT2, 16);
		}
		memcpy(CT, IV, 16);

		if (!is_same(CT, ANSWER, strlen(input_str) / 2))
		{
			printf("cbcMCT Fail...\n");
			return;
		}
	}
	printf("cbcMCT Success!!\n");

	fclose(fp);
}

void LEA_ctr_KAT()
{
	FILE* fp;
	unsigned char input_str[1000] = { 0 };
	uint8_t KEY[16] = { 0 };
	uint8_t CTR[16] = { 0 };
	uint8_t PT[16] = { 0 };
	uint8_t CT[16] = { 0 };
	uint8_t ANSWER[16] = { 0 };
	uint8_t buf[16] = { 0 };
	LEA_KEY key;
	int len;

	// 128bit 키
	fp = fileOpen("LEA128(CTR)KAT.txt");

	while (fscanf(fp, "%s %s %s", buf, buf, input_str) != EOF)
	{
		//KEY값 저장
		str2hex(input_str, KEY, strlen(input_str) / 2);

		//CTR값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, CTR, strlen(input_str) / 2);

		//PT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, PT, strlen(input_str) / 2);
		len = strlen(input_str) / 2;

		//정답인 CT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, ANSWER, strlen(input_str) / 2);

		KeySchedule(KEY, 128, &key);
		LEA_ctr_encrypt(PT, CT, len, &key, CTR);

		if (!is_same(CT, ANSWER, strlen(input_str) / 2))
		{
			printf("ctrKAT Fail...\n");
			return;
		}
	}
	printf("ctrKAT Success!!\n");

	fclose(fp);
}

void LEA_ctr_MMT()
{
	FILE* fp;
	unsigned char input_str[1000] = { 0 };
	uint8_t KEY[16] = { 0 };
	uint8_t CTR[16] = { 0 };
	uint8_t PT[1000] = { 0 };
	uint8_t CT[1000] = { 0 };
	uint8_t ANSWER[1000] = { 0 };
	uint8_t buf[16] = { 0 };
	LEA_KEY key;
	int len;

	// 128bit 키
	fp = fileOpen("LEA128(CTR)MMT.txt");
	while (fscanf(fp, "%s %s %s", buf, buf, input_str) != EOF)
	{
		//KEY값 저장
		str2hex(input_str, KEY, strlen(input_str) / 2);

		//CTR값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, CTR, strlen(input_str) / 2);

		//PT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, PT, strlen(input_str) / 2);
		len = strlen(input_str) / 2;

		//정답인 CT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, ANSWER, strlen(input_str) / 2);

		KeySchedule(KEY, 128, &key);
		LEA_ctr_encrypt(PT, CT, len, &key, CTR);

		if (!is_same(CT, ANSWER, len))
		{
			printf("ctrMMT Fail...\n");
			return;
		}
	}
	printf("ctrMMT Success!!\n");

	fclose(fp);
}

void LEA_ctr_MCT()
{
	FILE* fp;
	unsigned char input_str[1000] = { 0 };
	uint8_t KEY[16] = { 0 };
	uint8_t CTR[16] = { 0 };
	uint8_t PT[16] = { 0 };
	uint8_t CT[16] = { 0 };
	uint8_t ANSWER[16] = { 0 };
	uint8_t buf[16] = { 0 };
	LEA_KEY key;
	int len;

	// 128bit 키
	fp = fileOpen("LEA128(CTR)MCT.txt");

	while (fscanf(fp, "%s %s %s", buf, buf, input_str) != EOF)
	{
		//KEY값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, KEY, strlen(input_str) / 2);

		//CTR값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, CTR, strlen(input_str) / 2);

		//PT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, PT, strlen(input_str) / 2);
		len = strlen(input_str) / 2;

		//정답인 CT값 저장
		fscanf(fp, "%s %s %s", buf, buf, input_str);
		str2hex(input_str, ANSWER, strlen(input_str) / 2);

		KeySchedule(KEY, 128, &key);
		for (int i = 0; i < 500; i++)
		{
			LEA_ctr_encrypt(PT, CT, len, &key, CTR);
			LEA_ctr_encrypt(CT, PT, len, &key, CTR);
		}
		memcpy(CT, PT, 16);

		if (!is_same(CT, ANSWER, strlen(input_str) / 2))
		{
			printf("ctrMCT Fail...\n");
			return;
		}
	}
	printf("ctrMCT Success!!\n");

	fclose(fp);
}