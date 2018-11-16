#define _CRT_SECURE_NO_WARNINGS
#define Nb 4
#define KEY_LENGHT 16
#include<stdio.h>
#include<stdlib.h>
#include <math.h>

int aes_arr[KEY_LENGHT] = { 0, };
int cipher_text[4][KEY_LENGHT];
int byte_arr[16] = { 2 , 3, 1 , 1 ,
1 , 2, 3 , 1 ,
1 , 1, 2 , 3 ,
3 , 1, 1 , 2 };
unsigned char sbox[KEY_LENGHT][KEY_LENGHT] = {
	{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 }, //0
	{ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 }, //1
	{ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 }, //2
	{ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 }, //3
	{ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 }, //4
	{ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf }, //5
	{ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 }, //6
	{ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 }, //7
	{ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 }, //8
	{ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb }, //9
	{ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 }, //a
	{ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 }, //b
	{ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a }, //c
	{ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e }, //d
	{ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf }, //e
	{ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 } }; //f
int* KeySchedule(int count, int inputkey[])
{
	unsigned  char R_con[10][4] = { //for xor with round con 
		{ 0x01 , 0x00, 0x00, 0x00 },
		{ 0x02 , 0x00, 0x00, 0x00 },
		{ 0x04 , 0x00, 0x00, 0x00 },
		{ 0x08 , 0x00, 0x00, 0x00 },
		{ 0x10 , 0x00, 0x00, 0x00 },
		{ 0x20 , 0x00, 0x00, 0x00 },
		{ 0x40 , 0x00, 0x00, 0x00 },
		{ 0x80 , 0x00, 0x00, 0x00 },
		{ 0x1b , 0x00, 0x00, 0x00 },
		{ 0x36 , 0x00, 0x00, 0x00 },
	};
	int round_arr[Nb][Nb];
	int lastKey_shift[Nb]; //마지막 key의 round shift 까지의 연산
	int lastKey_sub[Nb]; // round SubByte까지의 연산
	int lastKey_RCon[Nb][Nb];
	int i, j, index = 0;
	for (i = 0; i < Nb; i++)   //세로로 집어넣기
	{
		for (j = 0; j < Nb; j++)
		{
			round_arr[j][i] = inputkey[index++];
		}
	}
	index = 0;
	for (i = 0; i < 3; i++)           // 마지막 키 (W3) 한칸씩 shift
	{
		lastKey_shift[i] = round_arr[i + 1][3];
	}
	lastKey_shift[3] = round_arr[0][3];

	for (i = 0; i < Nb; i++)       //마지막 키 (W3) sbox랑 match (subByte)
	{
		lastKey_sub[i] = sbox[lastKey_shift[i] >> 4][lastKey_shift[i] & 0x0000000f];
	}

	for (i = 0; i < 4; i++)
	{
		lastKey_RCon[i][0] = lastKey_sub[i] ^ R_con[count][i] ^ round_arr[i][0];  //lastkey XOR roundKey
	}


	for (i = 1; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			lastKey_RCon[j][i] = lastKey_RCon[j][i - 1] ^ round_arr[j][i];
		}
	}

	static int roundkey[16];
	int k = 0;
	for (i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			roundkey[k++] = lastKey_RCon[j][i];
		}
	}

	return roundkey;
}
void AddRoundKey(int inputkey[], int cipherkey[])
{
	int i;
	static int roundKey[KEY_LENGHT];
	for (i = 0; i < KEY_LENGHT; i++)
	{
		aes_arr[i] = inputkey[i] ^ cipherkey[i];
	}
}
void SubByte(int input[])
{
	int round_arr[Nb][Nb];

	int i, j, index = 0, index2 = 0;

	for (i = 0; i < Nb; i++)   //세로로 집어넣기
	{
		for (j = 0; j < Nb; j++)
		{
			round_arr[j][i] = input[index++];
		}
	}
	for (i = 0; i < Nb; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			aes_arr[index2++] = sbox[round_arr[i][j] >> 4][round_arr[i][j] & 0x0000000f];
		}
	}
}
void ShiftRow(int input[])
{
	int round_arr[Nb][Nb];
	int resultKey[Nb][Nb];
	int i = 0, j, index = 0, index2 = 0;

	for (i = 0; i < Nb; i++)   //가로로 집어넣기
	{
		for (j = 0; j < Nb; j++)
		{
			round_arr[i][j] = input[index++];
		}
	}

	for (j = 0; j < Nb; j++)  //0행
	{
		resultKey[0][j] = round_arr[0][j];
	}

	for (j = 1; j < Nb; j++)  //1행
	{
		resultKey[1][j - 1] = round_arr[1][j];
	}
	resultKey[1][3] = round_arr[1][0];

	for (j = 2; j < Nb; j++) //2
	{
		resultKey[2][j - 2] = round_arr[2][j];
	}
	resultKey[2][2] = round_arr[2][0];
	resultKey[2][3] = round_arr[2][1];

	for (j = 3; j < Nb; j++) //3
	{
		resultKey[3][j - 3] = round_arr[3][j];
	}
	resultKey[3][1] = round_arr[3][0];
	resultKey[3][2] = round_arr[3][1];
	resultKey[3][3] = round_arr[3][2];

	for (i = 0; i < Nb; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			aes_arr[index2++] = resultKey[i][j];
		}
	}
}


void MixColumn(int key[], int byte_arr[])
{
	int round_arr[Nb][Nb];
	int i = 0, j, index = 0, index2 = 0;

	for (i = 0; i < Nb; i++)   //세로로 집어넣기
	{
		for (j = 0; j < Nb; j++)
		{
			round_arr[j][i] = key[index++];
		}
	}
	unsigned char result[Nb];
	int mix_result[4][4] = { 0, };
	int a, row;

	for (row = 0; row < 4; row++)
	{
		for (a = 0; a < 4; a++)
		{
			for (i = 0; i < Nb; i++)
			{
				if (byte_arr[i + (a * 4)] == 1)
				{
					result[i] = round_arr[row][i];
					mix_result[row][a] ^= result[i];
				}
				else if (byte_arr[i + (a * 4)] == 2)
				{
					if (round_arr[row][i] >> 7 == 0)  //최상위비트가 0
					{
						result[i] = round_arr[row][i] << 1;
					}
					else if (round_arr[row][i] >> 7 == 1)
					{
						result[i] = 0b00011011 ^ (round_arr[row][i] << 1);
					}
					mix_result[row][a] ^= result[i];
				}
				else if (byte_arr[i + (a * 4)] == 3)
				{
					if (round_arr[row][i] >> 7 == 1)
						result[i] = (0b00011011 ^ (round_arr[row][i] << 1)) ^ round_arr[row][i];
					else
						result[i] = (round_arr[row][i] << 1) ^ round_arr[row][i];
					mix_result[row][a] ^= result[i];
				}
			}
		}
	}

	for (i = 0; i < Nb; i++)
	{
		for (j = 0; j< 4; j++)
			aes_arr[index2++] = mix_result[i][j];
	}
}
void main(void)
{
	int key[KEY_LENGHT]; // = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	int input_block[4][KEY_LENGHT]; /* = { { 0xf0, 0xf1, 0xf2, 0xf3,0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe ,0xff },
	{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x00 },
	{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x01 },
	{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x02 }
	}; */
	int Tag_t[KEY_LENGHT];// = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
	int m[3][KEY_LENGHT]; /* = { { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 },
	{ 0x30,0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef },
	{ 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37,0x10 }}; */
	int round_arr[10][16];
	int key_s[16];
	 
	FILE *fp_key , *fp_input, *fp_plain, *fp_tag;
	fp_key = fopen("AES_CTR_KEY.txt", "rb");
	fp_input = fopen("AES_CTR_INPUT.txt", "rb");
	fp_plain = fopen("AES_CTR_PLAIN.txt", "rb");
	fp_tag = fopen("AES_CTR_TAG.txt", "rb");

	if (fp_key == NULL) exit(1); if (fp_input == NULL) exit(1); if (fp_tag == NULL) exit(1); if (fp_plain == NULL) exit(1);

	int data;
	for (int i = 0; i < KEY_LENGHT; i++)
	{
		fscanf(fp_key, "%02x", &data);
		key[i] = (unsigned char)data;
		key_s[i] = key[i];
	}
	for (int i = 0; i < 3; i++)
	{
		for (int j = 0; j < KEY_LENGHT; j++)
		{
			fscanf(fp_plain, "%02x", &data);
			m[i][j] = (unsigned char)data;
		}
	}
	for (int i = 0; i < KEY_LENGHT; i++)
	{
		fscanf(fp_tag, "%02x", &data);
		Tag_t[i] = (unsigned char)data;
	}

	for (int i = 0; i < 10; i++)  //키생성
	{
		int *round_key = KeySchedule(i, key);
		for (int j = 0; j < 16; j++)
		{
			round_arr[i][j] = key[j] = round_key[j];
		}
	}
	int i, j, count = 0;
	int r[4][4];
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			r[j][i] = round_arr[9][count++];
		}
	}
	int finalround[16], index = 0;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			finalround[index++] = r[i][j];
		}
	}

	for (int b = 0; b < 4; b++)  //블록 마다 암호
	{

		for (int i = 0; i < 16; i++)
		{
			fscanf(fp_input, "%02x", &data);
			input_block[b][i] = (unsigned char)data;
			aes_arr[i] = input_block[b][i]; //암호화할 블록 ase_arr에 복사
		}

		AddRoundKey(aes_arr, key_s);

		int round;
		for (round = 0; round < 9; round++)
		{
			SubByte(aes_arr);
			ShiftRow(aes_arr);
			MixColumn(aes_arr, byte_arr);
			AddRoundKey(aes_arr, round_arr[round]);
		}

		SubByte(aes_arr);
		ShiftRow(aes_arr);
		AddRoundKey(aes_arr, finalround);

		count = 0;
		int for_transit[Nb][Nb];

		int countt = 0;
		for (int i = 0; i < Nb; i++) //행과열을 바꾸기 위함 (xor을 위해)
		{
			for (int j = 0; j < Nb; j++)
			{
				for_transit[j][i] = aes_arr[countt++];
			}
		}
		countt = 0;
		for (int i = 0; i < Nb; i++)
		{
			for (int j = 0; j < Nb; j++)
			{
				cipher_text[b][countt++] = for_transit[i][j];
			}
		}

		if (b == 0)  //1라운드 일때만 tag랑 xor
		{
			for (int i = 0; i < 16; i++)
			{
				cipher_text[b][i] = cipher_text[b][i] ^ Tag_t[i];
			}
		}
		else
		{
			for (int i = 0; i < 16; i++)
			{
				cipher_text[b][i] = cipher_text[b][i] ^ m[b - 1][i];
			}
		}

		for (i = 0; i < KEY_LENGHT; i++)
		{
			count++;
			if (count == 4)
			{
				printf("%x \n", cipher_text[b][i]);
				count = 0;
			}

			else
				printf("%x ", cipher_text[b][i]);
		}
		printf("\n");
	}
}