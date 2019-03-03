#include "encrypt.h"

unsigned char sbox[256] = 
{
     0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
     0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
     0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
     0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
     0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
     0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
     0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
     0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
     0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
     0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
     0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
     0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
     0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
     0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
     0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
     0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

unsigned char matrix_mix[] = 
{
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02
};

void Search(char * path, ENC_DATA * data)
{
	DIR * dir;
	struct dirent * ent;

	if(!(dir = opendir(path)))
	{
		printf("open %s error \n", path);
		return;
	}

	printf("%s \n", path);

	while((ent = readdir(dir))!=NULL)
	{
		const char * nameptr = &(ent->d_name[strlen(ent->d_name)-4]);
		if((strcmp(nameptr, ".enc"))!=0)
		{
			if(ent->d_type == DT_DIR)
			{
				char dirname[255];

				if(ent->d_name[0] == '.')
				{
					continue;
				}
				else
				{
					strcpy(dirname, path);
					strcat(dirname, ent->d_name);
					strcat(dirname, "/");
					Search(dirname, data);
				}
			}
			else if(ent->d_type == DT_REG)
			{
				char file_original[255];
				char file_encrypt[255];

				strcpy(file_original, path);
				strcat(file_original, ent->d_name);

				strcpy(file_encrypt, path);
				strcat(file_encrypt, ent->d_name);
				strcat(file_encrypt, ".enc");

				FILE * fpin;
				FILE * fpout;

				if(!(fpin = fopen(file_original, "r")))
				{
					printf("read %s open error \n", file_original);
					continue;
				}

				if(!(fpout = fopen(file_encrypt, "w")))
				{
					printf("write %s open error \n", file_encrypt);
					continue;
				}

				Encryption_CBC(data, fpin, fpout);

				remove(file_original);
				
				fclose(fpin);
				fclose(fpout);
			}
		}
	}
	
	closedir(dir);
}

void Padding(unsigned char plain[], int readlen)
{
	int i;

	for(i=readlen; i<BLOCK; i++)
	{
		plain[i] = (unsigned char)(BLOCK-readlen);
	}
}

void InitEncryption(ENC_DATA * data, DATA ikey[], unsigned char vec[])
{
	MakeRcon(data->rcon);
	KeyExpansion(data->key, data->rcon, ikey);
	memcpy(data->vec, vec, BLOCK);
}

void Encryption_CBC(ENC_DATA * data, FILE * fpin, FILE * fpout)
{
	int readlen;
	unsigned char buf[BLOCK];
	unsigned char vec[BLOCK];

	memcpy(vec, data->vec, BLOCK);
	
	while(1)
	{
		readlen = fread(buf, sizeof(unsigned char), BLOCK, fpin);
		if(readlen < BLOCK)
		{
			Padding(buf, readlen);
			CBC(vec, buf);
			Encrypt(data->key, buf);
			fwrite(buf, sizeof(unsigned char), BLOCK, fpout);
			break;
		}
		CBC(vec, buf);
		Encrypt(data->key, buf);
		memcpy(vec, buf, BLOCK);
		fwrite(buf, sizeof(unsigned char), BLOCK, fpout);
	}
}

void CBC(unsigned char vector[], unsigned char text[])
{
	int i;
	
	for(i=0; i<BLOCK; i++)
	{	
		text[i] ^= vector[i];
	}
}

void Encrypt(DATA * key, unsigned char plain[])
{
	int i;

	AddRoundKey(key, plain, 0); 
		
	for(i=1; i<Nr; i++)
	{
		SubBytes(plain);
		ShiftRows(plain);
		MixColumns(plain);
		AddRoundKey(key, plain, i);
	}

	SubBytes(plain);
	ShiftRows(plain);
	AddRoundKey(key, plain, 14);	
}

void MixColumns(unsigned char plain[])
{
	int i, j;
	unsigned char temp[4];

	for(i=0; i<Nb; i++)
	{
		for(j=0; j<4; j++)
		{
			temp[j] = Multiplication(matrix_mix[j*Nb], plain[i*Nb]);
			temp[j] = Addition(temp[j], Multiplication(matrix_mix[j*Nb+1], plain[i*Nb+1]));
			temp[j] = Addition(temp[j], Multiplication(matrix_mix[j*Nb+2], plain[i*Nb+2]));
			temp[j] = Addition(temp[j], Multiplication(matrix_mix[j*Nb+3], plain[i*Nb+3]));
		}
		for(j=0; j<4; j++)
		{
			plain[i*Nb+j] = temp[j];
		}
	}
}

void ShiftRows(unsigned char plain[])
{
	int i, j;
	unsigned char temp;

	for(i=1; i<4; i++)
	{
		for(j=i; j>0; j--)
		{
			temp = plain[i];
			plain[i] = plain[i+Nb];
			plain[i+Nb] = plain[i+Nb*2];
			plain[i+Nb*2] = plain[i+Nb*3];
			plain[i+Nb*3] = temp;
		}
	}
}
	
void SubBytes(unsigned char plain[])
{
	int i;

	for(i=0; i<Nb; i++)
	{
		SubWord((DATA*) &plain[i*4]);
	}
}

void AddRoundKey(DATA * key, unsigned char plain[], int idx)
{
	int i, j;

	for(i=0; i<Nb; i++)
	{
		for(j=0; j<4; j++)
		{
			plain[4*i+j] = key[idx*4+i].arr[j] ^ plain[4*i+j];
		}
	}
}

unsigned char Addition(int n1, int n2)
{
	return (unsigned char)(n1^n2);
}	

unsigned char Multiplication(int n1, int n2)
{
	int res = 0x0;

	while(1)
	{
		if(n2 % 2) // 나머지가 1일 경우 xor (초기값부터 포함하기 위해 제일 먼저 검사)
			res ^= n1;

		if((n2 /= 2) == 0) // n2가 2로 더이상 나누어지지 않을 때까지
		{
			break;
		}
		else
		{
			/* n1에 2곱하고 8bit를 넘어서면 xor 11b(x^8+x^4+x^3+x^1+x^0)를 해준다. */
			/* 그리고 그 값을 n1에 대입한다. */
			n1 *= 2;
			if(n1 > 0xff)
			{	
				n1 ^= 0x11b;
			}
		}
	}

	return (unsigned char)res;
}

unsigned char GenerateRconNum(int num)
{
	int shift = num-1;
	int res = 1;
	int delta = num-8;

	if(shift < 8)
		return (res << shift);
	else
	{	
		res = res << 7;
		
		// shift 할 때 마다 8bit넘는지 검사 후 넘을 시 xor 11b를 해준다.
		while(1)
		{
			if(delta > 0)
				delta--;
			else
				break;
			
			res = res << 1;
			if(res > 0xff)
			{
				res ^= 0x11b;
			}
		}
	}

	return (unsigned char)res;
}

void MakeRcon(DATA * rcon)
{
	int i;

	for(i=0; i<Nk-1; i++)
	{
		rcon[i].arr[0] = GenerateRconNum(i+1);
		rcon[i].arr[1] = 0x0;
		rcon[i].arr[2] = 0x0;
		rcon[i].arr[3] = 0x0;
	}
}

void RotWord(DATA * data)
{
	unsigned char temp;
	temp = data->arr[0];

	data->arr[0] = data->arr[1];
	data->arr[1] = data->arr[2];
	data->arr[2] = data->arr[3];
	data->arr[3] = temp;
}

void SubWord(DATA * data)
{
	data->arr[0] = sbox[data->arr[0]];
	data->arr[1] = sbox[data->arr[1]];
	data->arr[2] = sbox[data->arr[2]];
	data->arr[3] = sbox[data->arr[3]];
}

void KeyExpansion(DATA * key, DATA * rcon, DATA * ikey)
{
	int i;
	
	// ikey값 8열을 key의 첫 8열에 입력
	for(i=0; i<Nk; i++)
	{
		key[i] = ikey[i];
	}
	
	// 나머지 keySchedule
	for(i=1; i<Nk; i++)
	{
		MakeKey(key, rcon, i);
	}	
}

void MakeKey(DATA * key, DATA * rcon, int idx)
{
	int i, j;
	DATA temp;
	
	if(idx == 7) // 마지막에는 4열만 생성하므로
	{
		for(i=0; i<Nb; i++)
		{
			temp = key[idx*Nk-1+i];

			if(i % Nk == 0)
			{
				RotWord(&temp);
				SubWord(&temp);
				for(j=0; j<4; j++)
				{
					temp.arr[j] = temp.arr[j] ^ rcon[idx-1].arr[j];
				}
			}

			for(j=0; j<4; j++)
			{
				temp.arr[j] = key[(idx-1)*Nk+i].arr[j] ^ temp.arr[j];
			}

			key[idx*Nk+i] = temp;	
		}
	}
	else
	{
		for(i=0; i<Nk; i++)
		{
			temp = key[idx*Nk-1+i];

			switch(i % Nk)
			{
				case 0 :
					RotWord(&temp);
					SubWord(&temp);
					for(j=0; j<4; j++)
					{
						temp.arr[j] = temp.arr[j] ^ rcon[idx-1].arr[j];
					}
					break;

				case 4 :
					SubWord(&temp);
					break; 
			}

			for(j=0; j<4; j++)
			{
				temp.arr[j] = key[(idx-1)*Nk+i].arr[j] ^ temp.arr[j];
			}

			key[idx*Nk+i] = temp;	
		}
	}
}