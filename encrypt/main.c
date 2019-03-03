/*
	AES 암호화

	경로를 입력하면 해당 경로의 모든 파일을 암호화한다.
*/

#include "encrypt.h"

int main(int argc, char * argv[])
{
	if(argc != 2)
	{
		fprintf(stderr, "Usage : %s [directory path]\n", argv[0]);
		exit(1);
	}

	ENC_DATA data;
	char startpath[255] = {0,};

	strcpy(startpath, argv[1]);

	if(startpath[strlen(startpath)-1] != '/')
	{
		startpath[strlen(startpath)] = '/';
	}

	DATA ikey[] = {
		{0x00, 0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06, 0x07},
		{0x08, 0x09, 0x0a, 0x0b},
		{0x0c, 0x0d, 0x0e, 0x0f},
		{0x10, 0x11, 0x12, 0x13},
		{0x14, 0x15, 0x16, 0x17},
		{0x18, 0x19, 0x1a, 0x1b},
		{0x1c, 0x1d, 0x1e, 0x1f}
	};

	unsigned char vec[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f
	};

	InitEncryption(&data, ikey, vec);

	Search(startpath, &data);

	return 0;
}