/* 
    AES 암호화 알고리즘 최종
*/
#ifndef __HEADER_H__
#define __HEADER_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#define Nb 4  // State를 구성하는 32bit word(한 열)의 수
#define Nk 8  // Cipher key를 구성하는 32bit word(한 열)의 수 
#define Nr 14 // 회전(round) 수
#define BLOCK 16 // 블록 크기

typedef struct {
    unsigned char arr[4];
} DATA;

typedef struct {
    DATA key[Nb*(Nr+1)];
    DATA rcon[Nk-1];
    unsigned char vec[BLOCK];
} ENC_DATA;

/* finite field arithmetic */
unsigned char Multiplication(int n1, int n2);
unsigned char Addition(int n1, int n2);

/* Rcon array */
unsigned char GenerateRconNum(int num);
void MakeRcon(DATA * rcon);

/* Key array */
void KeyExpansion(DATA * key, DATA * rcon, DATA * ikey);
void MakeKey(DATA * key, DATA * rcon, int order);
void SubWord(DATA * data);
void RotWord(DATA * data);

/* Encrypt steps */
void SubBytes(unsigned char plain[]);
void ShiftRows(unsigned char plain[]);
void MixColumns(unsigned char plain[]);
void AddRoundKey(DATA * key, unsigned char plain[], int idx);
void CBC(unsigned char vector[], unsigned char text[]);
void Encrypt(DATA * key, unsigned char plain[]);

/* Encryption */
void Encryption_CBC(ENC_DATA * data, FILE * fpin, FILE * fpout);
void InitEncryption(ENC_DATA * data, DATA ikey[], unsigned char vec[]);

/* Search */
void Search(char * path, ENC_DATA * data);

/* Padding */
void Padding(unsigned char plain[], int readlen);

#endif