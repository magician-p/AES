//
// Created by 98314 on 2026/5/1.
//
#include "AES.h"
#include <iostream>
#include <string.h>
using namespace std;
static const unsigned char S[16][16]={
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
static const unsigned char S_t[16][16]={
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
static const char colM[4][4] = {
    2, 3, 1, 1,
    1, 2, 3, 1,
    1, 1, 2, 3,
    3, 1, 1, 2 };
static const char deColM[4][4] = {
    0x0e, 0x0b, 0x0d, 0x09,
    0x09, 0x0e, 0x0b, 0x0d,
    0x0d, 0x09, 0x0e, 0x0b,
    0x0b, 0x0d, 0x09, 0x0e};
static const unsigned int Rcon[10]={0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};
static int W[44];
static char S_change(unsigned char c) {
    char high = c>>4&0x0f;
    char low = c&0x0f;
    return S[high][low];
}
static  int leafByteLoop(unsigned int w, int num) {
    int w_1 = w<<8*num;
    int w_2 = w>>32-(8*num);
    return w_1 | w_2;
}
static void splitIntToArray( int w,  char Array[4]) {
    Array[0] = w>>24&0xff;
    Array[1] = w>>16&0xff;
    Array[2] = w>>8&0xff;
    Array[3] = w&0xff;
}
static  int getIntFromChar( char c) {
     int result = c;
    return result & 0x000000ff;
}
static  int getWordFromChar( char *c) {
     int k_1 = getIntFromChar(c[0])<<24;
     int k_2 = getIntFromChar(c[1])<<16;
     int k_3 = getIntFromChar(c[2])<<8;
     int k_4 = getIntFromChar(c[3]);
    return k_1 | k_2 | k_3 | k_4;
}
static int T(int w, int round) {
    int w_1 = leafByteLoop(w, 1);
    char Array[4];
    splitIntToArray(w_1, Array);
    for ( char & i : Array) {
        i = S_change(i);
    }
    int w_2 = getWordFromChar(Array);
    return w_2^Rcon[round];
}
static void key_extend(char *key) {
    for (int i=0;i<4;i++) {
        W[i] = getWordFromChar(key+i*4);
    }
    for (int i=4, j=0; i<44; i++) {
        if (i%4 == 0) {
            W[i] = W[i-4]^T(W[i-1], j);
            j++;
        }else {
            W[i] = W[i-1]^W[i-4];
        }
    }
}
static void roundKeyEncrypt(char plaintext[4][4], int round) {
    char w_Array[4];
    for (int i=0; i<4; i++) {
        splitIntToArray(W[4*round+i], w_Array);
        for (int j=0; j<4; j++) {
            plaintext[j][i] ^= w_Array[j];
        }
    }
}
static void byteReplace(char plaintext[4][4]) {
    for (int i = 0; i<4; i++) {
        for (int j=0; j<4; j++) {
            plaintext[i][j] = S_change(plaintext[i][j]);
        }
    }
}
static void rowLeftLoop( char plaintext[4][4]) {
    char two_Array[4], three_Array[4], four_Array[4];
    int p_2 = getWordFromChar(plaintext[1]);
    p_2 = leafByteLoop(p_2, 1);
    splitIntToArray(p_2, two_Array);
    int p_3 = getWordFromChar(plaintext[2]);
    p_3 = leafByteLoop(p_3, 2);
    splitIntToArray(p_3, three_Array);
    int p_4 = getWordFromChar(plaintext[3]);
    p_4 = leafByteLoop(p_4, 3);
    splitIntToArray(p_4, four_Array);
    for (int i=0;i<4;i++) {
        plaintext[1][i] = two_Array[i];
        plaintext[2][i] = three_Array[i];
        plaintext[3][i] = four_Array[i];
    }
}
static  char GFMul2( char c) {//0010
    char a7 = c & 0x80;
    char result = c << 1;
    if (a7 == 0) {
        return result;
    }
    return result ^ 0x1b;
}
static  char GFMul3( char c) {//0011
    return c^GFMul2(c);
}
static char GFMul4(int s) {//0100
    return GFMul2(GFMul2(s));
}
static char GFMul8(int s) {//1000
    return GFMul2(GFMul4(s));
}
static char GFMul9(int s) {//1001
    return GFMul8(s)^s;
}
static char GFMulB(int s) {//1011
    return GFMul9(s) ^ GFMul2(s);
}
static char GFMul12(int s) {//1100
    return GFMul8(s) ^ GFMul4(s);
}
static char GFMulD(int s) {//1101
    return GFMul12(s) ^ s;
}
static char GFMulE(int s) {//1110
    return GFMul12(s) ^ GFMul2(s);
}
static char GFMul( char mix,  char c) {
    switch (mix) {
        case 1:
            return c;
        case 2:
            return GFMul2(c);
        case 3:
            return GFMul3(c);
        case 0x09:
            return GFMul9(c);
        case 0x0b:
            return GFMulB(c);
        case 0x0d:
            return GFMulD(c);
        case 0x0e:
            return GFMulE(c);
        default: return 0;
    }
}
static void mixColumn( char plaintext[4][4]) {
    char temp[4][4];
    for (int i=0; i<4; i++) {
        for(int j=0; j<4; j++) {
            temp[i][j] = plaintext[i][j];
        }
    }
    for (int i=0; i<4; i++) {
        for (int j=0; j<4; j++) {
            plaintext[i][j] = GFMul(colM[i][0], temp[0][j])^GFMul(colM[i][1], temp[1][j])^GFMul(colM[i][2], temp[2][j])^GFMul(colM[i][3], temp[3][j]);
        }
    }
}
static void convertArrayToStr(const char plaintext[4][4],  char *str) {
    for (int i=0; i<4; i++) {
        for (int j=0; j<4; j++) {
            *(str+4*i+j)=plaintext[j][i];
        }
    }
}
static void convertStrToArray( char plaintext[4][4], const char *str) {
    for (int i=0; i<4; i++) {
        for (int j=0; j<4; j++) {
            plaintext[j][i]=*(str+4*i+j);
        }
    }
}
static bool checkKeyLength(const char *key) {
    if (strlen(key)==16)
        return true;
    return false;
}
static void PKCS7Padding(char *plaintext, int BlockSize) {
    size_t padding_size = BlockSize - strlen(plaintext) % BlockSize;
    char padding_char = static_cast<char>(padding_size);
    int length = strlen(plaintext);
    for (int i=0; i<padding_size; i++) {
        *(plaintext + length +i) = padding_char;
    }
    plaintext[length +padding_size] = '\0';
}
static void PKCS7UnPadding(char *plaintext) {
    size_t padding_size = plaintext[strlen(plaintext)-1];
    int length = strlen(plaintext)-padding_size;
    plaintext[length] = '\0';
}
void AES(char *plaintext, char *key) {
    int p_length = strlen(plaintext);
    if (p_length==0) {
        cout<<"Plaintext length is 0."<<endl;
        exit(0);
    }
    if (p_length % 16!=0) {
        PKCS7Padding(plaintext, 16);
    }
    p_length = strlen(plaintext);
    key[16]='\0';
    if (!checkKeyLength(key)) {
        cout <<"Key length should be 16."<<endl;
        exit(0);
    }
    char p_Array[4][4];
    key_extend(key);
    for (int i=0; i<p_length; i+=16) {
        convertStrToArray(p_Array,plaintext+i);
        roundKeyEncrypt(p_Array, 0);
        for (int round=1; round<10; round++) {
            byteReplace(p_Array);
            rowLeftLoop(p_Array);
            mixColumn(p_Array);
            roundKeyEncrypt(p_Array, round);
        }
        byteReplace(p_Array);
        rowLeftLoop(p_Array);
        roundKeyEncrypt(p_Array, 10);
        convertArrayToStr(p_Array, plaintext+i);
    }
}
static char getCharFromSt(char c) {
    char heigh = c>>4 & 0x0f;
    char low = c & 0x0f;
    return S_t[heigh][low];
}
static void deByteReplace(char ciphertext[4][4]) {
    for (int i=0; i<4; i++) {
        for (int j=0; j<4; j++) {
            ciphertext[i][j]=getCharFromSt(ciphertext[i][j]);
        }
    }
}
static int rightLoop(unsigned int w, int num) {
    int w_1 = w>>(num*8);
    int w_2 = w<<(32-num*8);
    return w_1|w_2;
}
static void rowRightLoop(char ciphertext[4][4]) {
    char two_Array[4], three_Array[4], four_Array[4];
    int p_2 = getWordFromChar(ciphertext[1]);
    p_2 = rightLoop(p_2, 1);
    splitIntToArray(p_2, two_Array);
    int p_3 = getWordFromChar(ciphertext[2]);
    p_3 = rightLoop(p_3, 2);
    splitIntToArray(p_3, three_Array);
    int p_4 = getWordFromChar(ciphertext[3]);
    p_4 = rightLoop(p_4, 3);
    splitIntToArray(p_4, four_Array);
    for (int i=0;i<4;i++) {
        ciphertext[1][i] = two_Array[i];
        ciphertext[2][i] = three_Array[i];
        ciphertext[3][i] = four_Array[i];
    }
}
static void de_ColumnMix(char ciphertext[4][4]) {
    char temp[4][4];
    for (int i=0; i<4; i++) {
        for (int j=0; j<4; j++) {
            temp[i][j] = ciphertext[i][j];
        }
    }
    for (int i=0; i<4; i++) {
        for (int j=0; j<4; j++) {
            ciphertext[i][j] = GFMul(deColM[i][0],temp[0][j]) ^ GFMul(deColM[i][1],temp[1][j])
                ^ GFMul(deColM[i][2],temp[2][j]) ^ GFMul(deColM[i][3],temp[3][j]);
        }
    }
}
void De_AES(char *ciphertext,char *key) {
    int c_length = strlen(ciphertext);
    if (c_length==0) {
        cout<<"Ciphertext length is 0."<<endl;
        exit(0);
    }
    if (c_length % 16!=0) {
        cout<<"The length of the ciphertext needs to be a multiple of 16."<<endl;
        exit(0);
    }
    key[16] = '\0';
    if (!checkKeyLength(key)) {
        cout <<"Key length should be 16."<<endl;
        exit(0);
    }
    char c_Array[4][4];
    key_extend(key);
    for (int i=0; i<strlen(ciphertext); i+=16) {
        convertStrToArray(c_Array,ciphertext+i);
        roundKeyEncrypt(c_Array, 10);
        for (int round=9; round>=1; round--) {
            rowRightLoop(c_Array);
            deByteReplace(c_Array);
            roundKeyEncrypt(c_Array, round);
            de_ColumnMix(c_Array);
        }
        rowRightLoop(c_Array);
        deByteReplace(c_Array);
        roundKeyEncrypt(c_Array, 0);
        convertArrayToStr(c_Array,ciphertext+i);
    }
    PKCS7UnPadding(ciphertext);
}


