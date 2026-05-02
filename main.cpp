#include <iostream>
#include "AES.h"
#include <fstream>
#include <cstring>
using namespace std;
void AesFile(string plaintextFileName, string ciphertextFileName, string keyFileName) {
    ifstream readfile(plaintextFileName);
    ifstream keyfile(keyFileName);
    ofstream writeFile(ciphertextFileName);
    if (!readfile.is_open()) {
        cout <<plaintextFileName<<" can not open!"<< endl;
        exit(0);
    }
    if (!keyfile.is_open()) {
        cout <<keyFileName<<" can not open!"<< endl;
        exit(0);
    }
    if (!writeFile.is_open()) {
        cout <<ciphertextFileName<<" can not open!"<< endl;
        exit(0);
    }

    string key_line;
    getline(keyfile, key_line);
    char key[100];
    strcpy(key, key_line.c_str());

    string line;
    while (getline(readfile, line)) {
        char plaintext[100];
        AES(strcpy(plaintext, line.c_str()), key);
        writeFile<<plaintext<<endl;;
    }

    writeFile.close();
    readfile.close();
}
void De_AesFile(string ciphertextFileName, string decryptedFileName, string keyFileName) {
    ifstream readfile(ciphertextFileName);
    ifstream keyfile(keyFileName);
    ofstream writeFile(decryptedFileName);

    string line;
    if (!readfile.is_open()) {
        cout <<ciphertextFileName<<" can not open!"<< endl;
        exit(0);
    }
    if (!keyfile.is_open()) {
        cout <<keyFileName<<" can not open!"<< endl;
        exit(0);
    }
    if (!writeFile.is_open()) {
        cout <<decryptedFileName<<" can not open!"<< endl;
        exit(0);
    }

    string key_line;
    getline(keyfile, key_line);
    char key[100];
    strcpy(key, key_line.c_str());

    while (getline(readfile, line)) {
        char ciphertext[100];
        De_AES(strcpy(ciphertext, line.c_str()), key);
        writeFile<<ciphertext<<endl;
    }

    writeFile.close();
    readfile.close();
}
int main() {
    string plaintextFileName="..\\data\\plaintext.txt";
    string ciphertextFileName="..\\data\\ciphertext.txt";
    string decryptedFileName="..\\data\\decrypted.txt";
    string keyFileName="..\\data\\key.txt";
    AesFile(plaintextFileName, ciphertextFileName, keyFileName);
    cout <<"Encryption is successful!"<< endl;
    De_AesFile(ciphertextFileName, decryptedFileName, keyFileName);
    cout <<"Decryption is successful!"<< endl;
    return 0;
}