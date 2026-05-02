#include <iostream>
#include "AES.h"
#include <fstream>
#include <cstring>
using namespace std;
void AesFile(string plaintextFileName, string ciphertextFileName, char *key) {
    ifstream readfile(plaintextFileName);
    ofstream writeFile(ciphertextFileName);

    string line;
    if (!readfile.is_open()) {
        cout <<plaintextFileName<<" can not open!"<< endl;
        exit(0);
    }
    if (!writeFile.is_open()) {
        cout <<ciphertextFileName<<" can not open!"<< endl;
        exit(0);
    }

    while (getline(readfile, line)) {
        char *plaintext;
        AES(strcpy(plaintext, line.c_str()), key);
        writeFile<<plaintext<<endl;;
        //writeFile.write(plaintext, strlen(plaintext));
    }

    writeFile.close();
    readfile.close();
}
void De_AesFile(string ciphertextFileName, string decryptedFileName, char *key) {
    ifstream readfile(ciphertextFileName);
    ofstream writeFile(decryptedFileName);

    string line;
    if (!readfile.is_open()) {
        cout <<ciphertextFileName<<" can not open!"<< endl;
        exit(0);
    }
    if (!writeFile.is_open()) {
        cout <<decryptedFileName<<" can not open!"<< endl;
        exit(0);
    }

    while (getline(readfile, line)) {
        char *ciphertext;
        De_AES(strcpy(ciphertext, line.c_str()), key);
        ciphertext[strlen(ciphertext)]='\n';
        writeFile.write(ciphertext, strlen(ciphertext));
    }

    writeFile.close();
    readfile.close();
}
int main() {
    //string plaintextFileName="..\\data\\plaintext.txt";
    //string ciphertextFileName="..\\data\\ciphertext.txt";
    //string decryptedFileName="..\\data\\decrypted.txt";
    //AesFile(plaintextFileName, ciphertextFileName, key);
    //De_AesFile(ciphertextFileName, decryptedFileName, key);
    //char key[] = "1234567890123456";
    char key[] = "1234567890123456";
    char plaintext[] = "12354515641651asd";
    AES(plaintext, key);
    De_AES(plaintext, key);
    cout << plaintext << endl;
    return 0;
}