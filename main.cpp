#include <iostream>
#include "AES.h"
using namespace std;

int main() {
    char plaintext[] = "12345678901x3456";
    char key[] = "1234567890123456";
    AES(plaintext, key);
    De_AES(plaintext, key);
    cout << plaintext << flush;
    return 0;
}