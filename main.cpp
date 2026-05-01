#include <iostream>
#include "AES.h"
using namespace std;
// TIP 要<b>Run</b>代码，请按 <shortcut actionId="Run"/> 或点击装订区域中的 <icon src="AllIcons.Actions.Execute"/> 图标。
int main() {
    char plaintext[] = "1234567890123456";
    char key[] = "1234567890123456";
    AES(plaintext, key);
    cout<<plaintext<<endl;
    return 0;
}