#ifndef RC4_H
#define RC4_H

#include <string>
#include <vector>

class RC4 {
private:
    std::vector<unsigned char> S;
    std::string key;

    void KSA();
    unsigned char PRGA();
    void reset();

    int i, j;

public:
    RC4(const std::string& key);
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);
    void printState(); // Print first 16 bytes of S
};

#endif
