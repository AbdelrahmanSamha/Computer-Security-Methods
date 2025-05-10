#pragma once
#ifndef RC4_H
#define RC4_H

#include <string>
#include <vector>

class RC4 {
private:
    std::vector<int> S;
    int keylen;
    void KSA(const std::string& key);
    std::vector<unsigned char> PRGA(const std::string& data);

public:
    RC4(const std::string& key);
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);
};

#endif
