#include "RC4.h"
#include <algorithm>
#include <iostream>
#include <iomanip>

RC4::RC4(const std::string& key) {
    keylen = static_cast<int>(key.length());
    KSA(key);
}

void RC4::KSA(const std::string& key) {
    S.resize(256);
    for (int i = 0; i < 256; ++i) {
        S[i] = i;
    }

    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + S[i] + static_cast<unsigned char>(key[i % keylen])) % 256;
        std::swap(S[i], S[j]);
    }
}

std::vector<unsigned char> RC4::PRGA(const std::string& data) {
    int i = 0, j = 0;
    std::vector<unsigned char> result;
    std::vector<int> S_local = S; // Copy to keep original

    for (size_t k = 0; k < data.size(); ++k) {
        i = (i + 1) % 256;
        j = (j + S_local[i]) % 256;
        std::swap(S_local[i], S_local[j]);
        int rnd = S_local[(S_local[i] + S_local[j]) % 256];
        result.push_back(data[k] ^ rnd);

        std::cout << "K matrix after processing byte " << k + 1 << ": ";
        for (int m = 0; m < 16; ++m)
            std::cout << std::setw(3) << S_local[m] << " ";
        std::cout << "...\n";
    }

    return result;
}

std::string RC4::encrypt(const std::string& plaintext) {
    std::vector<unsigned char> cipher = PRGA(plaintext);
    return std::string(cipher.begin(), cipher.end());
}

std::string RC4::decrypt(const std::string& ciphertext) {
    return encrypt(ciphertext); // RC4 is symmetric
}
