#include "RC4.h"
#include <iostream>
#include <iomanip>

RC4::RC4(const std::string& key) : key(key), S(256), i(0), j(0) {
    KSA();
}

void RC4::KSA() {
    for (int i = 0; i < 256; ++i)
        S[i] = i;

    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + S[i] + static_cast<unsigned char>(key[i % key.length()])) % 256;
        std::swap(S[i], S[j]);
    }

    i = j = 0;
}

unsigned char RC4::PRGA() {
    i = (i + 1) % 256;
    j = (j + S[i]) % 256;
    std::swap(S[i], S[j]);
    return S[(S[i] + S[j]) % 256];
}

void RC4::reset() {
    S.resize(256);
    i = j = 0;
    KSA();
}

std::string RC4::encrypt(const std::string& plaintext) {
    reset();
    std::string ciphertext;

    for (unsigned char c : plaintext) {
        unsigned char k = PRGA();
        ciphertext += c ^ k;
        printState();
    }

    return ciphertext;
}

std::string RC4::decrypt(const std::string& ciphertext) {
    return encrypt(ciphertext); // same function for decryption
}

void RC4::printState() {
    std::cout << "Key matrix (K): ";
    for (int idx = 0; idx < 16; ++idx)
        std::cout << std::setw(2) << std::setfill('0') << std::hex
        << std::uppercase << static_cast<int>(S[idx]) << " ";
    std::cout << std::dec << "\n";
}
