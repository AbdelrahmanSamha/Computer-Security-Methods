#pragma once
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
// These are defined globally in the .cpp file
extern const uint8_t initial_permutation_table[64];
extern const uint8_t ip_INV[64];
extern const uint8_t pc1[56];
extern const uint8_t pc2[48];
extern const uint8_t key_shifts[16];
extern const uint8_t expansion_table[48];
extern const uint8_t pbox[32];
extern const uint8_t sboxes[8][4][16];



class DES {
public:
    std::vector<uint8_t> ctr_encrypt(const std::string& plaintext, uint64_t key, uint64_t counter);
    std::string ctr_decrypt(const std::vector<uint8_t>& ciphertext, uint64_t key, uint64_t counter);
    

private:
    uint64_t encrypt(uint64_t plaintext, uint64_t key);
    uint64_t decrypt(uint64_t ciphertext, uint64_t key);
    uint32_t feistel(uint32_t R, uint64_t subkey);
    void generate_subkeys(uint64_t key);
    uint64_t left_rotate_28(uint64_t half, int shifts);
    uint64_t initial_permutation(uint64_t input);
    uint64_t final_permutation(uint64_t input);
    uint64_t subkeys[16];
};
