#include "DES.h"


// Helper to convert 8 bytes from a vector to a uint64_t
uint64_t bytes_to_uint64(const uint8_t* bytes) {
    uint64_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result = (result << 8) | bytes[i];
    }
    return result;
}

// Helper to convert a uint64_t to 8 bytes
void uint64_to_bytes(uint64_t value, uint8_t* out) {
    for (int i = 7; i >= 0; --i) {
        out[i] = value & 0xFF;
        value >>= 8;
    }
}

std::vector<uint8_t> DES::ctr_encrypt(const std::string& plaintext, uint64_t key, uint64_t counter) {
    std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(plaintext_bytes.size());

    
    

    for (size_t i = 0; i < plaintext_bytes.size(); i += 8) {
        uint64_t keystream = encrypt(counter, key);
        uint8_t keystream_block[8];
        uint64_to_bytes(keystream, keystream_block);

        for (int j = 0; j < 8 && (i + j) < plaintext_bytes.size(); ++j) {
            ciphertext.push_back(plaintext_bytes[i + j] ^ keystream_block[j]);
        }

        ++counter;
    }

    return ciphertext;
}

std::string DES::ctr_decrypt(const std::vector<uint8_t>& ciphertext, uint64_t key, uint64_t counter) {
    std::vector<uint8_t> plaintext;
    plaintext.reserve(ciphertext.size());

    
    

    for (size_t i = 0; i < ciphertext.size(); i += 8) {
        uint64_t keystream = encrypt(counter, key);
        uint8_t keystream_block[8];
        uint64_to_bytes(keystream, keystream_block);

        for (int j = 0; j < 8 && (i + j) < ciphertext.size(); ++j) {
            plaintext.push_back(ciphertext[i + j] ^ keystream_block[j]);
        }

        ++counter;
    }

    return std::string(plaintext.begin(), plaintext.end());
}



uint64_t DES::encrypt(uint64_t pt, uint64_t key) {

    
    generate_subkeys(key);
    
    pt = initial_permutation(pt);

    
    uint32_t L = (pt >> 32) & 0xFFFFFFFF;
    uint32_t R = pt & 0xFFFFFFFF;

    // 16 rounds of festel
    for (int round = 0; round < 16; ++round) {
        uint32_t temp = R;
        R = L ^ feistel(R, subkeys[round]);
        L = temp;
    }
    
    //  Combine R and L (note: R goes first due to last swap)
    uint64_t preoutput = ((uint64_t)R << 32) | L;
    
    //  Final Permutation
    return final_permutation(preoutput);
}


uint64_t DES::decrypt(uint64_t ciphertext, uint64_t key) {

    generate_subkeys(key);  // Generate subkeys as usual

    // Apply initial permutation
    uint64_t permuted = initial_permutation(ciphertext);

    uint32_t L = (permuted >> 32) & 0xFFFFFFFF;
    uint32_t R = permuted & 0xFFFFFFFF;

    // 16 rounds in reverse order
    for (int i = 15; i >= 0; --i) {
        uint32_t temp = R;
        R = L ^ feistel(R, subkeys[i]);
        L = temp;
    }

    // Combine R and L in reverse order
    uint64_t combined = (uint64_t(R) << 32) | L;

    // Apply final permutation
    return final_permutation(combined);
}

uint32_t DES::feistel(uint32_t R, uint64_t subkey) {
    uint64_t expanded = 0;
    for (int i = 0; i < 48; ++i) {
        int bit_from_R = expansion_table[i];            // Which bit to pick (1-based)
        int shift_amount = 32 - bit_from_R;             // Convert to 0-based index
        uint64_t bit = (R >> shift_amount) & 1ULL;      // Extract the bit from R
        expanded |= bit << (47 - i);                    // Place the bit in the output
    }

    expanded ^= subkey;

    uint32_t sbox_output = 0;
    for (int i = 0; i < 8; ++i) {
        
        uint8_t six_bits = (expanded >> (42 - i * 6)) & 0b111111;           // for the S-box we need to get 6 bits of the expanded 48-bits and find the corresponding
                                                                            // value that we should find in in the Substitution tables in each iteration 
       
        int row = ((six_bits & 0b100000) >> 4) | (six_bits & 0b000001);     //row bit 5 and 0
        int col = (six_bits >> 1) & 0b1111;                                 //column bit 4321
        uint8_t sbox_val = sboxes[i][row][col];
        sbox_output |= sbox_val << (28 - (4 * i));
    }

    uint32_t output = 0;
    for (int i = 0; i < 32; ++i) {
        output |= ((sbox_output >> (32 - pbox[i])) & 1) << (31 - i);        // table, find index, shift by 32- index, mask, correct its position. 
    }

    return output;
}

uint64_t DES::left_rotate_28(uint64_t half, int shifts) {
    return ((half << shifts) | (half >> (28 - shifts))) & 0x0FFFFFFF;
}

void DES::generate_subkeys(uint64_t key) {
    uint64_t permuted_key = 0;                   // in the document, it is assumed that the count for any value starts from the left 
    for (int i = 0; i < 56; ++i) {              // and the count is (1-based), but in C++, the the indexing is 0 based, so to tell what bit we want to mask we 
        int bit_index = 64 - pc1[i];            // we ask the question, what is the index of the bit at position X countin from the left, which is equivilant to                            bit63       bit0 
       // int maskpc1 = ((key >> bit_index) & 1ULL); // 64-X count from the right, then to mask it we need to shift it to the right by (64-x) and Bitwise AND it with 1ULL; which is a 64 bit 1 -> 0000....0001
        permuted_key |= (((key >> bit_index) & 1ULL) << (55 - i));     // after we have the bit of interest in vatiable mask, we need to find its correct position (refer to the table PC-1), to do this we shift it to the right by (55-i)
    }                                           // which will yeild in the position that bit should be at, then Bitwise OR it with they permuted key we are building through the for-loop 
                                                // **********THE SAME CONSIPT IS APPLIED TO ALL THE STEPS THAT REQUIERE PERMUTATION THROUGH A TABLE BUT WITH CHANGES MADE TO THE ITERATION LIMIT***********
                                                

    uint32_t C = (permuted_key >> 28) & 0x0FFFFFFF;
    uint32_t D = permuted_key & 0x0FFFFFFF;

    for (int round = 0; round < 16; ++round) {
        C = left_rotate_28(C, key_shifts[round]);
        D = left_rotate_28(D, key_shifts[round]);

        uint64_t combined = ((uint64_t)C << 28) | D; // casted C to become 64bit here, because when we defined we made it 32bit in order to mask the 28 bits of out interest
        subkeys[round] = 0;
        for (int i = 0; i < 48; ++i) {
            int bit_index = 56 - pc2[i];
            
            subkeys[round] |= ((combined >> bit_index) & 1ULL) << (47 - i);
        }
    }
}




uint64_t DES::initial_permutation(uint64_t input) {
    uint64_t output = 0;
    for (int i = 0; i < 64; ++i) {
        int source_bit_pos = 64 - initial_permutation_table[i]; // Convert IP table to 0-based index
        uint64_t bit = (input >> source_bit_pos) & 1ULL;
        output |= (bit << (63 - i));
    }
    return output;
}

uint64_t DES::final_permutation(uint64_t input) {
    uint64_t output = 0;
    for (int i = 0; i < 64; ++i) {
        int source_bit_pos = 64 - ip_INV[i]; // Convert IP table to 0-based index
        uint64_t bit = (input >> source_bit_pos) & 1ULL;
        output |= (bit << (63 - i));
    }
    return output;
}
const uint8_t initial_permutation_table[64] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
};
const uint8_t ip_INV[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9,  49, 17, 57, 25
};

const uint8_t pc1[56] = {
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
};
const uint8_t pc2[48] = {
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
};

const uint8_t key_shifts[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
};

const uint8_t expansion_table[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1
};
const uint8_t pbox[32] = {
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
};

const uint8_t sboxes[8][4][16] = {
    // S1
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    // S2
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    // S3
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    // S4
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    // S5
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    // S6
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    // S7
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    // S8
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};