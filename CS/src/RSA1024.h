
//struct RSAKeys {
//    int n;
//    int e;
//    int d;
//};
//
//class RSA1024 {
//public:
//    RSA1024();
//    ~RSA1024();
//
//    RSAKeys generateKeys(int p, int q, int e);
//    int encrypt(int plaintext);     // Use stored public key
//    int decrypt(int ciphertext);    // Use stored private key
//
//private:
//    int gcd(int a, int b);
//    int modInverse(int e, int phi);
//    int modExp(int base, int exp, int mod);
//
//    int n, e, d;  // Store the keys inside the object
//};
//
//#ifndef RSA1024_H
//#define RSA1024_H

#include <vector>
#include <string>

struct RSAKeys {
    int n;
    int e;
    int d;
};

class RSA1024 {
public:
    RSA1024();
    ~RSA1024();

    RSAKeys generateKeys(int p, int q, int e);
    std::vector<int>encryptConf(const std::string& message);
    std::string decryptConf(const std::vector<int>& ciphertext);
    std::vector<int>encryptAtho(const std::string& message);
    std::string decryptAtho(const std::vector<int>& ciphertext);


private:
    int gcd(int a, int b);
    int modInverse(int e, int phi);
    int modExp(int base, int exp, int mod);

    int n, e, d;
};
 

