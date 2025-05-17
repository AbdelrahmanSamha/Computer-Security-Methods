#include "RSA1024.h"
#include <iostream>
using namespace std;

RSA1024::RSA1024() {}
RSA1024::~RSA1024() {}

int RSA1024::gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

int RSA1024::modInverse(int e, int phi) {
    int t = 0, newt = 1;
    int r = phi, newr = e;
    while (newr != 0) {
        int quotient = r / newr;
        int temp = newt;
        newt = t - quotient * newt;
        t = temp;

        temp = newr;
        newr = r - quotient * newr;
        r = temp;
    }
    if (r > 1) return -1;
    if (t < 0) t += phi;
    return t;
}

int RSA1024::modExp(int base, int exp, int mod) {
    int result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

RSAKeys RSA1024::generateKeys(int p, int q, int e_input) {
    RSAKeys keys;
    n = p * q;
    int phi = (p - 1) * (q - 1);

    while (gcd(e_input, phi) != 1) e_input++;
    e = e_input;
    d = modInverse(e, phi);

    keys.n = n;
    keys.e = e;
    keys.d = d;

    return keys;
}

vector<int> RSA1024::encryptConf(const string& message) {
    vector<int> encrypted;
    for (char ch : message) {
        int cipherChar = modExp((int)ch, e, n);
        encrypted.push_back(cipherChar);
    }
    return encrypted;
}
vector<int> RSA1024::encryptAtho(const string& message) {
    vector<int> encrypted;
    for (char ch : message) {
        int cipherChar = modExp((int)ch, d, n);
        encrypted.push_back(cipherChar);
    }
    return encrypted;

}

string RSA1024::decryptConf(const vector<int>& ciphertext) {
    string decrypted;
    for (int cipherChar : ciphertext) {
        char ch = (char)modExp(cipherChar, d, n);
        decrypted.push_back(ch);
    }
    return decrypted;
}
string RSA1024::decryptAtho(const vector<int>& ciphertext) {
    string decrypted;
    for (int cipherChar : ciphertext) {
        char ch = (char)modExp(cipherChar,e, n);
        decrypted.push_back(ch);
    }
    return decrypted;
}

