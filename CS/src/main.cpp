#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <random>
#include "SHA512.h"
#include "RSA1024.h"
#include "DES.h"
#include "RC4.h"


// Helper to convert hex string to binary data
std::string hexToBytes(const std::string& hex) {
	std::string result;
	std::istringstream iss(hex);
	std::string byteStr;
	while (iss >> byteStr) {
		unsigned int byte;
		std::stringstream ss;
		ss << std::hex << byteStr;
		ss >> byte;
		result += static_cast<unsigned char>(byte);
	}
	return result;
}

uint64_t random_uint64() {
	std::random_device rd;
	std::mt19937_64 gen(rd());
	return gen();
}

int main() {
	char runAgain;

	do {
		char userchoice;

		std::cout << "Choose Security Solution:\n\n";
		std::cout << "  a. Data confidentiality assurance by symmetric encryption.\n\n";
		std::cout << "  b. Message Authentication assurance.\n\n";
		std::cout << "  c. Data confidentiality assurance by hybrid encryption (digital envelope).\n\n";

		std::cout << " your choice:";
		std::cin >> userchoice;

		std::cout << "user chose : " << userchoice << std::endl;



		if (userchoice == 'a') {
			std::string key, input;
			char mode;

			std::cout << "\n--- RC4 Stream Cipher Menu ---\n";
			std::cout << "1. Encrypt\n";
			std::cout << "2. Decrypt\n";
			std::cout << "Choose an option: ";
			std::cin >> mode;
			std::cin.ignore(); // Clear newline after mode input

			std::cout << "Enter key: ";
			std::getline(std::cin, key);

			std::cout << "Enter text: ";
			std::getline(std::cin, input);

			RC4 rc4(key);
			std::string result;

			if (mode == '1') {
				result = rc4.encrypt(input);
				std::cout << "Encrypted output (hex): ";
				for (unsigned char c : result) {
					std::cout << std::hex << std::uppercase
						<< std::setw(2) << std::setfill('0') << (int)c << " ";
				}
				std::cout << std::dec << "\n";
			}
			else if (mode == '2') {
				input = hexToBytes(input); // Convert hex to bytes
				result = rc4.decrypt(input);
				std::cout << "Decrypted output: " << result << "\n";
			}
			else {
				std::cout << "Invalid option.\n";
			}

		}
		else if (userchoice == 'b') {
			// message autentication  with RSA
			std::string message;
			std::cout << "Enter a message to encrypt: ";
			std::cin.ignore();
			std::getline(std::cin, message);
			message = sha512_hex(message); // hash with SHA-512

			RSA1024 rsa;
			int p = 61;
			int q = 53;
			int e = 17;

			RSAKeys keys = rsa.generateKeys(p, q, e);
			std::cout << "Public Key: (e = " << keys.e << ", n = " << keys.n << ")\n";
			std::cout << "Private Key: (d = " << keys.d << ", n = " << keys.n << ")\n";

			std::cout << "Message hashed: " << message << "\n";

			std::vector<int> encryptedConf = rsa.encryptConf(message);
			std::cout << "Encrypted message for confidentiality: ";
			for (int c : encryptedConf) std::cout << c << " ";
			std::cout << "\n";

			std::vector<int> encryptedAuth = rsa.encryptAtho(message);
			std::cout << "Encrypted message for authenticity: ";
			for (int c : encryptedAuth) std::cout << c << " ";
			std::cout << "\n";

			std::string decryptedConf = rsa.decryptConf(encryptedConf);
			std::cout << "Decrypted message for confidentiality: " << decryptedConf << "\n";

			std::string decryptedAuth = rsa.decryptAtho(encryptedAuth);
			std::cout << "Decrypted message for authenticity: " << decryptedAuth << "\n";
		}
		else if (userchoice == 'c') {
			// ——— Read the plaintext ———
			std::cout << "enter the plaintext to be enveloped...: \n";
			std::cin.ignore();
			std::string message;
			std::getline(std::cin, message);

			// ——— 1) Symmetric key & CTR  ———
			uint64_t sym_key = random_uint64();
			//uint64_t nonce = random_uint64(); // this can be used to generate a random counter  
			uint64_t nonce = 1; // test with counter 1. 

			std::cout << "\n";
			std::cout << "Generated DES-CTR key: 0x"
				<< std::hex << std::setw(16) << std::setfill('0') << sym_key << "\n"
				<< "Generated nonce/counter:  0x"
				<< std::hex << std::setw(16) << std::setfill('0') << nonce << std::dec << "\n\n";

			// ——— 2) Symmetrically encrypt with DES-CTR 
			DES des;
			auto sym_cipher = des.ctr_encrypt(message, sym_key, nonce);

			std::cout << "Symmetric ciphertext (hex): ";
			for (auto b : sym_cipher)
				std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
			std::cout << std::dec << "\n\n";

			// ——— 3) RSA keygen & wrap the sym_key (digital envelope) ———
			RSA1024 rsa;
			int p = 61, q = 53, e = 17;
			RSAKeys keys = rsa.generateKeys(p, q, e);

			std::cout << "Public Key:  (e = " << keys.e << ", n = " << keys.n << ")\n"
				<< "Private Key: (d = " << keys.d << ", n = " << keys.n << ")\n\n";

			// Encrypt the sym_key (as a decimal string) for confidentiality
			std::string sym_key_str = std::to_string(sym_key);
			auto wrappedKey = rsa.encryptConf(sym_key_str);

			std::cout << "Encrypted DES key under RSA:\n ";
			for (int c : wrappedKey) std::cout << c << ' ';
			std::cout << "\n\n";

			// ——— 4) Emit the “digital envelope” ———
			std::cout << "----- DIGITAL ENVELOPE -----\n";
			std::cout << "Nonce:      0x" << std::hex << std::setw(16) << std::setfill('0') << nonce << "\n";
			std::cout << "Sym-Cipher: ";
			for (auto b : sym_cipher)
				std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;


			std::cout << "\nWrappedKey: ";

			for (int c : wrappedKey) std::cout << c << ' ';
			std::cout << "\n\n";

			// ——— 5) Reverse: unwrap sym_key then decrypt DES?CTR ———
			std::string recovered_key_str = rsa.decryptConf(wrappedKey);
			uint64_t recovered_key = std::stoull(recovered_key_str);

			std::cout << "Recovered DES key: 0x"
				<< std::hex << std::setw(16) << std::setfill('0') << recovered_key
				<< std::dec << "\n";

			std::string recovered = des.ctr_decrypt(sym_cipher, recovered_key, nonce);
			std::cout << "Recovered plaintext: " << recovered << "\n";
		}


		std::cout << "\nWould you like to run the program again? (y/n): ";
		std::cin >> runAgain;
		std::cin.ignore(); 
	} while (runAgain == 'y' || runAgain == 'Y');
	return 0;
}

