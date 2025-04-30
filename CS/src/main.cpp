#include <iostream>
#include "SHA512.h"


int main() {

	char userchoice;

	std::cout << "Choose Security Solution:\n\n";
	std::cout << "  A. Data confidentiality assurance by symmetric encryption.\n\n";
	std::cout << "  B. Message Authentication assurance.\n\n";
	std::cout << "  C. Data confidentiality assurance by hybrid encryption (digital envelope).\n\n";

	std::cout << " your choice:";
	std::cin >> userchoice;

	std::cout << "user chose \n" << userchoice;

	//now that we have the user option saved in userchoice it should determine the program flow
	//there should be 3 flows, each flow can use the classes presented in the src file that provide methods, to help with the flow of the program. 

	if (userchoice == 'a') {
		//flow for RC4
		//create object 
		//call routines and methods...

	}
	else if (userchoice == 'b') {
		//flow for MAC
		//create object 
		//call routines and methods...
	}
	else if (userchoice == 'c') {
		//flow for digital envelope
		//create object 
		//call routines and methods...


	}
	
	std::cout << sha512_hex("") << std::endl;     // cf83e1357eefb8bdf... (SHA-512 of empty string)
	std::cout << "\n";
	std::cout << sha512_hex("abc") << std::endl;  // ddaf35a193617aba... (SHA-512 of "abc")

}