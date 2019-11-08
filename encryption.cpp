#include "encryption.h"
#include "handlers.h"
#include "definitions.h"
#include "analysis.h"
#include <iostream>
#define EXTERN extern
#include "globals.h"
using namespace std;

int roundKeyPermute(int keyIn) {	// OK
	if (DEBUG) {
		cout << "Round Key Permute:" << endl;
		cout << "\tkeyIn (hex) = " << hex << keyIn << endl;
	}
	int permuted;
	int PC2[] = { 3, 1, 7, 5, 0, 6, 4, 2 };
	// PC-2 for choosing round key bits
	permuted = bitChange(keyIn, PC2, 8);
	if (DEBUG) {
		cout << "\tpermuted key (hex) = " << hex << permuted << endl;
	}
	return permuted;
}

void keySchedule(int key) {	// OK
							// apply initial permutation to key
	int originalKey = key;
	int permutedKey1 = 0; //C0
	int permutedKey2 = 0; //D0

	int C0perm[] = { 9,7,3,8,0 }; // first half of PC1
	int D0perm[] = { 2,6,5,1,4 }; // second half of PC1

	permutedKey1 = bitChange(originalKey, C0perm, 5);
	permutedKey2 = bitChange(originalKey, D0perm, 5);

	int halfkeys1[2] = { permutedKey1, permutedKey2 };

	if (DEBUG) {
		cout << "Debug: Master key (hex) = " << hex << key << endl;
		cout << "Debug: Permuted key C0 (hex) = " << hex << halfkeys1[0]
			<< endl
			<< "\t Permuted key D0 (hex) = " << hex << halfkeys1[1]
			<< endl;
	}

	// Shift left once for first round
	// Looks like the MSB is dropped instead of circular shift
	halfkeys1[0] <<= 1;
	halfkeys1[1] <<= 1;
	// Nemo 8/25/18
	halfkeys1[0] += halfkeys1[0] >> 5;	// add bit shifted out left
	halfkeys1[1] += halfkeys1[0] >> 5;	// add bit shifted out left
	halfkeys1[0] &= 0x1f;	// restrict to lower 5 bits
	halfkeys1[1] &= 0x1f;	// restrict to lower 5 bits

	// Shift left twice for second round
	int halfkeys2[2] = { halfkeys1[0], halfkeys1[1] };
	halfkeys2[0] <<= 2;
	halfkeys2[1] <<= 2;
	halfkeys2[0] += halfkeys2[0] >> 5;	// add bits shifted out left
	halfkeys2[1] += halfkeys2[0] >> 5;	// add bits shifted out left
	halfkeys2[0] &= 0x1f;	// restrict to lower 5 bits
	halfkeys2[1] &= 0x1f;	// restrict to lower 5 bits

	if (DEBUG) {
		cout << "Debug: Permuted keys: (hex): " << endl;
		cout << "\t C1 (hex) = " << hex << halfkeys1[0] << endl
			<< "\t D1 (hex) = " << hex << halfkeys1[1] << endl
			<< "\t C2 (hex) = " << hex << halfkeys2[0] << endl
			<< "\t D2 (hex) = " << hex << halfkeys2[1] << endl;
	}

	// Combine halfkeys into full keystate to get round keys
	int round1key = (halfkeys1[0] << 5) | halfkeys1[1];
	int round2key = (halfkeys2[0] << 5) | halfkeys2[1];

	// Actually select the bits for the round keys
	roundKeys[0] = roundKeyPermute(round1key);
	roundKeys[1] = roundKeyPermute(round2key);

	if (DEBUG) {
		cout << "Debug: Round keys: (hex): " << endl;
		cout << "\t K1 (hex) = " << hex << roundKeys[0] << endl
			<< "\t K2 (hex) = " << hex << roundKeys[1] << endl;
	}
}

int feistel(int rightHalf, int key) {	// OK

	// This function takes in a 4-bit input and an 8-bit round key,
	// expands the input, sends them to the s-boxes, puts that result
	// through the p-box, and returns that value

	// Official SDES Expansion Permutation
	int expansion[] = { 3, 0, 1, 2, 1, 2, 3, 0 };

	if (DEBUG) {
		cout << "Debug: Feistel: " << endl;
	}
	//expand bits
	int expandedBits = bitChange(rightHalf, expansion, 8);
	//xor with key
	int sBoxInput = expandedBits ^ key;
	if (DEBUG) {
		cout << "\t Right half (hex) = " << hex << rightHalf << endl
			<< "\t Expanded (hex) = " << hex << expandedBits << endl
			<< "\t Whitened (hex) = " << hex << sBoxInput << endl;
	}
	//split in half
	int inputS0 = (sBoxInput & 0x0f);
	int inputS1 = sBoxInput >> 4;


	if (DEBUG) {
		cout << "\t inputS0: " << inputS0 << endl;
		cout << "\t inputS1: " << inputS1 << endl;
	}
	// Process S-Boxes
	int S0output = SboxOut(inputS0, Sbox0);
	int S1output = SboxOut(inputS1, Sbox1);

	// Process P-Box
	int sOut = (S0output << 2) | S1output;
	int permuted = 0;
	int pbox[] = { 1, 0, 3, 2 };
	permuted = bitChange(sOut, pbox, 4);

	if (DEBUG) {
		cout << "\tCombined output = " << hex << sOut << endl;
		cout << "\tPermuted output = " << hex << permuted << endl;
	}
	return permuted;
}

int encrypt(int input) {

	int initialPermutation[] = { 7, 6, 4, 0, 2, 5, 1, 3 };
	int invInitialPermutation[] = { 3, 6, 4, 7, 2, 5, 1, 0 };

	int roundIn = bitChange(input, initialPermutation, 8);
	int LR[] = { 0,0 }; // L is 0, R is 1
	int roundOut;
	int cipherText;
	
	if (DEBUG) {
		cout << "In encrypt function..." << endl;
		cout << "input: " << input << endl;
		cout << "roundIn at start: " << roundIn << endl;
	}
	// ===> Start of the round
	for (int i = 0; i < NUM_ROUNDS; i++) { 

		//split into left and right halves
		LR[0] = roundIn >> 4; 
		LR[1] = roundIn & 0x0f; 

		if (DEBUG) {
		   cout << "Round " << i << endl
			    << hex << "Left[" << i << "] = " << LR[0]
				<< "  Right[" << i << "] = " << LR[1]
				<< "  Round key[" << i << "] = " << roundKeys[i]
				<< endl;
		}
		
		roundOut = (feistel(LR[1], roundKeys[i]) ^ LR[0]);
		roundOut += LR[1] << 4;

		if (DEBUG) {
			cout << hex << "Output[" << i << "] = " << roundOut
				<< endl;
		}
		roundIn = roundOut;
	}
	cipherText = bitChange(roundOut, invInitialPermutation, 8);
	return cipherText;
}

void encrypt_data() { // ideally would be able to break larger inputs into byte-sized blocks
	string plaintextString;
	int plaintextInt = 0;

	cout << "Enter plaintext as binary 8 bit value: " << flush;
	cin >> plaintextString;
	// string to character array, then 
	plaintextInt = binaryStringToInt(plaintextString);
	if (DEBUG) {
		cout << "encrypt_data: " << endl
			 << "plaintext entered: " << plaintextString << endl
			 << "plaintext as integer: " << dec << plaintextInt << endl;
	}

	keySchedule(key);
	int ciphertextInt = encrypt(plaintextInt);
	cout << "Ciphertext (hex) = " << hex << ciphertextInt << endl;
}