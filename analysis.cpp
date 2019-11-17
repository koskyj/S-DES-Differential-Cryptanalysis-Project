#include "analysis.h"
#include "user_interface.h"
#include "encryption.h"
#include "definitions.h"
#include "handlers.h"
#include <iostream>
#define EXTERN extern
#include "globals.h"
using namespace std;

int SboxOut(int input, int box[4][4]) {	
	// Takes 4 bit input and selects 2 output bits from the s-box array
	// the two "inner" bits select column, the two "outer" bits select row
	//col is input AND 6 (0b0110), shifted right 1 to isolate middle 2 bits
	int colOut = (input & 6) >> 1;
	//row is input AND 8 (0b1000) shifted right 2 to isolate leftmost bit, 
	//OR with the col rightmost bit, isolated by AND with 1 (0b0001) 
	int rowOut = ((input & 8) >> 2) | (input & 1);
	int output = box[rowOut][colOut];
	return output;
}

int* invSbox(int output, int box[4][4]) {
	// Takes 2 bit value representing s-box output
	// and returns an array of the 4 possible inputs that would produce that output
	int* xes = new int[4]; // array of 
	int count = 0;
	int x; // s-box input value

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			if (box[i][j] == output) {
				int row; // i = row
				int col; // j = col

				row = (i & 2) << 2 | (i & 1); // outer bits
				col = j << 1; // inner bits

				x = row | col;
				
				xes[count] = x;
				count++;
			}
		}
	}

	return xes;
}

int twoBoxOut(int in) {
	// 

	int boxRow = 0;
	int boxCol = 0;
	int expansion[] = { 3, 0, 1, 2, 1, 2, 3, 0 };
	
	int expandedBits = bitChange(in, expansion, 8);
	int inputS0 = (expandedBits & 0x0f);
	int inputS1 = expandedBits >> 4;


	if (DEBUG) {
		cout << "\t inputS0: " << inputS0 << endl;
		cout << "\t inputS1: " << inputS1 << endl;
	}

	int S0output = SboxOut(inputS0, Sbox0);
	int S1output = SboxOut(inputS1, Sbox1);

	int sOut = (S0output << 2) | S1output;
	
	int pbox[] = { 1, 0, 3, 2 };
	int permuted = bitChange(sOut, pbox, 4);

	return permuted;
}

/*int count(int x, int y, int z[16][16]) {	// OK
	int total = 0;
	for (int i = 0; i < 16; i++) {
		if ((int)z[i][x] == y) {
			total++;
		}
	}
	return total;
}*/

void totalDifferencePairs() {

	int z;
	int zp;
	int dz;
	int in_xor;

	for (int dr = 0; dr < 16; dr++) {
		for (int r = 0; r < 16; r++) {
			in_xor = r ^ dr;
			zp = twoBoxOut(in_xor);
			z = twoBoxOut(r);
			dz = z ^ zp;
			diffPairTable[dr][dz]++;
		}
	}
}

/*void totalDifferenceDistribution() {
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			diffPairTable[i][j] = count(i, j, diffPairTable);
		}
	}
}*/

void findBestDifferencePairs() {
	int highestValue = 0;
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			if ((diffPairTable[i][j] > highestValue) && (diffPairTable[i][j] != 16)) {
				highestValue = diffPairTable[i][j];
			}
		}
	}
	int counter = 0;
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			if (diffPairTable[i][j] == highestValue) {
				highestTableVals[0][counter] = i;
				highestTableVals[1][counter] = j;
				counter++;
			}
		}
	}
	bestRow = highestTableVals[0][TABLE_PAIR];
	bestCol = highestTableVals[1][TABLE_PAIR];
	highestProb = (double)highestValue / 16;
}

int invRoundKeyPermute(int r2key) {
	int invRoundPerm[8] = {4, 1, 7, 0, 6, 3, 5, 2 };
	int rval = bitChange(r2key, invRoundPerm, 8);
	return rval;
}

void analyze() {
	int counter = 0;
	int r2keyguess = 0;
	int inputCharacteristic;
	int outputCharacteristic;
	int expansion[] = { 3, 0, 1, 2, 1, 2, 3, 0 };

	totalDifferencePairs();
	
	printDifferencePairTable();
	
	findBestDifferencePairs();
	
	cout << "The highest value detected is " << diffPairTable[bestRow][bestCol] << " in row " << bestRow << ", column " << bestCol  << "." << endl;
	
	int initialPermutation[] = { 7, 6, 4, 0, 2, 5, 1, 3 };
	int invInitialPermutation[] = { 3, 6, 4, 7, 2, 5, 1, 0 };
	int invPbox[] = {1, 0, 3, 2}; // pbox is same fwd and bckwd

	inputCharacteristic = (bestCol << 4) | bestRow;
	inputCharacteristic = bitChange(inputCharacteristic, invInitialPermutation, 8);

	outputCharacteristic = (0 << 4) | bestRow;
	outputCharacteristic = bitChange(outputCharacteristic, invInitialPermutation, 8);

	//int characteristic[2] = { inputCharacteristic, outputCharacteristic };
	
	cout << "Once the characteristics have been obtained, a partial subkey can be extracted by comparing plaintext and its corresponding ciphertext through the last round." << endl;
	// input and encrypt values 0 through 255
	keySchedule(key);
	for (int ptext = 0; ptext < 255; ptext++) {
		int ctext = encrypt(ptext);
		encryptedPairs[ptext] = ctext;
		int ctext2 = encrypt(ptext ^ inputCharacteristic);
		int dctext = ctext ^ ctext2;
		if (dctext == outputCharacteristic) {
			counter++;
			//ctext, work back through inverse IP to get L2 and R2
			//L2 = R1 = input to sboxes        w's are post expansion
			//output to sboxes can be found from R2 and L1, and L1 = R0 which is the right half input after IP
			int L1, R1, L2, R2, n, zs, ws, w1, w2, x1, x2, y1, y2, z1, z2;
			int* x1s;
			int* x2s;
			n = bitChange(ctext, initialPermutation, 8);
			L2 = n >> 4;
			R2 = n & 0x0f;
			
			R1 = L2;
			ws = bitChange(R1, expansion, 8);
			w1 = ws & 0x0f;
			w2 = ws >> 4;

			L1 = bitChange(ptext, initialPermutation, 8) & 0x0f;
			zs = R2 ^ L1;
			z1 = zs & 0x3;
			z2 = zs >> 2;

			y1 = bitChange(z1, invPbox, 4);
			y2 = bitChange(z2, invPbox, 4);

			x1s = invSbox(y1, Sbox0);
			x2s = invSbox(y2, Sbox1);


			for (int k = 0; k < 64; k++) {
				for (int i = 0; i < 4; i++) {
					if (k == x1s[i] ^ w1) {
						// Test keys
						potentialKeysL[k]++; // make half key tables
					}
					if (k == x2s[i] ^ w2) {
						potentialKeysR[k]++;
					}
				}
			}
			//concat highest half keys
			int highR = 0;
			int highL = 0;
			
			for (int i = 0; i < 64; i++) {
				if (potentialKeysL[i] > highL) {
					highL = potentialKeysL[i];
				}
				if (potentialKeysR[i] > highR) {
					highR = potentialKeysR[i];
				}
			}
			r2keyguess = (highL << 4) | highR;
		}
	}

//	cout << "Expected subkey: " << roundKeys[1] << endl;
//	cout << "Guessed subkey: " << r2keyguess << endl;

	if (roundKeys.at(1) == r2keyguess) {
		cout << "Guess successful." << endl;
	}
	// if this is working, replace key comparator with loop to guess the 4 full key options
	int keybits[10] = { 1, 3, 2, 6, 5, 8, 9, 0, 4, 7 }; // bits 8 and 9 in key 2 are 0
	int knownbits = bitChange(r2keyguess, keybits, 10); // this lets knownbits have all bits from key 2, leaving zeroes in bits 5 and 6
	if (DEBUG) {
		cout << "knownbits with zeros in 5 and 6: " << hex << knownbits << endl;
	}
	int testkey;
	int foundkeyflag = 1;
	int testpairs[256];
	int fullkeyguess;
	for (int i = 0; i < 4; i++) {
		testkey = (knownbits | (i << 5));
		keySchedule(testkey);
		for (int ptext = 0; ptext < 256; ptext++) {
			testpairs[ptext] = encrypt(ptext);
			if (testpairs[ptext] != encryptedPairs[ptext]) {
				foundkeyflag = 0;
				break;
			}
		}
		if (foundkeyflag == 1) {
			fullkeyguess = testkey;
			break;
		}
	}
	if (foundkeyflag) {
		cout << "Key guess is: " << fullkeyguess << endl;
		cout << "Input key was: " << key << endl;
	}
	else {
		cout << "No valid keys found :(" << endl;
	}
}