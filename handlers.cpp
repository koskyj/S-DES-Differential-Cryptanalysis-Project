#include "handlers.h"
#include "user_interface.h"
#include "analysis.h"
#include "encryption.h"
#include "definitions.h"
#include <iostream>
#include <cmath>
#define EXTERN extern
#include "globals.h"
using namespace std;

int binaryStringToInt(string input) {
	int decimal = 0;
	int addVal;
	if (DEBUG) {
		cout << "in binaryStringtoInt" << endl;
		cout << "input string: " << input << endl;
		cout << "decimal int at start is " << dec << decimal << endl;
	}
	for (int i = 0; i < input.length(); i++) { // may need to cast unsigned value to signed
		if (input[input.length() - 1 - i] == '1') {
			decimal += (1 << i); // shift function works better than pow() for powers of 2
			if (DEBUG) {
				cout << "i: " << i << endl;
				cout << "adding: " << (1 << i) << endl;
				cout << "current int: " << decimal << endl;
			}
		}
	}
	if (DEBUG) {
		cout << "returning value " << decimal << " from binaryStringToInt." << endl;
	}
	return decimal;
}

int bitChange(int start, int* permutation, int size) {
	int end = 0;
	int bit;
	//cout << "In bitChange" << endl;
	for (int i = 0; i < size; i++) {
		bit = (1 << permutation[i]); // shift function works better than pow() for powers of 2
		//cout << "i: " << i << endl;
		//cout << "permutation[" << i << "]: " << permutation[i] << endl;
		//cout << "bit: " << bit << endl;
		if (start & bit) {
			end += (1 << (size - 1 - i)); // shift function works better than pow() for powers of 2
			//cout << "end: " << end << endl;
		}
	}
	return end;
}
void inputHandle(int choice) {
	if (choice == 1) {
		init(); // prevents global variables from carrying over on multiple tests
		setKey();
	}
	else if (choice == 2) {
		analyze();
	}
	else if (choice == 3) {
		loopCondition = false;
	}
	else if (choice == 4) {
		encrypt_data();
	}
}
void init() {
	key = 0;
	Sbox0[0][0] = 1;
	Sbox0[0][1] = 0;
	Sbox0[0][2] = 2;
	Sbox0[0][3] = 3;
	Sbox0[1][0] = 3;
	Sbox0[1][1] = 1;
	Sbox0[1][2] = 0;
	Sbox0[1][3] = 2;
	Sbox0[2][0] = 2;
	Sbox0[2][1] = 0;
	Sbox0[2][2] = 3;
	Sbox0[2][3] = 1;
	Sbox0[3][0] = 1;
	Sbox0[3][1] = 3;
	Sbox0[3][2] = 2;
	Sbox0[3][3] = 0;

	Sbox1[0][0] = 0;
	Sbox1[0][1] = 3; 
	Sbox1[0][2] = 1; 
	Sbox1[0][3] = 2; 
	Sbox1[1][0] = 3;
	Sbox1[1][1] = 2;
	Sbox1[1][2] = 0;
	Sbox1[1][3] = 1;
	Sbox1[2][0] = 1;
	Sbox1[2][1] = 0;
	Sbox1[2][2] = 3;
	Sbox1[2][3] = 2;
	Sbox1[3][0] = 2;
	Sbox1[3][1] = 1;
	Sbox1[3][2] = 3;
	Sbox1[3][3] = 0;
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 16; j++) {
			diffPairTable[i][j] = 0;
		}
	}
	for (int i = 0; i < 2; i++) {
		for (int j = 0; j < 256; j++) {
			highestTableVals[i][j] = 0;
		}
	}

	loopCondition = true;
	highestProb = 0.0;
	inputCharacteristic = 0;
	outputCharacteristic = 0;
}