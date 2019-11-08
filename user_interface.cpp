#include "user_interface.h"
#include "handlers.h"
#include "definitions.h"
#include <string>
#include <iostream>
#include <iomanip>
#define EXTERN extern
#include "globals.h"
#include "analysis.h"
using namespace std;

void setKey() {
	string temp;

	key = 0;	// reset master key - Nemo
	cout << "Please enter a 10-bit key as a string of 1s and 0s, most significant bit first: " << flush;
	cin >> temp; //assumes key is properly input
	key = binaryStringToInt(temp);

	if (DEBUG) {
		cout << "Debug: key (hex) = " << hex << key << endl;
	}
}

void printDifferencePairTable() { // OK
	cout << setw(2) << "Difference pair table: " << endl;
	cout << "        Output delta" << endl << "       ";
	for (int j = 0; j < 16; ++j) cout << setw(2) << dec << j << " ";
	cout << endl;
	cout << " Input" << endl <<  " delta" << endl;
	for (int i = 0; i < 16; i++) {
		cout << setw(2) << setfill(' ') << dec << i << "     ";
		for (int j = 0; j < 16; j++) {
			cout << setw(2) << diffPairTable[i][j] << " ";
		}
		cout << endl;
	}
}

void printMenu() {
	cout << endl << "XXXXXXXXXXXXXXXXXXXXXX" << endl;
	cout << "What would you like to do?" << endl
		<< "1. Input key " << endl
		<< "2. Perform differential analysis " << endl
		<< "3. Quit " << endl
		<< "4. Encrypt " << endl << flush;

}