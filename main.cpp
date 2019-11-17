// Noah Greene
// CIS4905 Individual Study project
// mods by Nemo 8/24/18

#define EXTERN
#include <iostream>
#include <iomanip>
#include <string>
#include <cmath>
#include "analysis.h"
#include "encryption.h"
#include "handlers.h"
#include "user_interface.h"
#include "definitions.h"
#include "globals.h"

using namespace std;

int main() {
	init();
	int menuChoice;
	cout << "Welcome!" << endl;
	// setKey();
	// encrypt_data();
	while (loopCondition) {
		printMenu();
		cin >> menuChoice;
		inputHandle(menuChoice);
	}
	cout << "Goodbye!" << endl;
}
