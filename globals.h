#ifndef GLOBALS_H
#define GLOBALS_H
#include <vector>

EXTERN int key;
EXTERN bool loopCondition;
EXTERN int Sbox0[4][4];
EXTERN int Sbox1[4][4];
EXTERN int diffPairTable[16][16];
EXTERN int highestTableVals[2][5];
EXTERN int bestRow;
EXTERN int bestCol;
EXTERN double highestProb;
EXTERN int inputCharacteristic;
EXTERN int outputCharacteristic;
EXTERN std::vector<int> roundKeys;
EXTERN int potentialKeysL[64];
EXTERN int potentialKeysR[64];
EXTERN int encryptedPairs[256];
//EXTERN int round1Input;
//EXTERN int round1OutputCurrent;
//EXTERN int round1Output;
//EXTERN int cipherText1;
//EXTERN int cipherText2;
#endif