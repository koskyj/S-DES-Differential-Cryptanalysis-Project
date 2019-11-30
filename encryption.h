#ifndef ENCRYPTION_H
#define ENCRYPTION_H

// key scheduling
void keySchedule(int, int numRounds = 2);
int roundKeyPermute(int);

// encryption proper
int encrypt(int, int numRounds = 2);
int feistel(int, int);

// others
int lastRound(int, int); // may not need (currently unimplemented)
void encrypt_data();

#endif