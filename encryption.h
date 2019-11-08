#ifndef ENCRYPTION_H
#define ENCRYPTION_H

// key scheduling
void keySchedule(int);
int roundKeyPermute(int);

// encryption proper
int encrypt(int);
int feistel(int, int);

// others
int lastRound(int, int); // may not need
void encrypt_data();

#endif