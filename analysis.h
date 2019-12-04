#ifndef ANALYSIS_H
#define ANALYSIS_H
int SboxOut(int, int[4][4]);
int twoBoxOut(int);
int count(int, int, int[16][16]);
void totalDifferencePairs();
void totalDifferenceDistribution();
void findBestDifferencePairs(); 
void analyze();
void keyVoting();
void checkTestKeys();
void findMasterKey(int, int, int, int[2]);
#endif