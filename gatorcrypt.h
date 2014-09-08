#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <utils.h>

void parge_args();
char * readPass();
char* generateKey(char * password);
FILE * readFile(char * fileName);
FILE * encrypt(FILE *);
char * add_auth_info(char *);
void dumpFile(char *fileName);
