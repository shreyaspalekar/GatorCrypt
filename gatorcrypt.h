#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <utils.h>
#include <string.h>
#include <gcrypt.h>

void write_buffer_to_file(FILE*,char*,size_t);
void print_buffer(char *p, int len);
void print_key(char *);
void generate_key(char *,char *);
arguments *parse_args(int argc,char *argv[]);
void check_args(int argc,char *argv[]);
char * readPass();
char* generateKey(char * password);
FILE * readFile(char * fileName);
FILE * encrypt(FILE *);
char * add_auth_info(char *);
void dumpFile(char *fileName);
