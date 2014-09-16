#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <utils.h>
#include <string.h>
#include <gcrypt.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include<sys/types.h>

void listen_and_decrypt(arguments *);
void decrypt_file(FILE *,arguments *);
void DieWithError(char *errorMessage);
void write_buffer_to_file(FILE*,char*,size_t);
void print_buffer(char *p, int len);
void print_buffer_d(char *p, int len);
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
