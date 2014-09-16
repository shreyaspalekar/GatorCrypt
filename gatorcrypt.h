#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <utils.h>
#include <string.h>
#include <gcrypt.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

arguments *parse_args(int argc,char *argv[]);
void check_args(int argc,char *argv[]);
void DieWithError(char *errorMessage);
void transmit(arguments *,char *,size_t);
