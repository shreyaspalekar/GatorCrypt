#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <utils.h>
#include <string.h>
#include <gcrypt.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
void listen_and_decrypt(arguments *);
void decrypt_file(FILE *,arguments *);
arguments *parse_args(int argc,char *argv[]);
void check_args(int argc,char *argv[]);

