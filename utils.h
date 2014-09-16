#include <gcrypt.h>
#define MAX_KEY_LEN 64

typedef enum boolean {
   false = 0,
   true = 1
}bool;

typedef struct arguments {
	char ip_addr[16];
	int port;
	bool isLocal;
	char fileName[20];
	char outFile[20];
}arguments;

void print_buffer(char *p, int len)
{
    	int i;
    	for (i = 0; i < len; ++i)
        	printf("%c", p[i]);
}
void print_buffer_d(char *p, int len)
{
    	int i;
    	for (i = 0; i < len; ++i)
        	printf(" %c %d %d ", p[i],p[i],i);
    	printf("i=%d\n",i);
}

void write_buffer_to_file(FILE *f,char *p, size_t len)
{
	write(fileno(f),p,len);
}

void print_key(char *key){
	unsigned char * ptr = key;
	int i =0;
	printf("Key: ");
	while(i<strlen(key)){
		printf("%X ",*ptr);
		ptr++;
		i++;
	}
	printf("\n");
}
void generate_key(char *password,char *key){

	gcry_kdf_derive( password, strlen(password)*sizeof(char), GCRY_KDF_PBKDF2 , GCRY_MD_SHA512 , "NaCl", 
					strlen("NaCl")*sizeof(char), 4096 , MAX_KEY_LEN, key );
}

void DieWithError(char *errorMessage)
{
        perror(errorMessage);
        exit(1);
}



