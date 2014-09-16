#include <gcrypt.h>
#define MAX_KEY_LEN 64
/*Enum defining a boolean*/
typedef enum boolean {
   false = 0,
   true = 1
}bool;
/*the argument struture*/
typedef struct arguments {
	char ip_addr[16];
	int port;
	bool isLocal;
	char fileName[20];
	char outFile[20];
}arguments;
/*print a buffer of the given length*/
void print_buffer(char *p, int len)
{
    	int i;
    	for (i = 0; i < len; ++i)
        	printf("%c", p[i]);
}
/*print a buffer of given length and also the ascii codes of the charecters*/
void print_buffer_d(char *p, int len)
{
    	int i;
    	for (i = 0; i < len; ++i)
        	printf(" %c %d %d ", p[i],p[i],i);
    	printf("i=%d\n",i);
}
/*write a buffer of the given size to the file*/
void write_buffer_to_file(FILE *f,char *p, size_t len)
{
	write(fileno(f),p,len);
}
/*Print the key stored in the buffer*/
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
/*generate a key for the password*/
void generate_key(char *password,char *key){

	gcry_kdf_derive( password, strlen(password)*sizeof(char), GCRY_KDF_PBKDF2 , GCRY_MD_SHA512 , "NaCl", 
					strlen("NaCl")*sizeof(char), 4096 , MAX_KEY_LEN, key );
}
/*Exit the program displaying the error*/
void DieWithError(char *errorMessage)
{
        perror(errorMessage);
        exit(1);
}



