#include<gatorcrypt.h>
#define DEBUG
#define BUFFER_SIZE 128
#define MAX_PASS_LEN 10
#define MAX_KEY_LEN 64

int main(int argc, char *argv[]){
	
	arguments* args = parse_args(argc,argv);
	char password[MAX_PASS_LEN];
	char key[MAX_KEY_LEN];
	char in_buffer[BUFFER_SIZE];
	char out_buffer[BUFFER_SIZE];
	gcry_cipher_hd_t handle;
	#ifdef DEBUG

	printf("filename %s\n",args->fileName);
	if(args->isLocal==true){	
		printf("isLocal true\n");
	}
	else{
		printf("IP %d\n",args->ip_addr);	
		printf("PORT %d\n",args->port);
	}
	#endif

	printf("Enter password: ");
	scanf("%s",password);

	generate_key(password,key);

	printf("Password: %s\n",password);
	
	print_key(key);

	gcry_cipher_open(&handle , GCRY_CIPHER_AES128 , GCRY_CIPHER_MODE_CBC , 0 );
	gcry_cipher_setkey(handle , key , strlen(key));
	gcry_cipher_setiv(handle , "5844" ,strlen("5844"));

	strcpy(in_buffer,"wolololololololo");
	int encrypted_bytes = (strlen(in_buffer)+1) *sizeof(char);
	printf("Bytes to encrypt: %d\n",encrypted_bytes);

	gcry_cipher_encrypt(handle, out_buffer , BUFFER_SIZE , in_buffer , encrypted_bytes);

	printf("\nencrypted %s\n",out_buffer);

	gcry_cipher_decrypt (handle , in_buffer , BUFFER_SIZE , out_buffer , encrypted_bytes );

	printf("\ndecrypted %s\n",in_buffer);

	gcry_cipher_close(handle);

	exit(0);
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
}
void generate_key(char *password,char *key){

	gcry_kdf_derive( password, strlen(password), GCRY_KDF_PBKDF2 , GCRY_MD_SHA512 , "NaCl", 
					strlen("NaCl"), 4096 , 64 , key );
}

arguments *parse_args(int argc,char *argv[]){

	#ifdef DEBUG
	int ctr;
	
	printf("argc: %d\n",argc);
	
	for(ctr=0; ctr < argc; ctr++ )
	{
		printf("ctr %d ",ctr);
		puts( argv[ctr] );
	}
	#endif
	
	check_args(argc,argv);
	arguments *args =  (arguments *) malloc(sizeof(arguments));

	strcpy(args->fileName,argv[1]);

	if(strcmp(argv[2],"-d")==0){
		args->ip_addr = atoi(strtok(argv[3],":"));
		args->port = atoi(strtok(NULL,":"));
		args->isLocal = false;  
	}
	else{
		args->isLocal = true;
	}

	return args;
};

void check_args(int argc,char *argv[]){

	if(argc<3){
		printf("Need atleast one argument\n");
		exit(-1);
	}
	else if(strcmp(argv[2],"-d")==0&&argc<4){
		printf("Specify destination ip and port\n");
		exit(-1);
	}	
	else if(strcmp(argv[2],"-l")!=0&&strcmp(argv[2],"-d")!=0){
		printf("Wrong parameters\n");
		exit(-1);
	}
}
