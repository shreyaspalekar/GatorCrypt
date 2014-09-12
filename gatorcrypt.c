#include<gatorcrypt.h>
#define DEBUG
#define BUFFER_SIZE 128
#define MAX_PASS_LEN 10
#define MAX_KEY_LEN 64

int main(int argc, char *argv[]){
	
	arguments* args = parse_args(argc,argv);
	char password[MAX_PASS_LEN];
	char key[MAX_KEY_LEN];
	gcry_cipher_hd_t handle;
	FILE * inp_file;
	FILE * out_file;
	size_t file_size;
	size_t buffer_size = BUFFER_SIZE;
	gcry_error_t err = 0;
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
	
	#ifdef DEBUG
	print_key(key);
	#endif
	//TODO:Close files
	inp_file = fopen(args->fileName,"r");
	out_file = fopen("out","w");

	fseek (inp_file, 0, SEEK_END);
	file_size=ftell(inp_file);
	fseek(inp_file, 0L, SEEK_SET);

	gcry_cipher_open(&handle , GCRY_CIPHER_AES128 , GCRY_CIPHER_MODE_CBC , GCRY_CIPHER_CBC_CTS );
	gcry_cipher_setkey(handle , key , strlen(key)*sizeof(char));
	
	size_t bytes_read = 0;

	while(bytes_read<file_size){
	
		char in_buffer[BUFFER_SIZE];
		char out_buffer[BUFFER_SIZE];
		char p_buffer[BUFFER_SIZE];
		size_t incr = fread(in_buffer,sizeof(char),BUFFER_SIZE,inp_file);
		size_t encrypted_bytes = incr;
//		printf("\n--------------Bytes to encrypt: %d-------------\n",encrypted_bytes);
//		print_buffer(in_buffer,encrypted_bytes);
		bytes_read+=incr;

		gcry_cipher_setiv(handle , "5844" ,strlen("5844")*sizeof(char));
		err = gcry_cipher_encrypt(handle, out_buffer , buffer_size , in_buffer , encrypted_bytes);
		if(!err==GPG_ERR_NO_ERROR){
			fprintf (stderr, "Failure: %s/%s\n",gcry_strsource (err),gcry_strerror (err));
			exit(-1);
		}
		write_buffer_to_file(out_file,out_buffer, encrypted_bytes);
		#ifdef DEBUG
		gcry_cipher_setiv(handle , "5844" ,strlen("5844")*sizeof(char));
		gcry_cipher_decrypt(handle , p_buffer , buffer_size , out_buffer , encrypted_bytes);
		print_buffer(p_buffer,encrypted_bytes);
		#endif
	}

	fclose(inp_file);
	fclose(out_file);
	gcry_cipher_close(handle);

	exit(0);
}

void print_buffer(char *p, int len)
{
    //printf("Printing Buffer\n");
    	int i;
//	printf("\n--------------------------------------------------------\n");
    	for (i = 0; i < len; ++i)
        	printf("%c", p[i]);
 //   	printf("\n");
//	printf("\n--------------------------------------------------------\n");
}

void write_buffer_to_file(FILE *f,char *p, size_t len)
{
	write(fileno(f),p,len);
//	printf("wrote %d bytes to file",len);	
    	//int i;
    	//for (i = 0; i < len; ++i){
       // 	fprintf(f,"%c", p[i]);	
       // 	printf("%c", p[i]);
//	}
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
}

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
