#include<gatorcrypt.h>
#define DEBUG
#define BUFFER_SIZE 128
#define HMAC_SIZE 64
#define MAX_PASS_LEN 10
#define MAX_KEY_LEN 64
#define MAX_FILE_SIZE 10000
int main(int argc, char *argv[]){
	
	arguments* args = parse_args(argc,argv);
	char password[MAX_PASS_LEN];
	char key[MAX_KEY_LEN];
	char *hmac;
	gcry_cipher_hd_t handle;
	gcry_md_hd_t h;
	FILE * inp_file;
	FILE * out_file;
	char out_file_name[20];
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
	strcpy(out_file_name, args->fileName);
	strcat(out_file_name, ".uf");
	out_file = fopen(out_file_name,"w");

	fseek (inp_file, 0, SEEK_END);
	file_size=ftell(inp_file);
	fseek(inp_file, 0L, SEEK_SET);

	gcry_cipher_open(&handle , GCRY_CIPHER_AES128 , GCRY_CIPHER_MODE_CBC , GCRY_CIPHER_CBC_CTS );
	gcry_cipher_setkey(handle , key , strlen(key)*sizeof(char));

	gcry_md_open(&h , GCRY_MD_SHA512 , GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(h , key ,  strlen(key)*sizeof(char));
	
	char in_buffer[MAX_FILE_SIZE];
	char out_buffer[MAX_FILE_SIZE+HMAC_SIZE];
	size_t encrypted_bytes = fread(in_buffer,sizeof(char),MAX_FILE_SIZE,inp_file);

	gcry_cipher_setiv(handle , "5844" ,strlen("5844")*sizeof(char));
	err = gcry_cipher_encrypt(handle, out_buffer , MAX_FILE_SIZE , in_buffer , encrypted_bytes);
	if(!err==GPG_ERR_NO_ERROR){
		fprintf (stderr, "Failure: %s/%s\n",gcry_strsource (err),gcry_strerror (err));
		exit(-1);
	}

	gcry_md_write(h , out_buffer, encrypted_bytes);
	gcry_md_final(h);
	hmac = gcry_md_read(h , GCRY_MD_SHA512 );

	memcpy(&out_buffer[encrypted_bytes],hmac,sizeof(char)*HMAC_SIZE);
	
	if(args->isLocal==true){
		printf("Print successful");	
		write_buffer_to_file(out_file,out_buffer, encrypted_bytes+HMAC_SIZE);
	}
	else{
		transmit(args,out_buffer,encrypted_bytes+HMAC_SIZE);
	}

	fclose(inp_file);
	fclose(out_file);
	gcry_cipher_close(handle);
	gcry_md_close(h);

	exit(0);
}

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


void transmit(arguments *args,char *buffer,size_t length){
	
	int sock;
	int echoServPort=88;
	struct sockaddr_in echoServAddr;	
	
	if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		DieWithError("socket() failed");

	echoServAddr.sin_family = AF_INET;/* Internet address family */
	echoServAddr.sin_addr.s_addr=htonl(INADDR_ANY); /* Server IP address */
	echoServAddr.sin_port =htons(echoServPort); /* Server port */
	
	if (connect(sock, (struct sockaddr*) &echoServAddr,sizeof(echoServAddr)) < 0)
		DieWithError("connect() failed");

	/* Send the string to the server */	
	if (send(sock,buffer,length, 0) !=length)
		DieWithError("send() sent a different number of bytes than expected");
	
	close(sock);

}
