#include<gatorcrypt.h>
//#define DEBUG
#define BUFFER_SIZE 128
#define HMAC_SIZE 64
#define MAX_PASS_LEN 10
#define MAX_FILE_SIZE 1000000
#define BLOCK_LENGTH 16
#define KEY_LENGTH 64

int main(int argc, char *argv[]){
	/*Set up variables*/	
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
	size_t blk_length =gcry_cipher_get_algo_blklen (GCRY_CIPHER_AES128);
	char iv[BLOCK_LENGTH] = "5844";
	char in_buffer[MAX_FILE_SIZE];
	char out_buffer[MAX_FILE_SIZE+HMAC_SIZE];


	#ifdef DEBUG
	printf("filename %s\n",args->fileName);
	if(args->isLocal==true){	
		printf("isLocal true\n");
	}
	else{
		printf("IP %s\n",args->ip_addr);	
		printf("PORT %d\n",args->port);
	}
	#endif
	/*get password and generate the key and print it*/
	printf("Enter password: ");
	scanf("%s",password);
	generate_key(password,key);
	print_key(key);

	/*Open input file for reading*/	
	inp_file = fopen(args->fileName,"r");
	strcpy(out_file_name, args->fileName);
	strcat(out_file_name, ".uf");
	
	/*Get filesize in bytes*/
	fseek (inp_file, 0, SEEK_END);
	file_size=ftell(inp_file);
	fseek(inp_file, 0L, SEEK_SET);

	/*open encryption and hashing handles and set the keys*/
	gcry_cipher_open(&handle , GCRY_CIPHER_AES128 , GCRY_CIPHER_MODE_CBC , GCRY_CIPHER_CBC_CTS );
	gcry_cipher_setkey(handle , key , KEY_LENGTH*sizeof(char));

	gcry_md_open(&h , GCRY_MD_SHA512 , GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(h , key ,  KEY_LENGTH*sizeof(char));

	/*read in the file into a buffer*/	
	size_t encrypted_bytes = fread(in_buffer,sizeof(char),MAX_FILE_SIZE,inp_file);

	/*set the initializtion vector and encrypt the file buffer and display an error if any*/
	gcry_cipher_setiv(handle , &iv[0] ,blk_length);
	err = gcry_cipher_encrypt(handle, out_buffer , MAX_FILE_SIZE , in_buffer , encrypted_bytes);

	if(!err==GPG_ERR_NO_ERROR){
		fprintf (stderr, "Failure: %s/%s\n",gcry_strsource (err),gcry_strerror (err));
		exit(-1);
	}

	/*generate the hash of the buffer data*/
	gcry_md_write(h , out_buffer, encrypted_bytes);
	gcry_md_final(h);
	hmac = gcry_md_read(h , GCRY_MD_SHA512 );

	/*append the hash to the buffer*/
	memcpy(&out_buffer[encrypted_bytes],hmac,sizeof(char)*HMAC_SIZE);
	
	/*check if local decryption is enabled else transmit it to the server*/
	if(args->isLocal==true){

		if( access( out_file_name, R_OK ) != -1 ) {
                        DieWithErrorCode("Output File exists!!!\n",33);
                }
 
		out_file  = fopen(out_file_name,"w");

		printf("\nencrypted data of length %d bytes along with HMAC of size %d bytes written to file %s.uf\n"
			,(const int)encrypted_bytes,HMAC_SIZE,args->fileName);

		write_buffer_to_file(out_file,out_buffer, encrypted_bytes+HMAC_SIZE);
		fclose(out_file);
	}
	else{
		transmit(args,out_buffer,encrypted_bytes+HMAC_SIZE);
	}

	/*close the file and encryption handles*/
	fclose(inp_file);
	gcry_cipher_close(handle);
	gcry_md_close(h);

	exit(0);
}

/*Parse the arguments with some sanity checking*/
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
	/*check the arguments*/	
	check_args(argc,argv);
	
	arguments *args =  (arguments *) malloc(sizeof(arguments));
	/*Copy filename to structure*/
	strcpy(args->fileName,argv[1]);

	/*Copy ip and port of server to structure*/
	if(strcmp(argv[2],"-d")==0){
		strcpy(args->ip_addr,strtok(argv[3],":"));
		args->port = atoi(strtok(NULL,":"));
		args->isLocal = false;  
	}
	else{
		/*set the local decrypt falg*/
		args->isLocal = true;
	}

	return args;
}

/*Check the correctness of the arguments*/
void check_args(int argc,char *argv[]){

	if(argc<3){
		DieWithErrorCode("Wrong argument count\n",-1);
	}
	else if(strcmp(argv[2],"-d")==0&&argc<4){
		DieWithErrorCode("Specify destination ip and port\n",-1);
	}	
	else if(strcmp(argv[2],"-l")!=0&&strcmp(argv[2],"-d")!=0){
		DieWithErrorCode("Wrong parameters\n",-1);
	}
}

/*Transmit buffer of given length to the server of ip and port specified in the argument structure*/

void transmit(arguments *args,char *buffer,size_t length){
	
	int sock;
	struct sockaddr_in servAddr;	
	
	if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		DieWithErrorCode("socket() failed",-1);

	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr=htonl(inet_network(args->ip_addr));
	servAddr.sin_port =htons(args->port);
	
	if (connect(sock, (struct sockaddr*) &servAddr,sizeof(servAddr)) < 0)
		DieWithErrorCode("connect() failed",-1);

	if (send(sock,buffer,length, 0) !=length)
		DieWithErrorCode("send() sent a different number of bytes than expected",-1);
	
	close(sock);

}
