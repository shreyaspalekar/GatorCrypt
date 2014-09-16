#include<gatorcrypt.h>
//#define DEBUG
#define MAXPENDING 10
#define BUFFER_SIZE 128
#define MAX_PASS_LEN 10
#define MAX_KEY_LEN 64
#define HMAC_SIZE 64
#define MAX_FILE_SIZE 10000
#define BLOCK_LENGTH 16
void listen_and_decrypt(arguments *args){
	int servSock;
	struct sockaddr_in servAddr;
	struct sockaddr_in clntAddr;
	FILE *outFile;

	if ((servSock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		DieWithError("socket() failed");

	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr =htonl(inet_network("127.0.0.1"));
	servAddr.sin_port =htons(args->port); 

	if (bind(servSock, (struct sockaddr*) &servAddr,sizeof(servAddr)) < 0)
	{
		DieWithError("bind() failed");
		exit(0);
	}

	if (listen(servSock, MAXPENDING) < 0)
		DieWithError("listen() failed");

//	for (;;) /* Run forever */
//	{
		
		int clntLen=sizeof(clntAddr);
		int clntSock;
		int recvMsgSize;
		char password[MAX_PASS_LEN];
		char key[MAX_KEY_LEN];
		char file_buffer[MAX_FILE_SIZE];
		char hmac[HMAC_SIZE];
		char *calculated_hmac;
		char output_buffer[MAX_FILE_SIZE];
		size_t file_size;
		size_t hmac_size=HMAC_SIZE;	
		gcry_cipher_hd_t handle;
		gcry_md_hd_t h;
		gcry_error_t err = 0;
		size_t blk_length = BLOCK_LENGTH;
		char iv[BLOCK_LENGTH] = "5844";

		if ((clntSock=accept(servSock,(struct sockaddr*)&clntAddr,&clntLen)) < 0)
			DieWithError("accept() failed");

		/* Receive message from client */
		if ((recvMsgSize=recv(clntSock,file_buffer,MAX_FILE_SIZE, 0)) < 0)
			DieWithError("recv() failed");
		
		printf("Enter password: ");
		scanf("%s",password);
		printf("Password: %s\n",password);

		generate_key(password,key);
		print_key(key);
		printf("\n");

		gcry_cipher_open(&handle , GCRY_CIPHER_AES128 , GCRY_CIPHER_MODE_CBC , GCRY_CIPHER_CBC_CTS );
		gcry_cipher_setkey(handle , key , strlen(key)*sizeof(char));
		gcry_md_open(&h , GCRY_MD_SHA512 , GCRY_MD_FLAG_HMAC);
	        gcry_md_setkey(h , key ,  strlen(key)*sizeof(char));

		memcpy(hmac,&file_buffer[recvMsgSize-hmac_size],sizeof(char)*HMAC_SIZE);
	
		gcry_md_write(h , file_buffer, recvMsgSize-hmac_size);
	        gcry_md_final(h);
	        calculated_hmac = gcry_md_read(h , GCRY_MD_SHA512 );	
		
		if(!(memcmp(calculated_hmac,hmac,hmac_size)==0)){
			printf("HMAC MISMATCH\n");
			exit(62);
		}	

		gcry_cipher_setiv(handle , &iv[0] ,blk_length);
		err = gcry_cipher_decrypt (handle , output_buffer , MAX_FILE_SIZE , file_buffer , recvMsgSize-hmac_size );

		if(!err==GPG_ERR_NO_ERROR){
			fprintf (stderr, "Failure: %s/%s\n",gcry_strsource (err),gcry_strerror (err));
			exit(-1);
		}


		outFile = fopen(args->outFile,"w");
		//print_buffer(output_buffer,recvMsgSize-hmac_size);
		write_buffer_to_file(outFile,output_buffer, recvMsgSize-hmac_size);
	
		gcry_cipher_close(handle);
		gcry_md_close(h);
       
		fclose(outFile); 
		close(clntSock); 
		
//	}

}


void decrypt_file(FILE *inp_file,arguments* args){
	char password[MAX_PASS_LEN];
	char key[MAX_KEY_LEN];
	char file_buffer[MAX_FILE_SIZE];
	char hmac[HMAC_SIZE];
	char *calculated_hmac;
	char output_buffer[MAX_FILE_SIZE];
	size_t file_size;
	size_t hmac_size=HMAC_SIZE;	
	gcry_cipher_hd_t handle;
	gcry_md_hd_t h;
	gcry_error_t err = 0;
	size_t blk_length = BLOCK_LENGTH;
	char iv[BLOCK_LENGTH] = "5844";
	FILE * outfile;

	outfile = fopen(args->outFile,"w");

	printf("Enter password: ");
	scanf("%s",password);
	printf("Password: %s\n",password);

	generate_key(password,key);
	print_key(key);
	printf("\n");

	gcry_cipher_open(&handle , GCRY_CIPHER_AES128 , GCRY_CIPHER_MODE_CBC , GCRY_CIPHER_CBC_CTS );
	gcry_cipher_setkey(handle , key , strlen(key)*sizeof(char));
	gcry_md_open(&h , GCRY_MD_SHA512 , GCRY_MD_FLAG_HMAC);
        gcry_md_setkey(h , key ,  strlen(key)*sizeof(char));

	fseek (inp_file, 0L, SEEK_END);
	file_size=ftell(inp_file);
	fseek(inp_file, 0L, SEEK_SET);

	fseek (inp_file, -64L, SEEK_END);
	fread(hmac,sizeof(char),hmac_size,inp_file);	
	fseek(inp_file, 0L, SEEK_SET);
     
	size_t read_bytes = fread(file_buffer,sizeof(char),file_size-hmac_size,inp_file);

	gcry_md_write(h , file_buffer, file_size-hmac_size);
        gcry_md_final(h);
        calculated_hmac = gcry_md_read(h , GCRY_MD_SHA512 );
	
	if(!(memcmp(calculated_hmac,hmac,hmac_size)==0)){
		printf("HMAC MISMATCH\n");
		exit(62);
	}


	gcry_cipher_setiv(handle , &iv[0] ,blk_length);
	err = gcry_cipher_decrypt (handle , output_buffer , MAX_FILE_SIZE , file_buffer , file_size-hmac_size );

	if(!err==GPG_ERR_NO_ERROR){
		fprintf (stderr, "Failure: %s/%s\n",gcry_strsource (err),gcry_strerror (err));
		exit(-1);
	}
	print_buffer(output_buffer,file_size-hmac_size);
	write_buffer_to_file(outfile,output_buffer,file_size-hmac_size);

	gcry_cipher_close(handle);
	gcry_md_close(h);
        
	fclose(inp_file);

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
	strcpy(args->outFile,argv[1]);
        strcat(args->fileName, ".uf");


	if(strcmp(argv[2],"-d")==0){
		args->port = atoi(argv[3]);
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
		printf("Specify port\n");
		exit(-1);
	}	
	else if(strcmp(argv[2],"-l")!=0&&strcmp(argv[2],"-d")!=0){
		printf("Wrong parameters\n");
		exit(-1);
	}
}

int main(int argc, char *argv[]){
	
	arguments* args = parse_args(argc,argv);
	FILE * inp_file;
	#ifdef DEBUG
	printf("filename %s\n",args->fileName);
	if(args->isLocal==true){	
		printf("isLocal true\n");
	}
	else{
		printf("PORT %d\n",args->port);
	}
	#endif

	
	if(args->isLocal==true){
		if( access( args->outFile, R_OK ) != -1 ) {
			printf("Output File exists!!!\n");
			exit(33);
		} 
		inp_file = fopen(args->fileName,"r");
		decrypt_file(inp_file,args);	
	}
	else{
//		if( access( args->outFile, R_OK ) != -1 ) {
//			printf("Output File exists!!!\n");
//			exit(33);
//		} 
		listen_and_decrypt(args);
	}
	exit(0);
}
