#include<gatorcrypt.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <arpa/inet.h>

//#define DEBUG
#define MAXPENDING 10
#define BUFFER_SIZE 128
#define MAX_PASS_LEN 10
#define MAX_KEY_LEN 64
#define HMAC_SIZE 64
#define MAX_FILE_SIZE 10000
#define BLOCK_LENGTH 16

/*listen to the given port and decrypt incoming data*/
void listen_and_decrypt(arguments *args){
	int servSock;
	struct sockaddr_in servAddr;
	struct sockaddr_in clntAddr;
 	struct ifreq ifr;
	FILE *outFile;
	
	/*set up the application to listen on the port*/
	if ((servSock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		DieWithErrorCode("socket() failed",-1);

	servAddr.sin_family = AF_INET;
	
	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
 	ioctl(servSock, SIOCGIFADDR, &ifr);
	servAddr.sin_addr.s_addr =htonl(inet_network(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)));
	servAddr.sin_port =htons(args->port); 

	if (bind(servSock, (struct sockaddr*) &servAddr,sizeof(servAddr)) < 0)
	{
		DieWithErrorCode("bind() failed",-1);
	}

	if (listen(servSock, MAXPENDING) < 0)
		DieWithErrorCode("listen() failed",-1);

//	for (;;) /* Run forever */
//	{
		/*set up variables*/		
		printf("ServerIp:%s\nListening on port: %d\n",inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr),args->port);
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
		
		/*accept client communication*/
		if ((clntSock=accept(servSock,(struct sockaddr*)&clntAddr,&clntLen)) < 0)
			DieWithErrorCode("accept() failed",-1);

		/* Receive message from client */
		if ((recvMsgSize=recv(clntSock,file_buffer,MAX_FILE_SIZE, 0)) < 0)
			DieWithErrorCode("recv() failed",-1);
		/*get password and generate key*/
		printf("Enter password: ");
		scanf("%s",password);
		printf("Password: %s\n",password);

		generate_key(password,key);
		print_key(key);
		printf("\n");

		/*open encryption and hashing handles*/
		gcry_cipher_open(&handle , GCRY_CIPHER_AES128 , GCRY_CIPHER_MODE_CBC , GCRY_CIPHER_CBC_CTS );
		gcry_cipher_setkey(handle , key , MAX_KEY_LEN*sizeof(char));
		gcry_md_open(&h , GCRY_MD_SHA512 , GCRY_MD_FLAG_HMAC);
	        gcry_md_setkey(h , key ,  MAX_KEY_LEN*sizeof(char));

		/*read the hmac bytes from the data*/
		memcpy(hmac,&file_buffer[recvMsgSize-hmac_size],sizeof(char)*HMAC_SIZE);
	
		/*calculate hmac*/
		gcry_md_write(h , file_buffer, recvMsgSize-hmac_size);
	        gcry_md_final(h);
	        calculated_hmac = gcry_md_read(h , GCRY_MD_SHA512 );	
		
		/*compare the hmacs*/
		if(!(memcmp(calculated_hmac,hmac,hmac_size)==0)){
			DieWithErrorCode("HMAC MISMATCH\n",62);
		}	

		/*set initailization vectors and decrypt*/
		gcry_cipher_setiv(handle , &iv[0] ,blk_length);
		err = gcry_cipher_decrypt (handle , output_buffer , MAX_FILE_SIZE , file_buffer , recvMsgSize-hmac_size );

		/*error checking*/
		if(!err==GPG_ERR_NO_ERROR){
			fprintf (stderr, "Failure: %s/%s\n",gcry_strsource (err),gcry_strerror (err));
			exit(-1);
		}

		/*write out to the output file*/
		outFile = fopen(args->outFile,"w");
		write_buffer_to_file(outFile,output_buffer, recvMsgSize-hmac_size);
	
		/*close the hashing and encryption handles*/
		gcry_cipher_close(handle);
		gcry_md_close(h);
       
		/*close the file handle and the client socket*/
		fclose(outFile); 
		close(clntSock); 
		
//	}

}

/*Decrypt a local file*/
void decrypt_file(FILE *inp_file,arguments* args){
	/*set up variables*/
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
	/*open output file*/
	outfile = fopen(args->outFile,"w");

	/*get password and generate key*/
	printf("Enter password: ");
	scanf("%s",password);
	printf("Password: %s\n",password);
	generate_key(password,key);
	print_key(key);
	printf("\n");
	
	/*open encryption and hashing handles*/
	gcry_cipher_open(&handle , GCRY_CIPHER_AES128 , GCRY_CIPHER_MODE_CBC , GCRY_CIPHER_CBC_CTS );
	gcry_cipher_setkey(handle , key , MAX_KEY_LEN*sizeof(char));
	gcry_md_open(&h , GCRY_MD_SHA512 , GCRY_MD_FLAG_HMAC);
        gcry_md_setkey(h , key ,  MAX_KEY_LEN*sizeof(char));
	
	/*get file size*/
	fseek (inp_file, 0L, SEEK_END);
	file_size=ftell(inp_file);
	fseek(inp_file, 0L, SEEK_SET);
	
	/*read the hmac which are the last 64 bytes*/
	fseek (inp_file, -64L, SEEK_END);
	fread(hmac,sizeof(char),hmac_size,inp_file);	
	fseek(inp_file, 0L, SEEK_SET);
     	
	/*read the encrypted contents*/
	size_t read_bytes = fread(file_buffer,sizeof(char),file_size-hmac_size,inp_file);
	
	/*calculate the hmac*/
	gcry_md_write(h , file_buffer, file_size-hmac_size);
        gcry_md_final(h);
        calculated_hmac = gcry_md_read(h , GCRY_MD_SHA512 );
	
	/*compare the calculated and the stored hmac*/
	if(!(memcmp(calculated_hmac,hmac,hmac_size)==0)){
		DieWithErrorCode("HMAC MISMATCH\n",62);
	}

	/*set the initialization vector and decrypt the data*/
	gcry_cipher_setiv(handle , &iv[0] ,blk_length);
	err = gcry_cipher_decrypt (handle , output_buffer , MAX_FILE_SIZE , file_buffer , file_size-hmac_size );

	/*Error checking*/
	if(!err==GPG_ERR_NO_ERROR){
		fprintf (stderr, "Failure: %s/%s\n",gcry_strsource (err),gcry_strerror (err));
		exit(-1);
	}
	/*print the decrypted contents and write out the data*/
	//print_buffer(output_buffer,file_size-hmac_size);
	write_buffer_to_file(outfile,output_buffer,file_size-hmac_size);

	/*close the hashing and encryption handles*/
	gcry_cipher_close(handle);
	gcry_md_close(h);
        

}
/*parse the arguments*/
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
	/*get the filename*/
	strcpy(args->fileName,argv[1]);
	strcpy(args->outFile,argv[1]);
        strcat(args->fileName, ".uf");

	/*set the port to listen to or incase of local decryption set the flag*/
	if(strcmp(argv[2],"-d")==0){
		args->port = atoi(argv[3]);
		args->isLocal = false;  
	}
	else{
		args->isLocal = true;
	}

	return args;
}
/*check if the arguments are correct*/
void check_args(int argc,char *argv[]){

	if(argc<3){
		DieWithErrorCode("Wrong argument count\n",-1);
	}
	else if(strcmp(argv[2],"-d")==0&&argc<4){
		DieWithErrorCode("Specify port\n",-1);
	}	
	else if(strcmp(argv[2],"-l")!=0&&strcmp(argv[2],"-d")!=0){
		DieWithErrorCode("Wrong parameters\n",-1);
	}
}

int main(int argc, char *argv[]){
	
	/*parse the arguments*/
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

	/*Check if the output file is present*/
	if( access( args->outFile, R_OK ) != -1 ) {
		DieWithErrorCode("Output File exists!!!\n",33);
	} 

	/* check if the local flag is set else start to listen on the specified port*/
	if(args->isLocal==true){
		inp_file = fopen(args->fileName,"r");
		decrypt_file(inp_file,args);	
		fclose(inp_file);
	}
	else{
		listen_and_decrypt(args);
	}

	exit(0);
}
