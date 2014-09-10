#include<gatorcrypt.h>
#define DEBUG

int main(int argc, char *argv[]){
	
	arguments* args = parse_args(argc,argv);
	char password[10];
	char *key;
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

	key = generate_key(password);

	printf("Password: %s\n",password);
	
	unsigned char * ptr = key;
	int i =0;
	printf("Key: ");
	while(i<strlen(key)){
		printf("%X ",*ptr);
		ptr++;
		i++;
	}

	exit(0);
}

char *generate_key(char *password){

	char key[64];
	gcry_kdf_derive( password, strlen(password), GCRY_KDF_PBKDF2 , GCRY_MD_SHA512 , "NaCl", 
					strlen("NaCl"), 4096 , 64 , key );

	return key;
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
