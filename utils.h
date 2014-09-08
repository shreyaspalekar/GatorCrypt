typedef enum boolean {
   false = 0,
   true = 1
}bool;

typedef struct args {
	int ip_addr;
	int port;
	bool isLocal;
	char* fileName;
}args;

