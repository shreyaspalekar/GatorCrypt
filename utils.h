typedef enum boolean {
   false = 0,
   true = 1
}bool;

typedef struct arguments {
	int ip_addr;
	int port;
	bool isLocal;
	char fileName[20];
}arguments;

