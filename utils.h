typedef enum boolean {
   false = 0,
   true = 1
}bool;

typedef struct arguments {
	char ip_addr[16];
	int port;
	bool isLocal;
	char fileName[20];
}arguments;

