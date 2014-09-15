CC = gcc
CFLAGS = -c -I.
LDFLAGS = -I.
COMMON_SOURCES = 
LIBS =-lgcrypt
ENCRYPT_SOURCES = gatorcrypt.c
DECRYPT_SOURCES = gatordec.c
SERVER_SOURCES = server.c
CLIENT_SOURCES = client.c
COMMON_OBJECTS = $(COMMON_SOURCES:.c=.o)
ENCRYPT_OBJECTS = $(ENCRYPT_SOURCES:.c=.o)
DECRYPT_OBJECTS = $(DECRYPT_SOURCES:.c=.o)
SERVER_OBJECTS = $(SERVER_SOURCES:.c=.o)
CLIENT_OBJECTS = $(CLIENT_SOURCES:.c=.o)
ENCRYPT = gatorcrypt 
DECRYPT = gatordec
SERVER = server
CLIENT = client
.PHONY: all encrypt decrypt clean server client

all: encrypt decrypt clean

encrypt: $(ENCRYPT)

decrypt: $(DECRYPT)

network: $(SERVER) $(CLIENT) clean

$(ENCRYPT): $(COMMON_OBJECTS) $(ENCRYPT_OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(DECRYPT): $(COMMON_OBJECTS) $(DECRYPT_OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(SERVER): $(SERVER_OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@

$(CLIENT): $(CLIENT_OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

clean:
	rm -rf *.o
