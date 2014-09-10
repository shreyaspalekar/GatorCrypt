CC = gcc
CFLAGS = -c -I.
LDFLAGS = -I.
COMMON_SOURCES = 
ENCRYPT_SOURCES = gatorcrypt.c
DECRYPT_SOURCES = gatordec.c
LIBS =-lgcrypt
COMMON_OBJECTS = $(COMMON_SOURCES:.c=.o)
ENCRYPT_OBJECTS = $(ENCRYPT_SOURCES:.c=.o)
DECRYPT_OBJECTS = $(DECRYPT_SOURCES:.c=.o)
ENCRYPT = gatorcrypt 
DECRYPT = gatordec

.PHONY: all encrypt decrypt clean

all: encrypt decrypt clean

encrypt: $(ENCRYPT)

decrypt: $(DECRYPT)

$(ENCRYPT): $(COMMON_OBJECTS) $(ENCRYPT_OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(DECRYPT): $(COMMON_OBJECTS) $(DECRYPT_OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

clean:
	rm -rf *.o
