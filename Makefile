CC = gcc
CFLAGS = -c -I.
LDFLAGS = -I.
COMMON_SOURCES = 
ENCRYPT_SOURCES = gatorcrypt.c
DECRYPT_SOURCES = gatordec.c
COMMON_OBJECTS = $(COMMON_SOURCES:.cpp=.o)
ENCRYPT_OBJECTS = $(ENCRYPT_SOURCES:.cpp=.o)
DECRYPT_OBJECTS = $(DECRYPT_SOURCES:.cpp=.o)
ENCRYPT = gatorcrypt 
DECRYPT = gatordec

.PHONY: all encrypt decrypt

all: encrypt decrypt

encrypt: $(ENCRYPT)

decrypt: $(DECRYPT)

$(ENCRYPT): $(COMMON_OBJECTS) $(ENCRYPT_OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@

$(DECRYPT): $(COMMON_OBJECTS) $(DECRYPT_OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

