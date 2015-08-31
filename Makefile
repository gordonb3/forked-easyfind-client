CC=gcc
CFLAGS=-c -Wall
LDFLAGS=-lcurl -lpcre -ljson-c

all:
	$(CC) $(CFLAGS) ef.c
	$(CC) $(CFLAGS) ef-lib.c
	$(CC) $(LDFLAGS) ef.o ef-lib.o -o ef
	ln -sf ef efd

clean:
	rm -f ef-lib.o ef.o efd ef
