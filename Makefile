CC=gcc
CFLAGS=-Wall

all:
	$(CC) $(CFLAGS) dnsproxyserver.c -o dnsproxyserver
	
clean:
	rm -rf *.o dnsproxyserver
