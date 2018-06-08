CC = gcc
CFLAGS = -Wall -O3 -march=native
LIBS = -lssl -lcrypto

certcheck: main.o certcheck.o
	$(CC) $(CFLAGS) -o certcheck main.o certcheck.o $(LIBS)

main.o: main.c certcheck.h
	$(CC) $(CFLAGS) -c main.c

certcheck.o: certcheck.c
	$(CC) $(CFLAGS) -c certcheck.c

clean:
	rm -f *.o certcheck output.csv

debug: CFLAGS += -g
debug: certcheck

