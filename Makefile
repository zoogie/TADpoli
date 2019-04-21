CFLAGS=-Wall -Wextra -pedantic -std=gnu99 -O3
CC := gcc

all: TADpoli
TADpoli: dsi.o aes.o TADpoli.o bn.o ec.o f_xy.o sha1.o tad.o cert.o
	$(CC) dsi.o aes.o TADpoli.o bn.o ec.o f_xy.o sha1.o tad.o cert.o -o TADpoli

dsi.o: dsi.c
	$(CC) -c dsi.c $(CFLAGS)

aes.o: aes.c
	$(CC) -c aes.c $(CFLAGS)

ec.o: ec.c
	$(CC) -c ec.c $(CFLAGS)

bn.o: bn.c
	$(CC) -c bn.c $(CFLAGS)
	
sha1.o: sha1.c
	$(CC) -c sha1.c $(CFLAGS)
	
tad.o: tad.c
	$(CC) -c tad.c $(CFLAGS)
	
cert.o: cert.c
	$(CC) -c cert.c $(CFLAGS)

TADpoli.o: TADpoli.c
	$(CC) -c TADpoli.c -I.. $(CFLAGS)

clean:
	-/bin/rm dsi.o aes.o TADpoli.o ec.o bn.o f_xy.o sha1.o tad.o cert.o TADpoli 2>/dev/null
