CC = gcc
CFLAGS = -Wall -g

all: libksocket.a user1 user2 initksocket

libksocket.a: ksocket.o
	ar rcs libksocket.a ksocket.o

ksocket.o: ksocket.c ksocket.h
	$(CC) $(CFLAGS) -c ksocket.c

initksocket: initksocket.c libksocket.a
	$(CC) $(CFLAGS) -o initksocket initksocket.c -L. -lksocket -pthread

user1: user1.c libksocket.a
	$(CC) $(CFLAGS) -o user1 user1.c -L. -lksocket 

user2: user2.c libksocket.a
	$(CC) $(CFLAGS) -o user2 user2.c -L. -lksocket 

clean:
	rm -f *.o *.a user1 user2 initksocket