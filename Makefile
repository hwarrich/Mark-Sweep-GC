CC            = gcc
#SPECIAL_FLAGS = -ggdb -Wall -DDEBUG_ALLOC
SPECIAL_FLAGS = -ggdb -Wall
#SPECIAL_FLAGS = -O3
CFLAGS        = -std=gnu99 $(SPECIAL_FLAGS)

libbf: bf-alloc.o safeio.o
	$(CC) $(CFLAGS) -fPIC -shared -o libbf.so bf-alloc.o safeio.o

bf-alloc.o: bf-alloc.c safeio.h
	$(CC) $(CFLAGS) -c bf-alloc.c

libsf: sf-alloc.o safeio.o
	$(CC) $(CFLAGS) -fPIC -shared -o libsf.so sf-alloc.o safeio.o

sf-alloc.o: sf-alloc.c safeio.h
	$(CC) $(CFLAGS) -c sf-alloc.c

memtest: memtest.c
	$(CC) $(CFLAGS) -o memtest memtest.c

safeio.o: safeio.c safeio.h
	$(CC) $(CFLAGS) -c safeio.c

docs:
	doxygen

clean:
	rm -rf *.o *.so memtest
