
#-finstrument-functions -lSaturn -pg 
#-pg gprof

S3LIB = ../libs3-1.4/build/lib/libs3.a

all: pdp-misc.o pdp.h pdp-core.o pdp-keys.o pdp-file.o pdp-app.c 
	gcc -g -Wall -O3 -lpthread -lcrypto -o pdp pdp-app.c pdp-core.o pdp-misc.o pdp-keys.o pdp-file.o

measurements: pdp-misc.o pdp.h pdp-core.o pdp-keys.o pdp-file.o pdp-measurements.c 
	gcc -pg -g -Wall -O3 -lpthread -lcrypto -o pdp-m pdp-measurements.c pdp-core.o pdp-misc.o pdp-keys.o pdp-file.o

pdp-s3: pdp-misc.o pdp.h pdp-core.o pdp-keys.o pdp-file.o pdp-s3.o pdp-app.c $(S3LIB)
	gcc -pg -DUSE_S3 -g -Wall -O3 -lpthread -lcurl -lxml2 -lz -lcrypto -o pdp-s3 pdp-app.c pdp-core.o pdp-misc.o pdp-keys.o pdp-file.o pdp-s3.o $(S3LIB)

pdp-core.o: pdp-core.c pdp.h
	gcc -g -Wall -O3 -c pdp-core.c

pdp-keys.o: pdp-keys.c pdp.h
	gcc -g -Wall -O3 -c pdp-keys.c

pdp-misc.o: pdp-misc.c pdp.h
	gcc -g -Wall -O3 -c pdp-misc.c

pdp-file.o: pdp-file.c pdp.h
	gcc -g -Wall -O3 -c pdp-file.c

pdp-s3.o: pdp-s3.c pdp.h ../libs3-1.4/build/include/libs3.h
	gcc -pg -DUSE_S3 -g -Wall -O3 -I../libs3-1.4/build/include/ -c pdp-s3.c

pdplib: pdp-core.o pdp-misc.o pdp-keys.o pdp-file.o
	ar -rv pdplib.a pdp-core.o pdp-misc.o pdp-keys.o pdp-file.o

clean:
	rm -rf *.o *.tag pdp.dSYM pdp pdp-s3
