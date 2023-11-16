LIBS=-lpcre -lcrypto -lm -lpthread
CFLAGS=-g -O3 -Wall -pthread -std=gnu99
OBJS=vanitygen.o pattern.o util.o sha3.o hex.o
PROGS=vanity oclvanity

PLATFORM=$(shell uname -s)
ifeq ($(PLATFORM),Darwin)
	OPENCL_LIBS=-framework OpenCL
	LIBS+=-L/usr/local/opt/openssl/lib
	CFLAGS+=-I/usr/local/opt/openssl/include
else ifeq ($(PLATFORM),NetBSD)
	LIBS+=`pcre-config --libs`
	CFLAGS+=`pcre-config --cflags`
else
	OPENCL_LIBS=-lOpenCL
endif


most: vanity

all: $(PROGS)

vanity: vanitygen.o pattern.o util.o sha3.o hex.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)
	@objcopy --only-keep-debug $@ $@.dbg
	@objcopy --strip-debug --strip-unneeded $@
	@objcopy --add-gnu-debuglink=$@.dbg $@

oclvanity: oclvanitygen.o oclengine.o pattern.o util.o sha3.o hex.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(OPENCL_LIBS)

clean:
	rm -rf $(OBJS) $(PROGS) $(TESTS) bin obj *.o *.oclbin *.exe *.dbg
