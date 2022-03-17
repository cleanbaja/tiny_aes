# Makefile for Tiny AES, a small cryptographic library for AES encryption
# Copyright (c) 2022 cleanbaja, All Rights Reserved.
# SPDX-License-Identifier: MIT

# Build a release build by default, with lto and ubsan
CFLAGS ?= -O0 -g -flto
CFLAGS += -I $(shell pwd)

# Enable CPU-based hardware acceleration if requested!
ifeq ($(ENABLE_ASM_STUBS),1)

ifeq ($(shell uname -m), x86_64)
ASM_ARCH := amd64
else
$(error Hardware based AES acceleration was requested, but the CPU is not supported!)
endif

CFLAGS += -DCPU_BASED_ACCELERATION=1

libtiny-aes.a: asm/aes_$(ASM_ARCH).S tiny_aes.c tiny_aes.h
	$(CC) $(CFLAGS) -c -o tiny_aes.o tiny_aes.c
	$(CC) $(CFLAGS) -c -o tables.o tables.c
	$(AS) -o aes_$(ASM_ARCH).o asm/aes_$(ASM_ARCH).S
	$(AR) rcs $@ tiny_aes.o tables.o aes_$(ASM_ARCH).o

else

libtiny-aes.a: tiny_aes.c tables.c tiny_aes.h
	$(CC) $(CFLAGS) -c -o tiny_aes.o tiny_aes.c
	$(CC) $(CFLAGS) -c -o tables.o tables.c
	$(AR) rcs $@ tiny_aes.o tables.o

endif

# Test targets for making sure the code works :-)
test-encrypt: libtiny-aes.a test/encrypt.c 
	$(CC) $(CFLAGS) -o test-encrypt test/encrypt.c libtiny-aes.a

test-decrypt: libtiny-aes.a test/decrypt.c 
	$(CC) $(CFLAGS) -o test-decrypt test/decrypt.c libtiny-aes.a

test: test-encrypt test-decrypt
	./test-encrypt
	./test-decrypt

# Build only the library by default
.PHONY: all
all: libtiny-aes.a

.PHONY: clean
clean:
	rm -f *.o *.a tinyaes_all.h tinyaes_all.c test-encrypt test-decrypt

.PHONY: pack
pack:
	cat *.c > tinyaes_all.c
	cat *.h > tinyaes_all.h

