/*
 * Copyright 2018 Jesse Kuang <jkuang@21cn.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */

#ifndef WIN32
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include "hex.h"

static const char hexdig[] = "0123456789abcdef";

bool hexdec(void *bin, size_t *binszp, const unsigned char *hex, size_t hexsz)
{
	size_t binsz = *binszp;
	const unsigned char *hexu = (void*)hex;
	uint8_t *binu = bin;
	size_t i;

	if (!hexsz) hexsz = strlen((const char *)hex);
	if (hexsz & 1) return false;
	if (*hexu == '0' && (hexu[1] | 0x20) == 'x') {
        hexu += 2;
        hexsz -= 2;
	}
	if (hexsz == 0 || binsz < hexsz/2) return false;
	binsz = hexsz/2;
	for(i=0;i<binsz;i++,binu++) {
        if (!isxdigit(*hexu)) return false;
        if (isdigit(*hexu)) *binu = (*hexu - '0') << 4; else {
            *binu = ((*hexu | 0x20) - 'a' + 10) << 4;
        }
        hexu++;
        if (!isxdigit(*hexu)) return false;
        if (isdigit(*hexu)) *binu |= (*hexu - '0'); else {
            *binu |= ((*hexu | 0x20) - 'a' + 10);
        }
        hexu++;
	}

	*binszp = binsz;

	return true;
}


bool hexenc(unsigned char *hex, size_t *hexsz, const void *data, size_t binsz)
{
	const uint8_t *bin = data;
	size_t i, len;
	if (*hexsz < binsz*2 +1) return false;
	len = 0;
	for(i=0;i<binsz;i++,bin++) {
        *hex++ = hexdig[*bin >> 4];
        len++;
        *hex++ = hexdig[*bin & 0xf];
        len++;
	}
	*hex = '\0';
	*hexsz = ++len;

	return true;
}
