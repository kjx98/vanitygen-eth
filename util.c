/*
 * Vanitygen ETH, vanity ETH address generator
 * Copyright (C) 2018 <jkuang@21cn.com>
 *
 * Vanitygen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * Vanitygen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Vanitygen.  If not, see <http://www.gnu.org/licenses/>.
 */

#if defined(_WIN32)
#define _USE_MATH_DEFINES
#endif /* defined(_WIN32) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#include <openssl/bn.h>

#include "sha3.h"
#include "pattern.h"
#include "util.h"
#include "hex.h"


void
fdumphex(FILE *fp, const unsigned char *src, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		fprintf(fp, "%02x", src[i]);
	}
	printf("\n");
}

void
fdumpbn(FILE *fp, const BIGNUM *bn)
{
	char *buf;
	buf = BN_bn2hex(bn);
	fprintf(fp, "%s\n", buf ? buf : "0");
	if (buf) OPENSSL_free(buf);
}

void
dumphex(const unsigned char *src, size_t len)
{
	fdumphex(stdout, src, len);
}

void
dumpbn(const BIGNUM *bn)
{
	fdumpbn(stdout, bn);
}


void
vg_encode_address(const EC_POINT *ppoint, const EC_GROUP *pgroup, char *result)
{
	unsigned char eckey_buf[128];
	unsigned char hash1[32];
	size_t      key_len, len=64;

	key_len = EC_POINT_point2oct(pgroup, ppoint,
			   POINT_CONVERSION_UNCOMPRESSED, eckey_buf,
			   sizeof(eckey_buf), NULL);
    SHA3_256(hash1, eckey_buf+1, 64);
    memcpy(result, "0x", 2);
    hexenc(result+2, &len, hash1+12, 20);
}


void
vg_encode_privkey(const EC_KEY *pkey, char *result)
{
	const BIGNUM *bn;
	int nbytes;
	unsigned char eckey_buf[64];
	size_t  len=80;

	bn = EC_KEY_get0_private_key(pkey);

	nbytes = BN_num_bytes(bn);
	assert(nbytes <= 32);
#if OPENSSL_VERSION_NUMBER >= 0x0010100000
	BN_bn2binpad(bn, eckey_buf, 32);
#else
    if (nbytes < 32) memset(eckey_buf, 0, 32 - nbytes);
    BN_bn2bin(bn, &eckey_buf[32 - nbytes]);
#endif // OPENSSL_VERSION_NUMBER
    memcpy(result, "0x", 2);
    hexenc(result+2, &len, eckey_buf, 32);
}


int
vg_set_privkey(const BIGNUM *bnpriv, EC_KEY *pkey)
{
	const EC_GROUP *pgroup;
	EC_POINT *ppnt;
	int res;

	pgroup = EC_KEY_get0_group(pkey);
	ppnt = EC_POINT_new(pgroup);

	res = (ppnt && EC_KEY_set_private_key(pkey, bnpriv) &&
	       EC_POINT_mul(pgroup, ppnt, bnpriv, NULL, NULL, NULL) &&
	       EC_KEY_set_public_key(pkey, ppnt));

	if (ppnt) EC_POINT_free(ppnt);

	if (!res) return 0;

	assert(EC_KEY_check_key(pkey));
	return 1;
}


/*
 * Pattern file reader
 * Absolutely disgusting, unable to free the pattern list when it's done
 */

int
vg_read_file(FILE *fp, char ***result, int *rescount)
{
	int ret = 1;

	char **patterns;
	char *buf = NULL, *obuf, *pat;
	const int blksize = 16*1024;
	int nalloc = 16;
	int npatterns = 0;
	int count, pos;

	patterns = (char**) malloc(sizeof(char*) * nalloc);
	count = 0;
	pos = 0;

	while (1) {
		obuf = buf;
		buf = (char *) malloc(blksize);
		if (!buf) {
			ret = 0;
			break;
		}
		if (pos < count) {
			memcpy(buf, &obuf[pos], count - pos);
		}
		pos = count - pos;
		count = fread(&buf[pos], 1, blksize - pos, fp);
		if (count < 0) {
			fprintf(stderr, "Error reading file: %s\n", strerror(errno));
			ret = 0;
		}
		if (count <= 0) break;
		count += pos;
		pat = buf;

		while (pos < count) {
			if ((buf[pos] == '\r') || (buf[pos] == '\n')) {
				buf[pos] = '\0';
				if (pat) {
					if (npatterns == nalloc) {
						nalloc *= 2;
						patterns = (char**)realloc(patterns, sizeof(char*)*nalloc);
					}
					patterns[npatterns] = pat;
					npatterns++;
					fprintf(stderr,	"\rLoading Pattern #%d: %s", npatterns, pat);
					pat = NULL;
				}
			}
			else if (!pat) {
				pat = &buf[pos];
			}
			pos++;
		}

		pos = pat ? (pat - buf) : count;
	}

	*result = patterns;
	*rescount = npatterns;
	fprintf(stderr,	"\n");
	return ret;
}
