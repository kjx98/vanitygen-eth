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

#if !defined (__VG_UTIL_H__)
#define __VG_UTIL_H__

#include <stdio.h>
#include <stdint.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

extern void fdumphex(FILE *fp, const unsigned char *src, size_t len);
extern void fdumpbn(FILE *fp, const BIGNUM *bn);
extern void dumphex(const unsigned char *src, size_t len);
extern void dumpbn(const BIGNUM *bn);

extern void vg_encode_address(const EC_POINT *ppoint, const EC_GROUP *pgroup, char *result);
extern void vg_encode_privkey(const EC_KEY *pkey, char *result);
extern int vg_set_privkey(const BIGNUM *bnpriv, EC_KEY *pkey);

extern int vg_read_file(FILE *fp, char ***result, int *rescount);

#endif /* !defined (__VG_UTIL_H__) */
