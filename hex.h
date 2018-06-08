#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


extern bool hexdec(void *bin, size_t *binsz, const uint8_t *hex, size_t hexsz);

extern bool hexenc(uint8_t *hex, size_t *hexsz, const void *bin, size_t binsz);

#ifdef __cplusplus
}
#endif
