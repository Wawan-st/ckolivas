#ifndef __DEVICE_CPU_H__
#define __DEVICE_CPU_H__

#include "miner.h" /* for work_restart, TODO: re-factor dependency */

#include "config.h"
#include <stdbool.h>

#ifndef OPT_SHOW_LEN
#define OPT_SHOW_LEN 80
#endif

#ifdef __SSE2__
#define WANT_SSE2_4WAY 1
#endif

#ifdef __ALTIVEC__
#define WANT_ALTIVEC_4WAY 1
#endif

#if defined(__i386__) && defined(HAS_YASM) && defined(__SSE2__)
#define WANT_X8632_SSE2 1
#endif

#if (defined(__i386__) || defined(__x86_64__)) &&  !defined(__APPLE__)
#define WANT_VIA_PADLOCK 1
#endif

#if defined(__x86_64__) && defined(HAS_YASM)
#define WANT_X8664_SSE2 1
#endif

#if defined(__x86_64__) && defined(HAS_YASM)
#define WANT_X8664_SSE4 1
#endif

enum sha256_algos {
	ALGO_C,			/* plain C */
	ALGO_4WAY,		/* parallel SSE2 */
	ALGO_VIA,		/* VIA padlock */
	ALGO_CRYPTOPP,		/* Crypto++ (C) */
	ALGO_CRYPTOPP_ASM32,	/* Crypto++ 32-bit assembly */
	ALGO_SSE2_32,		/* SSE2 for x86_32 */
	ALGO_SSE2_64,		/* SSE2 for x86_64 */
	ALGO_SSE4_64,		/* SSE4 for x86_64 */
	ALGO_ALTIVEC_4WAY,	/* parallel Altivec */
};

extern const char *algo_names[];
extern struct device_api cpu_api;
extern int num_processors;

extern char *set_algo(const char *arg, void *unused);
extern void show_algo(char buf[OPT_SHOW_LEN], void *unused);
extern char *force_nthreads_int(const char *arg, int *i);
extern void init_max_name_len();
extern double bench_algo_stage3(enum sha256_algos algo);

extern const char *get_algo(void);


#endif /* __DEVICE_CPU_H__ */
