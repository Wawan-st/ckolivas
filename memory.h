/*
 * Copyright 2012 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 *
 * This optional include is to help with debugging cgminer using memory
 *  protection to identify code that reads or writes unexpectedly in RAM
 *
 * You enable it in miner.h by uncommenting the include line to include this
 *
 * It intercepts each of the functions defined in here (malloc, free etc)
 * If cgminer adds any new fuctions to the code that internally call malloc
 *  or free with RAM that is available to cgminer to do the same -
 *  e.g. strdup()
 *  then those function have to be intercepted and coded in here also
 *
 * A memory protection change in linux can only be applied to a full page
 *
 * cgmalloc() allocates a minimum of 3 pages of RAM for each call to malloc
 *  so it will use a lot more memory if it is used a lot
 * The 1st page is set to read only protection and has the size of the memory
 *  allocated stored in it
 * The last page is set to no access protection
 * The 2nd+ pages are the actual memory allocated that is returned
 * The size of this allocation is the mininum number of pages greater than
 *  or equal to the amount of ram requested - typically one 4k page
 * If ALIGN_TOP is set to 1 then the memory address returned will be the
 *  start of the 2nd page and the end of the last page will be empty if the
 *  amount of memory requested is not a multiple of the RAM page size
 * The side effect of this is that if any code should write to the RAM just
 *  before the start of the memory address, it will crash - if any code
 *  should read or write to the memory address on the page after the RAM
 *  allocated it will crash
 * If ALIGN_TOP is set to 0 then the memory address returned will be in
 *  the middle of the first page such that the end of the memory requested
 *  is at the end of the last page - this is rounded up to 4 bytes - so the
 *  last 1-3 bytes of the last page may be unused if the amount of memory
 *  requested is not a multiple of 4
 * The side effect of this is that if any code should write to the RAM on
 *  the page before the RAM allocated then it will crash - if any code
 *  should read or write to the memory address just after the end of the
 *  RAM allocated then it will crash
 * The side affect of all this is to attempt to find the code that corrupts
 *  memory when it does it, rather than after the fact when that memory
 *  value may cause code to crash
 *
 * TODO: add the option to set unused data page RAM to specific values that
 *	 can be checked when free is called (or called directly by the code)
 *	 This will slow down memory allocation and deallocation so should be
 *	 optional
 */

#ifndef _CGMINER_MEMORY
#define _CGMINER_MEMORY 1

#if defined (__linux) || defined (LINUX)

#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/mman.h>

/*
 * This determines where the data is placed in the page
 * Set to 1 to put it at the start of the page
 * Set to 0 to put the data at the end of the last page
 */
#define ALIGN_TOP 1

static inline void *cgmalloc(size_t size)
{
	size_t pgsz = (size_t)sysconf(_SC_PAGESIZE);

	size_t real, offset;
	void *ptr, *usermem;

	if ((size % 4) != 0)
		size += (4 - (size %4));

	real = (pgsz - (size % pgsz)) + size + pgsz + pgsz;

	ptr = memalign(pgsz, real);
	if (!ptr)
		return NULL;

	if (ALIGN_TOP)
		offset = 0;
	else
		offset = pgsz - (size % pgsz);

	usermem = ptr + pgsz + offset;

	*((size_t *)(usermem - pgsz)) = size;

	mprotect(ptr, pgsz, PROT_READ);
	mprotect(ptr + real - pgsz, pgsz, PROT_NONE);

	return usermem;
}

static inline void cgfree(void *usermem)
{
	if (usermem == NULL)
		return;

	size_t pgsz = (size_t)sysconf(_SC_PAGESIZE);

	size_t size, real;

	size = *((size_t *)(usermem - pgsz));
	real = (pgsz - (size % pgsz)) + size + pgsz + pgsz;

	if (!ALIGN_TOP)
		usermem -= (pgsz - (size % pgsz));

	mprotect(usermem - pgsz, pgsz, PROT_WRITE);
	mprotect(usermem - pgsz + real - pgsz, pgsz, PROT_WRITE);
	free(usermem - pgsz);
}


static inline void *cgcalloc(size_t nmemb, size_t size)
{
	size_t sz = nmemb * size;
	void *ptr = cgmalloc(sz);

	if (ptr)
		memset(ptr, 0, sz);

	return ptr;
}

static inline void *cgrealloc(void *usermem, size_t newsize)
{
	size_t pgsz = (size_t)sysconf(_SC_PAGESIZE);

	size_t size;
	void *newptr = cgmalloc(newsize);

	if (newptr && usermem) {
		size = *((size_t *)(usermem - pgsz));

		if (size > newsize)
			size = newsize;

		memcpy(newptr, usermem, size);

		cgfree(usermem);
	}

	return newptr;
}

static inline char *cgstrdup(const char *s)
{
	size_t size = strlen(s) + 1;
	char *ptr = (char *)cgmalloc(size);
	if (ptr)
		memcpy(ptr, s, size);
	return ptr;
}

#ifdef calloc
#undef calloc
#endif

#ifdef malloc
#undef malloc
#endif

#ifdef realloc
#undef realloc
#endif

#ifdef free
#undef free
#endif

#ifdef strdup
#undef strdup
#endif

#define malloc cgmalloc
#define calloc cgcalloc
#define realloc cgrealloc
#define free cgfree
#define strdup cgstrdup

#endif

#endif
