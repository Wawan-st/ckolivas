#ifndef __OCL_H__
#define __OCL_H__

#include "config.h"

#include <stdbool.h>
#ifdef HAVE_OPENCL
#ifdef __APPLE_CC__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#include "miner.h"

typedef struct {
	cl_context context;
	cl_kernel kernel;
	cl_command_queue commandQueue;
	cl_program program;
	cl_mem outputBuffer;
	bool hasBitAlign;
	bool hasOpenCL11plus;
	cl_uint preferred_vwidth;
	size_t max_work_size;
	size_t work_size;
	enum cl_kernels chosen_kernel;
} _clState;

extern char *file_contents(const char *filename, int *length);
extern int clDevicesNum(void);
extern _clState *initCl(unsigned int gpu, char *name, size_t nameSize);
extern int opt_platform_id;
#endif /* HAVE_OPENCL */
#endif /* __OCL_H__ */
