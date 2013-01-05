/*
 * Copyright 2012, Joshua Lackey <jl@thre.at>
 */

#ifndef __PICOMINER_H__
#define __PICOMINER_H__

#ifdef __cplusplus
extern "C" {
#endif
struct picominer_device_s;

#include "miner.h"
#include "dynclock.h"


typedef struct data_list_s {
	uint32_t		data;
	struct data_list_s *	next;
} data_list_t;


typedef struct picominer_device_s {
	char			device_name[32];
	unsigned int		device_model;
	bool			is_work_running;	// if the fpga is working
	struct work		work;			// the current submitted work
	struct work		last_work;		// the last work we were given
	unsigned char		next_work[44];		// buffer containing the representation of the work given to the fpga
	struct timeval		tv_workstart;		// when we started the current work
	uint32_t		hashes;
	int			bad_share_counter;
	int			good_share_counter;

	struct dclk_data	dclk;

	void *			pd;
	int			streamd;		// pico stream descriptor
	void *			read_threadid;

	data_list_t *		nonce_list;
	pthread_mutex_t		nonce_lock;
} picominer_device;


typedef struct picominer_dev_list_s { 
	picominer_device *		dev;
	struct picominer_dev_list_s *	next;
} picominer_dev_list;


// forward defines
int picominer_loads();
int picominer_get_all_available(picominer_dev_list **);
int picominer_send_hash_data(picominer_device *, const unsigned char *);
int picominer_has_nonce(picominer_device *);
int picominer_get_nonce(picominer_device *, uint32_t *);
void picominer_destroy_device(picominer_device *);
void picominer_destroy_device_list(picominer_dev_list *);
void picominer_destroy_list(picominer_dev_list *);
int picominer_get_stats(picominer_device *, float *, float *, float *);
#ifdef __cplusplus
}
#endif
#endif /* __PICOMINER_H__ */
