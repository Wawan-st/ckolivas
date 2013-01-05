/*
 * driver-pico.c - cgminer worker for Pico Computing
 *
 * Copyright 2012, Joshua Lackey <jl@thre.at>
 */

/*
 * This driver is designed for the Pico Computing EX devices with M-50x
 * FPGAs installed.  Multiple EX devices are supported by the Pico drivers.
 *
 * This code has only been tested with an EX-400 and 2 M-501 FPGAs.
 *
 * Bitstreams are currently available for:
 * 	Virtex-6 240T
 */

#include <unistd.h>
#include <sha2.h>
#include <errno.h>

//#include "fpgautils.h"
#include "miner.h"
#include "logging.h"

#include "libpicominer/picominer.h"

// forwards
static void pico_detect();
static void pico_statline_before(char *, struct cgpu_info *);
static bool pico_init(struct thr_info *);
static int64_t pico_scan_hash(struct thr_info *, struct work *, int64_t);
static void pico_shutdown(struct thr_info *);

struct device_api pico_api = {
	.dname				= "pico",
	.name				= "pico",
	.api_detect			= pico_detect,
	.get_statline_before		= pico_statline_before,
	.thread_init			= pico_init,
	.scanhash			= pico_scan_hash,
	.thread_shutdown		= pico_shutdown,
};


typedef struct cgpu_info cgpu_info_t;


static void pico_detect() {

	int i, fpgacount;
	picominer_dev_list *devices, *p;
	picominer_device *device;
	cgpu_info_t *cgpu_info;

	fpgacount = picominer_get_all_available(&devices);
	if(fpgacount > 0)
		applog(LOG_NOTICE, "Found %d Pico M-50x board%s", fpgacount, (fpgacount > 1)? "s" : "");
	else
		return;

	for(p = devices, i = 0; p; p = p->next, i++) {
		if(!(cgpu_info = malloc(sizeof(cgpu_info_t)))) {
			applog(LOG_ERR, "error: malloc: %s", strerror(errno));
			picominer_destroy_device_list(devices);
			return;
		}
		memset(cgpu_info, 0, sizeof(cgpu_info_t));
		cgpu_info->api = &pico_api;
		cgpu_info->device_pico = p->dev;
		cgpu_info->threads = 1;
		snprintf(p->dev->device_name, sizeof(p->dev->device_name), "p%x", p->dev->device_model);
		cgpu_info->name = strdup(p->dev->device_name);
		add_cgpu(cgpu_info);
		applog(LOG_NOTICE, "%s-%d: Found Pico (Pico %s)", cgpu_info->api->name, cgpu_info->device_id, cgpu_info->name);
	}
	picominer_destroy_list(devices);
}


static int64_t calc_hashes(struct timeval *tv_workstart, unsigned int device_freq, struct timeval *tv_now) {

	struct timeval tv_delta;
	int64_t hashes;

	timersub(tv_now, tv_workstart, &tv_delta);
	hashes = (((int64_t)tv_delta.tv_sec * 1000000) + tv_delta.tv_usec) * (int64_t)(device_freq);
	if(unlikely(hashes >= 0x100000000))
		hashes = 0xffffffff;
	return hashes;
}


static bool test_nonce(struct work *work, uint32_t nonce) {

	unsigned char hash[32], hash1[32], hash2[32], data[128], swap[80];
	uint32_t *data32 = (uint32_t *)data;
	uint32_t *swap32 = (uint32_t *)swap;
	uint32_t *hash32 = (uint32_t *)hash;
	uint32_t *work_nonce = (uint32_t *)(data + 64 + 12);
	bool ret = false;

	memcpy(data, work->data, sizeof(work->data));
	*work_nonce = nonce;
	flip80(swap32, data32);
	sha2(swap, 80, hash1);
	sha2(hash1, 32, hash2);
	flip32(hash32, hash2);

	if (hash32[7] != 0)
		return false;
	return true;
}


static int64_t pico_process_results(struct thr_info *thr) {

	struct cgpu_info *cgpu = thr->cgpu;
	picominer_device *device = thr->cgpu->device_pico;
	int r;
	uint32_t nonce, v;
	int64_t hashes = 0, lasthashes;
	bool overflow = false;
	struct timeval tv_now, tv_workend, elapsed;

	while(!(overflow || thr->work_restart)) {
		if((r = picominer_has_nonce(device)) < 0) {
			applog(LOG_ERR, "%s-%d: error: picominer_has_nonce failed\n", cgpu->api->name, cgpu->device_id);
			return 0;
		}
		if(r > 0) {
			if((r = picominer_get_nonce(device, &nonce)) < 0) {
				applog(LOG_ERR, "%s-%d: error: picominer_get_nonce failed\n", cgpu->api->name, cgpu->device_id);
				return 0;
			}
			nonce -= 0xff; // offset from placing nonce in sha256 pipeline
			nonce = le32toh(nonce);

			// test the nonce against the current work
			if(test_nonce(&device->work, nonce)) {
				applog(LOG_DEBUG, "%s-%d: Nonce for current work: 0x%8.8x", cgpu->api->name, cgpu->device_id, nonce);
				submit_nonce(thr, &device->work, nonce);
			}

			// it may be for the last work
			else if(test_nonce(&device->last_work, nonce)) {
				applog(LOG_DEBUG, "%s-%d: Nonce for previous work: 0x%8.8x", cgpu->api->name, cgpu->device_id, nonce);
				submit_nonce(thr, &device->last_work, nonce);
			}

			else {
				applog(LOG_DEBUG, "%s-%d: Invalid nonce: 0x%8.8x", cgpu->api->name, cgpu->device_id, nonce);
				cgpu->hw_errors += 1;
			}
		}

		if(thr->work_restart)
			break;

		// estimate the number of hashes performed on this work item
		gettimeofday(&tv_now, 0);
		lasthashes = hashes;
		hashes = calc_hashes(&device->work_start, device->devfreq, &tv_now);

		// check for overflow: if we're closer to the end then we are to the last count, we're going to overflow
		if(((0xffffffff - hashes) < (hashes - lasthashes))) {
			applog(LOG_DEBUG, "%s-%d: overflow hashes = 0x%8.8x  lasthashes = 0x%8.8x", cgpu->api->name, cgpu->device_id, hashes, lasthashes);
			overflow = true;
		}

		if(!overflow)
			nmsleep(10);
	}

	// estimate the number of hashes performed on this work item
	gettimeofday(&tv_workend, NULL);
	hashes = calc_hashes(&device->work_start, device->devfreq, &tv_workend);

	return hashes;
}


static bool pico_prepare_next_work(picominer_device *device, struct work *work) {

	// copy midstate and taildata from work item (data in low bits; midstate in high)
	memcpy(device->next_work, work->data + 64, 12);
	memcpy(device->next_work + 12, work->midstate, 32);

	return true;
}


static bool pico_start_work(struct thr_info *thr) {

	picominer_device *device = thr->cgpu->device_pico;

	if(picominer_send_hash_data(device, device->next_work)) {
		fprintf(stderr, "error: picominer_send_hash_data failed\n"); fflush(stderr);
		return false;
	}

	gettimeofday(&device->work_start, NULL);

	return true;
}


static int64_t pico_scan_hash(struct thr_info *thr, struct work *work, int64_t __maybe_unused max_nonce) {

	struct cgpu_info *cgpu = thr->cgpu;
	picominer_device *device = cgpu->device_pico;
	uint64_t hashes = 0;
	bool startwork;

	pico_prepare_next_work(device, work);
	if(!pico_start_work(thr)) {
		applog(LOG_ERR, "%s-%d: error: pico_start_work failed", cgpu->api->name, cgpu->device_id);
		return 0;
	}
	memcpy(&device->last_work, &device->work, sizeof(device->last_work));
	memcpy(&device->work, work, sizeof(device->work));
	hashes = pico_process_results(thr);
	work->blk.nonce = 0xffffffff;

	return hashes;
}


static void pico_statline_before(char *buf, struct cgpu_info *cgpu) {

	char before[] = "               ";
	char information_string[16];
	picominer_device *dev = cgpu->device_pico;
	float t, v, i;

	if(!picominer_get_stats(dev, &t, &v, &i)) {
		snprintf(information_string, sizeof(information_string), "%2.1fC %s%2.1fW", t, (v * i < 10.0)? " " : "", v * i);
		memcpy(before, information_string, strlen(information_string));
	}
	tailsprintf(buf, "%s| ", &before[0]);
}


static bool pico_init(struct thr_info *thr) {

	struct timeval now;
	struct cgpu_info *cgpu = thr->cgpu;
	picominer_device *device = cgpu->device_pico;

	applog(LOG_NOTICE, "%s-%d: loading bitstream: ``%s''", cgpu->api->name, cgpu->device_id, device->bitfile_name);
	if(picominer_prepare_device(device))
		return false;
	applog(LOG_NOTICE, "%s-%d: bitstream loaded", cgpu->api->name, cgpu->device_id);

	gettimeofday(&now, NULL);
	get_datestamp(cgpu->init, &now);
	device->is_ready = 1;

	return true;
}


static void pico_shutdown(struct thr_info *thr) {

	struct cgpu_info *cgpu = thr->cgpu;
	picominer_device *device = cgpu->device_pico;
	
	if(!device)
		return;
	
	cgpu->device_pico = NULL;
	applog(LOG_DEBUG, "%s: shutdown", cgpu->name);
	picominer_destroy_device(device);
}


static void pico_disable(struct thr_info *thr) {

	applog(LOG_ERR, "%s: Disabling!", thr->cgpu->name);
	devices[thr->cgpu->device_id]->deven = DEV_DISABLED;
	pico_shutdown(thr);
}
