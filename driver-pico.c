/*
 * driver-pico.c - BFGMiner worker for Pico Computing
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

#include "dynclock.h"
#include "fpgautils.h"
#include "miner.h"
#include "logging.h"

#include "libpicominer/picominer.h"

// forwards
static void pico_detect();
static void pico_statline_before(char *, struct cgpu_info *);
static struct api_data *pico_get_api_extra_device_status(struct cgpu_info *);
static bool pico_init(struct thr_info *);
static int64_t pico_scan_hash(struct thr_info *, struct work *, int64_t);
static void pico_shutdown(struct thr_info *);

struct device_api pico_api = {
	.dname				= "pico",
	.name				= "pico",
	.api_detect			= pico_detect,
	.get_statline_before		= pico_statline_before,
	.get_api_extra_device_status	= pico_get_api_extra_device_status,
	.thread_init			= pico_init,
	.scanhash			= pico_scan_hash,
	.thread_shutdown		= pico_shutdown,
};


typedef struct cgpu_info cgpu_info_t;


static int pico_autodetect() {

	int i, fpgacount;
	picominer_dev_list *devices, *p;
	picominer_device *device;
	cgpu_info_t *cgpu_info;

	fpgacount = picominer_get_all_available(&devices);
	if(fpgacount > 0)
		applog(LOG_INFO, "Found %d Pico M-50x board%s", fpgacount, (fpgacount > 1)? "s" : "");
	else
		return 0;

	for(p = devices, i = 0; p; p = p->next, i++) {
		if(!(cgpu_info = malloc(sizeof(cgpu_info_t)))) {
			applog(LOG_ERR, "error: malloc: %s", strerror(errno));
			picominer_destroy_device_list(devices);
			return -1;
		}
		memset(cgpu_info, 0, sizeof(cgpu_info_t));
		cgpu_info->api = &pico_api;
		cgpu_info->device_pico = p->dev;
		cgpu_info->threads = 1;
		snprintf(p->dev->device_name, sizeof(p->dev->device_name), "p%x", p->dev->device_model);
		cgpu_info->name = strdup(p->dev->device_name);
		add_cgpu(cgpu_info);
		applog(LOG_INFO, "%s %u: Found Pico (Pico %s)", cgpu_info->api->name, cgpu_info->device_id, cgpu_info->name);
	}
	picominer_destroy_list(devices);

	return fpgacount;
}


static void pico_detect() {

	// ensures users can specify -S pico:noauto to disable it
	noserial_detect(&pico_api, pico_autodetect);
}


static bool pico_change_clock(struct thr_info *thr, int bestM) {

	picominer_device *device = thr->cgpu->device_pico;

	// XXX not yet
	return true;
}


static bool pico_update_freq(struct thr_info *thr) {

	bool r;
	picominer_device *device = thr->cgpu->device_pico;

	r = dclk_updateFreq(&device->dclk, pico_change_clock, thr);
	if(unlikely(!r)) {
		// XXX not yet
		// picominer_reset_fpga(device);
	}
	return r;
}


static bool pico_prepare_next_work(picominer_device *device, struct work *work) {

	//fprintf(stderr, "debug: pico_prepare_next_work\n"); fflush(stderr);

	// do we already have the next work item?
	if(!(memcmp(device->next_work + 12, work->midstate, 32) || memcmp(device->next_work, work->data + 64, 12))) {
		//fprintf(stderr, "debug: pico_prepare_next_work: already have work item\n"); fflush(stderr);
		return false;
	}

	// copy midstate and taildata from work item (data in low bits; midstate in high)
	memcpy(device->next_work, work->data + 64, 12);
	memcpy(device->next_work + 12, work->midstate, 32);

	return true;
}


static bool pico_start_work(struct thr_info *thr) {

	picominer_device *device = thr->cgpu->device_pico;

	//fprintf(stderr, "debug: pico_start_work: sending work\n"); fflush(stderr);

	if(picominer_send_hash_data(device, device->next_work)) {
		fprintf(stderr, "error: picominer_send_hash_data failed\n"); fflush(stderr);
		return false;
	}

	gettimeofday(&device->tv_workstart, NULL);
	device->hashes = 0;
	device->is_work_running = true;

	return true;
}


static
int64_t calc_hashes(struct timeval *tv_workstart, uint8_t freqM, struct timeval *tv_now)
{
	struct timeval tv_delta;
	int64_t hashes;

	timersub(tv_now, tv_workstart, &tv_delta);
	hashes = (((int64_t)tv_delta.tv_sec * 1000000) + tv_delta.tv_usec) * (int64_t)(freqM + freqM / 4);
	if(unlikely(hashes >= 0x100000000))
		hashes = 0xffffffff;
	return hashes;
}


#define work_restart(thr)  thr->work_restart

#define NONCE_CHARS(nonce)  \
	(int)((unsigned char*)&nonce)[3],  \
	(int)((unsigned char*)&nonce)[2],  \
	(int)((unsigned char*)&nonce)[1],  \
	(int)((unsigned char*)&nonce)[0]

static int64_t pico_process_results(struct thr_info *thr) {

	struct cgpu_info *cgpu = thr->cgpu;
	picominer_device *device = thr->cgpu->device_pico;
	struct work *work = &device->work;

	int r, finished_early = 0; // XXX finished early not implemented
	uint32_t nonce, v;
	int64_t hashes;
	int immediate_bad_nonces = 0, immediate_nonces = 0;
	bool bad;
	struct timeval tv_now, tv_workend, elapsed;

	// XXX get temp here

	while(1) {
		if((r = picominer_has_nonce(device)) < 0) {
			applog(LOG_ERR, "error: %s: picominer_has_nonce failed\n", cgpu->name);
			return 0;
		}
		if(r > 0) {
			if((r = picominer_get_nonce(device, &nonce)) < 0) {
				applog(LOG_ERR, "error: %s: picominer_get_nonce failed\n", cgpu->name);
				return 0;
			}
			nonce -= 0xff; // offset from placing nonce in sha256 pipeline
			nonce = le32toh(nonce);
			++immediate_nonces;

			// test the nonce against the current work
			bad = !test_nonce(work, nonce, false);
			if(!bad)
				applog(LOG_DEBUG, "%s %u: Nonce for current  work: %02x%02x%02x%02x", cgpu->api->name, cgpu->device_id, NONCE_CHARS(nonce));

			// it may be for the last work
			else if(test_nonce(&device->last_work, nonce, false)) {

				applog(LOG_DEBUG, "%s %u: Nonce for previous work: %02x%02x%02x%02x", cgpu->api->name, cgpu->device_id, NONCE_CHARS(nonce));
				work = &device->last_work;
				bad = false;
			}

			// did it check out okay?
			if(!bad) {
				++device->good_share_counter;
				submit_nonce(thr, work, nonce); // submit it

			} else {
				applog(LOG_DEBUG, "%s %u: Nonce with H not zero  : %02x%02x%02x%02x", cgpu->api->name, cgpu->device_id, NONCE_CHARS(nonce));
				++hw_errors;
				++cgpu->hw_errors;
				++device->bad_share_counter;
				++immediate_bad_nonces;
			}
		}

		gettimeofday(&tv_now, NULL);
		hashes = calc_hashes(&device->tv_workstart, device->dclk.freqM, &tv_now);
		if(thr->work_restart || hashes >= 0xf0000000)
			break;
		usleep(10000);
		gettimeofday(&tv_now, NULL);
		hashes = calc_hashes(&device->tv_workstart, device->dclk.freqM, &tv_now);
		if(thr->work_restart || hashes >= 0xf0000000)
			break;
	}

	// estimate the number of hashes performed on this work item
	gettimeofday(&tv_workend, NULL);
	hashes = calc_hashes(&device->tv_workstart, device->dclk.freqM, &tv_workend);
	device->hashes = hashes;

	dclk_gotNonces(&device->dclk);
	if(immediate_bad_nonces)
		dclk_errorCount(&device->dclk, ((double)immediate_bad_nonces) / (double)immediate_nonces);
	dclk_preUpdate(&device->dclk);
	if(!dclk_updateFreq(&device->dclk, pico_change_clock, thr))
		{}  // TODO: handle error

	return hashes;
}


static int64_t pico_scan_hash(struct thr_info *thr, struct work *work, int64_t __maybe_unused max_nonce) {

	picominer_device *device = thr->cgpu->device_pico;
	int64_t hashes = 0;
	bool startwork;

	startwork = pico_prepare_next_work(device, work);
	if(device->is_work_running) {
		hashes = pico_process_results(thr);
		if(work_restart(thr)) {
			device->is_work_running = false;
			return hashes;
		}
	}

	if(startwork) {
		memcpy(&device->last_work, &device->work, sizeof(device->work));
		memcpy(&device->work, work, sizeof(device->work));
		if(!pico_start_work(thr))
			return 0;
	}

	// This is intentionally early
	work->blk.nonce += hashes;
	return hashes;
}


static void pico_statline_before(char *buf, struct cgpu_info *cgpu) {

	char before[] = "               ";
	char information_string[16];
	picominer_device *dev;
	float t, v, i;

	if(cgpu->device_pico) {
		dev = (picominer_device *)cgpu->device_pico;
		if(!picominer_get_stats(dev, &t, &v, &i)) {
			snprintf(information_string, sizeof(information_string), "%2.1fC %s%2.1fW", t, (v * i < 10.0)? " " : "", v * i);
			memcpy(before, information_string, strlen(information_string));
		}
		// TODO: put something interesting here
		// memcpy(before, information_string, strlen(information_string));
	}
	tailsprintf(buf, "%s| ", &before[0]);
}


static struct api_data *pico_get_api_extra_device_status(struct cgpu_info *cgpu) {

	struct api_data *root = NULL;
	picominer_device *device = cgpu->device_pico;

	if(device) {
		// TODO: put something interesting here
	}

	return root;
}


static bool pico_init(struct thr_info *thr) {

	struct timeval now;
	struct cgpu_info *cgpu = thr->cgpu;
	picominer_device *device = cgpu->device_pico;

	gettimeofday(&now, NULL);
	get_datestamp(cgpu->init, &now);
	device->dclk.freqM = 200;
	device->dclk.freqMaxM = 200;
	device->dclk.freqMDefault = 200;

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
