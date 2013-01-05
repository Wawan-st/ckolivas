/**
 *   ztex.c - cgminer worker for Ztex 1.15x fpga board
 *
 *   Copyright (c) 2012 nelisky.btc@gmail.com
 *
 *   This work is based upon the Java SDK provided by ztex which is
 *   Copyright (C) 2009-2011 ZTEX GmbH.
 *   http://www.ztex.de
 *
 *   This work is based upon the icarus.c worker which is
 *   Copyright 2012 Luke Dashjr
 *   Copyright 2012 Xiangfu <xiangfu@openmobilefree.com>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License version 2 as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, see http://www.gnu.org/licenses/.
**/
#include <unistd.h>
#include <sha2.h>
#include "miner.h"
#include "libztex.h"
#include "uthash.h"

#define GOLDEN_BACKLOG 5

struct device_api ztex_api;

// Forward declarations
static void ztex_disable(struct thr_info* thr);
static bool ztex_prepare(struct thr_info *thr);

static void ztex_selectFpga(struct libztex_device* ztex)
{
	if (ztex->root->numberOfFpgas > 1) {
		if (ztex->root->selectedFpga != ztex->fpgaNum)
			mutex_lock(&ztex->root->mutex);
		libztex_selectFpga(ztex);
	}
}

static void ztex_releaseFpga(struct libztex_device* ztex)
{
	if (ztex->root->numberOfFpgas > 1) {
		ztex->root->selectedFpga = -1;
		mutex_unlock(&ztex->root->mutex);
	}
}

static void ztex_detect(void)
{
	int cnt;
	int i,j;
	int fpgacount;
	struct libztex_dev_list **ztex_devices;
	struct libztex_device *ztex_slave;
	struct cgpu_info *ztex;

	cnt = libztex_scanDevices(&ztex_devices);
	if (cnt > 0)
		applog(LOG_WARNING, "Found %d ztex board%s", cnt, cnt > 1 ? "s" : "");

	for (i = 0; i < cnt; i++) {
		ztex = calloc(1, sizeof(struct cgpu_info));
		ztex->api = &ztex_api;
		ztex->device_ztex = ztex_devices[i]->dev;
		ztex->threads = 1;
		ztex->device_ztex->fpgaNum = 0;
		ztex->device_ztex->root = ztex->device_ztex;
		add_cgpu(ztex);

		fpgacount = libztex_numberOfFpgas(ztex->device_ztex);

		if (fpgacount > 1)
			pthread_mutex_init(&ztex->device_ztex->mutex, NULL);

		for (j = 1; j < fpgacount; j++) {
			ztex = calloc(1, sizeof(struct cgpu_info));
			ztex->api = &ztex_api;
			ztex_slave = calloc(1, sizeof(struct libztex_device));
			memcpy(ztex_slave, ztex_devices[i]->dev, sizeof(struct libztex_device));
			ztex->device_ztex = ztex_slave;
			ztex->threads = 1;
			ztex_slave->fpgaNum = j;
			ztex_slave->root = ztex_devices[i]->dev;
			ztex_slave->repr[strlen(ztex_slave->repr) - 1] = ('0' + j);
			add_cgpu(ztex);
		}

		applog(LOG_WARNING,"%s: Found Ztex (fpga count = %d) , mark as %d", ztex->device_ztex->repr, fpgacount, ztex->device_id);
	}

	if (cnt > 0)
		libztex_freeDevList(ztex_devices);
}

bool ztex_updateFreq(struct libztex_device* ztex)
{
	int i, maxM, bestM;
	double bestR, r;

	for (i = 0; i < ztex->freqMaxM; i++)
		if (ztex->maxErrorRate[i + 1] * i < ztex->maxErrorRate[i] * (i + 20))
			ztex->maxErrorRate[i + 1] = ztex->maxErrorRate[i] * (1.0 + 20.0 / i);

	maxM = 0;
	while (maxM < ztex->freqMDefault && ztex->maxErrorRate[maxM + 1] < LIBZTEX_MAXMAXERRORRATE)
		maxM++;
	while (maxM < ztex->freqMaxM && ztex->errorWeight[maxM] > 150 && ztex->maxErrorRate[maxM + 1] < LIBZTEX_MAXMAXERRORRATE)
		maxM++;

	bestM = 0;
	bestR = 0;
	for (i = 0; i <= maxM; i++) {
		r = (i + 1 + (i == ztex->freqM? LIBZTEX_ERRORHYSTERESIS: 0)) * (1 - ztex->maxErrorRate[i]);
		if (r > bestR) {
			bestM = i;
			bestR = r;
		}
	}

	if (bestM != ztex->freqM) {
		ztex_selectFpga(ztex);
		libztex_setFreq(ztex, bestM);
		ztex_releaseFpga(ztex);
	}

	maxM = ztex->freqMDefault;
	while (maxM < ztex->freqMaxM && ztex->errorWeight[maxM + 1] > 100)
		maxM++;
	if ((bestM < (1.0 - LIBZTEX_OVERHEATTHRESHOLD) * maxM) && bestM < maxM - 1) {
		ztex_selectFpga(ztex);
		libztex_resetFpga(ztex);
		ztex_releaseFpga(ztex);
		applog(LOG_ERR, "%s: frequency drop of %.1f%% detect. This may be caused by overheating. FPGA is shut down to prevent damage.",
		       ztex->repr, (1.0 - 1.0 * bestM / maxM) * 100);
		return false;
	}
	return true;
}


static const int	MIN_MULT			= 49;
static const int	TARGET_DEFAULT			= 2;
static const int	TARGET_MAX			= 128;
static const int	TARGET_MIN			= 2;
static const float	MAX_ERROR			= 0.02;

static bool ztex_set_freq(struct libztex_device *ztex, int d) {

	int M;

	if(!d)
		return true;

	if(d < 0)
		M = ztex->freqM - 1;
	else
		M = ztex->freqM + 1;
	if(M < MIN_MULT)
		return false;
	ztex_selectFpga(ztex);
	libztex_setFreq(ztex, M);
	ztex_releaseFpga(ztex);

	return true;
}


static bool ztex_good_share(struct libztex_device *ztex) {

	ztex->shares_since_freq_change += 1;
	// applog(LOG_WARNING, "%s: valid: C+:%d T:%d E:%d", ztex->repr, ztex->shares_since_freq_change, ztex->shares_target, ztex->errors_since_freq_change);

	if(ztex->shares_since_freq_change >= ztex->shares_target) {
		ztex->shares_since_freq_change = 0;
		ztex->errors_since_freq_change = 0;
		if(ztex->shares_target > TARGET_MIN) {
			ztex->shares_target -= 2;
			if(ztex->shares_target < TARGET_MIN)
				ztex->shares_target = TARGET_MIN;
		}
		return ztex_set_freq(ztex, 1);
	}

	return true;
}


static bool ztex_bad_share(struct libztex_device *ztex) {

	ztex->errors_since_freq_change += 1;
	// applog(LOG_WARNING, "%s: invalid: C+:%d T:%d E:%d", ztex->repr, ztex->shares_since_freq_change, ztex->shares_target, ztex->errors_since_freq_change);

	if(ztex->errors_since_freq_change > MAX_ERROR * (float)ztex->shares_since_freq_change) {
		ztex->shares_since_freq_change = 0;
		ztex->errors_since_freq_change = 0;
		if(ztex->shares_target < TARGET_MAX) {
			ztex->shares_target *= 2;
			if(ztex->shares_target > TARGET_MAX)
				ztex->shares_target = TARGET_MAX;
		}
		return ztex_set_freq(ztex, -1);
	}

	return true;
}


static void ztex_clock_stats(struct thr_info *thr, int *accepted, int *errors, int *target) {

	struct libztex_device *ztex = thr->cgpu->device_ztex;

	*accepted = ztex->shares_since_freq_change;
	*errors = ztex->errors_since_freq_change;
	*target = ztex->shares_target;

	// applog(LOG_WARNING, "%s: C+:%u T:%u E:%u", ztex->repr, *accepted, *errors, *target);
}


static bool ztex_hashtest(struct libztex_device *ztex, struct work *work, uint32_t nonce) {

	unsigned char data[80], swap[80], hash[32], hash1[32], hash2[32];
	uint32_t *data32 = (uint32_t *)data, *swap32 = (uint32_t *)swap, *hash32 = (uint32_t *)hash;

	memcpy(data, work->data, 80);
	data32[18] = nonce;
	flip80(swap32, data32);
	sha2(swap, 80, hash1);
	sha2(hash1, 32, hash2);
	flip32(hash32, hash2);

	if (hash32[7] != 0) {
		applog(LOG_WARNING, "%s: internal invalid nonce - HW error: %8.8x -> %8.8x", ztex->repr, nonce, hash32[7]);
		return false;
	}
	return true;
}


/*
 * Each packet the ztex bitstream returns contains 2 possible valid
 * nonces, a nonce used as a count, and a "check" word in the hash for
 * the nonce used as a count.
 *
 * My guess is the author wanted to be able to poll the device to
 * determine when the nonce was about to overflow.  Each poll can be
 * checked for hardware errors by comparing the check word with a
 * locally generated one.
 *
 * However, there are a couple of problems with this.  First, it really
 * shouldn't be necessary to check for errors that often.  On submission
 * of a valid share should be sufficient.
 *
 * Second, while this is an interesting idea, it would have been much
 * better to include a flag indicating if one or both of the possible
 * valid nonces were actually valid.
 */
static bool ztex_checkNonce(struct libztex_device *ztex, struct work *work, struct libztex_hash_data *hdata)
{
	uint32_t *data32 = (uint32_t *)(work->data);
	unsigned char swap[80];
	uint32_t *swap32 = (uint32_t *)swap;
	unsigned char hash1[32];
	unsigned char hash2[32];
	uint32_t *hash2_32 = (uint32_t *)hash2;
	int i;

#if defined(__BIGENDIAN__) || defined(MIPSEB)
	hdata->nonce = swab32(hdata->nonce);
	hdata->hash7 = swab32(hdata->hash7);
#endif

	work->data[64 + 12 + 0] = (hdata->nonce >> 0) & 0xff;
	work->data[64 + 12 + 1] = (hdata->nonce >> 8) & 0xff;
	work->data[64 + 12 + 2] = (hdata->nonce >> 16) & 0xff;
	work->data[64 + 12 + 3] = (hdata->nonce >> 24) & 0xff;

	for (i = 0; i < 80 / 4; i++)
		swap32[i] = swab32(data32[i]);

	sha2(swap, 80, hash1);
	sha2(hash1, 32, hash2);
#if defined(__BIGENDIAN__) || defined(MIPSEB)
	if (hash2_32[7] != ((hdata->hash7 + 0x5be0cd19) & 0xFFFFFFFF)) {
#else
	if (swab32(hash2_32[7]) != ((hdata->hash7 + 0x5be0cd19) & 0xFFFFFFFF)) {
#endif
		// ztex->errorCount[ztex->freqM] += 1.0 / ztex->numNonces;
		applog(LOG_WARNING, "%s: HW error - check nonce failed: 0x%8.8x", ztex->repr, hdata->nonce);
		return false;
	}

	return true;
}


typedef struct nonce_list_s {
	uint32_t	nonce_used;

	UT_hash_handle	hh;
} nonce_list_t;


static int64_t ztex_scanhash(struct thr_info *thr, struct work *work, __maybe_unused int64_t max_nonce) {

	struct libztex_device *ztex;
	unsigned char sendbuf[44];
	int i, j;
	uint32_t *lastnonce;
	uint32_t nonce, noncecnt = 0;
	bool overflow;
	struct libztex_hash_data hdata[GOLDEN_BACKLOG];
	int good_nonce = 0, bad_nonce = 0;
	nonce_list_t *nonce_list = NULL, *nonce_entry, *nonce_entry_tmp;


	if (thr->cgpu->deven == DEV_DISABLED)
		return -1;

	ztex = thr->cgpu->device_ztex;

	memcpy(sendbuf, work->data + 64, 12);
	memcpy(sendbuf + 12, work->midstate, 32);

	ztex_selectFpga(ztex);
	i = libztex_sendHashData(ztex, sendbuf);
	if (i < 0) {
		// Something wrong happened in send
		applog(LOG_ERR, "%s: Failed to send hash data with err %d, retrying", ztex->repr, i);
		nmsleep(500);
		i = libztex_sendHashData(ztex, sendbuf);
		if (i < 0) {
			// And there's nothing we can do about it
			ztex_disable(thr);
			applog(LOG_ERR, "%s: Failed to send hash data with err %d, giving up", ztex->repr, i);
			ztex_releaseFpga(ztex);
			return -1;
		}
	}
	ztex_releaseFpga(ztex);

	applog(LOG_DEBUG, "%s: sent hashdata", ztex->repr);

	lastnonce = calloc(1, sizeof(uint32_t)*ztex->numNonces);
	if (lastnonce == NULL) {
		applog(LOG_ERR, "%s: failed to allocate lastnonce[%d]", ztex->repr, ztex->numNonces);
		return -1;
	}

	overflow = false;
	applog(LOG_DEBUG, "%s: entering poll loop", ztex->repr);
	while (!(overflow || thr->work_restart)) {
		nmsleep(250);
		if (thr->work_restart) {
			applog(LOG_DEBUG, "%s: New work detected", ztex->repr);
			break;
		}
		ztex_selectFpga(ztex);
		i = libztex_readHashData(ztex, &hdata[0]);
		if (i < 0) {
			// Something wrong happened in read
			applog(LOG_ERR, "%s: Failed to read hash data with err %d, retrying", ztex->repr, i);
			nmsleep(500);
			i = libztex_readHashData(ztex, &hdata[0]);
			if (i < 0) {
				// And there's nothing we can do about it
				ztex_disable(thr);
				applog(LOG_ERR, "%s: Failed to read hash data with err %d, giving up", ztex->repr, i);
				free(lastnonce);
				ztex_releaseFpga(ztex);
				return -1;
			}
		}
		ztex_releaseFpga(ztex);

		for (i = 0; i < ztex->numNonces; i++) {
			// first, ensure hash is valid for counting nonce
			if (!ztex_checkNonce(ztex, work, &hdata[i])) {
				bad_nonce++;
				thr->cgpu->hw_errors++;
				continue;
			}

			// counting nonce is valid
			nonce = hdata[i].nonce;
#if defined(__BIGENDIAN__) || defined(MIPSEB)
			nonce = swab32(nonce);
#endif
			// check for overflow: if we're closer to the end then we are to the last nonce we poll'ed, we're going to overflow
			if (nonce > noncecnt)
				noncecnt = nonce;
			if (((0xffffffff - nonce) < (nonce - lastnonce[i])) || nonce < lastnonce[i]) {
				applog(LOG_DEBUG, "%s: overflow nonce=%0.8x lastnonce=%0.8x", ztex->repr, nonce, lastnonce[i]);
				overflow = true;
			} else
				lastnonce[i] = nonce;

			for (j=0; j<=ztex->extraSolutions; j++) {
				nonce = hdata[i].goldenNonce[j];
				HASH_FIND_INT(nonce_list, &nonce, nonce_entry);
				if(nonce_entry)
					continue;
				if(!(nonce_entry = malloc(sizeof(*nonce_entry)))) {
					applog(LOG_ERR, "%s: malloc", ztex->repr);
					break;
				}
				nonce_entry->nonce_used = nonce;
				HASH_ADD_INT(nonce_list, nonce_used, nonce_entry);

#if defined(__BIGENDIAN__) || defined(MIPSEB)
				nonce = swab32(nonce);
#endif
				/*
				if(!ztex_hashtest(ztex, work, nonce)) {
					if(nonce != 0)
						applog(LOG_WARNING, "%s: HW error (driver) -- invalid nonce: 0x%8.8x", ztex->repr, nonce);
					continue;
				}
				 */
				if(nonce == 0)
					continue;

				applog(LOG_DEBUG, "%s: Share found N%dE%d", ztex->repr, i, j);
				work->blk.nonce = 0xffffffff;
				submit_nonce(thr, work, nonce);
				applog(LOG_DEBUG, "%s: submitted %0.8x", ztex->repr, nonce);
				good_nonce++;
			}
		}
	}

	if(bad_nonce)
		ztex_bad_share(ztex);
	else if(good_nonce)
		ztex_good_share(ztex);

	// remove our repeat list
	HASH_ITER(hh, nonce_list, nonce_entry, nonce_entry_tmp) {
		HASH_DEL(nonce_list, nonce_entry);
		free(nonce_entry);
	}

	applog(LOG_DEBUG, "%s: exit %1.8X", ztex->repr, noncecnt);

	work->blk.nonce = 0xffffffff;

	free(lastnonce);

	return noncecnt;
}


static void ztex_statline_before(char *buf, struct cgpu_info *cgpu)
{
	if (cgpu->deven == DEV_ENABLED) {
		tailsprintf(buf, "%s-%d   | ", cgpu->device_ztex->snString, cgpu->device_ztex->fpgaNum);
		tailsprintf(buf, "%3uMHz | ", (unsigned int)(cgpu->device_ztex->freqM1 * (cgpu->device_ztex->freqM + 1)));
	}
}

static bool ztex_prepare(struct thr_info *thr)
{
	struct timeval now;
	struct cgpu_info *cgpu = thr->cgpu;
	struct libztex_device *ztex = cgpu->device_ztex;

	gettimeofday(&now, NULL);
	get_datestamp(cgpu->init, &now);

	ztex_selectFpga(ztex);
	if (libztex_configureFpga(ztex) != 0) {
		libztex_resetFpga(ztex);
		ztex_releaseFpga(ztex);
		applog(LOG_ERR, "%s: Disabling!", thr->cgpu->device_ztex->repr);
		thr->cgpu->deven = DEV_DISABLED;
		return true;
	}
	// ztex->freqM = ztex->freqMaxM+1;;
	// ztex_updateFreq(ztex);
	ztex->freqM = 49;
	ztex->freqMDefault = 53;
	// ztex->freqMaxM = 54;
	libztex_setFreq(ztex, ztex->freqMDefault);
	ztex_releaseFpga(ztex);
	applog(LOG_DEBUG, "%s: prepare", ztex->repr);
	return true;
}

static void ztex_shutdown(struct thr_info *thr)
{
	if (thr->cgpu->device_ztex != NULL) {
		if (thr->cgpu->device_ztex->fpgaNum == 0)
			pthread_mutex_destroy(&thr->cgpu->device_ztex->mutex);  
		applog(LOG_DEBUG, "%s: shutdown", thr->cgpu->device_ztex->repr);
		libztex_destroy_device(thr->cgpu->device_ztex);
		thr->cgpu->device_ztex = NULL;
	}
}

static void ztex_disable(struct thr_info *thr)
{
	applog(LOG_ERR, "%s: Disabling!", thr->cgpu->device_ztex->repr);
	devices[thr->cgpu->device_id]->deven = DEV_DISABLED;
	ztex_shutdown(thr);
}

struct device_api ztex_api = {
	.dname = "ztex",
	.name = "ZTX",
	.api_detect = ztex_detect,
	.get_statline_before = ztex_statline_before,
	.thread_prepare = ztex_prepare,
	.scanhash = ztex_scanhash,
	.thread_shutdown = ztex_shutdown,
	.clock_stats = ztex_clock_stats
};
