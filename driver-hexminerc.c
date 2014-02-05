/*$T indentinput.c GC 1.140 10/16/13 10:19:47 */
/*
 * Copyright 2013 Con Kolivas <kernel@kolivas.org> Copyright 2012-2013 Xiangfu
 * <xiangfu@openmobilefree.com> Copyright 2012 Luke Dashjr Copyright 2012 Andrew
 * Smith This program is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software Foundation;
 * either version 3 of the License, or (at your option) any later version. See
 * COPYING for more details. Thank you guys!
 */
#include "config.h"
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#ifndef WIN32
#include <sys/select.h>
#include <termios.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef O_CLOEXEC
#define O_CLOEXEC	0
#endif
#else
#include "compat.h"
#include <windows.h>
#include <io.h>
#endif
#include "elist.h"
#include "miner.h"
#include "usbutils.h"
#include "driver-hexminerc.h"
#include "util.h"

static int option_offset = -1;
struct device_drv hexminerc_drv;
int opt_hexminerc_core_voltage = HEXC_DEFAULT_CORE_VOLTAGE;
#include "libhexc.c"

static void
hexminerc_flush_work (struct cgpu_info *hexminerc)
{
    struct hexminerc_info *info = hexminerc->device_data;
    cgsem_post(&info->qsem);
}

static int
hexminerc_send_task (struct hexminerc_task *ht, struct cgpu_info *hexminerc)
{
    unsigned char buf[HEXMINERC_TASK_SIZE + 6];
    int ret, amount = 0;
    struct hexminerc_info *info;
    size_t nr_len = HEXMINERC_TASK_SIZE + 6;
    uint16_t workqueue_adr = htole16 (HEXC_WORKQUEUE_ADR);
    buf[0] = 0x53;
    buf[2] = 0x57;                /* Write Command - char 'W' (0x57) */
    info = hexminerc->device_data;
    libhexc_generateclk (info->frequency, HEXC_DEFAULT_XCLKIN_CLOCK,
                         (uint32_t *) & ht->clockcfg[0]);
    libhexc_setvoltage (info->core_voltage, &ht->refvoltage);
    ht->chipcount = htole16 (info->asic_count);
    ht->hashclock = htole16 ((uint16_t) info->frequency);
    ht->startnonce = 0x00000000;
    memcpy (buf + 5, ht, HEXMINERC_TASK_SIZE);
    /* Count Words */
    buf[1] = (uint8_t) ((HEXMINERC_TASK_SIZE) / 2);
    memcpy (buf + 3, &workqueue_adr, 2);
    libhexc_csum (buf, buf + HEXMINERC_TASK_SIZE + 5,
                  buf + HEXMINERC_TASK_SIZE + 5);
    if (info->wr_status != HEXC_STAT_IDLE)
        return nr_len;
        
    ret = libhexc_sendHashData (hexminerc, buf, nr_len);
    if (ret != nr_len) {
        libhexc_reset (hexminerc);
        mutex_lock (&info->lock);
        info->usb_w_errors++;
        mutex_unlock (&info->lock);
        return -1;
    }
    if (info->reset_work) {
        mutex_lock (&info->lock);
        //info->start_up  = false;
        info->reset_work = false;
        mutex_unlock (&info->lock);
    }
    return ret;
}

static inline void
hexminerc_create_task (bool reset_work, struct hexminerc_task *ht, struct work *work)
{
    if (reset_work) {
        ht->status = HEXC_STAT_NEW_WORK_CLEAR_OLD;
    } else {
        ht->status = HEXC_STAT_NEW_WORK;
    }
    memcpy (ht->midstate, work->midstate, 32);
    memcpy (ht->merkle, work->data + 64, 12);
    ht->id = (uint8_t) work->subid;
    libhexc_calc_hexminer (work, ht);
}

static void *
hexminerc_send_tasks (void *userdata)
{
    struct cgpu_info *hexminerc = (struct cgpu_info *) userdata;
    struct hexminerc_info *info = hexminerc->device_data;
    char threadname[24];
    snprintf (threadname, 24, "hexc_send/%d", hexminerc->device_id);
    RenameThread (threadname);
    libhexc_reset (hexminerc);
    while(!libhexc_usb_dead(hexminerc)) {
        int start_count, end_count, ret;
        cgtimer_t ts_start;
        struct hexminerc_task ht;
        cgsleep_prepare_r (&ts_start);
        mutex_lock (&info->lock);
        start_count = info->read_pos;
        end_count =
            info->read_pos + MIN (info->cg_queue_cached_works,
                                  HEXMINERC_ARRAY_MAX_POP);
        while (info->read_pos < HEXMINERC_ARRAY_SIZE_REAL && info->hexworks[info->read_pos] != NULL &&
               start_count < end_count && info->wr_status == HEXC_STAT_IDLE) {
            hexminerc_create_task (info->reset_work, &ht, info->hexworks[info->read_pos++]);
            info->cg_queue_cached_works--;
            mutex_unlock (&info->lock);
            ret = hexminerc_send_task (&ht, hexminerc);
            mutex_lock (&info->lock);
            start_count++;
        }
        mutex_unlock (&info->lock);
        cgsem_post(&info->qsem);

       cgsleep_us_r (&ts_start, info->usb_timing);
    }
    pthread_exit (NULL);
}

static struct cgpu_info
*hexminerc_detect_one (libusb_device * dev, struct usb_find_devices *found)
{
    int miner_count, asic_count, frequency;
    int this_option_offset = ++option_offset;
    struct hexminerc_info *info;
    struct cgpu_info *hexminerc;
    bool configured;
    int i = 0;
    hexminerc = usb_alloc_cgpu (&hexminerc_drv, HEXC_MINER_THREADS);
    if (!usb_init (hexminerc, dev, found)) {
        usb_uninit(hexminerc);
        return NULL;
    }
    hexminerc->device_data = calloc (sizeof (struct hexminerc_info), 1);
    if (unlikely (!(hexminerc->device_data))) {
        hexminerc->device_data = NULL;
        usb_uninit(hexminerc);
        return NULL;
    }
    configured =
        libhexc_get_options (this_option_offset, &asic_count, &frequency);
    if (opt_hexminerc_core_voltage < HEXC_MIN_COREMV
        || opt_hexminerc_core_voltage > HEXC_MAX_COREMV) {
        applog
        (LOG_ERR,
         "Invalid hexminerc-voltage %d must be %dmV - %dmV",
         opt_hexminerc_core_voltage, HEXC_MIN_COREMV, HEXC_MAX_COREMV);
        free(hexminerc->device_data);
        hexminerc->device_data = NULL;
        usb_uninit(hexminerc);
        return NULL;
    }
    info = hexminerc->device_data;
    info->hexworks = calloc (sizeof (struct work *), HEXMINERC_ARRAY_SIZE);
    if (unlikely (!(info->hexworks))) {
        free(hexminerc->device_data);
        hexminerc->device_data = NULL;
        usb_uninit(hexminerc);
        return NULL;
    }
    while (i < HEXMINERC_ARRAY_SIZE) info->hexworks[i++] = NULL;
    //info->start_up = true;
    info->reset_work = true;
    info->read_pos = 0;
    info->write_pos = 0;
    info->cg_queue_cached_works = 0;
    info->wr_status = HEXC_STAT_IDLE;
    info->miner_count = HEXC_DEFAULT_MINER_NUM;
    info->asic_count = HEXC_DEFAULT_ASIC_NUM;
    info->frequency = HEXC_DEFAULT_FREQUENCY;
    info->pic_voltage_readings = HEXC_DEFAULT_CORE_VOLTAGE;
    info->core_voltage = opt_hexminerc_core_voltage;
    if (configured) {
        info->asic_count = asic_count;
        info->frequency = frequency;
    }
    info->usb_timing = (int64_t) (0x100000000ll / info->asic_count / info->frequency *
            HEXMINERC_WORK_FACTOR);
    if (!add_cgpu (hexminerc)) {
        free(info->hexworks);
        free(hexminerc->device_data);
        hexminerc->device_data = NULL;
        hexminerc = usb_free_cgpu (hexminerc);
        usb_uninit(hexminerc);
        return NULL;
    }
    libhexc_generatenrange_new ((unsigned char *) &info->nonces_range,
                                info->asic_count);
    return hexminerc;
}

static void
hexminerc_detect (bool __maybe_unused hotplug)
{
    usb_detect (&hexminerc_drv, hexminerc_detect_one);
}

static void
do_hexminerc_close (struct thr_info *thr)
{
    struct cgpu_info *hexminerc = thr->cgpu;
    struct hexminerc_info *info = hexminerc->device_data;
    int i = 0;
    cgsleep_ms(200);
    pthread_join (info->read_thr, NULL);
    pthread_join (info->write_thr, NULL);
    pthread_mutex_destroy (&info->lock);
    cgsem_destroy(&info->qsem);
    while (i < HEXMINERC_ARRAY_SIZE) {
        if(info->hexworks[i] != NULL) free_work(info->hexworks[i]);
        i++;
    }
    free (info->hexworks);
    //Hotplug Story
    //free (hexminerc->device_data);
    //hexminerc->device_data = NULL;
    //thr->cgpu = usb_free_cgpu(hexminerc);
}

static void
hexminerc_shutdown (struct thr_info *thr)
{
    struct cgpu_info *hexminerc = thr->cgpu;
    struct hexminerc_info *info = hexminerc->device_data;
    if (!hexminerc->shutdown) hexminerc->shutdown = true;
    cgsem_post(&info->qsem);
    do_hexminerc_close (thr);
}

static void *
hexminerc_get_results (void *userdata)
{
    struct cgpu_info *hexminerc = (struct cgpu_info *) userdata;
    struct hexminerc_info *info = hexminerc->device_data;
    unsigned char readbuf[HEXC_HASH_BUF_SIZE];
    struct workc_result *wr;
    struct chip_resultsc *array_nonce_cache;
    struct thr_info *thr = info->thr;
    int i, lastchippos;
    int usb_r_reset = 0;
    int found;
    uint32_t nonce;
    char threadname[24];
    int ret_r = 0, hash_read_pos = 0, hash_write_pos = 0, amount = 0;
    float auto_times = 0, busy_times = 0, a_count = 0, a_val = 0, err_rate = 0;
    wr = (struct workc_result *) malloc (sizeof (struct workc_result));
    array_nonce_cache = calloc (16, sizeof (struct chip_resultsc));
    int need_work_reset = 0;
    bzero(array_nonce_cache, 16 * sizeof (struct chip_resultsc));
    bzero(wr, sizeof (struct workc_result));
    snprintf (threadname, 24, "hexc_recv/%d", hexminerc->device_id);
    RenameThread (threadname);
    while(!libhexc_usb_dead(hexminerc)) {
        found = true;
        cgtimer_t ts_start;
        cgsleep_prepare_r (&ts_start);
        /* Rotate */
        ret_r = 0;
        if (hash_write_pos + HEXC_USB_R_SIZE >= HEXC_HASH_BUF_SIZE) {
            hash_write_pos = hash_write_pos - hash_read_pos;
            memcpy (readbuf, readbuf + hash_read_pos, hash_write_pos);
            hash_read_pos = 0;
        }
        if (hash_write_pos - hash_read_pos >= HEXC_BASE_WORK_SIZE + 2) {
again:
            ret_r =
                libhexc_eatHashData (wr, readbuf, &hash_read_pos,
                                     &hash_write_pos);
            if (ret_r == 1 && wr->status < HEXC_STAT_UNUSED) {
            
              if(wr->status == HEXC_STAT_WAITING) 
            		busy_times++;
            		
            	auto_times++;
              mutex_lock (&info->lock);
              if(auto_times > HEXC_USB_TIMING_AUTO) {
              	//Not an error some debug stuff
              	//applog (LOG_ERR , "From %i us", (int)info->usb_timing); 
              	a_count++;
              	a_val = HEXC_USB_TIMING_AJUST / a_count;
              	err_rate  = busy_times  / auto_times * 100;
              	if(a_val<HEXC_USB_TIMING_AJUST_LOW_RES) a_val = HEXC_USB_TIMING_AJUST_LOW_RES;
              	if (err_rate > HEXC_USB_TIMING_TARGET) {
    							if (err_rate > 0.5) {
    								//Be aggressive
    								info->usb_timing+=800;
    							} else {
    								info->usb_timing+= a_val;       	
              		}
              	} else {
              		info->usb_timing-= a_val;
              	}
              	//Not an error some debug stuff
              	//applog (LOG_ERR , "To %i us err %f%%", (int)info->usb_timing, err_rate); 
              	busy_times = 0;
              	auto_times = 0;
              	//Do not go above
              	if(info->usb_timing > (int64_t)(0x100000000ll / info->asic_count / info->frequency))
              		info->usb_timing = (int64_t) (0x100000000ll / info->asic_count / info->frequency * 0.995);
              }
              info->wr_status = wr->status;
              mutex_unlock (&info->lock);
            } else {
                goto out;
            }
            if (wr->address != HEXC_WORKANSWER_ADR)
                goto out;
            if (wr->lastnonceid > HEXMINERC_ARRAY_SIZE_REAL ) {
                wr->lastnonceid = 0;
                need_work_reset++;
            } else {
                need_work_reset = 0;
            }
            found = 0;
            nonce = htole32(wr->lastnonce);
            i = 0;
            while (i < info->asic_count) {
                if (nonce < info->nonces_range[++i]) {
                    lastchippos = --i;
                    break;
                }
            }
            if (i == info->asic_count)
                lastchippos = info->asic_count - 1;
            if (libhexc_cachenonce
                (&array_nonce_cache[lastchippos], nonce) || need_work_reset < HEXC_USB_R_BAD_ID) {
                uint8_t work_id = wr->lastnonceid;
                found+=hexminerc_predecode_nonce (hexminerc, thr, nonce,
                                                  work_id);
                if (found>0) {
                    mutex_lock (&info->lock);
                    if(info->nonces == 0) libhexc_getvoltage (htole16 (wr->lastvoltage),
                                &info->pic_voltage_readings);
                    info->nonces+=found;
                    info->matching_work[lastchippos]++;
                    mutex_unlock (&info->lock);
                } else {
                    inc_hw_errors (thr);
                }
            } else {
                mutex_lock (&info->lock);
                info->dupe[lastchippos]++;
                info->reset_work = true;
                info->dev_reset_count++;
                mutex_unlock (&info->lock);
            }
out:
            if (ret_r == 2) {
                mutex_lock (&info->lock);
                info->usb_r_errors++;
                mutex_unlock (&info->lock);
            }
            if (hash_write_pos - hash_read_pos > HEXC_MAX_WORK_SIZE)
                goto again;
        }
        ret_r = libhexc_readHashData (hexminerc, readbuf, &hash_write_pos, HEXMINERC_BULK_READ_TIMEOUT, true);
        if (ret_r != LIBUSB_SUCCESS) {
            usb_r_reset++;
            if(usb_r_reset > HEXC_USB_RES_THRESH) {
                libhexc_reset (hexminerc);
                usb_r_reset = 0;
            }
        } else {
            usb_r_reset = 0;
        }
        // if(libhexc_usb_dead(hexminerc)) break;
        cgsleep_us_r (&ts_start, HEXMINERC_READ_TIMEOUT);
    }
    free (wr);
    free (array_nonce_cache);
    pthread_exit (NULL);
}

static bool
hexminerc_prepare (struct thr_info *thr)
{
    struct cgpu_info *hexminerc = thr->cgpu;
    struct hexminerc_info *info = hexminerc->device_data;
    info->thr = thr;
    mutex_init (&info->lock);
    cgsem_init(&info->qsem);
    if (pthread_create
        (&info->write_thr, NULL, hexminerc_send_tasks, (void *) hexminerc))
        quit (1, "Failed to create hexminerc write_thr");
    if (pthread_create
        (&info->read_thr, NULL, hexminerc_get_results, (void *) hexminerc))
        quit (1, "Failed to create hexminerc read_thr");
    return true;
}

static int64_t
hexminerc_scanhash (struct thr_info *thr)
{
    struct cgpu_info *hexminerc = thr->cgpu;
    struct hexminerc_info *info = hexminerc->device_data;
    struct work *work = NULL;
    int64_t ms_timeout;
    int64_t hash_count = 0;
    if(thr->work_restart) goto res;
    /* 200 ms */
    ms_timeout = 200;
    mutex_lock (&info->lock);
    /* Rotate buffer */
    if (info->read_pos >= HEXMINERC_ARRAY_SIZE_REAL
        && info->write_pos >= HEXMINERC_ARRAY_SIZE_REAL ) {
        info->write_pos = 0;
        info->read_pos = 0;
        info->cg_queue_cached_works = 0;
    }
    while(!(info->cg_queue_cached_works > HEXMINERC_PUSH_THRESH ||
            info->write_pos >= HEXMINERC_ARRAY_SIZE_REAL)) {
        mutex_unlock (&info->lock);
        work = get_work(thr, thr->id);
        mutex_lock (&info->lock);
        if (work == NULL) break;
        work->subid = info->write_pos;
        if(info->hexworks[info->write_pos]!=NULL) free_work(info->hexworks[info->write_pos]);
        info->hexworks[info->write_pos++] = work;
        info->cg_queue_cached_works++;
    }
    hash_count = 0xffffffffull * (uint64_t) info->nonces;
    info->nonces = 0;
    mutex_unlock (&info->lock);
    cgsem_mswait(&info->qsem, ms_timeout);
res:
    if (libhexc_usb_dead(hexminerc)) {
        if(!hexminerc->shutdown) hexminerc->shutdown = true;
        return -1;
    }
    if(thr->work_restart) {
    	  work = get_work(thr, thr->id);
        mutex_lock (&info->lock);
        info->reset_work = true;
        /* Eat Buffer */
        info->read_pos = 0;
        info->write_pos = 0;
        if (work != NULL){
        	work->subid = info->write_pos;
        	if(info->hexworks[info->write_pos]!=NULL) free_work(info->hexworks[info->write_pos]);
        		info->hexworks[info->write_pos++] = work;
        		info->cg_queue_cached_works = 1;
        } else {
        	info->cg_queue_cached_works = 0;
        }
        mutex_unlock (&info->lock);
    }

    return hash_count;
}

static void
get_hexminerc_statline_before (char *buf, size_t bufsiz,
                               struct cgpu_info *hexminerc)
{
    struct hexminerc_info *info = hexminerc->device_data;
    tailsprintf (buf, bufsiz, "%3d %4d/%4dmV | ", info->frequency,
                 info->core_voltage, info->pic_voltage_readings);
}

static struct api_data *
hexminerc_api_stats (struct cgpu_info *cgpu) {
    struct api_data *root = NULL;
    struct hexminerc_info *info = cgpu->device_data;
    uint64_t dh64, dr64;
    double dev_runtime;
    struct timeval now;
    int i;
    char displayed_hashes[16], displayed_rolling[16];
    double hwp =
        (cgpu->hw_errors +
         cgpu->diff1) ? (double) (cgpu->hw_errors) / (double) (cgpu->hw_errors +
                 cgpu->diff1) : 0;
    if (cgpu->dev_start_tv.tv_sec == 0)
        dev_runtime = total_secs;
    else {
        cgtime (&now);
        dev_runtime = tdiff (&now, &(cgpu->dev_start_tv));
    }
    if (dev_runtime < 1.0)
        dev_runtime = 1.0;
    dh64 = (double) cgpu->total_mhashes / dev_runtime * 1000000ull;
    dr64 = (double) cgpu->rolling * 1000000ull;
    suffix_string (dh64, displayed_hashes, sizeof (displayed_hashes), 4);
    suffix_string (dr64, displayed_rolling, sizeof (displayed_rolling), 4);
    root = api_add_string (root, "MHS 5s", displayed_rolling, true);
    root = api_add_string (root, "MHS av", displayed_hashes, true);
    root = api_add_int (root, "Hardware Errors", &(cgpu->hw_errors), true);
    root = api_add_percent (root, "Hardware Errors%", &hwp, true);
    root = api_add_int (root, "USB Read Errors", &(info->usb_r_errors), true);
    root = api_add_int (root, "USB Write Errors", &(info->usb_w_errors), true);
    root = api_add_int (root, "Idled for 60 sec", &(info->idled), true);
    root = api_add_int (root, "Reset Count", &(info->dev_reset_count), true);
    root =
        api_add_time (root, "Last Share Time", &(cgpu->last_share_pool_time),
                      true);
    root = api_add_int (root, "Chip Count", &(info->asic_count), true);
    root = api_add_int (root, "Frequency", &(info->frequency), true);
    root = api_add_int (root, "Core Voltage", &(info->core_voltage), true);
    root =
        api_add_int (root, "PIC Voltage Readings", &(info->pic_voltage_readings),
                     true);
    for (i = 0; i < info->asic_count; i++) {
        /*~ */
        char mcw[24];
        /*~ */
        sprintf (mcw, "Chip%d Nonces", i + 1);
        root = api_add_int (root, mcw, &(info->matching_work[i]), true);
        sprintf (mcw, "Chip%d Dupes", i + 1);
        root = api_add_int (root, mcw, &(info->dupe[i]), true);
    }
    return root;
}

static bool hexminerc_thread_init(struct thr_info *thr)
{
	struct cgpu_info *hexminerc = thr->cgpu;
	unsigned int wait;

	/* Pause each new thread at least 100ms between initialising
	 * so the devices aren't making calls all at the same time. */
	wait = thr->id * HEXC_MAX_START_DELAY_MS;
	//applog(LOG_DEBUG, "%s%d: Delaying start by %dms",
		//	hexminerc->drv->name, hexminerc->device_id, wait / 1000);
	cgsleep_ms(wait);

	return true;
}

struct device_drv hexminerc_drv = {
    .drv_id = DRIVER_hexminerc,
    .dname = "hexminerc",
    .name = "HEXc",
    .drv_detect = hexminerc_detect,
    .thread_prepare = hexminerc_prepare,
    //.thread_init = hexminerc_thread_init,
    .hash_work = hash_queued_work,
    .scanwork = hexminerc_scanhash,
    .flush_work = hexminerc_flush_work,
    .get_api_stats = hexminerc_api_stats,
    .get_statline_before = get_hexminerc_statline_before,
    .thread_shutdown = hexminerc_shutdown,
};
