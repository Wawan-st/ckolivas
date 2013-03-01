#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "picominer.h"
#include "sha2.h"


typedef struct block_header {
	unsigned int	version;
	char		prev_block[65];
	char		merkle_root[65];
	unsigned int	timestamp;
	unsigned int	bits;
	unsigned int	nonce;
} block_header;


void display_hex(unsigned char *data, int len) {

	int c;

	for(c = 0; c < len; c++)
		printf("%2.2x", data[c]);
}


void h2b(unsigned char *dest, const char *src, unsigned int srclen) {

	unsigned int i;
	unsigned char *d = dest;
	char buf[3];

	for(i = 0; i < srclen; i += 2) {
		buf[0] = src[i];
		buf[1] = src[i + 1];
		*d = strtoul(buf, 0, 16);
		d++;
	}
}


void byte_swap(unsigned char *data, int len) {
	
	int c;
	unsigned char tmp[len];
	
	for(c = 0; c < len; c++)
		tmp[c] = data[len - (c + 1)];

	memcpy(data, tmp, len);
}


void calc_midstate(unsigned char *data, unsigned char *midstate) {

	sha2_context ctx;

	sha2_starts(&ctx, 0);
	sha2_update(&ctx, data, 64);
	memcpy(midstate, ctx.state, 32);
}


void finish_sha256(unsigned char *midstate, unsigned char *data, unsigned char *hash) {

	sha2_context ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.total[0] = 64;
	memcpy(ctx.state, midstate, 8 * sizeof(uint32_t));
	sha2_update(&ctx, data, 16);
	sha2_finish(&ctx, hash);
}


void final_sha256(unsigned char *hash_in, unsigned char *hash_out) {

	sha2_context ctx;

	sha2_starts(&ctx, 0);
	sha2_update(&ctx, hash_in, 32);
	sha2_finish(&ctx, hash_out);
}


void sha256twice(unsigned char *data, unsigned int datalen, unsigned char *hash) {

	sha2_context ctx;
	unsigned char hash1[32];

	sha2_starts(&ctx, 0);
	sha2_update(&ctx, data, datalen);
	sha2_finish(&ctx, hash1);
	sha2_starts(&ctx, 0);
	sha2_update(&ctx, hash1, 32);
	sha2_finish(&ctx, hash);
}


void dump_tod() {

	struct timeval tv;
	double t;

	if(gettimeofday(&tv, 0)) {
		perror("gettimeofday");
		return;
	}
	t = (double)tv.tv_sec + ((double)tv.tv_usec / 1000000.0);
	printf("%.6lf: ", t);
}


int main() {

	int num;
	int i;
	uint32_t nonce;
	unsigned char hash0[32], hash1[32];
	unsigned char block[80], midstate[32], data1[44], data2[44], *d1p, *d2p;
	picominer_dev_list *l;
	picominer_device *d1, *d2;
	static const block_header gen_0 = {
		.version	= 1,
		.prev_block	= "0000000000000000000000000000000000000000000000000000000000000000",
		.merkle_root	= "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",	// big endian
		.timestamp	= 1231006505,
		.bits		= 486604799,
		.nonce		= 2083236893,
	};

	static const block_header bh202810 = {
		.version	= 2,
		.prev_block	= "00000000000004bc7bd1ea3508816ead38fe6ba9f88420173a83d12f55db0d91",	// big endian
		.merkle_root	= "a6c3fdd1886f790a0f7467176636e5851acc4415dec2d8e0063105bdedd22f1b",	// big endian
		.timestamp	= 1349959440,
		.bits		= 436567560,
		.nonce		= 4072088149,
	};
	

	if((num = picominer_get_all_available(&l)) < 0) {
		fprintf(stderr, "error: picominer_get_all_available failed\n");
		return -1;
	}
	printf("found %d devices!\n", num);

	if(num != 2) {
		printf("did not find 2 devices\n");
		return 0;
	}

	d1 = l->dev;
	d2 = l->next->dev;
	if((!d1) || (!d2)) {
		fprintf(stderr, "error: device(s) null\n");
		return -1;
	}

	// setup data for FPGA
	memset(block, 0, sizeof(block));
	memcpy(block, &gen_0.version, sizeof(gen_0.version));
	h2b(block + 4, gen_0.prev_block, strlen(gen_0.prev_block));
	byte_swap(block + 4, 32);						// make little-endian
	h2b(block + 4 + 32, gen_0.merkle_root, strlen(gen_0.prev_block));
	byte_swap(block + 4 + 32, 32);						// make little-endian
	memcpy(block + 4 + 32 + 32, &gen_0.timestamp, 4);
	memcpy(block + 4 + 32 + 32 + 4, &gen_0.bits, 4);
	memcpy(block + 4 + 32 + 32 + 4 + 4, &gen_0.nonce, 4);

	memcpy(data1, block + 64, 12);		// data goes in low bits
	for(i = 0; i < 3; i++)
		byte_swap(data1 + 4 * i, 4);
	calc_midstate(block, midstate);
	memcpy(data1 + 12, midstate, 32);	// high bits are midstate
	d1p = data1;

	sha256twice(block, 80, hash0);
	printf("block:\t");
	display_hex(block, 80);
	printf("\nnonce:\t%x\n", gen_0.nonce);
	printf("hash:\t");
	display_hex(hash0, 32);
	printf("\n");

	printf("sending data 1:\t");
	if(picominer_send_hash_data(d1, d1p)) {
		fprintf(stderr, "picominer_send_hash_data failed\n");
		return -1;
	}
	printf("done\n");

	memset(block, 0, sizeof(block));
	memcpy(block, &bh202810.version, sizeof(bh202810.version));
	h2b(block + 4, bh202810.prev_block, strlen(bh202810.prev_block));
	byte_swap(block + 4, 32);
	h2b(block + 4 + 32, bh202810.merkle_root, strlen(bh202810.prev_block));
	byte_swap(block + 4 + 32, 32); // make little-endian
	memcpy(block + 4 + 32 + 32, &bh202810.timestamp, 4);
	memcpy(block + 4 + 32 + 32 + 4, &bh202810.bits, 4);
	memcpy(block + 4 + 32 + 32 + 4 + 4, &bh202810.nonce, 4);

	memcpy(data2, block + 64, 12);		// data goes in low bits
	for(i = 0; i < 3; i++)
		byte_swap(data2 + 4 * i, 4);
	calc_midstate(block, midstate);
	memcpy(data2 + 12, midstate, 32);	// high bits are midstate
	d2p = data2;

	sha256twice(block, 80, hash1);
	printf("block:\t");
	display_hex(block, 80);
	printf("\nnonce:\t%x\n", bh202810.nonce);
	printf("hash:\t");
	display_hex(hash1, 32);
	printf("\n");

	printf("sending data 2:\t");
	if(picominer_send_hash_data(d2, d2p)) {
		fprintf(stderr, "picominer_send_hash_data failed\n");
		return -1;
	}
	printf("done\n");


	while(1) {
		if(picominer_has_nonce(d1)) {
			picominer_get_nonce(d1, &nonce);
			nonce = nonce - 0xff;
			byte_swap((unsigned char *)&nonce, 4);
			dump_tod();
			printf("1: nonce found:\t%x\n", nonce);
			/*
			d1p = (d1p == data1)? data2 : data1;
			if(picominer_send_hash_data(d1, d1p)) {
				fprintf(stderr, "error: picominer_send_hash_data failed\n");
				return -1;
			}
			 */
		}
		if(picominer_has_nonce(d2)) {
			picominer_get_nonce(d2, &nonce);
			nonce = nonce - 0xff;
			byte_swap((unsigned char *)&nonce, 4);
			dump_tod();
			printf("2: nonce found:\t%x\n", nonce);
			/*
			d2p = (d2p == data1)? data2 : data1;
			if(picominer_send_hash_data(d2, d2p)) {
				fprintf(stderr, "picominer_send_hash_data failed\n");
				return -1;
			}
			 */
		}
		usleep(1000);
	}

	return 0;
}
