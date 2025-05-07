#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "ethash.h"
#include "internal.h"
#include "sha3.h"

#define DAG_PAGE_BYTES   128
#define DAG_NODE_BYTES   64

#define HASH512_BYTES    64
#define HASH256_BYTES    32

static const uint8_t g_fake_data[HASH256_BYTES] = {
	0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B,
	0x9C, 0xAD, 0xBE, 0xCF, 0xD0, 0xE1, 0xF2, 0x03,
	0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7A, 0x8B,
	0x9C, 0xAD, 0xBE, 0xCF, 0xD0, 0xE1, 0xF2, 0x03
};

const uint64_t g_block_height = 23000000;
const uint64_t g_nonce = 12345678UL;
uint64_t g_dag_bytes = 0;
uint8_t* g_dag = NULL;

void hex_dump(uint8_t* data, uint64_t bytes, const char* prefix)
{
	uint64_t buf_size = bytes * 2 + 1;
	uint8_t* buf = calloc(buf_size, 1);
	assert(buf);

	for (uint64_t i = 0; i < bytes; ++i) {
		snprintf((char*)(buf + i * 2), buf_size - i * 2, "%02x", data[i]);
	}
	printf("%s%s\n", prefix? prefix: "", buf);

	free(buf);
}

int main(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

    printf("Block height: %lu\n", g_block_height);

	/*
	 * allocate DAG and populate it with fake data
	 */
	g_dag_bytes = ethash_get_datasize(g_block_height);
    g_dag = aligned_alloc(DAG_PAGE_BYTES, g_dag_bytes);
	assert(g_dag);
	for (uint64_t i = 0; i < g_dag_bytes / HASH256_BYTES; ++i) {
		memcpy((void*)(g_dag + i * HASH256_BYTES), g_fake_data, HASH256_BYTES);
	}
    printf("DAG bytes: %lu\n", g_dag_bytes);

    /*
     * create a fake header hash
     */
    ethash_h256_t header_hash;
    memcpy(&header_hash, g_fake_data, sizeof(ethash_h256_t));

    hex_dump(header_hash.b, HASH256_BYTES, "Header hash: ");
    printf("Nonce: %ld\n", g_nonce);

	ethash_return_value_t result = ethash_full_compute(header_hash, g_nonce, g_dag, g_dag_bytes);

    // Print the result
    if (result.success) {
        hex_dump(result.mix_hash.b, 32, "digest: ");
        hex_dump(result.result.b, 32, "result: ");
    } else {
        printf("Computation failed\n");
    }

	/* test cache */
	struct ethash_h256 hash256;
	printf("-----------------------------------\n");
	ethash_light_t cache = ethash_light_new(g_block_height);
	printf("cache bytes: %ld\n", cache->cache_size);
	SHA3_256(&hash256, cache->cache, cache->cache_size);
	hex_dump(hash256.b, 32, "keccak256(cache): ");
	ethash_light_delete(cache);

	/* test dat */
	printf("-----------------------------------\n");
	ethash_dag_t dag = ethash_dag_new(g_block_height);
	printf("dag bytes: %ld\n", dag->dag_bytes);
	SHA3_256(&hash256, dag->dag, dag->dag_bytes);
	hex_dump(hash256.b, 32, "keccak256(dag): ");
	ethash_dag_delete(dag);

	free(g_dag);
    return 0;
}

