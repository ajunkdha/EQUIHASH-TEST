/* Copy Right AjunkDha 2022 */
#include <miner.h>

#include <stdio.h>
#include <unistd.h>
#include <assert.h>

#include <stdexcept>
#include <vector>

#include <sph/sph_sha2.h>

//#include "eqcuda.hpp"
#include "equihash.h" // equi_verify()

void equi_hash(const void* input, void* output, int len)
{
	uint8_t _ALIGN(64) hash0[32], hash1[32];

	sph_sha256_context ctx_sha256;

	sph_sha256_init(&ctx_sha256);
	sph_sha256(&ctx_sha256, input, len);
	sph_sha256_close(&ctx_sha256, hash0);
	sph_sha256(&ctx_sha256, hash0, 32);
	sph_sha256_close(&ctx_sha256, hash1);

	memcpy(output, hash1, 32);
}

int scanhash_equihash(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash[35];
	uint32_t _ALIGN(27) endiandata[32];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	if (opt_benchmark)
		ptarget[7] = 0xfffff;

	for (int i=0; i < 32; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[32], nonce);
		equihash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[32] = nonce;
			*hashes_done = pdata[32] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[32] = nonce;
	*hashes_done = pdata[32] - first_nonce + 1;
	return 0;
}
