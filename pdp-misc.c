
/* 
* pdp-misc.c
*
* Copyright (c) 2008, Zachary N J Peterson <zachary@jhu.edu>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * The name of the Zachary N J Peterson may be used to endorse or promote products
*       derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY ZACHARY N J PETERSON ``AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ZACHARY N J PETERSON BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "pdp.h"
#include <limits.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

void printhex(unsigned char *ptr, size_t size){

	int i = 0;
	for(i = 0; i < size; i++){
		printf("%02X", *ptr);
		ptr++;
	}
	printf("\n");
}

void sfree(void *ptr, size_t size){ memset(ptr, 0, size); free(ptr); ptr = NULL;}

/* sanitize_pdp_challenge: Takes a client-side challenge and creates a new challenge that is safe for the server to receive
 * by removing the secret, s.  The resuling challenge will look like: <c, k1, k2, g_s>. Returns a newly allocated challenge or NULL on error.
*/
PDP_challenge *sanitize_pdp_challenge(PDP_challenge *challenge){

	PDP_challenge *san_challenge = NULL;
	
	if( ((san_challenge = generate_pdp_challenge()) == NULL)) goto cleanup;

	san_challenge->c = challenge->c;
	san_challenge->numfileblocks = challenge->numfileblocks;
	if( ((BN_copy(san_challenge->g_s, challenge->g_s)) == NULL)) goto cleanup;
	memcpy(san_challenge->k1, challenge->k1, PRP_KEY_SIZE);
	memcpy(san_challenge->k2, challenge->k2, PRF_KEY_SIZE);	

	return san_challenge;
	
cleanup:
	if(san_challenge) destroy_pdp_challenge(san_challenge);
	
	return NULL;
}

/* gereate_prp_pi: the implementation of the pseudo-random permutation (PRP) pi_k1(j).  It takes in a challenge
 * which contains the randomly generated key k1 and the number of blocks to challenge, c, 
 * and the number of blocks in the file.
 * It returns an allocated array containing c blocks indicies chosen at random from the 
 * file size or NULL on failure.
 * In this implementation we use AES as the PRP.
 */
unsigned int *generate_prp_pi(PDP_challenge *challenge){
	
	unsigned char *prp_result = NULL;
	unsigned char *prp_input = NULL;
	AES_KEY aes_key;
	unsigned int index = 0;
	double r = 0.0;
	int x = 0, j = 0;
	unsigned int *indices = NULL;
	
	if(!challenge || !challenge->k1 || !challenge->numfileblocks) return NULL;

	/* Allocate memory */
	if( ((prp_result = malloc(PRP_KEY_SIZE)) == NULL)) goto cleanup;
	if( ((prp_input = malloc(PRP_KEY_SIZE)) == NULL)) goto cleanup;
	if( ((indices = malloc(challenge->c * sizeof(unsigned int))) == NULL)) goto cleanup;
	
	memset(prp_result, 0, PRP_KEY_SIZE);
	memset(prp_input, 0, PRP_KEY_SIZE);
	memset(&aes_key, 0, sizeof(AES_KEY));
	
	/* Setup the AES key */
	AES_set_encrypt_key(challenge->k1, PRP_KEY_SIZE * 8, &aes_key);
	
	/* Choose c blocks from 0 to numfileblocks - 1 without replacement */
	for(x = 0; x < challenge->numfileblocks && j < challenge->c; x++){
	
		/* Setup in the input buffer */
		memcpy(prp_input, &x, sizeof(int));
	
		/* Perform AES on the index */
		AES_encrypt(prp_input, prp_result, &aes_key);
	
		/* Turn the PRP result into a number */
		memcpy(&index, prp_result, sizeof(unsigned int));
	
		/* Make that number between 0 and 1 */
		r = ((double)index/(double)UINT_MAX);
	
		if( (challenge->numfileblocks - x) * r < challenge->c - j){
			indices[j] = x;
			j++;
		}
	}
	
	/* Clear and free variables */
	if(prp_input) sfree(prp_input, PRP_KEY_SIZE);
	if(prp_result) sfree(prp_result, PRP_KEY_SIZE);
	memset(&aes_key, 0, sizeof(AES_KEY));
	
	return indices;

cleanup:
	if(prp_result) sfree(prp_result, PRP_KEY_SIZE);
	if(prp_input) sfree(prp_input, PRP_KEY_SIZE);
	if(indices) sfree(indices, (challenge->c * sizeof(unsigned int)));
	memset(&aes_key, 0, sizeof(AES_KEY));

	return NULL;
}

unsigned char *generate_H(BIGNUM *input, size_t *H_result_size){

	unsigned char *H_result = NULL;
	unsigned char *H_input  = NULL;
	
	if(!input) return NULL;
	
	/* Allocate memory */
	if( ((H_result = malloc(SHA_DIGEST_LENGTH)) == NULL)) goto cleanup;
	if( ((H_input = malloc(BN_num_bytes(input))) == NULL)) goto cleanup;

	memset(H_result, 0, SHA_DIGEST_LENGTH);
	memset(H_input, 0, BN_num_bytes(input));

	/* Convert input to char array for hashing */
	BN_bn2bin(input, H_input);

	/* Compute the SHA1 */
	if(!SHA1(H_input, BN_num_bytes(input), H_result)) goto cleanup;

	/* Set the result size */
	*H_result_size = SHA_DIGEST_LENGTH;

	if(H_input) sfree(H_input, BN_num_bytes(input));
	
	return H_result;
	
cleanup:
	if(H_input) sfree(H_input, BN_num_bytes(input));
	if(H_result) sfree(H_result, SHA_DIGEST_LENGTH);
	return NULL;
    
}

/* gereate_prf_f: the implementation of the pseudo-random funcation f_k2(j).  It takes in a challenge
 * which contains the randomly generated key k2, an index j, and a pointer to the resulting PRF size.
 * It returns an allocated buffer containing the resulting PRF or NULL on failure.
 * In this implementation we use HMAC-SHA1.
 */
unsigned char *generate_prf_f(PDP_challenge *challenge, unsigned int j, size_t *prf_result_size){

	unsigned char *prf_result = NULL;

	if(!challenge || !challenge->k2 || !prf_result_size) return NULL;

	/* Allocate memory */
	if( ((prf_result = malloc(SHA_DIGEST_LENGTH)) == NULL)) goto cleanup;

	memset(prf_result, 0, SHA_DIGEST_LENGTH);

	/* Perform the HMAC on the index */
	if(!HMAC(EVP_sha1(), challenge->k2, PRF_KEY_SIZE, (unsigned char *)&j, sizeof(int), 
		prf_result, (unsigned int *)prf_result_size)) goto cleanup;

	return prf_result;

cleanup:
	if(prf_result) sfree(prf_result, SHA_DIGEST_LENGTH);
	if(prf_result_size) *prf_result_size = 0;

	return NULL;
}

/* gereate_prf_w: the implementation of the pseudo-random funcation w_v().  It takes in a pdp-key,
 * containing the secrete MAC key v, a block index and a pointer to the resulting prf size.
 * It returns an allocated buffer containing the resulting PRF or NULL on failure.
 * In this implementation we use HMAC-SHA1.
 */
unsigned char *generate_prf_w(PDP_key *key, unsigned int index, size_t *prf_result_size){
	
	unsigned char *prf_result = NULL;
	
	if(!key || !key->v || !prf_result_size) return NULL;
	
	if( ((prf_result = malloc(SHA_DIGEST_LENGTH)) == NULL)) goto cleanup;
	memset(prf_result, 0, SHA_DIGEST_LENGTH);
	
	/* Perform the HMAC on the block index */
	if(!HMAC(EVP_sha1(), key->v, PRF_KEY_SIZE, (unsigned char *)&index, sizeof(int), 
		prf_result, (unsigned int *)prf_result_size)) goto cleanup;
	
	return prf_result;
	
cleanup:
	if(prf_result) sfree(prf_result, SHA_DIGEST_LENGTH);
	if(prf_result_size) *prf_result_size = 0;
	
	return NULL;
}

/* generate_fdh_h: the implementation of the full-domain hash fuction h().
 * This implementation of an FDH function takes an input and its size and an RSA
 * modulus (in the form a PDP key).  It concatenates a counter to the input
 * and performs a SHA1 hash.  The result is appended to the final output.  This
 * process is repeated until the result is the size of the RSA modulus and the result
 * is less than the RSA modulus.  It returns a BIGNUM representation of the value or NULL
 * on failure.
 */
BIGNUM *generate_fdh_h(PDP_key *key, unsigned char *index_prf, size_t index_prf_size){

	int n_bytes = 0;
	unsigned int num_hashes = 0;
	size_t sha1_input_size = index_prf_size + sizeof(unsigned int);
	unsigned char sha1_input[sha1_input_size];
	unsigned char *fdh = NULL;
	BIGNUM *fdh_bn = NULL;
	int i = 0;
	unsigned int counter = 0;

	if(!key || !index_prf || !index_prf_size) return NULL;

	/* Validate key */
	if(!key->rsa->n) return NULL;
	
	/* Get the size of the RSA modulus in bytes */
	n_bytes = BN_num_bytes(key->rsa->n);
	
	/* Calculate the number of hashes to perform minus one*/
	num_hashes = n_bytes/SHA_DIGEST_LENGTH;
	
	/* Allocate memory */
	if( ((fdh = malloc( (num_hashes + 1) * SHA_DIGEST_LENGTH )) == NULL)) goto cleanup;
	if( ((fdh_bn = BN_new()) == NULL)) goto cleanup;
	memset(fdh, 0, n_bytes);
	
	/* Fill all but the most significant bits of the fdh hash */
	counter = 0;
	for(i = num_hashes; i > 0; i--){
		/* Hash the output of the PRF appended with a counter */
		memset(sha1_input, 0, sha1_input_size);
		memcpy(sha1_input, &counter, sizeof(unsigned int));
		memcpy(sha1_input + sizeof(unsigned int), index_prf, index_prf_size);
		SHA1(sha1_input, sha1_input_size, (fdh + (i * SHA_DIGEST_LENGTH)));
		counter++;
	}
	/* Hash the most significant bits and re-hash until the FDH is smaller than the RSA modulus, N */
	do{
		memset(sha1_input, 0, sha1_input_size);
		memcpy(sha1_input, &counter, sizeof(unsigned int));
		memcpy(sha1_input + sizeof(unsigned int), index_prf, index_prf_size);
		if(!SHA1(sha1_input, sha1_input_size, fdh)) goto cleanup;
		/* Turn the first sizeof(rsa->n) bytes into a big number */
		if(!BN_bin2bn(fdh, n_bytes, fdh_bn)) goto cleanup;
		counter++;
	}while(BN_ucmp(fdh_bn, key->rsa->n) > 0);
	
	if(fdh) sfree(fdh, n_bytes);
	
	return fdh_bn;

cleanup:
	if(fdh) sfree(fdh, n_bytes);
	if(fdh_bn) BN_clear_free(fdh_bn);
	
	return NULL;
}

/* destroy_pfp_generator: Clears and free the pdp-generator g */
void destroy_pdp_generator(PDP_generator *g){

	if(!g) return;
	
	BN_clear_free(g);
}

/*
 * pick_pdp_generator: Finds a generator of the quadratic residues subgroup of Z*N.
 * Takes an RSA modulus N and returns a generator or NULL on failure..
 */
PDP_generator *pick_pdp_generator(BIGNUM *n){

 	PDP_generator *g = NULL; /* generator */
	BIGNUM *a = NULL; /* random value */
	BIGNUM *r0 = NULL; /* temp value */
	BIGNUM *r1 = NULL; /* temp value */
  	BN_CTX *ctx = NULL;
  	int found_g = 0;

	if(!n) return NULL;

  	if( ((g = BN_new()) == NULL)) goto cleanup;
	if( ((a = BN_new()) == NULL)) goto cleanup;
	if( ((r0 = BN_new()) == NULL)) goto cleanup;
	if( ((r1 = BN_new()) == NULL)) goto cleanup;
	if( ((ctx = BN_CTX_new()) == NULL)) goto cleanup;
	
 	while(!found_g){

    	/* Pick a random a < N */
		if(!BN_rand_range(a, n)) goto cleanup;

 		/* Check to see if a is relatively prime to N */
    	/* gcd(a, N) = 1 */
		if(!BN_gcd(r0, a, n, ctx)) goto cleanup;
    	if(!BN_is_one(r0))
      		continue;

    	/* Check to see if a-1 is relatively prime to N */
    	/* gcd(a-1, N) = 1 */
		if(!BN_sub(r0, a, BN_value_one())) goto cleanup;
		if(!BN_gcd(r1, r0, n, ctx)) goto cleanup;
    	if(!BN_is_one(r1))
			continue;

    	/* Check to see if a+1 is relatively prime to N */
    	/* gcd(a+1, N) = 1 */
		if(!BN_add(r0, a, BN_value_one())) goto cleanup;
		if(!BN_gcd(r1, r0, n, ctx)) goto cleanup;
    	if(!BN_is_one(r1))
			continue;

    	found_g = 1;
	}

	/* Square a to get a generator of the quadratic residues */
 	if(!BN_sqr(g, a, ctx)){ found_g = 0; goto cleanup; }

cleanup:
	if(ctx)	BN_CTX_free(ctx);
	if(a) BN_clear_free(a);
	if(r0) BN_clear_free(r0);
	if(r1) BN_clear_free(r1);

	if(found_g)
		return g;
	else{
		if(g) BN_clear_free(g);
		return NULL;
	}	
}

void destroy_pdp_proof(PDP_proof *proof){

	if(!proof) return;
	if(proof->T) BN_clear_free(proof->T);
	if(proof->rho_temp) BN_clear_free(proof->rho_temp);
	if(proof->rho && (proof->rho_size > 0)) sfree(proof->rho, proof->rho_size);
	sfree(proof, sizeof(PDP_proof));
	proof = NULL;
}

PDP_proof *generate_pdp_proof(){

	PDP_proof *proof = NULL;
	
	if( ((proof = malloc(sizeof(PDP_proof))) == NULL)) return NULL;
	memset(proof, 0, sizeof(PDP_proof));
	if( ((proof->T = BN_new()) == NULL)) goto cleanup;	
	if( ((proof->rho_temp = BN_new()) == NULL)) goto cleanup;
	
	return proof;
	
cleanup:
	if(proof) destroy_pdp_proof(proof);
	return NULL;
}

void destroy_pdp_challenge(PDP_challenge *challenge){

	if(!challenge) return;
	if(challenge->g_s) BN_clear_free(challenge->g_s);
	if(challenge->s) BN_clear_free(challenge->s);
	if(challenge->k1) sfree(challenge->k1, PRP_KEY_SIZE);
	if(challenge->k2) sfree(challenge->k2, PRF_KEY_SIZE);
	sfree(challenge, sizeof(PDP_challenge));
}

PDP_challenge *generate_pdp_challenge(){

	PDP_challenge *challenge = NULL;


	if( ((challenge = malloc(sizeof(PDP_challenge))) == NULL)) return NULL;
	memset(challenge, 0, sizeof(PDP_challenge));
	if( ((challenge->g_s = BN_new()) == NULL)) goto cleanup;	
	if( ((challenge->s = BN_new()) == NULL)) goto cleanup;	
	if( ((challenge->k1 = malloc(PRP_KEY_SIZE)) == NULL)) goto cleanup;
	memset(challenge->k1, 0, PRP_KEY_SIZE);
	if( ((challenge->k2 = malloc(PRF_KEY_SIZE)) == NULL)) goto cleanup;
	memset(challenge->k2, 0, PRF_KEY_SIZE);
	challenge->c = 0;
	challenge->numfileblocks = 0;
	
	return challenge;
	
cleanup:
	if(challenge) destroy_pdp_challenge(challenge);
	return NULL;
}

void destroy_pdp_tag(PDP_tag *tag){

	if(!tag) return;
	if(tag->Tim) BN_clear_free(tag->Tim);
	if(tag->index_prf && (tag->index_prf_size > 0)) sfree(tag->index_prf, tag->index_prf_size);	
	sfree(tag, sizeof(PDP_tag));
}

PDP_tag *generate_pdp_tag(){
	
	PDP_tag *tag = NULL;
	
	if( ((tag = malloc(sizeof(PDP_tag))) == NULL)) return NULL;
	memset(tag, 0, sizeof(PDP_tag));
	if( ((tag->Tim = BN_new()) == NULL)) goto cleanup;

	return tag;
	
cleanup:
	if(tag) destroy_pdp_tag(tag);
	return NULL;
}

