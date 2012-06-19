/* 
* pdp-measurements.c
*
* Copyright (c) 2011, Zachary N J Peterson <zachary@jhu.edu>
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

/* pdp-app is a simple user interface providing the fundemental PDP file operations and
*  basic key management.  The application allows you to generate a PDP key pair, tag
*  files and challenge and verify files that have been tagged.
*/

#include "pdp.h"
#include <stdio.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/stat.h>

static struct option longopts[] = {
	{"gen-key", no_argument, NULL, 'g'}, //TODO optional argument for key location
	{"tag", no_argument, NULL, 't'},
	{"verify", no_argument, NULL, 'v'},
	{"blocksize", no_argument, NULL 'b'},
	{NULL, 0, NULL, 0}
};

void usage(){

	fprintf(stdout, "pdp (provable data possesion) 1.0\n");
	fprintf(stdout, "Copyright (c) 2008 Zachary N J Peterson <znpeters@nps.edu>\n");
	fprintf(stdout, "This program comes with ABSOLUTELY NO WARRANTY.\n");
	fprintf(stdout, "This is free software, and you are welcome to redistribute it\n");
	fprintf(stdout, "under certain conditions.\n\n");
	fprintf(stdout, "usage: pdp [options] [file]\n\n");
	fprintf(stdout, "Commands:\n\n");
	fprintf(stdout, "-t, --tag [file]\t\t tag a file\n");
	fprintf(stdout, "-v, --verify [file]\t\t verify data possession\n\n");
	fprintf(stdout, "-k, --gen-key\t\t\t generate a new PDP key pair\n\n");
	
}

int main(int argc, char **argv){

	PDP_key *key = NULL;
	PDP_challenge *challenge = NULL, *server_challenge = NULL;
	PDP_proof *proof = NULL;
	int opt = -1;
	unsigned int numfileblocks = 0;
	struct stat st;
	size_t pdp_blocksize = 0;
	PDP_tag *tag = NULL;
#ifdef USE_S3
	char tagfilepath[MAXPATHLEN];
#endif
#ifdef DEBUG_MODE
	struct timeval tv1, tv2;
#endif
	
	if(argc < 2) usage();

	OpenSSL_add_all_algorithms();

	while((opt = getopt_long(argc, argv, "b:kt:v:s:z:", longopts, NULL)) != -1){
		switch(opt){
			case 'b':
				pdp_blocksize = atoi(optarg);
				break;
			case 'k':
				key = pdp_create_new_keypair();
				if(key) destroy_pdp_key(key);
				break;
			case 't':
				if(strlen(optarg) >= MAXPATHLEN){
					fprintf(stderr, "ERROR: File name is too long.\n");
					break;
				}
				fprintf(stdout, "Tagging %s...\n", optarg);
#ifdef DEBUG_MODE
				gettimeofday(&tv1, NULL);
				
#endif
				if(pdp_blocksize == 0)



				tag = pdp_tag_block(PDP_key *key, unsigned char *block, pdp_blocksize, unsigned int index);
					

				if(pdp_tag_file(optarg, strlen(optarg), NULL, 0))
					fprintf(stdout, "Done!\n");
#ifdef DEBUG_MODE
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );

#endif
				break;
			case 'v':
				if(strlen(optarg) >= MAXPATHLEN){
					fprintf(stderr, "ERROR: File name is too long.\n");
					break;
				}
				fprintf(stdout, "Verifying %s...\n", optarg);

				/* Calculate the number pdp blocks in the file */
				stat(optarg, &st);
				numfileblocks = (st.st_size/PDP_BLOCKSIZE);
				if(st.st_size%PDP_BLOCKSIZE)
					numfileblocks++;
				
				challenge = pdp_challenge_file(numfileblocks);
				if(!challenge) fprintf(stderr, "No challenge\n");
				key = pdp_get_pubkey();
				server_challenge = sanitize_pdp_challenge(challenge);
				proof = pdp_prove_file(optarg, strlen(optarg), NULL, 0, server_challenge, key);
				if(!proof) fprintf(stderr, "No proof\n");
				if(pdp_verify_file(challenge, proof))
					fprintf(stdout, "Verified!\n");
				else
					fprintf(stdout, "Cheating!\n");
				
				destroy_pdp_challenge(challenge);
				destroy_pdp_challenge(server_challenge);
				destroy_pdp_proof(proof);
				break;

			case 's':
#ifdef USE_S3
				memset(tagfilepath, 0, MAXPATHLEN);
				
				snprintf(tagfilepath, MAXPATHLEN, "%s.tag", optarg);
				
				if(strlen(optarg) >= MAXPATHLEN){
					fprintf(stderr, "ERROR: File name is too long.\n");
					break;
				}

				gettimeofday(&tv1, NULL);
				fprintf(stdout, "Tagging %s...", optarg);
				fflush(stdout);
				if(pdp_tag_file(optarg, strlen(optarg), NULL, 0)) printf("Done.\n");
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );

				gettimeofday(&tv1, NULL);				
				fprintf(stdout, "\tWriting file %s to S3...", optarg);
				fflush(stdout);
				if(!pdp_s3_put_file(optarg, strlen(optarg))) printf("Couldn't write %s to S3.\n", optarg);
				else printf("Done.\n");
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );

				gettimeofday(&tv1, NULL);				
				fprintf(stdout, "\tWriting tag %s to S3...", optarg);
				if(!pdp_s3_put_file(tagfilepath, strlen(tagfilepath))) printf("Couldn't write %s to S3.\n", optarg);
				else printf("Done.\n");				
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );

				
				gettimeofday(&tv1, NULL);
				fprintf(stdout, "Challenging file %s...\n", optarg);
				fflush(stdout);				
				fprintf(stdout, "\tCreating challenge %s...", optarg);fflush(stdout);
				/* Calculate the number pdp blocks in the file */
				stat(optarg, &st);
				numfileblocks = (st.st_size/PDP_BLOCKSIZE);
				if(st.st_size%PDP_BLOCKSIZE)
					numfileblocks++;
				
				challenge = pdp_challenge_file(numfileblocks);
				if(!challenge) fprintf(stderr, "No challenge\n");
				key = pdp_get_pubkey();
				server_challenge = sanitize_pdp_challenge(challenge);
				printf("Done.\n");
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );

				gettimeofday(&tv1, NULL);
				printf("\tGetting tag file...");fflush(stdout);
				fflush(stdout);
				if(!pdp_s3_get_file(tagfilepath, strlen(tagfilepath))) printf("Cloudn't get tag file.\n");
				else printf("Done.\n");
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );

				gettimeofday(&tv1, NULL);				
				printf("\tComputing proof...");fflush(stdout);
				proof = pdp_s3_prove_file(optarg, strlen(optarg), tagfilepath, strlen(tagfilepath), server_challenge, key);
				if(!proof) fprintf(stderr, "No proof\n");
				else printf("Done\n");
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );

				gettimeofday(&tv1, NULL);
				printf("\tVerifying proof...");fflush(stdout);				
				if(pdp_verify_file(challenge, proof))
					fprintf(stdout, "Verified!\n");
				else
					fprintf(stdout, "Cheating!\n");
			
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );
				
				destroy_pdp_challenge(challenge);
				destroy_pdp_challenge(server_challenge);
				destroy_pdp_proof(proof);
#endif				
				break;

/*				
#ifdef DEBUG_MODE
				gettimeofday(&tv1, NULL);

				if(pdp_challenge_and_verify_file(optarg, strlen(optarg), NULL, 0))
					fprintf(stdout, "Verified!\n");
				else
					fprintf(stdout, "Cheating!\n");

				gettimeofday(&tv2, NULL);
#endif
*/
			default:
				printf("usage!\n");
				usage();
				break;
		}
	}

#ifdef DEBUG_MODE
//	printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );
#endif

	return 0;
}

