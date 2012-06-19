/* 
* pdp-s3.c
*
* Copyright (c) 2010, Zachary N J Peterson <zachary@jhu.edu>
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

#ifdef USE_S3

#include "pdp.h"
#include <libs3.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>


#define S3_BUCKET_NAME "znjp"
#define S3_ACCESS_KEY "AKIAJVTSBM6DGDFVV7EQ"
#define S3_SECRET_ACCESS_KEY "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" 

/*
#define S3_BUCKET_NAME ""
#define S3_ACCESS_KEY ""
#define S3_SECRET_ACCESS_KEY "" 
*/


struct buffer_pointer{

	unsigned char *buf;
	int offset;
};

static int putObjectDataCallback(int bufferSize, char *buffer, void *callbackData)
{
	int ret = 0;

	ret = fread(buffer, 1, PDP_BLOCKSIZE, callbackData);

	return ret;
	
}

static S3Status getObjectDataCallbackFile(int bufferSize, const char *buffer, void *callbackData)
{

    FILE *outfile = (FILE *) callbackData;

    size_t wrote = fwrite(buffer, 1, bufferSize, outfile);
    
    return ((wrote < (size_t) bufferSize) ? 
            S3StatusAbortedByCallback : S3StatusOK);

}

static S3Status getObjectDataCallback(int bufferSize, const char *buffer, void *callbackData)
{

	struct buffer_pointer *bp = callbackData;

	memcpy((char *)bp->buf + bp->offset, (char *)buffer, bufferSize);
	bp->offset += bufferSize;
	
	return S3StatusOK;
}

static S3Status responsePropertiesCallback(const S3ResponseProperties *properties, void *callbackData){         

	return S3StatusOK; 
}


static void responseCompleteCallback(S3Status status, const S3ErrorDetails *error, void *callbackData){ }


int pdp_s3_get_block(char *filepath, size_t filepath_len, unsigned char *block, size_t block_len, unsigned int index){

	if(!filepath || !filepath_len || !block || !block_len) return 0;
	
	S3Status status;
    if ((status = S3_initialize("s3", S3_INIT_ALL))
        != S3StatusOK) {
        fprintf(stderr, "Failed to initialize libs3: %s\n", 
                S3_get_status_name(status));
        exit(-1);
    }

	S3BucketContext bucketContext =
    {
        S3_BUCKET_NAME, //bucket name
        S3ProtocolHTTPS,
        S3UriStylePath,
        S3_ACCESS_KEY, //access key
        S3_SECRET_ACCESS_KEY //secret access key
    };

    S3GetConditions getConditions =
    {
        -1, //ifModifiedSince,
        -1, // ifNotModifiedSince,
        0, //ifMatch,
        0 //ifNotMatch
    };

    S3GetObjectHandler getObjectHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &getObjectDataCallback
    };

	struct buffer_pointer bp;
	bp.buf = block;
	bp.offset = 0;

	S3_get_object(&bucketContext, filepath, &getConditions, (index * PDP_BLOCKSIZE), PDP_BLOCKSIZE, 0, &getObjectHandler, &bp);

	S3_deinitialize();

	return 1;
	
	
}

int pdp_s3_put_file(char *filepath, size_t filepath_len){
	
	FILE *file = NULL;
	unsigned char buffer[PDP_BLOCKSIZE];
	struct stat statbuf;
	
	if(!filepath || !filepath_len) return 0;
	
	memset(buffer, 0, PDP_BLOCKSIZE);
	
	file = fopen(filepath, "r");
	if(file == NULL){
		printf("Couldn't open file %s\n", filepath);
		return -1;
	}
	
	/* Initialize the S3 library */
	S3Status status;
    if ((status = S3_initialize("s3", S3_INIT_ALL)) != S3StatusOK) {
        fprintf(stderr, "Failed to initialize libs3: %s\n", S3_get_status_name(status));
		goto cleanup;
    }
	
	/* Set the S3 context */
	S3BucketContext bucketContext =
    {
        S3_BUCKET_NAME,
        S3ProtocolHTTPS,
        S3UriStylePath,
        S3_ACCESS_KEY,
        S3_SECRET_ACCESS_KEY
    };

	/* Set the object properties */
    S3PutProperties putProperties =
    {
        0, //content-type defaults to "binary/octet-stream"
        0, //md5 sum, not required
        0, //cacheControl, not required
        0, //contentDispositionFilename, This is only relevent for objects which are intended to be shared to users via web browsers and which is additionally intended to be downloaded rather than viewed.
        0, //contentEncoding, This is only applicable to encoded (usually, compressed) content, and only relevent if the object is intended to be downloaded via a browser.
        (int64_t)-1,  //expires, This information is typically only delivered to users who download the content via a web browser.
        S3CannedAclPrivate,
        0, //metaPropertiesCount, This is the number of values in the metaData field.
        0 //metaProperties
    };

	/* Set the callbacks */
    S3PutObjectHandler putObjectHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &putObjectDataCallback
    };

	/* Get the file size */
	if (stat(filepath, &statbuf) == -1) {
		fprintf(stderr, "\nERROR: Failed to stat file %s: ", filepath);
		goto cleanup;
	}

	S3_put_object(&bucketContext, filepath, statbuf.st_size, &putProperties, 0, &putObjectHandler, file);

	S3_deinitialize();
	if(file) fclose(file);
	
	return 1;

cleanup:
	if(file) fclose(file);
	S3_deinitialize();
	
	return 0;
}

int pdp_s3_get_file(char *filepath, size_t filepath_len){

	FILE *file = NULL;

	if(!filepath || !filepath_len) return 0;
	
	file = fopen(filepath, "w");
	if(!file){
		fprintf(stderr, "ERROR: Was not able to create %s.\n", filepath);
		goto cleanup;
	}
	
	S3Status status;
    if ((status = S3_initialize("s3", S3_INIT_ALL))
        != S3StatusOK) {
        fprintf(stderr, "Failed to initialize libs3: %s\n", 
                S3_get_status_name(status));
        exit(-1);
    }

	S3BucketContext bucketContext =
    {
        S3_BUCKET_NAME,
        S3ProtocolHTTPS,
        S3UriStylePath,
        S3_ACCESS_KEY,
        S3_SECRET_ACCESS_KEY
    };

    S3GetConditions getConditions =
    {
        -1, //ifModifiedSince,
        -1, // ifNotModifiedSince,
        0, //ifMatch,
        0 //ifNotMatch
    };

    S3GetObjectHandler getObjectHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &getObjectDataCallbackFile
    };

	S3_get_object(&bucketContext, filepath, &getConditions, 0, 0, 0, &getObjectHandler, file);

	S3_deinitialize();
	if(file) fclose(file);

	return 1;

cleanup:	
	if(file) fclose(file);
	return 0;
}


/* pdp_prove_file: Computes the server-side proof.
 * Takes in the file to be proven, its corresponding tag file, and a "sanitized" challenge and key structure.
 * Returns an allocated proof structure or NULL on error.
*/
PDP_proof *pdp_s3_prove_file(char *filepath, size_t filepath_len, char *tagfilepath, size_t tagfilepath_len, PDP_challenge *challenge, PDP_key *key){

	PDP_proof *proof = NULL;
	PDP_tag *tag = NULL;
	unsigned int *indices = NULL;
	FILE *tagfile = NULL;
	char realtagfilepath[MAXPATHLEN];
	unsigned char buf[PDP_BLOCKSIZE];
	int j = 0;

	memset(realtagfilepath, 0, MAXPATHLEN);
	
	if(!filepath || !challenge || !key) return NULL;
	if(filepath_len >= MAXPATHLEN) return NULL;
	if(tagfilepath_len >= MAXPATHLEN) return NULL;
	
	/* If no tag file path is specified, add a .tag extension to the filepath */
	if(!tagfilepath && (filepath_len < MAXPATHLEN - 5)){
		if( snprintf(realtagfilepath, MAXPATHLEN, "%s.tag", filepath) >= MAXPATHLEN) goto cleanup;
		tagfilepath_len = filepath_len + 4;
	}else{
		memcpy(realtagfilepath, tagfilepath, tagfilepath_len);
	}

	/* Get the tag file from S3 */
	//if(!pdp_s3_get_file(realtagfilepath, tagfilepath_len)) goto cleanup;

	/* Open the tag file for reading */
	tagfile = fopen(realtagfilepath, "r");
	if(!tagfile){
		fprintf(stderr, "ERROR: Was not able to create %s.\n", realtagfilepath);
		goto cleanup;
	}

	/* Compute the indices i_j = pi_k1(j); the block indices to sample */
	indices = generate_prp_pi(challenge);
	if(!indices) goto cleanup;
	
	for(j = 0; j < challenge->c; j++){
		memset(buf, 0, PDP_BLOCKSIZE);
		
		/* Get block at indices[j] from S3 */
		if(!pdp_s3_get_block(filepath, filepath_len, buf, PDP_BLOCKSIZE, indices[j])){ fprintf(stderr, "Error reading block %d from S3.\n", indices[j]); goto cleanup; }
		
		/* Read tag for data block at indices[j] */
		tag = read_pdp_tag(tagfile, indices[j]);
		if(!tag){ fprintf(stderr, "Error reading tag.\n"); goto cleanup; }
		
		proof = pdp_generate_proof_update(key, challenge, tag, proof, buf, PDP_BLOCKSIZE, j);
		if(!proof){ fprintf(stderr, "Error generating proof.\n"); goto cleanup; }

		destroy_pdp_tag(tag);
		tag = NULL;
	}

	proof = pdp_generate_proof_final(key, challenge, proof);
	if(!proof){ fprintf(stderr, "Error finalizing proof.\n"); goto cleanup; }
	
	if(indices) sfree(indices, (challenge->c * sizeof(unsigned int)));
	/* Destroy the tag file */
	if(tagfile){ 
		//ftruncate(fileno(tagfile), 0);
		//unlink(realtagfilepath);
		fclose(tagfile);
	}
	return proof;

cleanup:
	if(indices) sfree(indices, (challenge->c * sizeof(unsigned int)));
	if(proof) destroy_pdp_proof(proof);
	if(tag) destroy_pdp_tag(tag);
	if(tagfile){ 
		ftruncate(fileno(tagfile), 0);
		//unlink(realtagfilepath);
		//fclose(tagfile);
	}
	
	return NULL;
}

#endif