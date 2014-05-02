#define _XOPEN_SOURCE 500
#define _ATFILE_SOURCE

#include <stdarg.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include "cloudapi.h"
#include "cloudfs.h"
#include <fcntl.h>
#include <openssl/md5.h>
#include "dedup.h"
#include <errno.h>

#include "uthash.h"
#include "cloud_helper.h"
#include "hash_helper.h"
#include "zlib.h"
#include "compressapi.h"

#define MAX_SEG_SIZE 16384
#define MIN_SEG_SIZE 2048


struct hash_struct *users = NULL;
struct cache_struct *users_cache = NULL;

extern int total_cache_size;

/*
 * @desc: buffer used for files for cloud operations
 * @param: char* - buffer, int - buffer length
 * @return: number of bytes read
 */
int put_buffer(char *buffer, int bufferLength) {
	fprintf(stdout, "put_buffer %d \n", bufferLength);
	return fread(buffer, 1, bufferLength, infile);
}

/*
 * @desc: buffer used for files for cloud operations
 * @param: char* - buffer, int - buffer length
 * @return: number of bytes read
 */
int put_buffer_new(char *buffer, int bufferLength) {
	fprintf(stdout, "put_buffer_new %d \n", bufferLength);
	return fread(buffer, 1, bufferLength, new_infile);
}

/*
 * @desc: Convert the file path to the path of the proxy file file that we will use to 
 * store the md5 values associated with the path.
 * An MD5 hash of the path is being computed and used for the same.
 * @param: string - full path to be converted, string - new path to be populated
 * @return: void
 */
void convert_proxy_path(char* fpath, char* new_path)
{
	char *dummy_path = fpath;
	int b;
	unsigned char md5[MD5_DIGEST_LENGTH];
	char tmp[(2*MD5_DIGEST_LENGTH) + 1];

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, dummy_path, strlen(fpath));
	MD5_Final(md5, &ctx);

	memset(new_path, 0, MAX_PATH_LEN);

	for(b = 0; b < MD5_DIGEST_LENGTH; b++) {
		sprintf(&tmp[b*2], "%02x", md5[b]);
	}

	sprintf(new_path, "%s%s%s",state_.ssd_path,".",tmp);      
}


/*
 * @desc: The function computes the rabin segments for the file path if
 * deduplication is enabled and 
 * correspondingly adds the MD5 of the computed segments to the 
 * proxy file and sends to cloud 
 * only if they are unique.
 * The Hash table is being updated and made to be consistent in
 * this case.
 * @param: string - full path of file to be rabinized
 * @return: void
 */
void cloudfs_compute_rabin(char *fpath){

	if(LOG_DEBUG)log_msg("coming to compute rabin\n");
	MD5_CTX ctx;
	unsigned char md5[MD5_DIGEST_LENGTH];   
	int new_segment = 0;
	int len = 0, segment_len = 0, b;
	struct stat stat_buf;
	lstat(fpath, &stat_buf);
	char buf[MAX_SEG_SIZE];
	int bytes;
	int fd;
	struct hash_struct* s = NULL;
	char md5_string[(2*MD5_DIGEST_LENGTH) + 1];
	char md5_path_ssd[MAX_PATH_LEN];
	char tmp_buffer_for_cache[MAX_SEG_SIZE];
	char ssd_cache_md5_path[MAX_PATH_LEN];
	fpos_t old_pos;


	convert_proxy_path(fpath, md5_path_ssd);

	FILE *hiddenfp = fopen(md5_path_ssd, "a");

	fd = open(fpath, O_RDONLY);
	if(fd < 0)
	{
		if(LOG_DEBUG)log_msg("Reading file failed\n");
		return;
	}

	rabinpoly_t *rp = rabin_init( state_.rabin_window_size,
			state_.avg_seg_size, 
			MIN_SEG_SIZE, MAX_SEG_SIZE);

	if (!rp) {
		if(LOG_DEBUG)log_msg("Rabin init failed\n");
		exit(1);
	}


	infile = fopen(fpath, "rb");
	MD5_Init(&ctx);

	while((bytes = read(fd, buf, sizeof buf)) > 0)
	{
		char *buftoread = (char *)&buf[0];
		while((len = rabin_segment_next(rp, buftoread, bytes, 
						&new_segment)) > 0)
		{

			MD5_Update(&ctx, buftoread, len);
			segment_len += len;

			if (new_segment) {

				MD5_Final(md5, &ctx);

				// Add to Hash Table
				for(b = 0; b < MD5_DIGEST_LENGTH; b++) {
					sprintf(&md5_string[b*2], "%02x", md5[b]);
				}

				s = find_user_string(md5_string);

				if(s != NULL){

					(s->ref_count)++;
					fseek(infile, segment_len, SEEK_CUR);
					fprintf(hiddenfp, "%s %d\n", md5_string,segment_len);  

				} 
				else if(s == NULL)
				{

					// add_user_string(md5_string);
					// cloud_put_object("test", md5_string, segment_len,
					// 		put_buffer);
					// fprintf(hiddenfp, "%s %d\n", md5_string,segment_len);

					if(!state_.no_cache)
					{
						if(segment_len + total_cache_size < state_.cache_size)
						{
							sprintf(ssd_cache_md5_path, "%s/.%s", ssd_cache_path, md5_string);
							if(LOG_6_DEBUG) log_msg("The path in adding cache crap is %s\n", ssd_cache_md5_path);
							FILE* cache_md5 = fopen(ssd_cache_md5_path, "w");
							fgetpos(infile, &old_pos);
							int return_fr = fread(tmp_buffer_for_cache, sizeof(char), segment_len, infile);
							if(return_fr < 0)
							{
								if(LOG_6_DEBUG)log_msg("Error in reading infile for cache population\n");
							}			 
							fwrite(tmp_buffer_for_cache, sizeof(char), sizeof(tmp_buffer_for_cache), cache_md5);
							fsetpos(infile, &old_pos);
							fclose(cache_md5);
							total_cache_size += segment_len;
							cache_add_user(md5_string, segment_len);
							if(LOG_6_DEBUG)log_msg("Adding the write back caching with segment %s and length %d\n", md5_string, segment_len);
							add_cache_hash_to_ssd();
						}
						else
						{
							// This is when the cache is full and all subsequent segments need to be pushed to cloud
							add_user_string(md5_string);
							cloud_put_object("test", md5_string, segment_len,
							put_buffer);
							fprintf(hiddenfp, "%s %d\n", md5_string,segment_len);

						}
					}

				}

				add_hash_to_ssd();

				MD5_Init(&ctx);
				segment_len = 0;
			}

			buftoread += len;
			bytes -= len;

			if(!bytes)
			{
				break;
			}
		}
		if(len == -1)
		{
			if(LOG_DEBUG)log_msg("Failed to process segment\n");
			exit(1);
		}

	}
	MD5_Final(md5, &ctx);

	for(b = 0; b < MD5_DIGEST_LENGTH; b++) {
		sprintf(&md5_string[b*2], "%02x", md5[b]);
	}
	s = find_user_string(md5_string);

	if(s != NULL){
		(s->ref_count)++;
		fprintf(hiddenfp, "%s %d\n", md5_string,segment_len);
		fseek(infile, segment_len, SEEK_CUR);          
	} 
	else if(s == NULL)
	{
		add_user_string(md5_string);
		cloud_put_object("test", md5_string, segment_len, put_buffer);
		fprintf(hiddenfp, "%s %d\n", md5_string,segment_len);

		if(!state_.no_cache)
		{
			if(segment_len + total_cache_size < state_.cache_size)
			{
				sprintf(ssd_cache_md5_path, "%s/.%s", ssd_cache_path, md5_string);
				if(LOG_6_DEBUG) log_msg("The path in adding cache crap is %s\n", ssd_cache_md5_path);
				FILE* cache_md5 = fopen(ssd_cache_md5_path, "w");
				fgetpos(infile, &old_pos);
				int return_fr = fread(tmp_buffer_for_cache, sizeof(char), segment_len, infile);
				if(return_fr < 0)
				{
					if(LOG_6_DEBUG)log_msg("Error in reading infile for cache population\n");
				}
				fwrite(tmp_buffer_for_cache, sizeof(char), sizeof(tmp_buffer_for_cache), cache_md5);
				fsetpos(infile, &old_pos);
				fclose(cache_md5);
				total_cache_size += segment_len;
				cache_add_user(md5_string, segment_len);
				if(LOG_6_DEBUG)log_msg("Adding the write back caching with segment %s and length %d\n", md5_string, segment_len);
				add_cache_hash_to_ssd();	
			}
		}

	}

	add_hash_to_ssd();
	fclose(infile);
	fclose(hiddenfp);
	close(fd);
	rabin_free(&rp);
}


/*
 * @desc: The function computes the rabin segments for the file path if 
 * deduplication is enabled and 
 * correspondingly adds the MD5 of the computed segments to the proxy 
 * file and sends to cloud 
 * only if they are unique.
 * The Hash table is being updated and made to be consistent in this case.
 * This handles the compression of the segments before pushing them to cloud.
 * @param: string - full path of file to be rabinized
 * @return: void 
 */
void cloudfs_compute_rabin_compress(char *fpath){

	if(LOG_DEBUG)log_msg("coming to compute rabin\n");
	MD5_CTX ctx;
	unsigned char md5[MD5_DIGEST_LENGTH];   
	int new_segment = 0;
	int len = 0, segment_len = 0, b;
	struct stat stat_buf;
	struct stat stat_compress;
	lstat(fpath, &stat_buf);
	char buf[MAX_SEG_SIZE];
	int bytes;
	int fd;
	struct hash_struct* s = NULL;
	char md5_string[(2*MD5_DIGEST_LENGTH) + 1];
	char md5_path_ssd[MAX_PATH_LEN];
	char tmp_compressed_path[MAX_PATH_LEN];
	int compress_return = 0;
	char tmp_buffer_for_cache[MAX_SEG_SIZE];
	char ssd_cache_md5_path[MAX_PATH_LEN];	
	fpos_t old_pos;	

	sprintf(tmp_compressed_path, "%s.%s", state_.ssd_path,
			"compress_storage");

	convert_proxy_path(fpath, md5_path_ssd);

	FILE *hiddenfp = fopen(md5_path_ssd, "a");

	fd = open(fpath, O_RDONLY);
	if(fd < 0)
	{
		if(LOG_DEBUG)log_msg("Reading file failed\n");
		return;
	}

	rabinpoly_t *rp = rabin_init( state_.rabin_window_size, 
			state_.avg_seg_size, 
			MIN_SEG_SIZE, MAX_SEG_SIZE);

	if (!rp) {
		if(LOG_DEBUG)log_msg("Rabin init failed\n");
		exit(1);
	}


	infile = fopen(fpath, "rb");

	MD5_Init(&ctx);

	while((bytes = read(fd, buf, sizeof buf)) > 0)
	{
		char *buftoread = (char *)&buf[0];
		while((len = rabin_segment_next(rp, buftoread, bytes, 
						&new_segment)) > 0)
		{

			MD5_Update(&ctx, buftoread, len);
			segment_len += len;

			if (new_segment) {

				MD5_Final(md5, &ctx);

				// Add to Hash Table
				for(b = 0; b < MD5_DIGEST_LENGTH; b++) {
					sprintf(&md5_string[b*2], "%02x", md5[b]);
				}

				s = find_user_string(md5_string);

				if(s != NULL){

					(s->ref_count)++;
					fseek(infile, segment_len, SEEK_CUR);
					fprintf(hiddenfp, "%s %d\n", md5_string,segment_len);  

				} 
				else if(s == NULL)
				{
					new_infile = fopen(tmp_compressed_path, "wb");

					add_user_string(md5_string);

					if(!state_.no_cache)
					{
						if((segment_len + total_cache_size) < state_.cache_size)
						{
							sprintf(ssd_cache_md5_path, "%s/.%s", ssd_cache_path, md5_string);
							if(LOG_6_DEBUG) log_msg("The path in adding cache crap is %s\n", ssd_cache_md5_path);
							if(LOG_6_DEBUG)log_msg("The total cache size is %d and threshold is %d\n", total_cache_size, state_.cache_size);
							if(LOG_6_DEBUG)log_msg("The new file segment size is %d\n", segment_len);					 
							FILE* cache_md5 = fopen(ssd_cache_md5_path, "w");
							fgetpos(infile, &old_pos);
							int return_fr = fread(tmp_buffer_for_cache, sizeof(char), segment_len, infile);
							if(return_fr < 0)
							{
								if(LOG_6_DEBUG)log_msg("Error in reading infile for cache population\n");
							}					 
							fwrite(tmp_buffer_for_cache, sizeof(char), segment_len, cache_md5);
							fsetpos(infile, &old_pos);
							fclose(cache_md5);
							total_cache_size += segment_len;
							cache_add_user(md5_string, segment_len);
							if(LOG_6_DEBUG)log_msg("Adding the write back caching with segment %s and length %d\n", md5_string, segment_len);
							add_cache_hash_to_ssd();
						}
					}


					compress_return = def(infile, new_infile, segment_len,
							Z_DEFAULT_COMPRESSION);

					if(compress_return < 0)
					{
						if(LOG_DEBUG) log_msg("Compress def returns <0\n");
					}
					fclose(new_infile);
					lstat(tmp_compressed_path, &stat_compress);
					new_infile = fopen(tmp_compressed_path, "r");
					cloud_put_object("test", md5_string, stat_compress.st_size,
							put_buffer_new);
					fprintf(hiddenfp, "%s %d\n", md5_string,segment_len);
					fclose(new_infile);
					unlink(tmp_compressed_path);

				}

				add_hash_to_ssd();

				MD5_Init(&ctx);
				segment_len = 0;
			}

			buftoread += len;
			bytes -= len;

			if(!bytes)
			{
				break;
			}
		}
		if(len == -1)
		{
			if(LOG_DEBUG)log_msg("Failed to process segment\n");
			exit(1);
		}

	}
	MD5_Final(md5, &ctx);

	for(b = 0; b < MD5_DIGEST_LENGTH; b++) {
		sprintf(&md5_string[b*2], "%02x", md5[b]);
	}
	s = find_user_string(md5_string);

	if(s != NULL){
		(s->ref_count)++;
		fprintf(hiddenfp, "%s %d\n", md5_string,segment_len);
		fseek(infile, segment_len, SEEK_CUR);          
	} 
	else if(s == NULL)
	{
		add_user_string(md5_string);
		new_infile = fopen(tmp_compressed_path, "wb");


		if(!state_.no_cache)
		{
			if((segment_len + total_cache_size) < state_.cache_size)
			{
				sprintf(ssd_cache_md5_path, "%s/.%s", ssd_cache_path, md5_string);
				if(LOG_6_DEBUG) log_msg("The path in adding cache crap is %s\n", ssd_cache_md5_path);
				if(LOG_6_DEBUG)log_msg("The total cache size is %d and threshold is %d\n", total_cache_size, state_.cache_size);
				if(LOG_6_DEBUG)log_msg("The new file segment size is %d\n", segment_len);
				FILE* cache_md5 = fopen(ssd_cache_md5_path, "w");
				fgetpos(infile, &old_pos);
				int return_fr = fread(tmp_buffer_for_cache, sizeof(char), segment_len, infile);
				if(return_fr < 0)
				{
					if(LOG_6_DEBUG)log_msg("Error in reading infile for cache population\n");
				}
				fwrite(tmp_buffer_for_cache, sizeof(char), segment_len, cache_md5);
				fsetpos(infile, &old_pos);
				fclose(cache_md5);
				total_cache_size += segment_len;
				cache_add_user(md5_string, segment_len);
				if(LOG_6_DEBUG)log_msg("Adding the write back caching with segment %s and length %d\n", md5_string, segment_len);
				add_cache_hash_to_ssd();
			}
		}		

		compress_return = def(infile, new_infile, segment_len,
				Z_DEFAULT_COMPRESSION);
		if(compress_return < 0)
		{
			if(LOG_DEBUG) log_msg("Compress def returns <0\n");
		}
		fclose(new_infile);
		lstat(tmp_compressed_path, &stat_compress);	
		new_infile = fopen(tmp_compressed_path, "r");	
		cloud_put_object("test", md5_string, stat_compress.st_size,
				put_buffer_new);
		fprintf(hiddenfp, "%s %d\n", md5_string,segment_len);
		fclose(new_infile);
		unlink(tmp_compressed_path);


	}

	add_hash_to_ssd();
	fclose(infile);
	fclose(hiddenfp);
	close(fd);
	rabin_free(&rp);
}
