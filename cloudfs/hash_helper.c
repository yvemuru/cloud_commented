
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

#include "uthash.h"
#include "cloud_helper.h"
#include "hash_helper.h"

extern struct hash_struct *users;
extern struct cache_struct *users_cache;

/*
 * @desc: The helper function to find the md5 hash struct if
 * it already exists.
 * @param: string to be checked in hash table
 * @return: struct if found else NULL
 */
struct hash_struct* find_user_string(char* str)
{
	if(LOG_1_DEBUG)log_msg("Coming to find user string \n");
	struct hash_struct* s;
	HASH_FIND_STR(users, str, s);
	return s;
}

/*
 * @desc: The helper function to add the new md5 to the table.
 * @param: string to be added in hash table
 * @return: void
 */
void add_user_string(char* str)
{
	if(LOG_1_DEBUG)log_msg("Coming to add user string \n");
	struct hash_struct* s;
	s = malloc(sizeof(struct hash_struct));
	strncpy(s->md5_key, str, sizeof(s->md5_key));
	s->ref_count = 1;
	HASH_ADD_STR(users, md5_key, s);
}

/*
 * @desc: The helper function to print the entire table.
 */
void print_hash_string()
{
	struct hash_struct* s;
	//int b;
	if(LOG_3_DEBUG)log_msg("********* PRINTING HASH TABLE **********\n");
	for(s = users; s != NULL; s = s->hh.next){
		if(LOG_3_DEBUG)log_msg("Key is %s\n", s->md5_key);
		if(LOG_3_DEBUG)log_msg("Ref is %d\n", s->ref_count);
	}
	if(LOG_DEBUG)log_msg("*****************************************\n");
}

/*
 * @desc: The helper function to delete a md5 structure from the table.
 * @param: struct to be deleted
 * @return: void
 */
void hash_del(struct hash_struct* s)
{
	HASH_DEL(users, s);
	free(s);
}

/*
 * @desc: The helper function to find the number of users from the hash.
 * @return: number of users in hash table
 */
int num_users_hash()
{
	if(LOG_DEBUG)log_msg("Coming to num users \n");
	int number_users;
	number_users = HASH_COUNT(users);
	return number_users;
}

/*
 * @desc: The helper function to add the table to ssd with path state_.ssd_path/.hash_table
 */
void add_hash_to_ssd()
{
	if(LOG_1_DEBUG)log_msg("Coming to add hash to ssd\n");
	char ssd_hash_path[MAX_PATH_LEN];
	struct hash_struct* s_test;

	sprintf( ssd_hash_path, "%s%s%s",state_.ssd_path, "." , "hash_table");
	if(LOG_1_DEBUG)log_msg("Creating the add hash to ssd path is %s\n",
			ssd_hash_path);
	FILE *hashfp = fopen(ssd_hash_path, "wb");

	for(s_test = users; s_test != NULL; s_test = s_test->hh.next){
		fprintf(hashfp, "%s %d\n", s_test->md5_key, s_test->ref_count);
	}   
	fclose(hashfp);    
}

/*
 * @desc: The helper function to check the existence of the table on ssd.
 * @return: 1 if found else 0
 */
int check_hash_on_ssd()
{
	char ssd_hash_path[MAX_PATH_LEN];
	char buf[((2 * MD5_DIGEST_LENGTH) + 5)];
	ssize_t readLen = 0;
	int retval;

	sprintf( ssd_hash_path, "%s%s%s",state_.ssd_path, "." , "hash_table");
	if(LOG_DEBUG)log_msg("hash ssd path in check hash on ssd %s\n",
			ssd_hash_path);
	FILE *hash_2_fp = fopen(ssd_hash_path, "rb");
	readLen = fread(buf, 1, sizeof(buf), hash_2_fp);
	if(readLen <= 0)
	{
		retval = 0;
	}
	else
	{
		retval = 1;
	}
	fclose(hash_2_fp);
	if(LOG_DEBUG)log_msg("Return value of hash checker is %d\n", retval);
	return retval;
}

/*
 * @desc: The helper function to reconstuct the table from the hash table path.
 */
void reconstruct_hash()
{
	if(LOG_DEBUG)log_msg("Coming to reconstruct hash \n");
	char ssd_hash_path[MAX_PATH_LEN];
	char md5_buf[(2*MD5_DIGEST_LENGTH) + 1];
	//char len_buf[sizeof(int)+1];
	struct hash_struct* s_recon;
	int lenbuf_int;

	sprintf( ssd_hash_path, "%s%s%s",state_.ssd_path, "." , "hash_table");
	if(LOG_1_DEBUG)log_msg("file path in reconstruct_hash %s\n",
			ssd_hash_path);
	FILE *hash_3_fp = fopen(ssd_hash_path, "rb");

	if(hash_3_fp==NULL)
	{
		return;
	}

	while(fscanf(hash_3_fp, "%s %d", md5_buf, &lenbuf_int) != EOF)
	{  
		s_recon = malloc(sizeof(struct hash_struct));
		strncpy(s_recon->md5_key, md5_buf, sizeof(s_recon->md5_key));
		s_recon->ref_count = lenbuf_int;
		HASH_ADD_STR(users, md5_key, s_recon);
	}
	fclose(hash_3_fp);
}

/*
 * @desc: The helper function to add the new md5 to the table.
 * @param: string to be added in hash table, length alos added
 * @return: void
 */
void cache_add_user(char *str, int lenbuf_int)
{
	struct cache_struct* s;
	s = malloc(sizeof(struct cache_struct));
	strncpy(s->md5_key_cache, str, sizeof(s->md5_key_cache));
	s->segment_length = lenbuf_int;
	s->ref_count = 1;
	HASH_ADD_STR(users_cache, md5_key_cache, s);	
}

/*
 * @desc: The helper function to delete a md5 structure from the table.
 * @param: struct to be deleted
 * @return: void
 */
void cache_hash_del(struct cache_struct* s)
{
	HASH_DEL(users_cache, s);
	free(s);
}

/*
 * @desc: The helper function to find the md5 hash struct if
 * it already exists.
 * @param: string to be checked in hash table
 * @return: struct if found else NULL
 */
struct cache_struct* cache_find_user_string(char* str)
{
	struct cache_struct* s;
	HASH_FIND_STR(users_cache, str, s);
	return s;
}

/*
 * @desc: The helper function to print the entire table.
 */
void print_cache_hash_table()
{
	struct cache_struct* s;
	log_msg("********* PRINTING HASH TABLE **********\n");
	for(s = users_cache; s != NULL; s = s->hh.next){
		log_msg("Key is %s\n", s->md5_key_cache);
		log_msg("Ref is %d\n", s->segment_length);
	}
	log_msg("*****************************************\n");
}

/*
 * @desc: The helper function to find the number of users from the hash.
 * @return: number of users in hash table
 */
int cache_num_users_hash()
{
	int number_users;
	number_users = HASH_COUNT(users_cache);
	return number_users;
}

/*
 * @desc: Sort the cache table by id in descending order
 * @param: struct of type cache
 * @return: int of operation performed
 */
int id_sort(struct cache_struct *a, struct cache_struct *b)
{
	//return(a->segment_length - b->segment_length);
	return(b->segment_length - a->segment_length);
}

/*
 * @desc: Sort the cache table by id
 */
void cache_sort_by_id()
{
	HASH_SORT(users_cache, id_sort);
}

/*
 * @desc: Sort the cache table by refcount in ascending order
 * @param: struct of type cache
 * @return: int of operation performed
 */
int ref_count_sort(struct cache_struct *a, struct cache_struct *b)
{
	//return(a->segment_length - b->segment_length);
	return(a->ref_count - b->ref_count);
}

/*
 * @desc: Sort the cache table by refcount
 */
void cache_sort_by_ref_count()
{
	HASH_SORT(users_cache, ref_count_sort);
}

/*
 * @desc: The helper function to add the table to ssd with path state_.ssd_path/.cache_table
 */
void add_cache_hash_to_ssd()
{
	char ssd_cache_hash_path[MAX_PATH_LEN];
	struct cache_struct* s_test;

	sprintf( ssd_cache_hash_path, "%s.%s", state_.ssd_path, "cache_hash");
	FILE *hashfp = fopen(ssd_cache_hash_path, "wb");

	for(s_test = users_cache; s_test != NULL; s_test = s_test->hh.next){
		fprintf(hashfp, "%s %d %d\n", s_test->md5_key_cache, s_test->segment_length, s_test->ref_count);
	}   
	fclose(hashfp);    
}

/*
 * @desc: The helper function to reconstuct the table from the hash table path.
 */
int reconstruct_cache_hash()
{
	char ssd_cache_hash_path[MAX_PATH_LEN];
	char md5_buf[(2*MD5_DIGEST_LENGTH) + 1];
	//char len_buf[sizeof(int)+1];
	struct cache_struct* s_recon;
	int lenbuf_int;
	int ref_count;
	int cache_hash_size = 0;
	if(LOG_6_DEBUG) log_msg("yash1\n");
	sprintf( ssd_cache_hash_path, "%s.%s", state_.ssd_path, "cache_hash");
	FILE *hash_3_fp = fopen(ssd_cache_hash_path, "rb");
	if(LOG_6_DEBUG) log_msg("yash2\n");
	if(hash_3_fp==NULL)
	{
		return 0;
	}
	if(LOG_6_DEBUG) log_msg("yash3\n");
	while(fscanf(hash_3_fp, "%s %d %d", md5_buf, &lenbuf_int, &ref_count) != EOF)
	{  
		if(LOG_6_DEBUG) log_msg("yash4\n");		
		s_recon = malloc(sizeof(struct cache_struct));
		strncpy(s_recon->md5_key_cache, md5_buf, sizeof(s_recon->md5_key_cache));
		s_recon->segment_length = lenbuf_int;
		s_recon->ref_count = ref_count;
		HASH_ADD_STR(users_cache, md5_key_cache, s_recon);
		cache_hash_size += s_recon->segment_length;
	}
	fclose(hash_3_fp);
	if(LOG_6_DEBUG)log_msg("reconstructed total size is %d\n", cache_hash_size);
	return cache_hash_size;
}
