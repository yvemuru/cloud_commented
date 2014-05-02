
/* 
 * References
 * 1) UTHASH.H 
 * 2) http://www.cs.nmsu.edu/pfeiffer/fuse-tutorial/
 * 3) http://fuse.sourceforge.net/doxygen/
 */ 

// For posix read and write
#define _XOPEN_SOURCE 700
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
#include "zlib.h"
#include "compressapi.h"

#define UNUSED __attribute__((unused))
#define NO_CACHE 0


void log_msg(const char *format, ...);
FILE *log_open(void);
extern struct hash_struct *users;
extern struct cache_struct *users_cache;


FILE *logfile;


/*
 * Very own log writer for debugging.
 */

FILE *log_open()
{  

	logfile = fopen("./cloudfs.log", "w");
	if (logfile == NULL) {
		perror("logfile");
		exit(EXIT_FAILURE);
	}

	setvbuf(logfile, NULL, _IOLBF, 0);
	return logfile;
}

void log_msg(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vfprintf(logfile, format, ap);
}

static int cloudfs_error(char *error_str)
{
	int retval = -errno;
	fprintf(stderr, "CloudFS Error: %s\n", error_str);
	return retval;
}

/*
 * @desc: Translation of full path/absolute path.
 * @param: string - fpath that needs to be populated, 
 * string - original path sent
 * @return: void
 */
void cloudfs_fullpath(char fpath[MAX_PATH_LEN], const char* path){

	strcpy(fpath, state_.ssd_path);
	strcat(fpath, path);
}


/*
 * @desc: Conversion of / to + for keying in S3.
 * @param: string - full path of file
 * string - resultant path populated with +
 * @return: void
 */
void string_to_cloud_format(char* fpath, char* result){

	char *dummy_path = fpath;
	int i = 0;
	while(dummy_path[i] != '\0'){
		if(dummy_path[i] == '/'){
			result[i] = '+';
			i++;
		}
		else {
			result[i] = dummy_path[i];
			i++;
		}
	}
	result[i] = '\0';
}

/*
 * @desc: Reconversion of + path to /
 * @param: string - full path of file
 * string - resultant path populated with /
 * @return: void
 */
void cloud_to_string_format(char* fpath, char* result){

	char *dummy_path = fpath;
	int i = 0;
	while(dummy_path[i] != '\0'){
		if(dummy_path[i] == '+'){
			result[i] = '/';
			i++;
		}
		else {
			result[i] = dummy_path[i];
			i++;
		}
	}
	result[i] = '\0';
}

/*
 * @desc: buffer used for files for cloud operations
 * @param: char* - buffer, int - buffer length
 * @return: number of bytes written
 */
int get_buffer(const char *buffer, int bufferLength) {
	return fwrite(buffer, 1, bufferLength, outfile);  
}

/*
 * @desc: buffer used for files for cloud operations
 * @param: char* - buffer, int - buffer length
 * @return: number of bytes written
 */
int get_buffer_new(const char *buffer, int bufferLength) {
	return fwrite(buffer, 1, bufferLength, new_outfile);  
}

/* 
 * @desc: Initializes the FUSE file system (cloudfs) by checking if the mount points
 * are valid, and if all is well, it mounts the file system ready for usage.
 * @param: struct - fuse conn_info
 * @return: void
 */
void *cloudfs_init(struct fuse_conn_info *conn UNUSED)
{
	cloud_init(state_.hostname);
	cloud_create_bucket("test");
	cloud_print_error();  

	return NULL;
}
/*
 * @desc: Destroy the cloud connection and also delete the buckets.
 * @param: void
 * @return: void
 */

void cloudfs_destroy(void *data UNUSED) {
	cloud_delete_bucket("test");
	cloud_destroy();

}
/*
 * @desc: This function is used/called to delete stuff from cloud after looking 
 * and taking into consideration the reference count.
 * @param: string - fullpath of file
 * @return: void
 */
void cloud_delete_helper(char* fpath)
{
	if(LOG_1_DEBUG) log_msg("Coming to delete helper with path as %s\n", fpath);
	char md5_buf[(2*MD5_DIGEST_LENGTH) + 1];
	struct hash_struct *s;
	char md5_path[MAX_PATH_LEN];
	int lenbuf_int = 0;

	convert_proxy_path(fpath, md5_path);


	FILE *hiddenfp = fopen(md5_path, "rb");
	if(hiddenfp == NULL)
	{
		if(LOG_DEBUG)log_msg("Failing to open proxy file in delete helper\n");
		return;
	}

	while(fscanf(hiddenfp, "%s %d", md5_buf, &lenbuf_int) != EOF)
	{ 
		s = find_user_string(md5_buf);
		if(s)
		{
			if((s->ref_count) == 1)
			{
				cloud_delete_object("test", md5_buf);
				cloud_print_error();
				hash_del(s);
			}
			else
			{
				(s->ref_count)--;
			}  

		}
	}
	add_hash_to_ssd();
	fclose(hiddenfp); 
}

/*
 * @desc: Used to Truncate the file sizes for file paths.
 * @param: string - path, off_t - newsize to be truncated to
 * @return: int
 */

int cloudfs_truncate(const char* path, off_t newsize){
	if(LOG_1_DEBUG) log_msg("Coming to truncate with path as %s\n", path);
	int retval = 0;
	char fpath[MAX_PATH_LEN];

	cloudfs_fullpath(fpath, path);
	retval = truncate(fpath, newsize);

	if(retval < 0){
		cloudfs_error("Cloud FS Truncate\n");
		if(LOG_DEBUG)log_msg("Cloud FS Truncate Error\n");
	}
	return retval;
}

/*
 * @desc: Get attributes will have to return correct attributes
 * in case of extended attributes also.
 * @param: string - path, struct - statbuf which stores attributes
 * @return: int
 */

int cloudfs_getattr(const char *path, struct stat *statbuf )
{
	if(LOG_1_DEBUG) log_msg("Coming to getattr with path as %s\n", path);
	int retval = 0;
	char fpath[MAX_PATH_LEN];
	time_t val = 0;
	off_t size_on_cloud = 0;
	int get_attr_checker = 0;

	cloudfs_fullpath(fpath, path);
	retval = lstat(fpath, statbuf);

	get_attr_checker = lgetxattr(fpath, "user.x-modified", &val, sizeof(time_t));
	if((get_attr_checker > 0) && (val > 0)){
		// Extended attr exist.
		lgetxattr(fpath, "user.x-size", &size_on_cloud, sizeof(off_t));
		statbuf->st_size = size_on_cloud;
	}
	if(retval != 0){
		retval = cloudfs_error("Cloud FS Getattr\n");
		if(LOG_DEBUG)log_msg("Cloud FS getattr Error\n");
	}
	return retval;
}

/*
 * @desc: Get Extended attribures for path.
 * @param: string - path, string - name of xattr
 * string - value, size_t size
 * @return: int
 */
int cloudfs_getxattr(const char* path, const char* name, char* value,
		size_t size){
	if(LOG_1_DEBUG) log_msg("Coming to getxattr with path as %s\n", path);
	int retval = 0;
	char fpath[MAX_PATH_LEN];

	cloudfs_fullpath(fpath,path);
	retval = lgetxattr(fpath, name, value, size);

	if(retval<0){
		retval = cloudfs_error("Cloud FS getxattr\n");
		if(LOG_1_DEBUG)log_msg("Cloud FS getxattr Error\n");
	}

	return retval;
}

/*
 * @desc: Set extended attributes for path.
 * @param: string - path, string - name of xattr
 * string - value, size_t size
 * @return: int
 */
int cloudfs_setxattr(const char* path, const char *name , const char* value,
		size_t size, int flags){
	if(LOG_1_DEBUG)log_msg("Coming to setxattr with path %s\n", path);
	int retval = 0;
	char fpath[MAX_PATH_LEN];

	cloudfs_fullpath(fpath, path);
	retval = setxattr(fpath, name, value, size, flags);
	if(retval < 0){
		retval = cloudfs_error("Cloud FS setxattr\n");
		if(LOG_DEBUG)log_msg("Cloud FS setxattr Error\n");
	}
	return retval;
}

/*
 * @desc: Open Call has to handle cases in which file has extended attributes and 
 * thus has to get file from cloud and open.
 * @param: string - path to be opened, struct - fuse file info
 * @return: int 
 */
int cloudfs_open(const char* path, struct fuse_file_info *fi){

	if(LOG_1_DEBUG) log_msg("Coming to open with path as %s\n", path);
	int retval = 0;
	int fd;
	char fpath[MAX_PATH_LEN];
	char actual_path[MAX_PATH_LEN];
	cloudfs_fullpath(fpath, path);
	int get_checker = 0;
	time_t val = 0;

	get_checker = lgetxattr(fpath, "user.x-modified", &val, sizeof(time_t));

	if((get_checker > 0) && (val > 0))
	{
		if(state_.no_dedup)
		{
			string_to_cloud_format(fpath,actual_path);
			if(LOG_5_DEBUG) log_msg("Putting to cloud with path %s\n", path);
			outfile = fopen(fpath, "wb");
			cloud_get_object("test", actual_path, get_buffer);
			fclose(outfile);
			cloud_print_error();
		} 
	}  

	// Regular open for files on SSD.
	fd = open(fpath, fi->flags);
	if(fd<0){
		retval = cloudfs_error("Cloud FS open\n");
		if(LOG_DEBUG)log_msg("Cloud FS open Error\n");
	}

	fi->fh = fd;
	return retval;
}

/*
 * @desc: This read function handles segment wise reads and populates the buf_for_read buffer
 * Compressed segments from cloud are obtained from cloud if no_compress = 0.
 * In the case of there being no extended attributes and no dedup, a regular read is done.
 * @param: string - path to be read, char* buffer to be populated, size_t - size to be read
 * off_t - offset from which read will start, struct - fuse file info
 * @return: int - number of bytes read
 */

int cloudfs_read(const char* path, char* buf_for_read, size_t size, 
		off_t offset, struct fuse_file_info* fi){

	if(LOG_6_DEBUG)log_msg("Coming to read with path as %s\n", path);
	int retval = 0;
	char fpath[MAX_PATH_LEN];
	int get_checker = 0;
	time_t val = 0;
	char md5_buf[(2*MD5_DIGEST_LENGTH) + 1];
	char md5_path[MAX_PATH_LEN];
	int lenbuf_int = 0;
	char segment_file_path[MAX_PATH_LEN];
	int total_length_p = 0, total_length_n = 0, size_from_pread = 0;
	int segment_found_flag = 0;
	int buf_offset = 0;
	size_t total_return = 0;
	int fd_for_read;
	char tmp_compressed_path[MAX_PATH_LEN];
	struct cache_struct* temp_struct;
	struct cache_struct* to_be_deleted_struct;
	struct cache_struct* find_temp_struct;
	char to_be_unlinked[MAX_PATH_LEN];
	int i=0;

	// Temporary path being used for compressed files from cloud.
	sprintf(tmp_compressed_path, "%s.%s", state_.ssd_path, "compress_storage");

	cloudfs_fullpath(fpath, path);

	get_checker = lgetxattr(fpath, "user.x-modified", &val, sizeof(time_t));

	if((get_checker > 0) && (val > 0)) 
	{
		if(!state_.no_dedup)
		{

			convert_proxy_path(fpath, md5_path);
			FILE *hiddenfp = fopen(md5_path, "rb");
			if(hiddenfp == NULL)
			{
				if(LOG_DEBUG)log_msg("Proxy in read fails\n");
				return 0;
			}
			while(fscanf(hiddenfp, "%s %d", md5_buf, &lenbuf_int) != EOF)
			{					
				total_length_n += lenbuf_int;
				if((offset < total_length_n) && (size > 0))
				{
					if(segment_found_flag)
					{
						//
						if(!state_.no_cache)
						{
							sprintf(segment_file_path, "%s/.%s", ssd_cache_path,  md5_buf);
							fd_for_read = open(segment_file_path, O_RDONLY);
							if(fd_for_read < 0)
							{
								if(LOG_6_DEBUG)log_msg("y1 er is %d\n",errno);
								while((lenbuf_int + total_cache_size) > state_.cache_size)
								{
									if(LOG_6_DEBUG) log_msg("The total length in cache eviction is %d\n", (lenbuf_int + total_cache_size));
									// Evict from Cache
									cache_sort_by_id();
									temp_struct = users_cache;
									// to_be_deleted_struct = users_cache;
									// temp_struct = temp_struct -> hh.next;
									// for(i=0;i<20;i++)
									// {
									// 	if((temp_struct->ref_count) < (to_be_deleted_struct->ref_count))
									// 	{
									// 		to_be_deleted_struct = temp_struct;
									// 	}
									// 	temp_struct = temp_struct -> hh.next;
									// }
									// temp_struct = to_be_deleted_struct;


									// while(temp_struct->ref_count > 8)
									// {
									// 	if(temp_struct != NULL)
									// 	temp_struct = temp_struct->hh.next;
									// }
									sprintf(to_be_unlinked, "%s/.%s", ssd_cache_path, temp_struct->md5_key_cache);
									total_cache_size -= temp_struct->segment_length;
									if(LOG_6_DEBUG)log_msg("To be unlinked path is %s\n", to_be_unlinked);
									if(LOG_6_DEBUG) log_msg("The path for the file is %s\n", fpath);									
									if(LOG_6_DEBUG)log_msg("The size of the unlinked path is %d\n", temp_struct->segment_length);
									unlink(to_be_unlinked);
									if(LOG_6_DEBUG)log_msg("y2 er is %d\n",errno);
									cache_hash_del(temp_struct);
									if(LOG_6_DEBUG)log_msg("y3 er is %d\n",errno);
									add_cache_hash_to_ssd();
									if(LOG_6_DEBUG)log_msg("y4 er is %d\n",errno);	
								}

								if(!state_.no_compress)
								{
									compressed_file_getter(tmp_compressed_path, segment_file_path, md5_buf);									
								}
								else
								{
									uncompressed_file_getter(segment_file_path, md5_buf);		
								}
								//close(fd_for_read);

								cache_add_user(md5_buf, lenbuf_int);
								total_cache_size += lenbuf_int;
								add_cache_hash_to_ssd();
								int test = cache_num_users_hash();
								if(LOG_6_DEBUG) log_msg("The number of elements are %d\n", test);
								if(LOG_6_DEBUG) log_msg("STRUCT is %s\n", users_cache->md5_key_cache);
								if(LOG_6_DEBUG) log_msg("The total cache size so far is %d\n", total_cache_size);							

							}	


							find_temp_struct = cache_find_user_string(md5_buf);
							if(find_temp_struct == NULL)
							{
								if(LOG_6_DEBUG) log_msg("The struct should be found but is not\n");
							}
							(find_temp_struct->ref_count++);
							add_cache_hash_to_ssd();
							close(fd_for_read);
							//fd_for_read = open(segment_file_path, O_RDONLY);
						}
						else
						{
							sprintf(segment_file_path, "%s.%s", state_.ssd_path,  md5_buf);							
							fd_for_read = open(segment_file_path, O_RDONLY);
							if(fd_for_read < 0)
							{
								if(!state_.no_compress)
								{
									compressed_file_getter(tmp_compressed_path, segment_file_path, md5_buf);					
								}
								else
								{
									uncompressed_file_getter(segment_file_path, md5_buf);
								}
							}	
							close(fd_for_read);

							//fd_for_read = open(segment_file_path, O_RDONLY);
						}
						fd_for_read = open(segment_file_path, O_RDONLY);
						size_from_pread = pread(fd_for_read, buf_for_read+(buf_offset),
								size, 0);
						total_return += size_from_pread;
						if(size_from_pread < 0)
						{
							if(LOG_DEBUG)log_msg("Error in reading pread\n");
						}  
						size = size - size_from_pread;
						buf_offset += size_from_pread;
						if(LOG_DEBUG)log_msg("Size left is %d\n", size);
						close(fd_for_read);	
					}


					else if(!segment_found_flag)   
					{
						// This is the segment that has to be read from cloud and put into ssd.
						// get this particular md5_buf to ssd.
						if(!state_.no_cache)
						{
							sprintf(segment_file_path, "%s/.%s", ssd_cache_path,  md5_buf);
							fd_for_read = open(segment_file_path, O_RDONLY);
							if(fd_for_read < 0)
							{
								if(LOG_6_DEBUG)log_msg("y5 er is %d\n",errno);
								while((lenbuf_int + total_cache_size) > state_.cache_size)
								{
									if(LOG_6_DEBUG) log_msg("The total length in cache eviction is %d\n", (lenbuf_int + total_cache_size));
									// Evict from Cache
									cache_sort_by_id();
									temp_struct = users_cache;
									// to_be_deleted_struct = users_cache;
									// temp_struct = temp_struct -> hh.next;
									// for(i=0;i<10;i++)
									// {
									// 	if((temp_struct->ref_count) < (to_be_deleted_struct->ref_count))
									// 	{
									// 		to_be_deleted_struct = temp_struct;
									// 	}
									// 	temp_struct = temp_struct -> hh.next;
									// }
									// temp_struct = to_be_deleted_struct;


									// while(temp_struct->ref_count > 8)
									// {
									// 	if(temp_struct != NULL)
									// 	temp_struct = temp_struct->hh.next;
									// }									
									sprintf(to_be_unlinked, "%s/.%s", ssd_cache_path, temp_struct->md5_key_cache);
									total_cache_size -= temp_struct->segment_length;
									if(LOG_6_DEBUG)log_msg("To be unlinked path is %s\n", to_be_unlinked);
									if(LOG_6_DEBUG) log_msg("The path for the file is %s\n", fpath);
									if(LOG_6_DEBUG)log_msg("The size of the unlinked path is %d\n", temp_struct->segment_length);
									unlink(to_be_unlinked);
									if(LOG_6_DEBUG)log_msg("y6 er is %d\n",errno);									
									cache_hash_del(temp_struct);
									if(LOG_6_DEBUG)log_msg("y7 er is %d\n",errno);
									add_cache_hash_to_ssd();
									if(LOG_6_DEBUG)log_msg("y7 er is %d\n",errno);

								}

								if(!state_.no_compress)
								{
									compressed_file_getter(tmp_compressed_path, segment_file_path, md5_buf);
								}
								else
								{
									uncompressed_file_getter(segment_file_path, md5_buf);
								}
								//close(fd_for_read);
								cache_add_user(md5_buf, lenbuf_int);
								total_cache_size += lenbuf_int;
								add_cache_hash_to_ssd();
								//cache_sort_by_id();
								//if(LOG_6_DEBUG) print_cache_hash_table();
								int test = cache_num_users_hash();
								if(LOG_6_DEBUG) log_msg("The number of elements are %d\n", test);
								if(LOG_6_DEBUG) log_msg("STRUCT is %s\n", users_cache->md5_key_cache);
								if(LOG_6_DEBUG) log_msg("The total cache size so far is %d\n", total_cache_size);
							}	

							find_temp_struct = cache_find_user_string(md5_buf);
							if(find_temp_struct == NULL)
							{
								if(LOG_6_DEBUG) log_msg("The struct should be found but is not\n");
							}
							(find_temp_struct->ref_count++);	
							add_cache_hash_to_ssd();						
							close(fd_for_read);
							//fd_for_read = open(segment_file_path, O_RDONLY);
						}
						else
						{
							sprintf(segment_file_path, "%s.%s", state_.ssd_path,  md5_buf);							
							fd_for_read = open(segment_file_path, O_RDONLY);
							if(fd_for_read < 0)
							{

								if(!state_.no_compress)
								{
									compressed_file_getter(tmp_compressed_path, segment_file_path, md5_buf);
								}
								else
								{
									uncompressed_file_getter(segment_file_path, md5_buf);
								}
							}	
							close(fd_for_read);

							//fd_for_read = open(segment_file_path, O_RDONLY);
						}
						fd_for_read = open(segment_file_path, O_RDONLY);
						size_from_pread = pread(fd_for_read, buf_for_read, size,
								(offset - total_length_p));
						total_return += size_from_pread;
						if(size_from_pread < 0)
						{
							if(LOG_DEBUG)log_msg("Error in pread1\n");
						}
						size = size - size_from_pread;
						buf_offset += size_from_pread;
						close(fd_for_read);
						segment_found_flag = 1;
					} 	
				}	
				total_length_p += lenbuf_int;    
			}			
			fclose(hiddenfp); 
			retval = total_return;
		}
		else
		{    
			retval = pread(fi->fh, buf_for_read , size, offset);
			if(retval < 0){
				retval = cloudfs_error("Cloud FS Read\n");
				if(LOG_DEBUG)log_msg("Cloud FS read Error\n");
			}
		}	
	}

	else {
		retval = pread(fi->fh, buf_for_read , size, offset);
		if(retval < 0){
			retval = cloudfs_error("Cloud FS Read\n");
			if(LOG_DEBUG)log_msg("Cloud FS read Error\n");
		}
	}
	return retval;

}

/* @desc: gets the compressed files from cloud
 * @param: string - tmp_path is the temporary file for storing compressed 
 * segments, string - ssd_local_path is populated with uncompressed file
 * @return: void
*/
void compressed_file_getter(char* tmp_path, char* ssd_local_path, char* md5_buf)
{
	new_outfile = fopen(tmp_path, "wb");
	cloud_get_object("test", md5_buf, get_buffer_new);
	fclose(new_outfile);	
	outfile = fopen(ssd_local_path, "wb");
	new_outfile = fopen(tmp_path, "rb");
	inf(new_outfile, outfile);
	fclose(outfile);
	fclose(new_outfile);
}

/* @desc: gets the uncompressed files from cloud
 * @param: string - ssd_local_path is populated with uncompressed file for md5_buf
 * @return: void
*/
void uncompressed_file_getter(char* ssd_local_path, char* md5_buf)
{
	outfile = fopen(ssd_local_path, "wb");
	cloud_get_object("test", md5_buf, get_buffer);
	fclose(outfile);
}

/*
 * @desc: Implemented the write case, in which offset is adjusted
 * and also an extra extended attribute is set for the same case to 
 * be handled in release.
 * @param: string - path to be read, char* buffer to be populated, size_t - size to be read
 * off_t - offset from which read will start, struct - fuse file info
 * @return: int - number of bytes written 
 */
int cloudfs_write(const char* path, const char* buf, size_t size,
		off_t offset, struct fuse_file_info *fi){

	if(offset > 0)
	{
		if(LOG_6_DEBUG)log_msg("The path with write offset > 0 is %s\n", path);
	}
	if(LOG_1_DEBUG)log_msg("Coming to write with path as %s\n", path);
	int retval = 0;
	int get_attr_checker = 0;
	char fpath[MAX_PATH_LEN];
	time_t val = 0;
	off_t size_attr = 0;
	char tmp_write_path[MAX_PATH_LEN];

	sprintf(tmp_write_path, "%s.%s", state_.ssd_path, ".temp_write");

	cloudfs_fullpath(fpath, path);
	// If extended attributes exist get the extended attributes size and readjust.
	get_attr_checker = lgetxattr(fpath, "user.x-modified", &val,
			sizeof(time_t));
	lgetxattr(fpath, "user.x-size", &size_attr, sizeof(off_t));

	if(get_attr_checker > 0)
	{
		if(!state_.no_dedup)
		{
			offset = offset - size_attr;
			//lsetxattr(fpath, "user.x-size-updated", (void*)1, sizeof(int), 0);
			write_modified = 1;
		}
	}

	retval = pwrite(fi->fh, buf, size, offset);

	if(retval<0){
		retval = cloudfs_error("Cloud FS Write\n");
		if(LOG_DEBUG)log_msg("Cloud FS write Error\n");
	}

	return retval;
}

/*
 * @desc: Basic wrapper for mkdir.
 * @param: string - path of new directory, mode_t - mode to be created with
 * @return: int
 */
int cloudfs_mkdir(const char* path, mode_t mode){

	int retval = 0;
	char fpath[MAX_PATH_LEN];

	cloudfs_fullpath(fpath, path);

	retval = mkdir(fpath, mode);
	if(retval<0){
		retval = cloudfs_error("Cloud FS Mkdir\n");
		if(LOG_DEBUG)log_msg("Cloud FS mkdir Error\n");
	}

	return retval;
}

/*
 * @desc: Basic wrapper for removing directories.
 * @param: string - path of new directory
 * @return: int
 */
int cloudfs_rmdir(const char* path){

	int retval = 0;
	char fpath[MAX_PATH_LEN];

	cloudfs_fullpath(fpath, path);

	retval = rmdir(fpath);
	if(retval<0){
		retval = cloudfs_error("Cloud FS Rmdir\n");
		if(LOG_DEBUG)log_msg("Cloud FS rmdir Error\n");
	}

	return retval;
}

/*
 * @desc: This is the close wrapper, in which most of the logic is implemented.
 * The decision to push to cloud and set the extended attributes is done 
 * in this wrapper.
 * In the case of attributes being set and deduplication being enabled,
 * we look at the compress option and appropriately segment the file and 
 * then compress and then push to cloud. Extended attributes
 * are updated to be consistent. In the case of no extended attributes, 
 * we push the segments again and 
 * set the attributes for the first time. 
 * 
 * Also implemented the write with append case in which, file is being 
 * written into same path and then size and mtime is made consistent
 * @param: string - path of file to close, struct - fuse file info
 * @return: int 
 */
int cloudfs_release(const char* path , struct fuse_file_info* fi){

	if(LOG_1_DEBUG)log_msg("Coming to release with path as %s\n", path);
	int retval = 0;
	char fpath[MAX_PATH_LEN];
	time_t attr_val = 0;
	int get_attr_checker = 0;
	struct stat stat_buf;
	char final_path_plus[MAX_PATH_LEN];
	off_t new_size = 0;
	off_t old_size = 0;
	int get_size_checker = 0;

	cloudfs_fullpath(fpath, path);

	retval = close(fi->fh);
	lstat(fpath, &stat_buf);
	string_to_cloud_format(fpath, final_path_plus);

	get_attr_checker = lgetxattr(fpath, "user.x-modified", &attr_val,
			sizeof(time_t));

	if(stat_buf.st_size <= state_.threshold)
	{

		if((get_attr_checker > 0) && (write_modified == 1))
		{
			if(LOG_6_DEBUG)log_msg("ya2\n");
			lgetxattr(fpath, "user.x-size", &old_size, sizeof(off_t));	
			new_size = old_size + stat_buf.st_size;
			lsetxattr(fpath, "user.x-size", (&(new_size)), sizeof(off_t), 0);
			lsetxattr(fpath, "user.x-modified", &(stat_buf.st_mtime),
					sizeof(time_t), 0);
			if(state_.no_compress)
			{
				if(LOG_6_DEBUG)log_msg("ya3\n");
				cloudfs_compute_rabin(fpath);
			}
			else
			{
				if(LOG_6_DEBUG)log_msg("ya4\n");				
				cloudfs_compute_rabin_compress(fpath);
			}
			cloudfs_truncate(path, 0);
			write_modified = 0;			
		}

		else if((get_attr_checker > 0) && (stat_buf.st_mtime > attr_val)
				&& (write_modified == 0))
		{
			if(LOG_6_DEBUG)log_msg("ynahi\n");
			if(!state_.no_dedup){

				cloud_delete_helper(fpath);  
				lremovexattr(fpath, "user.x-modified");
				lremovexattr(fpath, "user.x-size");
			}
			else
			{
				cloud_delete_object("test", final_path_plus);
				cloud_print_error();      
				lremovexattr(fpath, "user.x-modified");
				lremovexattr(fpath, "user.x-size");

			}

		}

	}

	else if(stat_buf.st_size > state_.threshold){

		if(get_size_checker > 0)
		{
			lgetxattr(fpath, "user.x-size", &old_size, sizeof(off_t));	
			new_size = old_size + stat_buf.st_size;
			lsetxattr(fpath, "user.x-size", (&(new_size)), sizeof(off_t), 0);
			//lremovexattr(fpath, "user.size-updated");
		}
		else
		{
			lsetxattr(fpath, "user.x-size", (&(stat_buf.st_size)),
					sizeof(off_t), 0);
		}

		if((get_attr_checker > 0) && (stat_buf.st_mtime > attr_val)) {
			if(!state_.no_dedup)
			{
				if(state_.no_compress)
				{
					cloudfs_compute_rabin(fpath);
				}
				else
				{
					cloudfs_compute_rabin_compress(fpath);
				}
			}
			else
			{
				infile = fopen(fpath, "rb");
				cloud_put_object("test", final_path_plus, stat_buf.st_size, put_buffer);
				fclose(infile);
			}      
		}

		else if(get_attr_checker < 0) {

			if(!state_.no_dedup)
			{
				if(state_.no_compress)
				{
					cloudfs_compute_rabin(fpath);
				}
				else
				{
					cloudfs_compute_rabin_compress(fpath);
				}
			}
			else
			{
				infile = fopen(fpath, "rb");
				cloud_put_object("test", final_path_plus, stat_buf.st_size, put_buffer);
				fclose(infile);
			}
		}
		cloudfs_truncate(path, 0);
		lstat(fpath, &stat_buf);
		lsetxattr(fpath, "user.x-modified", &(stat_buf.st_mtime),
				sizeof(time_t), 0);
	}
	return retval;
}

/*
 * @desc: Basic wrapper for open directory.
 * @param: string - path of file to close, struct - fuse file info
 * @return: int 
 */
int cloudfs_opendir(const char* path, struct fuse_file_info* fi){
	DIR* dp;
	int retval = 0;
	char fpath[MAX_PATH_LEN];

	cloudfs_fullpath(fpath, path);

	dp = opendir(fpath);
	if(dp == NULL){
		retval = cloudfs_error("Cloud FS openDir\n");
		if(LOG_DEBUG)log_msg("Cloud FS opendir Error\n");
	}
	fi->fh = (intptr_t) dp;
	return retval;
}

/*
 * @desc: Basic wrapper for read directory.
 * @param: string - path, void buffer, fuse_fill_dir_t filler,
 * struct - fuse file info that has handle to be read
 * @return: int retval
 */
int cloudfs_readdir(const char* path UNUSED, void* buf, 
		fuse_fill_dir_t filler, off_t offset UNUSED, struct fuse_file_info *fi){

	int retval = 0;
	DIR* dp;
	struct dirent *de;

	dp = (DIR*)(uintptr_t)fi->fh;

	de = readdir(dp);

	if(de == 0){
		retval = cloudfs_error("Cloud FS readdir\n");
		if(LOG_DEBUG)log_msg("Cloud FS readdir Error\n");
		return retval;
	}

	do {
		if(filler(buf,de->d_name, NULL, 0) != 0){
			return -ENOMEM;
		}

	} while((de = readdir(dp)) != NULL);
	return retval;
}

/*
 * @desc: Basic wrapper for making node
 * @param: string - path of file to make, mode of node, dev_t dev for node
 * @return: int retval
 */
int cloudfs_mknod(const char* path, mode_t mode, dev_t dev){

	int retval = 0;
	char fpath[MAX_PATH_LEN];

	cloudfs_fullpath(fpath, path);

	if(S_ISREG(mode)){

		retval = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if(retval < 0){
			retval = cloudfs_error("Cloud FS mknod\n");
			if(LOG_DEBUG)log_msg("Cloud FS mknod Error\n");
		}
		else{
			retval = close(retval);
			if(retval<0){
				retval = cloudfs_error("Cloud FS close\n");
				if(LOG_DEBUG)log_msg("Cloud FS close Error\n");
			}
		}
	}
	else if(S_ISFIFO(mode)){
		retval = mkfifo(fpath, mode);
		if(retval < 0){
			retval = cloudfs_error("Cloud FS mkfifo\n");
			if(LOG_DEBUG)log_msg("Cloud FS mkfifo Error\n");
		}
		else{
			retval = mknod(fpath, mode, dev);
			if(retval<0){
				retval = cloudfs_error("Cloud FS mknod\n");
				if(LOG_DEBUG)log_msg("Cloud FS mknod-2 Error\n");
			}
		}
	}
	return retval;
}


/*
 * @desc: Basic wrapper for accessing the path.
 * @param: string - path needed to be accessed, int value to be accessed
 * @return: int retval
 */
int cloudfs_access(const char* path, int value){

	int retval = 0;
	char fpath[MAX_PATH_LEN];

	cloudfs_fullpath(fpath, path);

	retval = access(fpath, value);
	if(retval<0){
		retval = cloudfs_error("Cloud FS access\n");
		if(LOG_DEBUG)log_msg("Cloud FS access Error\n");
	}
	return retval;
}

/*
 * Basic wrapper for changing permissions.
 * @param: string - path needed to chmod, mode - new mode given to path
 * @return: int retval 
 */
int cloudfs_chmod(const char* path, mode_t mode){
	int retval = 0;
	char fpath[MAX_PATH_LEN];

	cloudfs_fullpath(fpath, path);

	retval = chmod(fpath, mode);
	if(retval<0){
		retval = cloudfs_error("Cloud FS chmod\n");
		if(LOG_DEBUG)log_msg("Cloud FS chmod Error\n");
	}
	return retval;
}

/*
 * @desc: Utimns is implemented using the utimensat syscall
 * @param: string - path of file , struct - timespec struct
 * @return - int retval
 */
int cloudfs_utimens(const char* path, const struct timespec* tv){

	int retval = 0;
	char fpath[MAX_PATH_LEN];

	cloudfs_fullpath(fpath, path);

	retval = utimensat(0, fpath, tv, 0);
	if(retval<0){
		cloudfs_error("Cloud FS utimens\n");
		if(LOG_DEBUG)log_msg("Cloud FS utimens Error\n");
	}
	return retval;
}

/*
 * @desc: Checks to see if path is a hidden file
 * @param: string - path that needs to be checked
 * @return - int 1 if it is a hidden file else 0
 */
int is_hidden_file(char* path_unlink)
{
	char* c;
	c = strchr(path_unlink, '.');
	if(c != NULL)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

/*
 * @desc: Unlink is changed to remove files from cloud in the case of extended 
 * attributes being set or else regular unlink is done.
 * @param: string - path to be unlinked
 * @return - int retval
 */
int cloudfs_unlink(const char* path){
	if(LOG_7_DEBUG)log_msg("Coming to unlink with path as %s\n", path);
	int retval = 0;
	char fpath[MAX_PATH_LEN];
	time_t val = 0;
	char final_path_plus[MAX_PATH_LEN];
	char proxy_path [MAX_PATH_LEN];
	int get_attr_checker = 0;
	char path_tester[MAX_PATH_LEN];

	cloudfs_fullpath(fpath, path);

	strncpy(path_tester, path, 3);

	int hidden_file_tester = is_hidden_file(path_tester);
	if(hidden_file_tester == 1)
	{
		if(LOG_6_DEBUG) log_msg("Coming to . unlink with path %s\n", fpath);
		return 0;
	}

	get_attr_checker = lgetxattr(fpath, "user.x-modified", &val, sizeof(time_t));

	// Checking for existing extended attributes
	if((get_attr_checker > 0) && (val > 0)){
		if(!state_.no_dedup)
		{ 
			cloud_delete_helper(fpath);
			convert_proxy_path(fpath, proxy_path);
			unlink(proxy_path);
		}
		else
		{
			string_to_cloud_format(fpath, final_path_plus);
			cloud_delete_object("test", final_path_plus);
			cloud_print_error();
		}
	}

	retval = unlink(fpath);
	if(retval<0){
		retval = cloudfs_error("Cloud FS unlink\n");
	}

	return retval;
}

/*
 * @desc: Basic wrapper for chown.
 * @param: string - path to chown, uid and gid to be passed to syscall
 * @return: int reval
 */
int cloudfs_chown(const char* path, uid_t uid, gid_t gid){
	int retval = 0;
	char fpath[MAX_PATH_LEN];

	cloudfs_fullpath(fpath, path);
	retval = chown(fpath, uid, gid);
	if(retval < 0){
		retval = cloudfs_error("Cloud FS Chown\n");
		if(LOG_DEBUG)log_msg("Cloud FS chown Error\n");
	}
	return retval;
}

/*
 * @desc: Basic wrapper for readlink.
 * @param: string - path to be read, string, read_link to be passed to syscall along 
 * with size_t size.
 * @return: int retval
 */
int cloudfs_readlink(const char* path, char* read_link, size_t size){
	int retval = 0;
	char fpath[MAX_PATH_LEN];

	cloudfs_fullpath(fpath, path);
	retval = readlink(fpath, read_link, size-1);
	if(retval < 0){
		retval = cloudfs_error("Cloud FS Readlink\n");
		if(LOG_DEBUG)log_msg("Cloud FS readlink Error\n");
	}
	else{
		read_link[retval] = '\0';
		retval = 0;
	}
	return retval;
}

/*
 * @desc: Basic wrapper for symlink.
 * @param: string - path, string - symlink that needs to be input to syscall
 * @return: int retval
 */
int cloudfs_symlink(const char* path UNUSED, const char* sym_link){
	int retval = 0;
	char flink[MAX_PATH_LEN];

	cloudfs_fullpath(flink, sym_link);

	retval = symlink(flink, sym_link);
	if(retval < 0){
		retval = cloudfs_error("Cloud FS symlink\n");
		if(LOG_DEBUG)log_msg("Cloud FS symlink Error\n");
	}
	return retval;
}

/*
 * Functions supported by cloudfs 
 */
static 
struct fuse_operations cloudfs_operations = {
	.init           = cloudfs_init,

	.getattr        = cloudfs_getattr,
	.getxattr       = cloudfs_getxattr,
	.setxattr       = cloudfs_setxattr,
	.mkdir          = cloudfs_mkdir,
	.mknod          = cloudfs_mknod,
	.open           = cloudfs_open,
	.read           = cloudfs_read,
	.write          = cloudfs_write,
	.release        = cloudfs_release,
	.opendir        = cloudfs_opendir,
	.readdir        = cloudfs_readdir,
	.destroy        = cloudfs_destroy,
	.access         = cloudfs_access,
	.utimens        = cloudfs_utimens,
	.chmod          = cloudfs_chmod,
	.unlink         = cloudfs_unlink,
	.chown          = cloudfs_chown,
	.symlink        = cloudfs_symlink,
	.readlink       = cloudfs_readlink,
	.truncate       = cloudfs_truncate,
	.rmdir          = cloudfs_rmdir
};

int cloudfs_start(struct cloudfs_state *state,
		const char* fuse_runtime_name) {

	int argc = 0;
	char* argv[10];
	argv[argc] = (char *) malloc(128 * sizeof(char));
	strcpy(argv[argc++], fuse_runtime_name);
	argv[argc] = (char *) malloc(1024 * sizeof(char));
	strcpy(argv[argc++], state->fuse_path);
	argv[argc++] = "-s"; // set the fuse mode to single thread
	//argv[argc++] = "-f"; // run fuse in foreground 


	state_  = *state;
	log_open();
	int num_users = num_users_hash();
	if(num_users == 0)
	{
		if(LOG_6_DEBUG)log_msg("Coming to num_users = 0\n");
		reconstruct_hash();
	} 

	int cache_num_users = cache_num_users_hash();
	if(cache_num_users == 0)
	{
		if(LOG_6_DEBUG)log_msg("Coming to cache num_users = 0\n");
		int total_size_from_hash = reconstruct_cache_hash();
		total_cache_size = total_size_from_hash;
	}

	sprintf(ssd_cache_path, "%s.%s", state_.ssd_path, "cache");
	int dir_return = mkdir(ssd_cache_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH );
	if(dir_return < 0)
	{
		if(LOG_5_DEBUG) log_msg("Creating cache directory in start failed\n");
		if(LOG_5_DEBUG) log_msg("The errno is %d\n", errno);
	}

	int fuse_stat = fuse_main(argc, argv, &cloudfs_operations, NULL);
	return fuse_stat;
}
