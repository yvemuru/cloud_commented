#ifndef __CLOUDFS_H_
#define __CLOUDFS_H_

#define MAX_PATH_LEN 4096
#define MAX_HOSTNAME_LEN 1024

#define LOG_DEBUG 0
#define LOG_2_DEBUG 0
#define LOG_1_DEBUG 0
#define LOG_3_DEBUG 0
#define LOG_4_DEBUG 0
#define LOG_5_DEBUG 0
#define LOG_6_DEBUG 1
#define LOG_7_DEBUG 1

struct cloudfs_state {
  char ssd_path[MAX_PATH_LEN];
  char fuse_path[MAX_PATH_LEN];
  char hostname[MAX_HOSTNAME_LEN];
  int ssd_size;
  int threshold;
  int avg_seg_size;
  int rabin_window_size;
  int cache_size;
  char no_dedup;
  char no_cache;
  char no_compress;
};

 struct cloudfs_state state_;

 char ssd_cache_path[MAX_PATH_LEN];
 int total_cache_size;
 int write_modified;

int cloudfs_start(struct cloudfs_state* state,
                  const char* fuse_runtime_name);  
void cloudfs_get_fullpath(const char *path, char *fullpath);
void compressed_file_getter(char* tmp_path, char* ssd_local_path, char* md5_buf);
void uncompressed_file_getter(char* ssd_local_path, char* md5_buf);
int is_hidden_file(char* path_unlink);

FILE *log_open();
void log_msg(const char *format, ...);
#endif
