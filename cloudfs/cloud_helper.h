#ifndef __CLOUDFS_HELPER_H_
#define __CLOUDFS_HELPER_H_


  struct hash_struct
  {
    char md5_key[(2*MD5_DIGEST_LENGTH)+1];
    int ref_count;
    UT_hash_handle hh;
  };

  struct cache_struct
  {
    char md5_key_cache[(2*MD5_DIGEST_LENGTH)+1];
    int segment_length;
    int ref_count;
    UT_hash_handle hh;
  };

FILE *infile;
FILE *outfile;
FILE *new_infile;
FILE *new_outfile;

void cloudfs_compute_rabin(char *fpath);
void cloudfs_compute_rabin_compress(char *fpath);
void convert_proxy_path(char* fpath, char* new_path);
int put_buffer(char *buffer, int bufferLength);
#endif