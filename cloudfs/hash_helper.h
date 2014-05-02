#ifndef __HASH_HELPER_H_
#define __HASH_HELPER_H_


struct hash_struct* find_user_string(char* str);
void add_user_string(char* str);
void print_hash_string();
void hash_del(struct hash_struct* s);
void add_hash_to_ssd();
int check_hash_on_ssd();
void reconstruct_hash();
int num_users_hash();

struct cache_struct* cache_find_user_string(char* str);
void cache_add_user(char *str, int lenbuf_int);
void cache_hash_del(struct cache_struct* s);
void print_cache_hash_table();
int cache_num_users_hash();
void cache_sort_by_id();
int id_sort(struct cache_struct *a, struct cache_struct *b);
void add_cache_hash_to_ssd();
int reconstruct_cache_hash();
int ref_count_sort(struct cache_struct *a, struct cache_struct *b);
void cache_sort_by_ref_count();

#endif