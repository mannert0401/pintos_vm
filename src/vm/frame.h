#include "vm/page.h"
#include <debug.h>
#include <list.h>
#include <stdint.h>


void lru_list_init (void);
void add_page_to_lru_list(struct page* page);
void del_page_from_lru_list(struct page* page);
struct page* alloc_page(enum palloc_flags flags);
void free_page(void *kaddr);
void __free_page(struct page* page);
struct page* eviction_and_alloc(enum palloc_flags flags);

