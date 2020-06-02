#include "devices/block.h"
#include "lib/kernel/bitmap.h"


void swap_init(void);

void swap_in(size_t used_index, void* kaddr);

size_t swap_out(void* kaddr);
