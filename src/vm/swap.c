#include "vm/swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "userprog/syscall.h"
//This is bitmap when we used at swap 
struct bitmap * swap_bitmap;
struct block * bl1;
struct lock swap_lock;

//swap slot initilizing. We make bitmap which has 1024 bits and lock initilizing.
void swap_init(void)
{
  lock_init(&swap_lock);

  swap_bitmap = bitmap_create(1024);    
}

//handle_mm_fault를 통하여 swap 영역에 저장된 page를 실제 page에 할당합니다.
void swap_in(size_t used_index, void* kaddr)
{
  
  lock_acquire(&swap_lock);
  
  //bl1에 swap block을 불러옵니다.
  bl1 = block_get_role(BLOCK_SWAP);

  
  //swap block은 1sector당512Byte 밖에 되지 않습니다. 1개의 page는 8개의 sector에 해당합니다
  used_index = used_index * 8;  
  
  int i;
  
  for(i=0; i<8; i++)
  {  
    block_read(bl1,used_index+i,kaddr+(i*BLOCK_SECTOR_SIZE));
  } 
 
  used_index = used_index / 8; 
  
  //bit map을비었다는 표시인 0로 전환시켜줍니다.
  bitmap_set(swap_bitmap, used_index, false);
 
  lock_release(&swap_lock);
  
}

//victim page로 설정되어 swap영역으로 page를 방출할 때 사용하는 함수입니다.
size_t swap_out(void* kaddr)
{

  lock_acquire(&swap_lock);      

  //bl1에 swap block을 불러옵니다.
  bl1 = block_get_role(BLOCK_SWAP);

  //사용가능한 swap 영역을 찾은 후 swap_num에 그 위치를 할당합니다.
  size_t swap_num = bitmap_scan(swap_bitmap,0,1,false);
  
  //1개의 page(4kB)는 8 sector(512B)에 해당합니다. 
  swap_num = swap_num*8;
 
  size_t i;
  
  for( i=0; i<8; i++)
   {
     block_write(bl1,swap_num + i, kaddr+(i*BLOCK_SECTOR_SIZE) );  
   }

  swap_num = swap_num /8;
  
  //swap_num에 해당하는 bit는 bitmap에서 사용하지 못한다고 설정해줍니다. 
  bitmap_set(swap_bitmap, swap_num ,true);

  lock_release(&swap_lock); 
  
  return swap_num;
}

//해당 swap 영역에 대응하는 vm_entry가 삭제될 때 이용되는 함수입니다.
void swap_delete(size_t used_index)
{
  lock_acquire(&swap_lock);
  //used_index에 해당하는 bit를 bitmap에서 이용가능하게 전환합니다.
  bitmap_set(swap_bitmap,used_index,true);
  lock_release(&swap_lock);
}
