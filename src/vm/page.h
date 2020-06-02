#include <debug.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hash.h>
#include "lib/kernel/hash.h"
#include "userprog/pagedir.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/swap.h"

#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2

/*
   load_segment 시에 실제 데이터 대신 할당하는 자료구조입니다.
   demand paging을 위하여 사용되는 자료구조로 대응되는 virtual address, load 여부,
   파일에서의 위치 등을 포함하고 있습니다.
*/ 
struct vm_entry
{
  /*
     vm_entry가 가리키는 파일의 타입을 나타냅니다. 
     "0 = VM_BIN" = 일반적인 binary 파일을 가리킵니다.
     "1 = VM_FILE" = Memory mapping file의 구성원 중 하나를 가리킵니다.
     "2 = VM_ANON" = 정체가 불분명한 것들로 swap 영역의 데이터나 stack을 가리킵니다. 
  */ 
  uint8_t type;
  
  /*
    vm_entry에 대응되는 virtual address 주소입니다. user process에서 해당 주소가 불리면
    page를 할당하고 실행됩니다.
  */
  void *vaddr;

  // 쓰기가 가능한지 확인하는 flag입니다.
  bool writable;

  // 실제로 data가 load 되어있는지 확인하는 flag입니다.
  bool is_loaded;

  // vm_entry가 파일의 일부분을  가리키고 있다면 이 포인터에 연결합니다.
  struct file * file;
 
  // mmap_file의 vme_list에 추가 되기 위하여 존재하는 list_elem입니다.
  struct list_elem mmap_elem;

  // file에서 이 vm_entry가 load해야 되는 위치를 나타냅니다.
  size_t offset;

  // load 시 read_bytes 만큼 파일에서 읽어야합니다.
  size_t read_bytes;
  
  // load 시 zero_bytes 만큼 0을 저장해야합니다.
  size_t zero_bytes;

  // swap_out 시 저장되는 swap 영역의 swap_slot입니다.
  size_t swap_slot;

  // vm_hash에 저장하기 위한 hash_elem입니다.
  struct hash_elem elem;
}; 
 

// mmap 시 생기는 구조체로 mmap file 1개 당 한 개씩 가집니다.
struct mmap_file {

  //mmap_file의 실질적인 이름입니다.
  int mapid;

  //mmap_file이 어떤 file을 mapping하고 있는지 표시하는 포인터입니다.
  struct file* file;

  //thread의 mmap_list에 저장하기 위한 list_elem입니다.
  struct list_elem elem;
  
  //memory에 올려서 생긴 vm_entry를 저장하는 list입니다.
  struct list vme_list;
};

/*
   page를 나타내는 구조체로 물리페이지를 실제로 할당할 때 사용됩니다.
   kaddr과 vm_entry를 포함하여 물리페이지 관리를 위해 사용됩니다.
*/
struct page {
   
        //물리페이지 주소를 나타내는 값입니다.
	void *kaddr;

        /*
          user process에서 호출되는 vm_entry를 저장합니다. 
          물리 페이지 할당 시 vm_entry와 page는 1:1mapping되어 관리됩니다.
        */  
	struct vm_entry *vme;

	//해당 page를 어떤 thread가 할당했는지 확인하는 포인터입니다.
        struct thread * thread;
 
        //lru_list에 투입하기 위한 list_elem입니다.
	struct list_elem lru;
};

void vm_hash_init (struct hash *vm_hash);

static unsigned vm_hash_func(const struct hash_elem *e, void * aux);

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b);

bool insert_vme(struct hash *vm_hash, struct vm_entry *vme);

bool delete_vme (struct hash *vm_hash, struct vm_entry *vme);

struct vm_entry * find_vme (void * vaddr);

void vm_hash_destroy (struct hash *vm_hash);

static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED);

bool load_file (void * kaddr, struct vm_entry *vme);









