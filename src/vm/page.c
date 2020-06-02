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
#include "vm/frame.h"

/*
  현재 thread의 hash table vm_hash를 initilizing을 진행합니다. 
  vm_hash_func와 vm_less_func를 인자로 가진 hash table을 생성합니다.
  이 hash table은element로 vm_entry를 가지며
  vm_entry에  내부에 있는 hash_elem을 통하여 연결합니다.
*/
void vm_hash_init (struct hash *vm_hash)
{
   hash_init(vm_hash,vm_hash_func,vm_less_func,NULL);   
}

/*
  hash_int 함수를 이용하여 vaddr값을 key value로 전환시켜 반환합니다.
*/
static unsigned vm_hash_func(const struct hash_elem *e, void * aux)
{
  unsigned result;
  struct vm_entry * e1 = hash_entry(e,struct vm_entry,elem);
  result = hash_int((uintptr_t)e1->vaddr);
  return result;

}

/*
  hash 구성원들의 vaddr 값들을 비교하여 결과 값을 bool값으로 반환합니다.
*/
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b)
{
 struct vm_entry * e1 = hash_entry(a,struct vm_entry,elem);
 struct vm_entry * e2 = hash_entry(b,struct vm_entry,elem);
 
 if(e1->vaddr<e2->vaddr)
 return true;

 else return false;

}

/*
  Hash table vm_hash에 vm_entry vme를 삽입합니다.
*/
bool insert_vme (struct hash *vm_hash, struct vm_entry *vme)
{
  struct hash_elem * e1 = hash_insert(vm_hash,&vme->elem);
  if(e1 == NULL)
  return true;

  else
  return false; 

}

/*
  Hash table vm_hash에서 vm_entry vme를 빼내고 만약 load된 상태라면 
  free_page_vme()를 이용하여 할당 해제를 한 후에 vm_entry를 반환시킵니다.
*/
bool delete_vme (struct hash *vm_hash, struct vm_entry *vme)
{
 struct hash_elem * e1 = hash_delete(vm_hash,&vme->elem);
  
 ASSERT(e1 !=NULL);
 
 if(vme->is_loaded == true)
 {
   free_page_vme(vme);
 }
 free(vme);
 return true;
 
} 

/*
  Hash table vm_hash에서 인자로 받은 vaddr과 동일한 vaddr을 가진 vm_entry를
  반환합니다. 만약 없다면 NULL을 반환합니다.
*/
struct vm_entry * find_vme (void * vaddr)
{
 struct vm_entry ve1;
 struct hash_elem * e1;

 void * pg_num =  pg_round_down (vaddr);  
 ve1.vaddr = pg_num;
 e1 = hash_find(&thread_current()->vm_hash,&ve1.elem);
 return e1!= NULL ? hash_entry(e1,struct vm_entry, elem) : NULL;
 
}

/*
  vm_destroy_func를 이용하여 hash table vm_hash를 해제합니다.
*/
void vm_hash_destroy (struct hash *vm_hash)
{
  hash_destroy(vm_hash, vm_destroy_func);
}

/*
  hash_destroy에서AUX자리에 사용하는 함수입니다.
  hash_elem을 vm_entry로 바꾸고 vm_entry를 해제합니다. 
*/
static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
  struct vm_entry * e1 = hash_entry(e,struct vm_entry,elem);
  
  if(e1==NULL)
  return;
   
  //swap slot 내부에 있다면 swap_delete을 통하여 swap_slot에서 제거합니다.  
  if(e1->type==VM_ANON && e1->swap_slot!=9999)
  swap_delete(e1->swap_slot);
  
  //만약 load되어 있다면 page를 해지합니다.
  if(e1->is_loaded==true)
  {
    free_page_vme(e1);
  }

  //vm_entry를 해지합니다.
  free(e1);
}

/*
  handle_mm_fault에서 page를 할당할 때 사용합니다. 
*/
bool load_file (void * kaddr, struct vm_entry *vme)
{   
  if(file_read_at (vme->file,kaddr,vme->read_bytes,vme->offset) == vme->read_bytes)
  {  
     memset (kaddr + vme->read_bytes, 0 , vme->zero_bytes);
     return true; 
  }
  else
  {
    return false;
  }
}

