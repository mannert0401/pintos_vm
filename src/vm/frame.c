#include "threads/thread.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

static struct list lru_list;
struct lock lru_list_lock;
static struct list_elem * lru_clock;
static struct list_elem* get_next_lru_clock();

//lru_list를 할당하고 lock을 initilizing을 합니다.
void lru_list_init (void)
{
 list_init(&lru_list);
 lock_init(&lru_list_lock);
 lru_clock = NULL;
}

//lru_list에 page를 삽입합니다. page가 실제로 할당됬을 때 반드시 호출되어야 합니다.
void add_page_to_lru_list(struct page* page)
{
  lock_acquire(&lru_list_lock);
  list_push_back(&lru_list,&page->lru);
  lock_release(&lru_list_lock);
}

/*
  lru_list에서 해당 page를 제거합니다. 만약 해당 page가 lru_clock이라면
  clock을 다음 page로 설정합니다.
*/   
void del_page_from_lru_list(struct page* page)
{
 
 if(&page->lru == lru_clock)
 {
  lru_clock = list_remove(&page->lru);
  if(lru_clock==list_end(&lru_list))
  lru_clock = list_begin(&lru_list);
 }
 else
 list_remove(&page->lru);

}

/*
  page를 할당할 때 사용합니다. palloc_get_page()를 이용하여 물리 페이지를 할당합니다.
  만약 page가 NULL이라면 victim page를 선정하여 방출한 뒤 그 자리에 새로운 페이지를
  할당합니다. 위 과정은 eviction_and_alloc()에서 실행됩니다. 
*/
struct page* alloc_page(enum palloc_flags flags)
{

 void * pg1 =  palloc_get_page(flags); 
 struct page * p1; 
 if(pg1 == NULL)
 {
  p1 = eviction_and_alloc(flags); 
  ASSERT(p1!=NULL); 
  return (p1);
 }
 ASSERT(pg1!= NULL);
 
 p1 = malloc(sizeof(struct page));
 ASSERT(p1 != NULL);
 p1->kaddr = pg1;
 p1->thread = thread_current();

 return (p1);
}

/*
  주어진 vm_entry를 이용하여 page를 해제합니다. lru_list를 한 바퀴 돌아서 page에 저장된
  vm_entry와 일치하는 것을 찾은 후 page를 해제합니다.
*/
void free_page_vme(struct vm_entry * vme)
{
 lock_acquire(&lru_list_lock); 

 struct list_elem * e1 = list_begin(&lru_list);
 struct page * p1;

 //lru를 traverse하며 vm_entry를 찾습니다. 
 while(e1 != list_end(&lru_list))
 {
   p1 = list_entry(e1,struct page,lru);
   if(p1->vme == vme)
   break;
   e1 = list_next(e1);
 }
 
 ASSERT(e1!=list_end(&lru_list)) 
 //__free_page()에서 실질적인 page 해지를 실행합니다.
 __free_page(p1);

 lock_release(&lru_list_lock); 
}

/*
  주어진 kaddr과 일치하는 page를 해제합니다. lru_list를 한 바퀴 돌아서 page에 저장된
  vm_entry와 일치하는 것을 찾은 후 page를 해제합니다.
*/
void free_page(void *kaddr)
{ 
  lock_acquire(&lru_list_lock); 

  struct list_elem * e1=list_begin(&lru_list);
  struct page * p1;
 
  //lru를 traverse하며 kaddr이 일치하는 page를 찾습니다.
  while(e1 != list_end(&lru_list))
 {
   p1 = list_entry(e1,struct page,lru);
   if(p1->kaddr == kaddr)
   break;
   e1 = list_next(e1);
 }

 //__free_page()에서 실질적인 page 해지를 실행합니다.
 ASSERT(e1!=list_end(&lru_list))
 __free_page(p1);
 
 lock_release(&lru_list_lock); 

}

/*
   page를 lru_list에서 제거하고 pagedir에서 유효하지 않게 만듭니다.
   그리고 vm_entry의 is_loaded를 false로 전환한 뒤에 해당 물리 page를 해지하고
   page 구조체도 해지합니다.
*/
void __free_page(struct page* page)
{ 
 del_page_from_lru_list(page);
 pagedir_clear_page(page->thread->pagedir,page->vme->vaddr);
 page->vme->is_loaded = false;
 palloc_free_page(page->kaddr);
 free(page);
}

/* clock의 다음 page를 return합니다. 만약 tail이라면 가장 앞으로 돌아갑니다. */
static struct list_elem* get_next_lru_clock()
{
 
 if(lru_clock == NULL||(list_next(lru_clock)==list_end(&lru_list)))
 {
   if(list_empty(&lru_list))
      return NULL;
    else      
      return list_begin(&lru_list);
 }
 return list_next(lru_clock);

}

/*
    victim page 선정 후에 swap영역으로 방출하고 page를 할당하여 return합니다.
*/
struct page* eviction_and_alloc(enum palloc_flags flags)
{  
    lock_acquire(&lru_list_lock);

    //lru_clock은 항상 한 번 넘어가고 시작합니다.
    lru_clock = get_next_lru_clock();

    struct page * p1 = list_entry(lru_clock,struct page,lru);   

    //accessed bit가 0인 page를 찾습니다. 만약 1이라면 0으로 전환하고 다음 lru로 넘어갑니다
    while(pagedir_is_accessed(p1->thread->pagedir,p1->vme->vaddr))
   {  
     pagedir_set_accessed(p1->thread->pagedir,p1->vme->vaddr,false); 
     lru_clock = get_next_lru_clock();
     p1 = list_entry(lru_clock,struct page,lru);
   }   
    
    //선정된 victim에 type에 따라 다르게 swap_out을 진행합니다.
    switch(p1->vme->type)
  {  
    //binary 파일의 경우에는 dirty page의 경우에만 swap영역으로 방출합니다.
    case VM_BIN :
    if(pagedir_is_dirty(p1->thread->pagedir,p1->vme->vaddr))
    {
     p1->vme->swap_slot = swap_out(p1->kaddr); 
     p1->vme->type = VM_ANON;
   
    }
    break;
    
    //memory mapped file의 경우에는 dirty page의 경우에만 덮어 쓰기를 진행합니다.
    case VM_FILE :
    if(pagedir_is_dirty(p1->thread->pagedir,p1->vme->vaddr))
    {
      lock_acquire(&filesys_lock); 
      file_write_at(p1->vme->file,p1->vme->vaddr,p1->vme->read_bytes,p1->vme->offset);
      pagedir_set_dirty(p1->thread->pagedir,p1->vme->vaddr,0);
      lock_release(&filesys_lock);
    }
    break;

    /*
      stack의 경우이거나 한 번 이상 swap 영역에 들어갔다 나온 binary 파일인 경우에
      그냥 swap_out을 진행합니다.
    */
    case VM_ANON :
    p1->vme->swap_slot = swap_out(p1->kaddr);
  
    break;

    default :
     return NULL;
   } 
  //해당 page를 제거하고 다시 만듭니다.
  __free_page(p1);
  p1 = malloc(sizeof(struct page));
  p1->kaddr = palloc_get_page(flags);
  p1->thread = thread_current();
  lock_release(&lru_list_lock);
  return p1;
}


