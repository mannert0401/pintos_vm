#include "userprog/syscall.h"
#include "vm/page.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

struct file
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };

/* using at filesystem's race condition */
struct lock filesys_lock;

/* using at parallel child thread's page allocation race condition */
struct lock alloc_lock;

/* process id. It is almost same with tid_t */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* mapping id. It is almost same with tid_t */
typedef int mapid_t;
#define MAP_FAILED ((mapid_t) -1);

static void syscall_handler (struct intr_frame *f);

struct vm_entry * check_address(void *addr,void *esp /*Unused*/);

void check_valid_buffer (void* buffer, unsigned size, void *esp, bool to_write);

void check_valid_string (const void *str, void * esp);

static mapid_t allocate_mapid (void);

void halt (void); 

void exit (int status);

pid_t exec (const char *file);

int wait (pid_t);

bool create (const char *file, unsigned initial_size);

bool remove (const char *file);

int open (const char *file);

int filesize (int fd);

int read (int fd, void *buffer, unsigned size);

int write (int fd, void *buffer, unsigned size);

void seek (int fd, unsigned position);

unsigned tell (int fd);

void close (int fd);

mapid_t mmap (int fd, void *addr);

void munmap (mapid_t mapid);

/* initilizing filesys_lock and 0x30 interrupt */
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
  lock_init(&alloc_lock);
}

/* It called when interrupt 0x30 is occur */
static void
syscall_handler (struct intr_frame *f) 
{
  /*
    p1 is user stack pointer saved at intr_frame
    we check p1 is user's address space and value of esp.   
  */
  uint32_t * p1 =(uint32_t*) f->esp;
  check_address((void*)p1,(void*)p1);
  
  int syscall_n=*p1;
    
  switch(syscall_n)
  {
    /*
      When system call is occured, then stack top is system call's number.
      We can select system call using this value. 
      And check all argument of system call whether they are in user address 
      and valid.
      I set p1 by uint32_t pointer. So when we increase p1 by 1, then actually
      increase value by 4byte. 
      Therefore, the esp is adjusted in units of 4bytes to pass the stack
      value to the system call function.
      And save at f->eax system call's result. 
   */ 
    case SYS_HALT:
    halt();
    break;
    
    case SYS_EXIT:
    check_address((void*)(p1+1),(void*)p1);
    exit(*(p1+1));
    break;
   
    case SYS_EXEC:
    check_address((void*)*(p1+1),(void*)p1);
    check_address((void*)p1+1,(void*)p1);
    f->eax=exec((const char*)*(p1+1));    
    break;
  
    case SYS_WAIT:
    check_address((void*)p1+1,(void*)p1);
    f->eax=wait((pid_t)*(p1+1));
    break;

    case SYS_CREATE:
    check_address((void*)p1+1,(void*)p1);
    check_address((void*)p1+2,(void*)p1);
    check_address((void*)*(p1+1),(void*)p1);
    f->eax=create((const char*)*(p1+1),(unsigned)*(p1+2));
    break;

    case SYS_REMOVE:
    check_address((void*)p1+1,(void*)p1);
    check_address((void*)*(p1+1),(void*)p1);
    f->eax=remove((const char*)*(p1+1));
    break;

    case SYS_OPEN:
    check_address((void*)p1+1,(void*)p1);
    check_address((void*)*(p1+1),(void*)p1);
    f->eax=open((const char*)*(p1+1));
    break;

    case SYS_FILESIZE:
    check_address((void*)p1+1,(void*)p1);
    f->eax=filesize(*(p1+1));
    break;

    case SYS_READ:
    check_address((void*)p1+1,(void*)p1);
    check_address((void*)p1+2,(void*)p1);
    check_valid_buffer((void*)*(p1+2),*(p1+3),(void*)p1,true);
    check_address((void*)p1+3,(void*)p1);
    f->eax=read(*(p1+1),(void*)*(p1+2),(unsigned)*(p1+3));
    break;

    case SYS_WRITE:
    check_address((void*)p1+1,(void*)p1);
    check_address((void*)p1+2,(void*)p1);
    check_valid_string((void*)*(p1+2),(void*)p1);
    check_address((void*)p1+3,(void*)p1);
    f->eax=write(*(p1+1),(void*)*(p1+2),(unsigned)*(p1+3));
    break;

    case SYS_SEEK:
    check_address((void*)p1+1,(void*)p1);
    check_address((void*)p1+2,(void*)p1);
    seek(*(p1+1),(unsigned)*(p1+2));
    break;


    case SYS_TELL:
    check_address((void*)p1+1,(void*)p1);
    f->eax=tell(*(p1+1));
    break;

    case SYS_CLOSE:
    check_address((void*)p1+1,(void*)p1);
    close(*(p1+1));
    break;

    case SYS_MMAP:
    f->eax=mmap(*(p1+1),(void*)*(p1+2));
    break;

    case SYS_MUNMAP:
    munmap((mapid_t)*(p1+1));
    break;


    default :
     exit(-1);
  }
}

/*
 check address whether this address is in user address and check whether exists vm_entry
 which is corresponding to virtual address. 
 */
struct vm_entry * check_address(void *addr,void *esp /*Unused*/)
{ 
 if(addr<=(void*)0x08048000||addr>=(void *)0xc0000000)  
    exit(-1); 
 struct vm_entry * e1 = find_vme(addr);
 if(e1 == NULL)
  exit(-1);
 return e1;
}

/* 
  READ system call 실행 시 buffer가 vm_entry를 PGSIZE마다 가지고 있고 
  쓰기 가능한지 확인하는 함수입니다. 
*/
void check_valid_buffer (void* buffer, unsigned size, void * esp, bool to_write)
{ 
  
  if(buffer==NULL)
  exit(-1);

  struct vm_entry * ve1 = check_address(buffer,esp);
  
  if(ve1 == NULL || ve1->writable != true)
  exit(-1);

  void * pg_num1 = pg_round_down(buffer); 
   
  while(pg_num1 >(void *)((uintptr_t)buffer+size))
  {
  ve1 =  check_address(pg_num1,esp); 
  if(ve1 == NULL || ve1->writable != to_write)
  exit(-1);
  pg_num1 =(void *)((uintptr_t)pg_num1 + PGSIZE);
  }
 
}

/*
  Write system call 실행 시 read해야 하는 string이 유요한지 check하는 함수입니다.
*/
void check_valid_string (const void *str, void * esp)
{
  struct vm_entry * ve1 =  check_address(str,esp);
  if(ve1==NULL)
 {
  exit(-1);
 }
}

/* halt is just shut down pintos program */
void halt (void)
{
  shutdown_power_off();
}

/* exit is finishing current process and print exit status. */
void exit (int status)
{ 
 struct thread * t1 = thread_current();
 t1->exit_status = status;
 printf("%s: exit(%d)\n",t1->name,status);
 thread_exit();
}

/* 
   exec is kind of fork at the pintos. 
   It execute file by calling process execute.  
*/
pid_t exec (const char *file)
{
 
 pid_t child_pid;

 child_pid = process_execute(file);
 sema_down(&thread_current()->sema_load);   
 if(thread_current()->pr_success==false)
 return -1;

 
 return child_pid; 
  
}

/*
   wait pid's process is terminate.  
*/
int 
wait (pid_t pid)
{
  return (process_wait(pid)); 
}

/*
    create file by initial size.
*/
bool
create (const char * file, unsigned initial_size)
{
  
  
  if(file==NULL)
  exit(-1);   
 
  return (filesys_create(file, initial_size));
}

/*
    remove given file using filesys_remove.
*/
bool
remove (const char *file)
{ 
 
  return (filesys_remove(file));
}

/*
   open file is already created using filesys_open function. 
   It must deny write because it is opend by this thread. 
   And add filedescriptor of this thread.
*/
int open(const char * file)
{

 if(file==NULL)
 return -1;

 
 lock_acquire(&filesys_lock); 
 struct file *f1 = filesys_open(file);
 lock_release(&filesys_lock);
 int fd1 = process_add_file(f1);
  
 
 return (fd1);
}

/*
   return filesize saved at filedescriptor.
   fd is index of filedescriptor.
*/
int filesize(int fd)
{
 struct file * f1 = process_get_file(fd);
 if(f1==NULL)
 return (-1);
 return (file_length(f1));
}

/*
   read file descriptor's file and save at buffer as size. 
   fd is stdinput, so we can implement using input_getc.
   If fd is not 0, we can implement using file_read function. 
   Equally, this function return reading file size. 
*/
int read(int fd, void * buffer, unsigned size)
{
  
 int i;
 lock_acquire(&filesys_lock); 
 if(fd==0)
 { 

  for(i=0; i<size; i++)
    { 
      ((uint8_t*)buffer)[i] = input_getc();
    }

    lock_release(&filesys_lock);
    return size;
 }
 else 
  { struct file * f1 = process_get_file(fd);
 
    if(f1==NULL)
    {
    lock_release(&filesys_lock);
    return -1;
    }
  
    size=file_read(f1,buffer,size);
  

    lock_release(&filesys_lock);

    return size;   
  }
 
}

/*
   Write at file from buffer. 
   If fd==1, then it is stdout. We can implement using putbuf.
   If fd=!1, we can implement using file_write and return size of write. 
*/
int write(int fd, void * buffer, unsigned size)
{  
   lock_acquire(&filesys_lock); 
  if(fd==1)
  {  
   putbuf(buffer,size);
    
    lock_release(&filesys_lock);
      
   return size;
    
  }
  else
  {   
   
    struct file * f1 = process_get_file(fd);
   if(f1==NULL)
    {   
     lock_release(&filesys_lock);
     return -1;
    }
   
   size = file_write(f1,buffer,size);
   lock_release(&filesys_lock);
   return size;
   
  }
  
}

/*
   seek position at file in filedescriptor index fd
   and set file structure's position.
   we can implement this system call using file_seek.
*/

void seek(int fd, unsigned position)
{
 struct file * f1 = process_get_file(fd);
 if(f1==NULL)
 exit(-1);
 file_seek(f1,position);
}

/* 
    tell file position in filedescriptor's fdth file
*/

unsigned tell(int fd)
{
 struct file * f1 = process_get_file(fd);
 if(f1==NULL)
 exit(-1);
 return (file_tell(f1));
}

/*
    close file using process_close_file.
*/
void close(int fd)
{
   process_close_file(fd);
}

/*
  file을 memory mapping할 때 사용하는 사용하는 system call입니다. 
  fd에 열려있는 file을 addr에 maaping합니다.
*/
mapid_t mmap (int fd, void *addr)
{
 //address가 유저 영역이 아니면 error를 return합니다.
 if(addr<(void*)0x08048000||addr>=(void *)0xc0000000)
  return MAP_FAILED;
  
 size_t fl1;
 
 off_t ofs = 0;
 
 //fd와 addr의 유효함을 check합니다.
 if(fd<2||fd>128||addr==0||addr==NULL)
 {
  return MAP_FAILED;
 }
 
 if(pg_ofs(addr)!=0)
 { 
  return MAP_FAILED;
 }

 //fd에 대응되는 file을 불러옵니다.
 struct file * f1 = process_get_file(fd);
 
 struct list_elem * e1;
  
 //f1의 크기를 불러옵니다. 
 fl1 = file_length(f1);
 
 //파일이 유효한지 체크합니다.
 if(f1 == NULL||fl1==0)
 {
   return MAP_FAILED;
 }

 //파일을 mapping할 것이기 때문에 reopen을 이용합니다.
 f1 =  file_reopen (f1);

 //reopen이 제대로 되었는지 확인합니다.
 if(f1 == NULL)
 {
  return MAP_FAILED;
 }

 //mmap id을 할당합니다. 
 mapid_t id1 = allocate_mapid(); 

 //mmap file을 할당하고 mmap에 관한 정보를 저장합니다. 
 //mmap file은 mmap에 이용된 vm_entry를 모아두기 위한 구조체입니다.
 struct mmap_file * mf1=malloc(sizeof(struct mmap_file));

 mf1->mapid = id1;
 mf1->file = f1;

 //현재 thread의 mmap_list에 mmap_file을 삽입합니다.
 list_push_back(&thread_current()->mmap_list,&mf1->elem);

 //mmap_file의 vme_list를 할당합니다.
 list_init(&mf1->vme_list);
 
 int i=0;
 
 //파일을 memory에 올리기 위하여 vm_entry를 할당하고 vme_list에 저장합니다.
 while(fl1>0)
{

 if(find_vme(addr)!=NULL)
 return MAP_FAILED;
 
 /* 
    vm_entry를 생성하고 데이터를 입력합니다. 나중에 실제로 page가 호출되면
    그때 load_page를 이용하여 할당합니다.
 */
 
 size_t page_read_bytes = fl1< PGSIZE? fl1 : PGSIZE;
 size_t page_zero_bytes = PGSIZE - page_read_bytes;
 struct vm_entry * ve1 = malloc(sizeof(struct vm_entry));
 ve1->type = VM_FILE;
 ve1->vaddr = addr;
 ve1->writable = (!f1->deny_write);
 ve1->is_loaded = false;
 ve1->file = f1;
 ve1->offset = ofs;
 ve1->read_bytes = page_read_bytes;
 ve1->zero_bytes = page_zero_bytes;
 ve1->swap_slot = 9999;
 
 insert_vme (&thread_current()->vm_hash,ve1);
 
 //vme_list에 순서대로 삽입합니다.
 list_push_back(&mf1->vme_list,&ve1->mmap_elem);

 /* advance */
 fl1 -= page_read_bytes;
 ofs += page_read_bytes;
 addr = (void *)((uintptr_t)addr + PGSIZE);
}

//mmap한 mmapid를 return합니다.
return id1;
}

//file을 memory unmapping 할 때 사용됩니다.
void munmap (mapid_t mapid)
{ 

  struct thread * cur = thread_current();
  struct list_elem * e1;
  struct mmap_file * mf1;

  //mmap_list에서 인자로 받은 mapid와 일치하는 mmap file을 찾습니다.
   for(e1=list_begin(&cur->mmap_list); e1!=list_end(&cur->mmap_list); e1=list_next(e1))
 {
   mf1 = list_entry(e1,struct mmap_file,elem);
   if(mf1->mapid == mapid)
    break;
 }

  //만약 존재하지 않으면 void를 반환하고 끝냅니다.
  if((e1) == list_end(&cur->mmap_list))
   return;
 
  //존재한다면 list에서 제거하고 do_munmap을 이용하여 memory unmapping을 진행합니다.
  list_remove(e1); 
  
  do_munmap(mf1);

 
} 


//static 변수를 이용하여 mapid를 생성합니다.
static mapid_t allocate_mapid (void)
{
 static mapid_t next_mapid = 1;
 mapid_t mapid = next_mapid;

 return mapid;
}

