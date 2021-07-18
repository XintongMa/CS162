#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "stdbool.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "string.h"
#include "threads/malloc.h"
#include "filesys/inode.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "filesys/off_t.h"

struct lock filesys_lock;

static void syscall_handler(struct intr_frame*);

static int allocate_fd(void){
  static int nextfd = 2;
  int fd;
  fd = nextfd++;
  return fd;
}

struct open_file *get_file (int fd)
{
  struct list *list_ = &thread_current ()->filetable;
  struct list_elem *e;
  for (e = list_begin(list_); e != list_end (list_); e = list_next (e)) {
    struct open_file *of = list_entry (e, struct open_file, elem);
    if (of->fd == fd)
      return of;
  }
  return NULL;
};

static bool argcheck(uint32_t* args, int argc){
  struct thread* cur = thread_current();
  uint32_t* pd;
  pd = cur->pagedir;
  for(int i=0; i<=argc; i++){
    if(!is_user_vaddr(&args[i])) return false;
    if(pagedir_get_page(pd,&args[i])==NULL) return false;
  }  
  return true;
}

static bool argcheck1(uint32_t* args){
  struct thread* cur = thread_current();
  uint32_t* pd;
  pd = cur->pagedir;
  if(!is_user_vaddr(args)) return false;
  if(pagedir_get_page(pd,args)==NULL) return false; 
  if(!is_user_vaddr(args + 1)) return false;
  if(pagedir_get_page(pd,args + 1)==NULL) return false; 
  return true;
}

static bool argcheck2(void* args, int size){
  struct thread* cur = thread_current();
  uint32_t* pd;
  pd = cur->pagedir;
  int i;
  for ( i = 0; i < size; i++)
    {
      if(!is_user_vaddr(args+i)) return false;
      if(pagedir_get_page(pd,args+i)==NULL) return false; 
    }   
  return true;
}

static void kille(uint32_t* args, int argc){
  if(!argcheck(args,argc)){
    printf("%s: exit(%d)\n", &thread_current()->name, -1);
    thread_exit();
  }
}

static void kille1(uint32_t* args){
  if(!argcheck1(args)){
    printf("%s: exit(%d)\n", &thread_current()->name, -1);
    thread_exit();
  }
}

static void kille2(void* args, int size){
  if(!argcheck2(args, size)){
    printf("%s: exit(%d)\n", &thread_current()->name, -1);
    thread_exit();
  }
}

void syscall_init(void)
  {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init (&filesys_lock);
  }

static void syscall_handler(struct intr_frame* f UNUSED) {

  //struct lock *l;
  //lock_init(l);

  uint32_t* args = ((uint32_t*)f->esp);

  kille1(args);

  if(f == NULL){
    printf("%s: exit(%d)\n", &thread_current()->name, -1);
    thread_exit();
  }

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */
  kille(args,1);

  if (args[0] == SYS_EXIT) {
    kille(args,2);
    thread_current()->ws->exit_code = args[1];
    thread_current()->ws->terminated = true;
    file_allow_write(thread_current()->ws->exe);
    printf("%s: exit(%d)\n", &thread_current()->name, args[1]);
    thread_exit();
  }

  if (args[0] == SYS_PRACTICE) {
    kille(args,1);
    f->eax = args[1] + 1;
  }

  if (args[0] == SYS_WRITE) {
    //lock_acquire (&filesys_lock);
    kille(args,4);
    kille1((uint32_t *)args[2]);
    //kille1(((uint32_t *)args[2])+args[3]);
    if(args[1]==1){
      putbuf ((void *) args[2], args[3]);
      f->eax = args[3];
    }
    if(args[1]>=2){
      struct open_file *of = get_file(args[1]);
      if(of!=NULL) f->eax = file_write(of->f,(void *)args[2],args[3]);
      else f->eax = -1;
    }
    //lock_release (&filesys_lock);
  }

  if(args[0] == SYS_HALT) {
    kille(args,1);
    shutdown_power_off();
  }

  if(args[0] == SYS_EXEC){
    kille(args,2);
    kille1((uint32_t *)args[1]);
    tid_t temp;
    
    temp = process_execute((const char*)args[1]);
    
    if((temp == TID_ERROR)||(temp == -1)) f->eax = ((pid_t)-1);
    else f->eax = ((pid_t)temp);
  }

  if (args[0] == SYS_WAIT) {
    kille(args,2);
    f->eax = process_wait(args[1]);
  }

  if (args[0] == SYS_CREATE) {
    //lock_acquire (&filesys_lock);
    kille(args,3);
    kille1((uint32_t *)args[1]);
    if(*(char *)args[1] == '\0'){
      printf("%s: exit(%d)\n", &thread_current()->name, -1);
      thread_exit();
      f->eax = -1;
    }
    else if(strlen((char *)args[1])>20) f->eax = 0;
    else f->eax = filesys_create((const char *)args[1],args[2]);
    //lock_release (&filesys_lock);
  }

  if (args[0] == SYS_REMOVE) {
    //lock_acquire (&filesys_lock);
    kille(args,2);
    f->eax = filesys_remove((const char*)args[1]);
    //lock_release (&filesys_lock);
  }

  if (args[0] == SYS_OPEN) {
    //lock_acquire (&filesys_lock);
    kille(args,2);
    kille1((uint32_t *)args[1]);
    if(*(char *)args[1] == '\0'){
      f->eax = -1;
    }
    struct file* temp = filesys_open((const char *)args[1]);
    if(temp==NULL){
      f->eax = -1;
      }
    else{
      struct open_file *of = malloc(sizeof(struct open_file));
      if (!of) 
      {
        file_close (temp);
        f->eax = -1;
        goto done;
      }
      of->fd = allocate_fd();
      of->size = file_length(temp);
      of->f = temp;
      of->position = 0;
      list_push_back(&thread_current()->filetable,&of->elem);
      f->eax = of->fd;
    }
    
    done:
    return;
      //lock_release (&filesys_lock);
  }

  if (args[0] == SYS_FILESIZE) {
    //lock_acquire (&filesys_lock);
    kille(args,2);
    struct open_file *of = get_file(args[1]);
    f->eax = of->size;
    //lock_release (&filesys_lock);
  }

  if (args[0] == SYS_READ) {
    //lock_acquire (&filesys_lock);
    kille(args,4);
    kille1((uint32_t *)args[2]);
    kille2((void *)args[2], args[3]);
    if(args[1]==0) input_getc();
    if(args[1]>=2){
      struct open_file *of = get_file(args[1]);

      if(of!=NULL) f->eax = file_read(of->f,(void *)args[2],args[3]);
      else f->eax = -1;
  
    }
    //lock_release (&filesys_lock);
  }

  if (args[0] == SYS_SEEK) {
    //lock_acquire (&filesys_lock);
    kille(args,3);
    struct open_file *of = get_file(args[1]);
    if(of!=NULL) {
      file_seek(of->f, args[2]);
    }
    //lock_release (&filesys_lock);
  }

  if (args[0] == SYS_TELL) {
    //lock_acquire (&filesys_lock);
    kille(args,2);
    struct open_file *of = get_file(args[1]);
    if(of!=NULL) {
      f->eax = file_tell(of->f);
    }
    //lock_release (&filesys_lock);
  }

  if (args[0] == SYS_CLOSE) {
    //lock_acquire (&filesys_lock);
    kille(args,2);
    struct open_file *of = get_file(args[1]);
    if(of!=NULL) {
      file_close(of->f);
      list_remove (&of->elem);
      free (of);
    }
    //lock_release (&filesys_lock);
  }

  /*if (args[0] == SYS_MMAP) {
    kille(args,3);
  }

  if (args[0] == SYS_MUNMAP) {
    kille(args,2);
  }

  if (args[0] == SYS_CHDIR) {
    kille(args,2);
  }

  if (args[0] == SYS_MKDIR) {
    kille(args,2);
  }

  if (args[0] == SYS_READDIR) {
    kille(args,3);
  }

  if (args[0] == SYS_ISDIR) {
    kille(args,2);
  }

  if (args[0] == SYS_INUMBER) {
    kille(args,2);
  }*/
}
