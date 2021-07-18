#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/off_t.h"

struct wait_status{
  struct list_elem elem;
  tid_t tid;
  int exit_code;
  struct semaphore dead;
  struct semaphore loaded;
  bool terminated;
  bool waited;
  bool load;
  struct file *exe; 
  struct lock lock; 
  int ref_cnt;  
  bool killed;
};

struct open_file{
  struct list_elem elem;
  int fd;
  unsigned size;
  struct file *f;
  off_t position;
};

tid_t process_execute(const char* file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

#endif /* userprog/process.h */
