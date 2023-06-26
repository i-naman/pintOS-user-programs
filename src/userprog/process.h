#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

typedef int pid_t;
#define PID_ERROR ((pid_t) -1)          

struct process_status {
  bool loaded;                        
  bool exited;                        
  bool failed;                        
  bool wait_called;                   
};

struct process_node {

  int pid;                            
  char name[16];                      
  struct thread * parent_thread;             
  int termination_status;                      
  struct process_status status;
  struct list open_files_list;                  
  struct list_elem process_ref;            

};



pid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (int status);
void process_activate (void);
struct process_node* initialize_status(struct process_node* p);
#endif 
