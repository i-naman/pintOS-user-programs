#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h" 

void syscall_init (void); 
void halt (void); 
void exit (int status); 
pid_t exec (const char * cmd_lime); 
int wait (pid_t pid); 
bool create (const char * file, unsigned initial_size); 
bool remove (const char * file); 
int open (const char * file); 
int filesize (int fd); 
int read (int fd , void * buffer , unsigned size); 
int write (int fd , const void * buffer ,unsigned size); 
void seek (int fd , unsigned position); 
unsigned tell (int fd); 
void close (int fd); 

/* declarations of syscalls related to files */
bool sys_create (const char *file, unsigned initial_size);
int sys_file_size (int fd);
int sys_open (const char *file);
void sys_seek (int fd, unsigned position);
int sys_file_tell (int fd);
void sys_close_file (int fd);
int sys_file_read (int fd, void *buffer, unsigned size);
bool sys_file_del (const char *file);


#endif /* userprog/syscall.h */
