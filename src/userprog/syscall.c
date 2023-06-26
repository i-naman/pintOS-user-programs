#include "userprog/syscall.h"
#include <stdlib.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include <string.h>


/* file_metadata: file descriptor struct */
struct file_metadata {
  int fd;
  int parent_pid;
  struct file * file;
  struct list_elem elem;
};

static struct list file_desc_list; 
static struct lock fd_lock;
static struct lock file_lock;
static int next_fd = 2;
static void syscall_handler (struct intr_frame *);

void fdlist_del_fd(int fd);
bool is_valid_stack_pointer(void * address);
bool check_valid_u_address(struct intr_frame *f, void * address);
int write (int fd, const void *buffer, unsigned size);
struct file_metadata * create_fd(int fd, struct file * new_file);
struct file * get_file(int fd);
struct file_metadata * fdlist_get_fd(int fd);

/* init */
void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fd_lock);
  lock_init (&file_lock);
  list_init (&file_desc_list);
}

static void syscall_handler (struct intr_frame *f) 
{
  void * address;
  int syscall_id;
  int fd;
  int pid;
  const void * buffer;
  int size;
  int status;
  const char *filename;
  unsigned initial_size;
  unsigned pos;
  const char * cmd_line;
  
  address = f->esp;
  check_valid_u_address(f, address);
  
  syscall_id = *(int *)address;

  switch (syscall_id) {
    
  case SYS_HALT:

    shutdown_power_off ();
    break;
    
  case SYS_EXIT:

    address = address + 4;
    if (check_valid_u_address(f, address)) break;

    status = *(int *)address;
    f->eax = sys_exit (status);
    break;
    
  case SYS_EXEC:
    
    address = address + 4;
    if (check_valid_u_address(f, address)) break;

    cmd_line = *(const char **)address;
    if (check_valid_u_address(f, cmd_line)) break;

    if (!cmd_line || !strcmp(cmd_line,"")) {
      f->eax = sys_exit(-1);
    }

    f->eax = (int)process_execute (cmd_line);
    break;
    
  case SYS_WAIT:

    address = address + 4;
    if (check_valid_u_address(f, address)) break;

    pid = *(int *)address;
    f->eax = (int)process_wait (pid);
    break;
    
  case SYS_CREATE:

    address = address + 4;
    if (check_valid_u_address(f, address)) break;

    filename = *(const char **)address;
    if (!filename || !strcmp(filename,"")) {
      f->eax = sys_exit(-1);
    }

    address = address + 4;
    if (check_valid_u_address(f, address)) break;

    initial_size = *(unsigned *)address;

    f->eax = sys_create(filename, initial_size);
    break;
    
  case SYS_REMOVE:

    address = address + 4;
    if (check_valid_u_address(f, address)) break;

    filename = *(const char **)address;
    if (!filename) {
      f->eax = false;
    }

    f->eax = sys_file_del (filename);
    break;
    
  case SYS_OPEN:

    address = address + 4;
    if (check_valid_u_address(f, address)) break;

    filename = *(const char **)address;
    if (!filename) {
      f->eax = sys_exit(-1);
    }

    f->eax = sys_open (filename);
    break;
    
  case SYS_FILESIZE:

    address = address + 4;
    if (check_valid_u_address(f, address)) break;
    
    fd = *(int *)address;
    f->eax = sys_file_size (fd);
    break;
    
  case SYS_READ:

    address = address + 4;
    if (check_valid_u_address(f, address)) break;
    fd = *(int *)address;
    
    address = address + 4;
    if (check_valid_u_address(f, address)) break;
    buffer = *(const void **)address;
    if (check_valid_u_address(f, buffer)) break;

    address = address + 4;
    if (check_valid_u_address(f, address)) break;
    size = *(unsigned *)address;

    f->eax = sys_file_read (fd, buffer, size);
    break;

  case SYS_WRITE:

    address = address + 4;
    if (check_valid_u_address(f, address)) break;
    fd = *(int *)address;
    
    address = address + 4;
    if (check_valid_u_address(f, address)) break;

    buffer = *(const void **)address;
    if (check_valid_u_address(f, buffer)) break;

    address = address + 4;
    if (check_valid_u_address(f, address)) break;

    size = *(unsigned *)address;
    f->eax = write(fd, buffer, size);
    
    break;

  case SYS_SEEK:

    address = address + 4;
    if (check_valid_u_address(f, address)) break;
    fd = *(int *)address;
    
    address = address + 4;
    if (check_valid_u_address(f, address)) break;
    pos = *(int *)address;
    
    sys_seek (fd, pos);
    break;
    
  case SYS_TELL:

    address = address + 4;
    if (check_valid_u_address(f, address)) break;
    fd = *(int *)address;

    f->eax = sys_file_tell (fd);
    break;
    
  case SYS_CLOSE:

    address = address + 4;
    if (check_valid_u_address(f, address)) break;
    fd = *(int *)address;

    sys_close_file (fd);
    break;
    
  default:
    f->eax = sys_exit (0);
  }
}

bool is_valid_stack_pointer(void * address)
{
  return ((address != NULL) && is_user_vaddr(address) && pagedir_get_page(thread_current ()->pagedir, address));
}

/* Check if memory access location is valid */
bool check_valid_u_address(struct intr_frame *f, void * address)
{
  if (is_valid_stack_pointer(address)) {
    return false;
  }
  else {
    f->eax = sys_exit (-1);
    return true;
  }
}



/* Write to a file */
int write (int fd, const void *buffer, unsigned size) 
{
  int bytes = 0;
  if (size == 0) return 0;

  lock_acquire (&file_lock);

  if (fd == 1) putbuf (buffer, size);

  struct file *file = get_file(fd);
  if (!file) {
    lock_release (&file_lock);
    return -1;
  }

  bytes = file_write (file, buffer, size);
  lock_release (&file_lock);

  return bytes;
}

int sys_exit (int status)
{
  printf("%s: exit(%d)\n", thread_current ()->name, status);
  thread_exit(status);

  return status;
}

/* Create a file */
bool sys_create (const char *filename, unsigned initial_size)
{
  bool success;
  lock_acquire (&file_lock);
  success = filesys_create (filename, initial_size);
  lock_release (&file_lock);
  return success;
}

/* Open a file */
int sys_open (const char *filename)
{
  struct file * new_file;
  struct file_metadata * fdesc;
  
  lock_acquire (&file_lock);
  new_file = filesys_open (filename);
  if (!new_file) {
    lock_release (&file_lock);
    return -1;
  }
  int fd;

  lock_acquire (&fd_lock);
  fd = next_fd++;
  lock_release (&fd_lock);
  fdesc = create_fd(fd, new_file);
  lock_release (&file_lock);
  
  return fd;
}

/* get file size */
int sys_file_size (int fd)
{
  struct file *file = NULL;

  lock_acquire (&file_lock);
  file = get_file(fd);
  if (!file) {
    lock_release (&file_lock);
    return -1;
  }

  lock_release (&file_lock);
  return (file_length (file));
}

/* seek in file. */
void sys_seek (int fd, unsigned position)
{
  struct file *file;
  lock_acquire (&file_lock);
  file = get_file(fd);
  if (!file) {
    lock_release (&file_lock);
    return;
  }
  file_seek (file, position);
  lock_release (&file_lock);
}

/* get curr position in file */
int sys_file_tell (int fd)
{
  struct file *file;

  lock_acquire (&file_lock);
  file = get_file(fd);
  if (!file) {
    lock_release (&file_lock);
    return -1;
  }
  lock_release (&file_lock);
  return (file_tell (file));
}

/* Close a file */
void sys_close_file (int fd)
{
  struct file_metadata *fdesc;

  lock_acquire (&file_lock);
  fdesc = fdlist_get_fd(fd);
  if (!fdesc->file) {
    lock_release (&file_lock);
    return;
  }

  if (fdesc->parent_pid != thread_current()->tid) {
    lock_release (&file_lock);
    return;
  }
  
  fdlist_del_fd(fd);
  file_close (fdesc->file);
  lock_release (&file_lock);
}

/* Read from file */
int sys_file_read (int fd, void *buffer, unsigned size)
{
  struct file *file;
  struct file_metadata *fdesc;
  int bytes = 0;

  lock_acquire (&file_lock);
  fdesc = fdlist_get_fd(fd);
  file = fdesc->file;

  if (!file) {
    lock_release (&file_lock);
    return (sys_exit(-1));
  }
  bytes = file_read (file, buffer, size);
  lock_release (&file_lock);
  
  return (bytes);
}

/* Delete file */
bool sys_file_del (const char *name)
{
  struct dir *dir;
  struct inode *inode = NULL;

  lock_acquire (&file_lock);
  dir = dir_open_root ();
  if (dir != NULL)
    dir_lookup (dir, name, &inode);
  dir_close (dir);

  if (!inode) {
    lock_release (&file_lock);
    return false;
  }
  inode_remove (inode);
  inode_close (inode);

  lock_release (&file_lock);
  return true;

}

/* Creates a new file_descriptor element and updates file_desc_list. */
struct file_metadata * create_fd(int fd, struct file * new_file)
{

  struct file_metadata * fdesc = (struct file_metadata *)malloc(sizeof(struct file_metadata));

  fdesc->fd = fd;
  fdesc->file = new_file;

  enum intr_level old_level = intr_disable();
  fdesc->parent_pid = thread_current()->tid;
  list_push_back (&file_desc_list, &fdesc->elem);
  intr_set_level (old_level);
  
  return fdesc;
}

/* Returns the file corresponding to given fd. */
struct file * get_file(int fd)
{
  struct file *file = NULL;
  enum intr_level old_level; 
  struct list_elem *e;
  
  old_level = intr_disable();

  e = list_begin (&file_desc_list);
  struct file_metadata *fdesc = list_entry (e, struct file_metadata, elem);
  while (e != list_end (&file_desc_list)) {
    
    if (fdesc->fd == fd) {
      file = fdesc->file;
      break;
    }
    e = list_next(e);
  }
  intr_set_level (old_level);

  return file;
}

/* removes fd from list. */
void fdlist_del_fd(int fd)
{
  enum intr_level old_level; 
  struct list_elem *e;
  
  old_level = intr_disable ();
  
  for (e = list_begin (&file_desc_list); e != list_end (&file_desc_list);
       e = list_next (e)) {
    
    struct file_metadata *fdesc = list_entry (e, struct file_metadata, elem);
    if (fdesc->fd == fd) {
      list_remove (&fdesc->elem);
      break;
    }
  }
  intr_set_level (old_level);

}

/* get the file corresponding to given fd */
struct file_metadata * fdlist_get_fd(int fd)
{
  enum intr_level old_level; 
  struct list_elem *e;
  struct file_metadata * res = NULL;
  
  old_level = intr_disable ();
  
  for (e = list_begin (&file_desc_list); e != list_end (&file_desc_list);
       e = list_next (e)) {
    
    struct file_metadata *fdesc = list_entry (e, struct file_metadata, elem);
    if (fdesc->fd == fd) {
      res = fdesc;
      break;
    }
  }
  intr_set_level (old_level);

  return res;
}
