# pintOS-user-programs
Operating Systems Project - PintOS User Programs 

# Instructions
Refer Project.doc for project information

# Report


		     +--------------------------+
             | CS 521	                |
		     | PROJECT 2: USER PROGRAMS	|
		     | DESIGN DOCUMENT        	|
		     +--------------------------+

---- GROUP ----

>> Fill in the names and email addresses of your group members.

Naman Agrawal <namanagr@buffalo.edu>
Venkata Hemanth Athota <vathota@buffalo.edu>
Hrushikesh Poola <hpoola@buffalo.edu>

---- PRELIMINARIES ----

>> If you have any preliminary comments on your submission, notes for the
>> TAs, or extra credit, please give them here.

>> Describe briefly which parts of the assignment were implemented by
>> each member of your team. If some team members contributed significantly
>> more or less than others (e.g. 2x), indicate that here.

Naman Agrawal :  1x
Venkata Hemanth Athota : 1x
Hrushikesh Poola : 1x

>> Please cite any offline or online sources you consulted while
>> preparing your submission, other than the Pintos documentation, course
>> text, lecture notes, and course staff.

			   ARGUMENT PASSING
			   ================

---- DATA STRUCTURES ----

>> A1: Copy here the declaration of each new or changed `struct' or
>> `struct' member, global or static variable, `typedef', or
>> enumeration.  Identify the purpose of each in 25 words or less.
	struct command_node
	{
	  char **argv; 
	  int argc;
	  int total_char_len;
	};
	This struct has been defined to store info about command 
	line arguments that are yet to be parsed and processed.

---- ALGORITHMS ----

>> A2: Briefly describe how you implemented argument parsing.  How do
>> you arrange for the elements of argv[] to be in the right order?
>> How do you avoid overflowing the stack page?

 1.Implementation of argument parsing:
 	- We have defined a new struct that handles the arguments 
 	from command line, using a recursive method for the 
 	function strtok_r()
 	- Memory is allocated using a allocator function.
 	- argc member has the count saved.
 	- All of this is done at the intial part of load()
	- We implement the argument parsing part by using setup_stack method after creating the page for each process

 2.Handling argv[] to get the correct order:
	- we have stored the stack pointer while pushing them to the stack using setup_stack method
	
	What we have as boilerplate as part of process_execute() method the parameter is filename which needs to be changed
	to handle arguments to the commands. so we split the filename using strtok_r() and split the command and arguments in the given order.

 3. Handling overflow:
	- you could limit the arguments size to some threshold value and if the size exceeds the threshold we will not allow the command to run.
	or
	- Since the above method seems restricitve on the number of arguments for a command we choose to accomodate all the arguments of the command and 
	  handle the page fault exception for each thead once the stack reached its limit and terminate the process.

---- RATIONALE ----

>> A3: Why does Pintos implement strtok_r() but not strtok()?

>> A4: In Pintos, the kernel separates commands into a executable name
>> and arguments.  In Unix-like systems, the shell does this
>> separation.  Identify at least two advantages of the Unix approach.

	A3, A4.
	strtok_r(), in this method save pointer save_ptr the output of the method
	when two theads call this function then call strtok() function it might change the save_ptr 
	argument which might leads to race conditions as both the theads trying to update same static variable save_ptr
	whereas strtok_r will return the corresponding save_ptr after each thread execution

			     SYSTEM CALLS
			     ============

---- DATA STRUCTURES ----

>> B1: Copy here the declaration of each new or changed `struct' or
>> `struct' member, global or static variable, `typedef', or
>> enumeration.  Identify the purpose of each in 25 words or less.
	// struct to store the metadata for a file
	struct file_metadata {
	  int fd;
	  int parent_pid;
	  struct file * file;
	  struct list_elem elem;
	};

	struct thread{
		//added to store children
		struct list child_list;
	};

	struct lock file_lock;
	struct lock fd_lock;

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
	
>> B2: Describe how file descriptors are associated with open files.
>> Are file descriptors unique within the entire OS or just within a
>> single process?

Each new open file has been mapped to a single integer value.
In case the file is closed the corresponding value is from the
stored list of numbers. Every process will consist of its 
corresponding set of file descriptor values. File descriptor 
may not be unique to entire OS.

---- ALGORITHMS ----

>> B3: Describe your code for reading and writing user data from the
>> kernel.
	
	Read:
		Check if the pointers to buffer start and end are both valid, if not, exit(-1).
		Acquire the filesystem_lock (file system lock).
		Once current thread holds the lock:
		- If file descriptor is STDOUT_FILENO : release the lock and return -1.
		- Else If file descriptor is STDIN_FILENO : release the lock and return 0.
		- Else, find the open file from the files list. Read the file, get status, release lock and return status.
	
	Write:
		Check if the pointers to buffer start and end are both valid, if not, exit(-1).
		Acquire the filesystem_lock (file system lock).
		Once current thread holds the lock:
		- If file descriptor is STDOUT_FILENO, release the lock and return -1.
		- Else If file descriptor is STDIN_FILENO, print the content of buffer to the console
		- Else, find the open file from the files list. Write buffer to file using file_write() and get status, then release lock and return status

>> B4: Suppose a system call causes a full page (4,096 bytes) of data
>> to be copied from user space into the kernel.  What is the least
>> and the greatest possible number of inspections of the page table
>> (e.g. calls to pagedir_get_page()) that might result?  What about
>> for a system call that only copies 2 bytes of data?  Is there room
>> for improvement in these numbers, and how much?

	Inspections of the page table:
	- least number is 1
	- greatest number is 4096 or 2 (depends on how data is stored)

	For a  system call that only copies 2 bytes of data, inspections of the page table:
	- least number is 1
	- greatest number is 2

>> B5: Briefly describe your implementation of the "wait" system call
>> and how it interacts with process termination.

	After locating the corresponding child thread under the parent thread, we call the function process_wait(). 
	All resources acquired by the child thread will be released when it is terminated.

>> B6: Any access to user program memory at a user-specified address
>> can fail due to a bad pointer value.  Such accesses must cause the
>> process to be terminated.  System calls are fraught with such
>> accesses, e.g. a "write" system call requires reading the system
>> call number from the user stack, then each of the call's three
>> arguments, then an arbitrary amount of user memory, and any of
>> these can fail at any point.  This poses a design and
>> error-handling problem: how do you best avoid obscuring the primary
>> function of code in a morass of error-handling?  Furthermore, when
>> an error is detected, how do you ensure that all temporarily
>> allocated resources (locks, buffers, etc.) are freed?  In a few
>> paragraphs, describe the strategy or strategies you adopted for
>> managing these issues.  Give an example.

	We avoid bad user memory access by verifying before validating.
	We check the buffer start and end pointer, and check if all arugument pointers are in user memory. 
	Terminate the process if invalid.

	

---- SYNCHRONIZATION ----

>> B7: The "exec" system call returns -1 if loading the new executable
>> fails, so it cannot return before the new executable has completed
>> loading.  How does your code ensure this?  How is the load
>> success/failure status passed back to the thread that calls "exec"?

	process->loaded is set as true whenever a new process loading is successful from the API start_process(). In a case where this fails, we set process->failed as true. 
	struct process_status {
	  bool loaded;                        
	  bool exited;                        
	  bool failed;                        
	  bool wait_called;                   
	};
	this struct will be used to maintain the states of a given 
	process.

>> B8: Consider parent process P with child process C.  How do you
>> ensure proper synchronization and avoid race conditions when P
>> calls wait(C) before C exits?  After C exits?  How do you ensure
>> that all resources are freed in each case?  How about when P
>> terminates without waiting, before C exits?  After C exits?  Are
>> there any special cases?

	The parent process P calls wait(c) runs before the child exits. We wait till the child process terminates that is complete or exit or fail. Unitl the above condition is met thread_yeild is continously called. This step is performed to ensure that the Parent waits on the corresponding child even before the child exits.
	If the parent exits without waiting, the child appears to lose control, but the operating system checks its state.
	once a given process status is changed to exited, we call thread_yeild to handle any threads or processes waiting on the current thread and post that the resources of the process are removed.

---- RATIONALE ----

>> B9: Why did you choose to implement access to user memory from the
>> kernel in the way that you did?

	Checking the safe memory access by checking instantly wherever user memory is about to be accessed, and exit with status -1, if it is an invalid access. We chose thos method as it is easy to implemnt.

>> B10: What advantages or disadvantages can you see to your design
>> for file descriptors?
	Having file descriptor, and parent id in the same struct is 
	derived from the rationale that all info needed for file system
related calls are wrapped in a single structure.

>> B11: The default tid_t to pid_t mapping is the identity mapping.
>> If you changed it, what advantages are there to your approach?

	We haven't changed the identity mapping, except special cases
	where process loading fails.

			   SURVEY QUESTIONS
			   ================

Answering these questions is optional, but it will help us improve the
course in future quarters.  Feel free to tell us anything you
want--these questions are just to spur your thoughts.  You may also
choose to respond anonymously in the course evaluations at the end of
the quarter.

>> In your opinion, was this assignment, or any one of the three problems
>> in it, too easy or too hard?  Did it take too long or too little time?

>> Did you find that working on a particular part of the assignment gave
>> you greater insight into some aspect of OS design?

>> Is there some particular fact or hint we should give students in
>> future quarters to help them solve the problems?  Conversely, did you
>> find any of our guidance to be misleading?

>> Do you have any suggestions for the TAs to more effectively assist
>> students, either for future quarters or the remaining projects?

>> Any other comments?