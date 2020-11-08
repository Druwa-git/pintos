#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);
void exit(int status);
int fibonacci(int n1);
int max_of_four_int(int n1, int n2, int n3, int n4);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf("syscall num %d\n",*(uint32_t*)(f->esp));
  struct thread *t = thread_current();
  //protect user memory accesses from system calls
  //Method 1 : verify the validity of a user-provided pointer
  if(!is_user_vaddr(f->esp)||pagedir_get_page(t->pagedir, f->esp) == NULL)
	  exit(-1);

  //system call
  //1 : halt, exit, exec, wait, read, write
  int system_number = *(int *)(f->esp);
  //hex_dump(f->esp, f->esp, 1000, 1);
  switch (system_number){
	  case SYS_HALT: shutdown_power_off(); break;
	  case SYS_EXIT:
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);
			exit(*(uint32_t *)(f->esp+4)); break;

	  case SYS_EXEC:
			if(!is_user_vaddr(f->esp) || pagedir_get_page(t->pagedir, f->esp) == NULL)
				exit(-1);
			if(!is_user_vaddr(*(char**)(f->esp+4)) || pagedir_get_page(t->pagedir, *(char**)(f->esp+4)) == NULL)
				exit(-1);

			f->eax = process_execute(*(char **)(f->esp +4)); break;

	  case SYS_WAIT:
			if(!is_user_vaddr(f->esp) || pagedir_get_page(t->pagedir, f->esp) == NULL)
				exit(-1);
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);
			f->eax = process_wait(*(tid_t *)(f->esp+4)); break;

	  case SYS_WRITE:
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);
			if(!is_user_vaddr(f->esp+8) || pagedir_get_page(t->pagedir, f->esp+8) == NULL)
				exit(-1);
			if(!is_user_vaddr(f->esp+12) || pagedir_get_page(t->pagedir, f->esp+12) == NULL)
				exit(-1);
			if(!is_user_vaddr((void *)*(uint32_t *)(f->esp+8) || pagedir_get_page(t->pagedir, (void *)*(uint32_t *)(f->esp+8)) == NULL))
				exit(-1);
			if((int)*(uint32_t *)(f->esp+4) == 1){
				putbuf((void *)*(uint32_t *)(f->esp+8), *(size_t *)(f->esp+12));
			}
			break;
	  case SYS_READ:
			break;
	  case SYS_FIBONACCI:
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);

			f->eax = fibonacci(*(int *)(f->esp+4));
			break;
	  case SYS_MAX_OF_FOUR_INT:
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);
			if(!is_user_vaddr(f->esp+8) || pagedir_get_page(t->pagedir, f->esp+8) == NULL)
				exit(-1);
			if(!is_user_vaddr(f->esp+12) || pagedir_get_page(t->pagedir, f->esp+12) == NULL)
				exit(-1);
			if(!is_user_vaddr(f->esp+16) || pagedir_get_page(t->pagedir, f->esp+16) == NULL)
				exit(-1);
			f->eax = max_of_four_int(*(int *)(f->esp+4), *(int *)(f->esp+8), *(int *)(f->esp+12), *(int *)(f->esp+16));
			break;
  }
}

void exit(int status){
	struct thread *t = thread_current();
	t->exit_status = status;
	printf("%s: exit(%d)\n", t->name, status);
	thread_exit();
}

int fibonacci(int n1){
	int a[3]={0};
	a[0] = 0; a[1] = 1;

	if(n1 <= 0)
		exit(-1);
	if(n1 == 1)
		return 0;

	for(int i=0;i<n1-1;i++){
		a[2] = a[0] + a[1];
		a[0] = a[1]; a[1] = a[2];
	}
	return a[2];
}

int max_of_four_int(int n1, int n2, int n3, int n4){
	int max=0;
	if(n1 > n2) max = n1;
	else max = n2;

	if(n3 > max) max = n3;
	if(n4 > max) max = n4;

	return max;
}
