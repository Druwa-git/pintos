#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);
void exit(int status);
int fibonacci(int n1);
int max_of_four_int(int n1, int n2, int n3, int n4);

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf("syscall num %d\n",*(uint32_t*)(f->esp));
  struct thread *t = thread_current();
  struct file *fp;
  //protect user memory accesses from system calls
  //Method 1 : verify the validity of a user-provided pointer
  if(!is_user_vaddr(f->esp)||pagedir_get_page(t->pagedir, f->esp) == NULL)
	  exit(-1);

  //system call
  //1 : halt, exit, exec, wait, read, write
  //2 : create, remove, open, close, filesize, read, write, seek, tell
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
			f->eax = process_wait(*(tid_t *)(f->esp+4)); 
			break;
	  
	  case SYS_CREATE:
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);
			if(!is_user_vaddr((*(char**)(f->esp+4))) || pagedir_get_page(t->pagedir, (*(char **)(f->esp+4))) == NULL)
				exit(-1);
			if(!is_user_vaddr(f->esp+8) || pagedir_get_page(t->pagedir, f->esp+8) == NULL)
				exit(-1);
			if(*(char **)(f->esp+4) == NULL) exit(-1);
			f->eax = filesys_create(*(char **)(f->esp+4), *(off_t *)(f->esp+8));
			break;

	  case SYS_REMOVE:
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);
			if(!is_user_vaddr((*(char**)(f->esp+4))) || pagedir_get_page(t->pagedir, (*(char **)(f->esp+4))) == NULL)
				exit(-1);
			if(*(char **)(f->esp+4) == NULL) exit(-1);
			f->eax = filesys_remove(*(char **)(f->esp+4));
			break;

	  case SYS_OPEN:
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);
			if(!is_user_vaddr(*(char**)(f->esp+4)) || pagedir_get_page(t->pagedir, *(char **)(f->esp+4)) == NULL)
				exit(-1);
			if(*(char **)(f->esp+4) == NULL) exit(-1);
			f->eax = -1;
			lock_acquire(&file_lock);
			fp = filesys_open(*(char **)(f->esp+4));
			if(fp == NULL) f->eax = -1;
			else{
				for(int i=3;i<131;i++){
					if(thread_current()->fn[i] == NULL){
						if(!strcmp(thread_current()->name, *(char **)(f->esp+4))) file_deny_write(fp);
						thread_current()->fn[i] = fp;
						f->eax = i;
						break;
					}
				}
			}	
			lock_release(&file_lock);
			break;

	  case SYS_FILESIZE:
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);
			fp = thread_current()->fn[*(int *)(f->esp+4)];
			if(fp == NULL) exit(-1);
			else f->eax = file_length(fp);
			break;

	  case SYS_READ:
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);
			if(!is_user_vaddr(f->esp+8) || pagedir_get_page(t->pagedir, f->esp+8) == NULL)
				exit(-1);
			if(!is_user_vaddr(f->esp+12) || pagedir_get_page(t->pagedir, f->esp+12) == NULL)
				exit(-1);
			if(!is_user_vaddr((*(char **)(f->esp+8))) || pagedir_get_page(t->pagedir, (*(char **)(f->esp+8))) == NULL)
				exit(-1);
			f->eax = -1;//initialize
			lock_acquire(&file_lock);
			if((int)*(uint32_t *)(f->esp+4) == 0){
				for(int i = 0;i< *(int *)(f->esp+12);i++)
					(*(char **)(f->esp+8))[i] = input_getc();
				f->eax = *(int *)(f->esp+12);
			}
			else if((int)*(uint32_t *)(f->esp+4) > 2){
				if(thread_current()->fn[*(int *)(f->esp+4)] == NULL){
					lock_release(&file_lock); 
					exit(-1);
				}
				f->eax = file_read(thread_current()->fn[*(int *)(f->esp+4)], *(void **)(f->esp+8), *(off_t *)(f->esp+12));
			}
			lock_release(&file_lock);
			break;

	  case SYS_WRITE:
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);
			if(!is_user_vaddr(f->esp+8) || pagedir_get_page(t->pagedir, f->esp+8) == NULL)
				exit(-1);
			if(!is_user_vaddr(f->esp+12) || pagedir_get_page(t->pagedir, f->esp+12) == NULL)
				exit(-1);
			if(!is_user_vaddr((void *)*(uint32_t *)(f->esp+8) || pagedir_get_page(t->pagedir, (void *)*(uint32_t *)(f->esp+8)) == NULL))
				exit(-1);
			f->eax = -1;
			lock_acquire(&file_lock);
			if((int)*(uint32_t *)(f->esp+4) == 1){
				putbuf((void *)*(uint32_t *)(f->esp+8), *(size_t *)(f->esp+12));
			}
			else if((int)*(uint32_t *)(f->esp+4) > 2){
				if(thread_current()->fn[*(int *)(f->esp+4)] == NULL){ 
					lock_release(&file_lock); exit(-1);
				}
				if(thread_current()->fn[*(int *)(f->esp+4)]->deny_write) 
					file_deny_write(thread_current()->fn[*(int *)(f->esp+4)]);
				f->eax = file_write(thread_current()->fn[*(int *)(f->esp+4)], *(void **)(f->esp+8), *(off_t *)(f->esp+12));
			}
			lock_release(&file_lock);
			break;

	  case SYS_SEEK:
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);
			if(!is_user_vaddr(f->esp+8) || pagedir_get_page(t->pagedir, f->esp+8) == NULL)
				exit(-1);
			if(thread_current()->fn[*(int *)(f->esp+4)] == NULL) exit(-1);
			file_seek(thread_current()->fn[*(int *)(f->esp+4)], *(off_t *)(f->esp+8));
			break;

	  case SYS_TELL:
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);
			if(thread_current()->fn[*(int *)(f->esp+4)] == NULL) exit(-1);
			f->eax = file_tell(thread_current()->fn[*(int *)(f->esp+4)]);
			break;

	  case SYS_CLOSE:
			if(!is_user_vaddr(f->esp+4) || pagedir_get_page(t->pagedir, f->esp+4) == NULL)
				exit(-1);
			if(thread_current()->fn[*(int *)(f->esp+4)] == NULL) exit(-1);
			//lock_acquire(&file_lock);
			file_close(thread_current()->fn[*(int *)(f->esp+4)]);
			thread_current()->fn[*(int *)(f->esp+4)] = NULL;//close file
			//lock_release(&file_lock);
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
