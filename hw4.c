#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include "elf64.h"

#include "hw3_part1.h"

#define MY_DONE 0

pid_t run_target(const char* programname, char* argv[]) //fix
{
	pid_t pid;
	
	pid = fork();
	
    if (pid > 0) {
		return pid;
		
    } else if (pid == 0) {
		/* Allow tracing of this process */
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
			perror("ptrace");
			exit(1);
		}
		/* Replace this process's image with the given program */
		execvp(programname, argv);
		
	} else {
		// fork error
		perror("fork");
        exit(1);
    }
}

void run_defined_function_debugger(pid_t child_pid, unsigned long func_addr){
    int wait_status;
    int counter = 0;
    struct user_regs_struct regs;

    wait(&wait_status);

    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)func_addr, NULL);
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr, (void*)data_trap);

    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    wait(&wait_status);
    while (WIFSTOPPED(wait_status)) {
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        if (regs.rip - 1 != func_addr) {
            printf("PROBLEM HERE\n");
            printf("rip: %lld\n", regs.rip);
            printf("func_addr: %ld\n", func_addr);
            return;
        }
        counter++;
        unsigned long rsp_orig = regs.rsp;
        // set trap on return address
        unsigned long ret_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)rsp_orig, NULL);
        unsigned long ret_addr_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)ret_addr, NULL);
        unsigned long ret_addr_trap = (ret_addr_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_addr_trap);
        printf("PRF:: run #%d first parameter is %d\n", counter, (int)regs.rdi);
        // restore rip and remove trap
        regs.rip = regs.rip - 1;
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
        ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr, (void*)data);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
        // each time we get to a trap, 
        while (WIFSTOPPED(wait_status)) {
            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            if (regs.rip - 1 == ret_addr && regs.rsp == rsp_orig + 8) {
                // remove trap from return address
                ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_addr_data);
                // restore trap to function address
                ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr, (void*)data_trap);
                // restore rip
                regs.rip = regs.rip - 1;
                printf("PRF:: run #%d returned with %d\n", counter, (int)regs.rax);
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                wait_status = MY_DONE;
                break;
            }
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            wait(&wait_status);
        }

        if (wait_status != MY_DONE) {
            printf("PROBLEM HERE2 (inf loop?)\n");
            return;
        }

        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
    }
}
// f390ffffffe1e9cc
void run_undefined_function_debugger(pid_t child_pid, unsigned long got_func_addr){
    int wait_status;
    int counter = 0;
    struct user_regs_struct regs;

    wait(&wait_status);

    // setting trap in the beginning of the plt entry
    unsigned long plt_instr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)got_func_addr, NULL) - 6;
    unsigned long plt_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)plt_instr, NULL);
    unsigned long plt_trap = (plt_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)plt_instr, (void*)plt_trap);

    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    wait(&wait_status);

    // first plt call of the function
    counter++;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    unsigned long rsp_orig = regs.rsp;
    // set trap on return address
    unsigned long ret_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)rsp_orig, NULL);
    unsigned long ret_addr_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)ret_addr, NULL);
    unsigned long ret_addr_trap = (ret_addr_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_addr_trap);
    printf("PRF:: run #%d first parameter is %d\n", counter, (int)regs.rdi);
    // restore rip and remove trap from plt entry
    regs.rip = regs.rip - 1;
    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
    ptrace(PTRACE_POKETEXT, child_pid, (void*)plt_instr, (void*)plt_data);
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);
    // each time we get to a trap,
    while (WIFSTOPPED(wait_status)) {
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        if (regs.rip - 1 == ret_addr && regs.rsp == rsp_orig + 8) {
            // remove trap from return address
            ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_addr_data);
            // restore rip
            regs.rip = regs.rip - 1;
            printf("PRF:: run #%d returned with %d\n", counter, (int)regs.rax);
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            wait_status = MY_DONE;
            break;
        }
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
    }

    // now we know the real address of the function
    // we need to set a trap on the function itself

    unsigned long real_func_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)got_func_addr, NULL);
    // setting trap in the beginning of the function
    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)real_func_addr, NULL);
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)real_func_addr, (void*)data_trap);

    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    wait(&wait_status);
    while (WIFSTOPPED(wait_status)) {
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        if (regs.rip - 1 != real_func_addr) {
            printf("PROBLEM HERE\n");
            printf("rip: %llx\n", regs.rip);
            printf("func_addr: %lx\n", real_func_addr);
            return;
        }
        counter++;
        unsigned long rsp_orig = regs.rsp;
        ret_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)rsp_orig, NULL);
        unsigned long rbp_orig = regs.rbp;
        // set trap on return address
        // unsigned long ret_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)rsp_orig, NULL);
        // unsigned long ret_addr_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)ret_addr, NULL);
        // unsigned long ret_addr_trap = (ret_addr_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        // ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_addr_trap);
        printf("PRF:: run #%d first parameter is %d\n", counter, (int)regs.rdi);
        // restore rip and remove trap
        regs.rip = regs.rip - 1;
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
        ptrace(PTRACE_POKETEXT, child_pid, (void*)real_func_addr, (void*)data);
        // we will now run single steps in a loop
        // until rip is equal to the return address and rsp is equal to the original rsp
        // this means we have returned from the function
        while (1) {
            ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            wait(&wait_status);
            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            if (regs.rip == ret_addr && regs.rsp == rsp_orig + 8) {
                // we returned from the function, print the return value
                printf("PRF:: run #%d returned with %d\n", counter, (int)regs.rax);
                // set trap on function address
                ptrace(PTRACE_POKETEXT, child_pid, (void*)real_func_addr, (void*)data_trap);
                break;
            }
        }
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
    }
}

/* 401237
00000000004011d4 <main>:
  4011d4:       f3 0f 1e fa             endbr64 
  4011d8:       55                      push   %rbp
  4011d9:       48 89 e5                mov    %rsp,%rbp
  4011dc:       be 00 00 00 00          mov    $0x0,%esi
  4011e1:       bf 65 00 00 00          mov    $0x65,%edi
  4011e6:       e8 5b ff ff ff          callq  401146 <hash>
  4011eb:       be 01 00 00 00          mov    $0x1,%esi
  4011f0:       bf 0b 00 00 00          mov    $0xb,%edi
  4011f5:       e8 4c ff ff ff          callq  401146 <hash>
  4011fa:       bf 05 00 00 00          mov    $0x5,%edi
  4011ff:       e8 7f ff ff ff          callq  401183 <fact>
  401204:       be 03 00 00 00          mov    $0x3,%esi
  401209:       bf f1 ff ff ff          mov    $0xfffffff1,%edi
  40120e:       e8 33 ff ff ff          callq  401146 <hash>
  401213:       bf 00 00 00 00          mov    $0x0,%edi
  401218:       e8 66 ff ff ff          callq  401183 <fact>
  40121d:       bf fe ff ff ff          mov    $0xfffffffe,%edi
  401222:       e8 5c ff ff ff          callq  401183 <fact>
  401227:       be 04 00 00 00          mov    $0x4,%esi
  40122c:       bf ff ff ff ff          mov    $0xffffffff,%edi
  401231:       e8 fa fd ff ff          callq  401030 <comp@plt>
  401236:       be fc ff ff ff          mov    $0xfffffffc,%esi
  40123b:       bf 06 00 00 00          mov    $0x6,%edi
  401240:       e8 eb fd ff ff          callq  401030 <comp@plt>
  401245:       48 c7 c0 08 00 00 00    mov    $0x8,%rax
  40124c:       48 c7 c7 04 00 00 00    mov    $0x4,%rdi
  401253:       e8 4f 00 00 00          callq  4012a7 <uselessFunc>
  401258:       e8 4a 00 00 00          callq  4012a7 <uselessFunc>
  40125d:       48 c7 c0 02 00 00 00    mov    $0x2,%rax
  401264:       bf 03 00 00 00          mov    $0x3,%edi
  401269:       e8 39 00 00 00          callq  4012a7 <uselessFunc>
  40126e:       be 09 00 00 00          mov    $0x9,%esi
  401273:       bf 09 00 00 00          mov    $0x9,%edi
  401278:       e8 b3 fd ff ff          callq  401030 <comp@plt>
  40127d:       bf 05 00 00 00          mov    $0x5,%edi
  401282:       e8 c9 fd ff ff          callq  401050 <recA@plt>
  401287:       be 00 00 00 00          mov    $0x0,%esi
  40128c:       bf 05 00 00 00          mov    $0x5,%edi
  401291:       e8 aa fd ff ff          callq  401040 <recB@plt>
  401296:       bf 07 00 00 00          mov    $0x7,%edi
  40129b:       e8 b0 fd ff ff          callq  401050 <recA@plt>
  4012a0:       b8 00 00 00 00          mov    $0x0,%eax
  4012a5:       5d                      pop    %rbp
  4012a6:       c3                      retq   
*/


/* The main function
    input: argv[1] - name of function to monitor
           argv[2] - name of executable file
           argv[3...] - arguments to executable file
*/
int main(int argc, char* argv[]){
    if (argc < 3) {
        printf("Usage: %s <function name> <executable file> <arguments>\n", argv[0]);
        return 0;
    }

    int* error_val;
    unsigned long symbol_addr = find_symbol(argv[1], argv[2], error_val);
    if (*error_val == -3) {
        printf("PRF:: %s not an executable!\n", argv[2]);
        return 0;
    }
    if (*error_val == -1) {
        printf("PRF:: %s not found! :(\n", argv[1]);
        return 0;
    }
    if (*error_val == -2) {
        printf("PRF:: %s is not a global symbol!\n", argv[1]);
        return 0;
    }

    pid_t child_pid = run_target(argv[2], argv + 2);

    if (*error_val == -4) {
        symbol_addr = find_shared_symbol(argv[1], argv[2]);
        run_undefined_function_debugger(child_pid, symbol_addr);
    }
    else {
        run_defined_function_debugger(child_pid, symbol_addr);
    }
}