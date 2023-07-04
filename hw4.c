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

pid_t run_target(const char* programname)
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
		execl(programname, programname, NULL);
		
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
// 68fa1e0ff3
void run_undefined_function_debugger(pid_t child_pid, unsigned long got_func_addr){
    int wait_status;
    int counter = 0;
    struct user_regs_struct regs;

    wait(&wait_status);

    // setting trap in the beginning of the plt entry
    unsigned long second_plt_instr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)got_func_addr, NULL);
    printf("second_plt_instr: %lx\n", second_plt_instr);
    // get 8 bytes from second_plt_instr
    unsigned long bytes_8 = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)second_plt_instr, NULL);
    printf("bytes_8: %lx\n", bytes_8);
    unsigned long first_plt_instr = second_plt_instr - 6;
    printf("first_plt_instr: %lx\n", first_plt_instr);
}


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

    pid_t child_pid = run_target(argv[2]);

    if (*error_val == -4) {
        symbol_addr = find_shared_symbol(argv[1], argv[2]);
        printf("symbol addr in hex: %lx\n", symbol_addr);
        run_undefined_function_debugger(child_pid, symbol_addr);
    }
    else {
        run_defined_function_debugger(child_pid, symbol_addr);
    }
}