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

void run_undefined_function_debugger_refactored(pid_t child_pid, unsigned long got_func_addr) {
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

    // function was called for the first time
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    counter++;
    printf("PRF:: run #%d first parameter is %d\n", counter, (int)regs.rdi);

    // setting a trap on the return address
    // for us to know that the function really returned,
    // we need to compare RSPs also
    unsigned long rsp_orig = regs.rsp;
    unsigned long ret_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)rsp_orig, NULL);
    unsigned long ret_addr_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)ret_addr, NULL);
    unsigned long ret_addr_trap = (ret_addr_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_addr_trap);

    // we can restore the plt entry now
    ptrace(PTRACE_POKETEXT, child_pid, (void*)plt_instr, (void*)plt_data);

    // to continue, we need to restore the rip
    regs.rip = regs.rip - 1;
    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

    // continue the program
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);

    // each time we get to a trap, we must check if we returned from the function
    // if not, we need to remove the trap, single step, and set the trap again
    while (WIFSTOPPED(wait_status)) {
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        if (regs.rip - 1 == ret_addr && regs.rsp == rsp_orig + 8) {
            ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_addr_data);
            printf("PRF:: run #%d returned with %d\n", counter, (int)regs.rax);
            regs.rip = regs.rip - 1;
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            break;
        }
        else {
            // single stepping manoeuvre
            ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_addr_data);
            regs.rip = regs.rip - 1;
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

            ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            wait(&wait_status);

            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_addr_trap);
            regs.rip = regs.rip - 1;
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            wait(&wait_status);
        }
    }

    // the loader loaded the real address of the function to the GOT entry
    // we can now set a trap on the function itself

    unsigned long real_func_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)got_func_addr, NULL);
    unsigned long func_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)real_func_addr, NULL);
    unsigned long func_data_trap = (func_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)real_func_addr, (void*)func_data_trap);

    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);

    while(WIFSTOPPED(wait_status)) {
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        if (regs.rip - 1 != real_func_addr) {
            printf("Stopped at a wrong address!\n");
            return;
        }
        // we are now at the beginning of the function
        counter++;
        printf("PRF:: run #%d first parameter is %d\n", counter, (int)regs.rdi);
        
        // retrieving the return address from the stack
        unsigned long rsp_orig = regs.rsp;
        unsigned long ret_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)rsp_orig, NULL);

        // restoring rip and removing the trap on the function
        regs.rip = regs.rip - 1;
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
        ptrace(PTRACE_POKETEXT, child_pid, (void*)real_func_addr, (void*)func_data);

        // placing a trap on the return address:
        // we might get to it before the function returns so we must check the RSPs
        unsigned long ret_addr_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)ret_addr, NULL);
        unsigned long ret_addr_trap = (ret_addr_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_addr_trap);

        // we can now continue the program
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);

        // each time we get to a trap, we must check if we returned from the function!!
        while(WIFSTOPPED(wait_status)) {
            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            if (regs.rip - 1 == ret_addr && regs.rsp == rsp_orig + 8) {
                ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_addr_data);
                printf("PRF:: run #%d returned with %d\n", counter, (int)regs.rax);
                regs.rip = regs.rip - 1;
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                break;
            }
            else {
                // single stepping manoeuvre once again
                ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_addr_data);
                regs.rip = regs.rip - 1;
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

                ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
                wait(&wait_status);

                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_addr_trap);
                regs.rip = regs.rip - 1;
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

                ptrace(PTRACE_CONT, child_pid, NULL, NULL);
                wait(&wait_status);
            }
        }
        // restore the trap on the function
        ptrace(PTRACE_POKETEXT, child_pid, (void*)real_func_addr, (void*)func_data_trap);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
    }
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

    pid_t child_pid = run_target(argv[2], argv + 2);

    if (*error_val == -4) {
        symbol_addr = find_shared_symbol(argv[1], argv[2]);
        run_undefined_function_debugger_refactored(child_pid, symbol_addr);
    }
    else {
        run_defined_function_debugger(child_pid, symbol_addr);
    }
}