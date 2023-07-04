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
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>

#include "elf64.h"
#include "hw3_part1.h"

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
	int fd = open(exe_file_name, O_RDONLY);
	
	Elf64_Ehdr ElfHeader;
	read(fd, &ElfHeader, sizeof(ElfHeader));

	if(ElfHeader.e_type != ET_EXEC){
		*error_val = -3;
		close(fd);
		return 0;
	}

	Elf64_Shdr SH_StringTableHeader;
	lseek(fd, ElfHeader.e_shoff + ElfHeader.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
	read(fd, &SH_StringTableHeader, sizeof(SH_StringTableHeader));

	char SH_StringTable[SH_StringTableHeader.sh_size];
 	lseek(fd, SH_StringTableHeader.sh_offset, SEEK_SET);
	read(fd, SH_StringTable, SH_StringTableHeader.sh_size);

	// finding the symbol table
	Elf64_Shdr SectionHeader;
	Elf64_Shdr SymbolTableHeader;
	Elf64_Shdr StringTableHeader;
	lseek(fd, ElfHeader.e_shoff, SEEK_SET);
	bool found_symtab = false;
	bool found_strtab = false;

	for(int i = 0; i < ElfHeader.e_shnum; i++){
		read(fd, &SectionHeader, sizeof(SectionHeader));
		if(strcmp(SH_StringTable + SectionHeader.sh_name, ".symtab") == 0){
			found_symtab = true;
			SymbolTableHeader = SectionHeader;
		}
		else if(strcmp(SH_StringTable + SectionHeader.sh_name, ".strtab") == 0){
			found_strtab = true;
			StringTableHeader = SectionHeader;
		}
		lseek(fd, ElfHeader.e_shoff + (i+1) * sizeof(Elf64_Shdr), SEEK_SET);
	}

	if(!found_strtab || !found_symtab){
		*error_val = -1;
		close(fd);
		return 0;
	}

	char StringTable[StringTableHeader.sh_size];
	lseek(fd, StringTableHeader.sh_offset, SEEK_SET);
	read(fd, StringTable, StringTableHeader.sh_size);

	// printf("~~~~~~~~~\n");

	// reading the symbol table
	// might be local, global, neither or both
	Elf64_Sym Symbol;
	Elf64_Sym GlobalSymbol;
	lseek(fd, SymbolTableHeader.sh_offset, SEEK_SET);
	bool local = false;
	bool global = false;

	for(int i = 0; i < SymbolTableHeader.sh_size / sizeof(Elf64_Sym); i++){
		read(fd, &Symbol, sizeof(Symbol));
		// printf("symbol name: %s\n", StringTable + Symbol.st_name);
		if(strcmp(StringTable + Symbol.st_name, symbol_name) == 0){
			// printf("found symbol %s\n", symbol_name);
			if(ELF64_ST_BIND(Symbol.st_info) == 0){
				local = true;
			}
			else if(ELF64_ST_BIND(Symbol.st_info) == 1){
				global = true;
				GlobalSymbol = Symbol;
			}
		}
	}

	// printf("local = %d, global = %d\n", local, global);

	if(!local && !global){
		*error_val = -1;
		close(fd);
		return 0;
	}

	if(local && !global){
		*error_val = -2;
		close(fd);
		return 0;
	}

	// symbol is global (and maybe local)
	// if it's not defined in the executable, it's defined in a shared library
	// checking if it's defined in the executable
	if(GlobalSymbol.st_shndx == 0){
		*error_val = -4;
		close(fd);
		return 0;
	}

	// symbol is defined in the executable
	*error_val = 1;
	close(fd);
	return GlobalSymbol.st_value;
}

// returns GOT entry address of symbol_name
// assumes that symbol_name is a global symbol not defined in the executable
unsigned long find_shared_symbol(char* symbol_name, char* exe_file_name) {
	int fd = open(exe_file_name, O_RDONLY);

	Elf64_Ehdr ElfHeader;
	read(fd, &ElfHeader, sizeof(ElfHeader));

	Elf64_Shdr SH_StringTableHeader;
	lseek(fd, ElfHeader.e_shoff + ElfHeader.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
	read(fd, &SH_StringTableHeader, sizeof(SH_StringTableHeader));

	char SH_StringTable[SH_StringTableHeader.sh_size];
 	lseek(fd, SH_StringTableHeader.sh_offset, SEEK_SET);
	read(fd, SH_StringTable, SH_StringTableHeader.sh_size);

	// finding the dynamic symbol table
	Elf64_Shdr SectionHeader;
	Elf64_Shdr DynamicSymbolTableHeader;
	Elf64_Shdr DynamicStringTableHeader;
	lseek(fd, ElfHeader.e_shoff, SEEK_SET);

	bool found_dynsym = false;
	bool found_dynstr = false;

	for(int i = 0; i < ElfHeader.e_shnum; i++){
		read(fd, &SectionHeader, sizeof(SectionHeader));
		if(strcmp(SH_StringTable + SectionHeader.sh_name, ".dynsym") == 0){
			found_dynsym = true;
			DynamicSymbolTableHeader = SectionHeader;
		}
		else if(strcmp(SH_StringTable + SectionHeader.sh_name, ".dynstr") == 0){
			found_dynstr = true;
			DynamicStringTableHeader = SectionHeader;
		}
		lseek(fd, ElfHeader.e_shoff + (i+1) * sizeof(Elf64_Shdr), SEEK_SET);
	}

	if(!found_dynsym || !found_dynstr){
		close(fd);
		printf("dynamic symbol table not found\n");
		return 0;
	}

	char StringTable[DynamicStringTableHeader.sh_size];
	lseek(fd, DynamicStringTableHeader.sh_offset, SEEK_SET);
	read(fd, StringTable, DynamicStringTableHeader.sh_size);

	// now that we have the dynamic symbol table, we will go over all sections that
	// begin with .rela and look for the symbol in the table
	// if we find it, we will return the address of the GOT entry
	// if we don't find it, we will return 0

	// finding the relocation table

	// printf("~~~~~~~~~\n");

	lseek(fd, ElfHeader.e_shoff, SEEK_SET);

	for(int i = 0; i < ElfHeader.e_shnum; i++){
		read(fd, &SectionHeader, sizeof(SectionHeader));
		if(strncmp(SH_StringTable + SectionHeader.sh_name, ".rela", 5) == 0){
			// printf("found relocation table %s\n", SH_StringTable + SectionHeader.sh_name);
			for (int j = 0; j < SectionHeader.sh_size / sizeof(Elf64_Rela); j++){
				Elf64_Rela Relocation;
				lseek(fd, SectionHeader.sh_offset + j * sizeof(Elf64_Rela), SEEK_SET);
				read(fd, &Relocation, sizeof(Relocation));
				// printf("symbol name: %s\n", StringTable + ELF64_R_SYM(Relocation.r_info));
				// printf("symbol index in dynstr: %ld\n", ELF64_R_SYM(Relocation.r_info));
				// get dynstr symbol
				Elf64_Sym Symbol;
				lseek(fd, DynamicSymbolTableHeader.sh_offset + ELF64_R_SYM(Relocation.r_info) * sizeof(Elf64_Sym), SEEK_SET);
				read(fd, &Symbol, sizeof(Symbol));
				// printf("symbol name: %s\n", StringTable + Symbol.st_name);
				if(strcmp(StringTable + Symbol.st_name, symbol_name) == 0){
					// printf("found symbol %s\n", symbol_name);
					close(fd);
					return Relocation.r_offset;
				}
			}
		}
		lseek(fd, ElfHeader.e_shoff + (i+1) * sizeof(Elf64_Shdr), SEEK_SET);
	}

	close(fd);
	printf("symbol %s not found\n", symbol_name);
	return 0;
}

unsigned long do_nothing(char* symbol_name, char* exe_file_name){
	unsigned long x = 10;
	return 0;
}

// int main(int argc, char *const argv[]) {
// 	int err = 0;
// 	unsigned long addr = find_symbol(argv[1], argv[2], &err);

// 	if (err >= 0)
// 		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
// 	else if (err == -2)
// 		printf("%s is not a global symbol! :(\n", argv[1]);
// 	else if (err == -1)
// 		printf("%s not found!\n", argv[1]);
// 	else if (err == -3)
// 		printf("%s not an executable! :(\n", argv[2]);
// 	else if (err == -4)
// 		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
// 	return 0;
// }